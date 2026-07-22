// Ignore-system + reporter tests. The ignore layer is load-bearing (it's how the tool
// stays quiet on false positives); the reporters are the machine-facing contract
// (SARIF for CI, JSONL for ML, JSON for agents).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { scan } from '../src/index.js';
import { render, renderSarif, renderJsonl } from '../src/core/report.js';

async function mkRepo(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'alltest-ig-'));
  for (const [name, content] of Object.entries(files)) {
    const p = path.join(dir, name);
    await fs.mkdir(path.dirname(p), { recursive: true });
    await fs.writeFile(p, content);
  }
  return dir;
}

test('inline // alltest-ignore suppresses a finding on that line', async () => {
  const clean = await mkRepo({
    'a.js': `const x = eval(inp); // ok\n`,
    'b.js': `const y = eval(inp); // alltest-ignore\n`,
  });
  const r = await scan({ root: clean });
  const evals = r.findings.filter((f) => f.ruleId === 'eval-use');
  assert.equal(evals.length, 1, 'only the un-ignored eval should be reported');
  assert.equal(evals[0].file, 'a.js');
  assert.ok(r.suppressed >= 1, 'suppression counted');
});

test('alltest-disable-next-line suppresses the following line', async () => {
  const repo = await mkRepo({
    'a.js': `// alltest-disable-next-line\nconst y = eval(inp);\n`,
  });
  const r = await scan({ root: repo });
  assert.equal(r.findings.filter((f) => f.ruleId === 'eval-use').length, 0);
});

test('rule-specific disable only suppresses that rule', async () => {
  const repo = await mkRepo({
    // eval-use ignored by name, but debugger on same line is not
    'a.js': `eval(x); debugger; // alltest-disable-line eval-use\n`,
  });
  const r = await scan({ root: repo });
  const rules = new Set(r.findings.map((f) => f.ruleId));
  assert.ok(!rules.has('eval-use'), 'eval-use suppressed by name');
  assert.ok(rules.has('debugger-stmt'), 'debugger still reported');
});

test('.alltestignore excludes whole paths', async () => {
  const repo = await mkRepo({
    '.alltestignore': `secrets/\n`,
    'secrets/leak.js': `const AWS='AKIAQZ7W2E9R4T6Y8UOP';\n`,
    'app.js': `const AWS='AKIAQZ7W2E9R4T6Y8UOP';\n`,
  });
  const r = await scan({ root: repo });
  const files = new Set(r.findings.map((f) => f.file));
  assert.ok(files.has('app.js'), 'app.js scanned');
  assert.ok(![...files].some((f) => f && f.startsWith('secrets/')), 'secrets/ path excluded');
});

// ---- reporters ----
test('SARIF output is valid and well-formed', async () => {
  const repo = await mkRepo({ 'a.js': `const x = eval(inp);\n` });
  const r = await scan({ root: repo });
  const sarif = JSON.parse(renderSarif(r, { version: '9.9.9' }));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].tool.driver.name, 'alltest');
  assert.ok(sarif.runs[0].results.length >= 1);
  assert.ok(sarif.runs[0].results[0].ruleId);
  assert.ok(['error', 'warning', 'note'].includes(sarif.runs[0].results[0].level));
});

test('JSONL reporter emits one valid JSON object per finding', async () => {
  const repo = await mkRepo({ 'a.js': `const x = eval(inp);\nconst AWS='AKIAQZ7W2E9R4T6Y8UOP';\n` });
  const r = await scan({ root: repo });
  const jsonl = renderJsonl(r);
  const lines = jsonl.split('\n').filter(Boolean);
  assert.ok(lines.length >= 1);
  for (const l of lines) {
    const obj = JSON.parse(l);
    assert.ok(obj.ruleId && obj.severity && 'signature' in obj);
  }
});

test('table + markdown render without throwing', async () => {
  const repo = await mkRepo({ 'a.js': `const x = eval(inp);\n` });
  const r = await scan({ root: repo });
  assert.ok(render(r, 'table', { color: false }).includes('alltest'));
  assert.ok(render(r, 'markdown').includes('# alltest report'));
});
