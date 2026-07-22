// BASELINE / DIFF MODE — accept existing debt once, then report only NEW findings.
// The key property: matching is line-INDEPENDENT, so moving code doesn't resurface
// accepted debt, but a genuinely new issue is still caught. This is what lets a large
// legacy repo gate CI on regressions instead of drowning in pre-existing findings.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { scan } from '../src/index.js';
import { writeBaseline, loadBaseline, diffAgainstBaseline, baselineKey } from '../src/core/baseline.js';
import { Finding } from '../src/core/finding.js';

async function repo(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'alltest-bl-'));
  for (const [n, c] of Object.entries(files)) await fs.writeFile(path.join(dir, n), c);
  return dir;
}

test('baselineKey is independent of line number', () => {
  const a = new Finding({ probe: 'p', ruleId: 'r', severity: 'high', title: 't', snippet: 'eval(x)', file: 'a.js', line: 1 });
  const b = new Finding({ probe: 'p', ruleId: 'r', severity: 'high', title: 't', snippet: 'eval(x)', file: 'a.js', line: 99 });
  assert.equal(baselineKey(a), baselineKey(b), 'same issue, different line → same key');
});

test('write + load baseline round-trips the keys', async () => {
  const dir = await repo({});
  const file = path.join(dir, 'baseline.json');
  const findings = [
    new Finding({ probe: 'p', ruleId: 'eval-use', severity: 'high', title: 't', snippet: 'eval(a)', file: 'a.js', line: 1 }),
    new Finding({ probe: 'p', ruleId: 'aws', severity: 'critical', title: 't', snippet: 'AKIA...', file: 'b.js', line: 5 }),
  ];
  const n = await writeBaseline(file, findings, { root: dir });
  assert.equal(n, 2);
  const bl = await loadBaseline(file);
  assert.equal(bl.count, 2);
  assert.ok(bl.keys.has(baselineKey(findings[0])));
});

test('diff splits new vs baselined and counts fixed', () => {
  const f1 = new Finding({ probe: 'p', ruleId: 'eval-use', severity: 'high', title: 't', snippet: 'eval(a)', file: 'a.js', line: 1 });
  const f2 = new Finding({ probe: 'p', ruleId: 'aws', severity: 'critical', title: 't', snippet: 'AKIA', file: 'b.js', line: 5 });
  const baseline = { keys: new Set([baselineKey(f1), baselineKey({ probe: 'p', ruleId: 'gone', file: 'c.js', signature: 'p::gone::any::x' })]) };
  const { isNew, baselined, fixedCount } = diffAgainstBaseline([f1, f2], baseline);
  assert.equal(baselined.length, 1, 'f1 is in the baseline');
  assert.equal(isNew.length, 1, 'f2 is new');
  assert.equal(isNew[0].ruleId, 'aws');
  assert.equal(fixedCount, 1, 'the "gone" baseline entry is no longer present → fixed');
});

test('incremental: onlyFiles restricts the scan to the given allowlist', async () => {
  const dir = await repo({
    'a.js': 'const k = "AKIAQZ7W2E9R4T6Y8UOP";\n',   // has a finding
    'b.js': 'const x = eval(y);\n',                    // has a finding
  });
  const all = await scan({ root: dir });
  assert.ok(all.fileCount >= 2);
  const only = await scan({ root: dir, onlyFiles: ['b.js'] });
  assert.equal(only.fileCount, 1, 'only b.js scanned');
  assert.ok(only.findings.every((f) => f.file === 'b.js'), 'no findings from excluded files');
  assert.ok(only.findings.some((f) => f.ruleId === 'eval-use'));
});

test('end-to-end: moving accepted code does not create a "new" finding; a real new issue does', async () => {
  const dir = await repo({ 'app.js': 'const x = eval(a);\n' });
  const file = path.join(dir, 'baseline.json');
  const first = await scan({ root: dir });
  await writeBaseline(file, first.findings, { root: dir });

  // move eval to a later line AND add a brand-new hardcoded AWS key
  await fs.writeFile(path.join(dir, 'app.js'), '// a\n// b\nconst k = "AKIAQZ7W2E9R4T6Y8UOP";\nconst x = eval(a);\n');
  const second = await scan({ root: dir });
  const bl = await loadBaseline(file);
  const { isNew } = diffAgainstBaseline(second.findings, bl);

  const newRules = new Set(isNew.map((f) => f.ruleId));
  assert.ok(newRules.has('aws-access-key'), 'the new AWS key is reported as new');
  assert.ok(!newRules.has('eval-use'), 'the moved (accepted) eval is NOT reported as new');
});
