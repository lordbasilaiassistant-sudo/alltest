// ROBUSTNESS — hostile & degenerate inputs must never crash the engine.
// A scanner that dies on a weird repo is useless in the wild. These assert graceful
// behavior on the inputs real codebases actually contain.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { scan } from '../src/index.js';
import { walk } from '../src/core/walker.js';
import { shannonEntropy, classifySecretCandidate } from '../src/core/entropy.js';

async function tmpdir() {
  return fs.mkdtemp(path.join(os.tmpdir(), 'alltest-rob-'));
}

test('nonexistent path does not throw; returns empty scan', async () => {
  const r = await scan({ root: path.join(os.tmpdir(), 'definitely-does-not-exist-' + Math.random().toString(36).slice(2)) });
  assert.equal(r.findings.length, 0);
  assert.equal(r.fileCount, 0);
});

test('empty directory scans cleanly', async () => {
  const dir = await tmpdir();
  const r = await scan({ root: dir });
  assert.equal(r.findings.length, 0);
  assert.equal(r.summary.total, 0);
});

test('single-file target scans just that file', async () => {
  const dir = await tmpdir();
  const f = path.join(dir, 'lonely.js');
  await fs.writeFile(f, 'const x = eval(y);\n');
  const files = await walk(f);
  assert.equal(files.length, 1);
  assert.equal(files[0].path, 'lonely.js');
  const r = await scan({ root: f });
  assert.ok(r.findings.some((x) => x.ruleId === 'eval-use'));
});

test('binary / non-UTF8 file does not crash the scan', async () => {
  const dir = await tmpdir();
  await fs.writeFile(path.join(dir, 'data.json'), Buffer.from([0x00, 0xff, 0xfe, 0x01, 0x02, 0x7b, 0x00]));
  await fs.writeFile(path.join(dir, 'ok.js'), 'const a = 1;\n');
  const r = await scan({ root: dir });
  assert.ok(Array.isArray(r.findings), 'scan completed without throwing');
});

test('file with extremely long lines (minified) does not hang', async () => {
  const dir = await tmpdir();
  const huge = 'var a=' + 'x'.repeat(500000) + ';';
  await fs.writeFile(path.join(dir, 'app.min.js'), huge); // .min.js is ignored by walker
  await fs.writeFile(path.join(dir, 'big.js'), huge);
  const start = Date.now();
  const r = await scan({ root: dir });
  assert.ok(Date.now() - start < 10000, 'must not hang on long lines');
  assert.ok(Array.isArray(r.findings));
});

test('hostile filenames and deep nesting are handled', async () => {
  const dir = await tmpdir();
  const deep = path.join(dir, 'a', 'b', 'c', 'd', 'e');
  await fs.mkdir(deep, { recursive: true });
  await fs.writeFile(path.join(deep, 'we ird $ na(me).js'), 'const x = eval(z);\n');
  const r = await scan({ root: dir });
  assert.ok(r.findings.some((f) => f.ruleId === 'eval-use'), 'finds vuln in weirdly-named deep file');
});

test('walker does not mutate the shared default ignore set across scans', async () => {
  // Two repos with different .gitignore dir entries; the second must not inherit the first.
  const a = await tmpdir();
  await fs.writeFile(path.join(a, '.gitignore'), 'onlyinA\n');
  await fs.mkdir(path.join(a, 'onlyinA'));
  await fs.writeFile(path.join(a, 'onlyinA', 'x.js'), 'const p = 1;\n');
  await walk(a);

  const b = await tmpdir();
  await fs.mkdir(path.join(b, 'onlyinA'));
  await fs.writeFile(path.join(b, 'onlyinA', 'y.js'), 'const q = 2;\n');
  const files = await walk(b);
  assert.ok(files.some((f) => f.path === 'onlyinA/y.js'), 'repo B must NOT inherit repo A gitignore dir "onlyinA"');
});

test('a probe that hangs is killed by the per-probe timeout', async () => {
  const dir = await tmpdir();
  await fs.writeFile(path.join(dir, 'a.js'), 'const a=1;\n');
  const hang = { id: 'static/hang', title: 'hang', layer: 'static', run: () => new Promise(() => {}) };
  const r = await scan({ root: dir, extraProbes: [hang], probeTimeout: 300 });
  assert.ok(r.summary.probesErrored.includes('static/hang'), 'hanging probe timed out and was recorded');
});

// ---- entropy math ----
test('shannonEntropy is correct for known inputs', () => {
  assert.equal(shannonEntropy(''), 0);
  assert.equal(shannonEntropy('aaaa'), 0, 'uniform char → 0 entropy');
  assert.equal(shannonEntropy('ab'), 1, 'two equally-likely chars → 1 bit');
  assert.ok(shannonEntropy('abcd') === 2, '4 equal chars → 2 bits');
});

test('classifySecretCandidate suppresses benign high-entropy strings', () => {
  // git SHA-256 without secret context → not a secret
  assert.equal(classifySecretCandidate('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'const commit = "..."', 'commit'), null);
  // UUID → not a secret
  assert.equal(classifySecretCandidate('550e8400-e29b-41d4-a716-446655440000', 'id = "..."', 'id'), null);
  // real-looking token in a key var → flagged
  const hit = classifySecretCandidate('a8Jd0fKq2Lm9Xz7Wp3Rt6Yv1Bn4Cs5Eh', 'const apiKey = "..."', 'apiKey');
  assert.ok(hit && hit.secretName, 'secret-named high-entropy token is flagged');
});
