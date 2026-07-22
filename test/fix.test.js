// FIX ENGINE — proves findings carry ACTUAL fixes (before→after), that auto-fixes are
// safe and produce valid code, and that applying them clears the findings.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { scan, applyFixes, fixForFinding } from '../src/index.js';
import { toEnvName } from '../src/core/fix.js';

async function repo(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'alltest-fix-'));
  for (const [n, c] of Object.entries(files)) {
    const p = path.join(dir, n);
    await fs.mkdir(path.dirname(p), { recursive: true });
    await fs.writeFile(p, c);
  }
  return dir;
}
async function fixes(dir) {
  const r = await scan({ root: dir, withFixes: true });
  return r.findings;
}
const fixFor = (findings, ruleId) => (findings.find((f) => f.ruleId === ruleId) || {}).fix;

test('toEnvName maps identifiers to SCREAMING_SNAKE', () => {
  assert.equal(toEnvName('dbPassword'), 'DB_PASSWORD');
  assert.equal(toEnvName('API_KEY'), 'API_KEY');
  assert.equal(toEnvName('stripe-secret'), 'STRIPE_SECRET');
  assert.equal(toEnvName('client.secret'), 'CLIENT_SECRET');
});

test('disable-tls fix removes the option, leaving valid object', async () => {
  const dir = await repo({ 'a.js': 'const o = { rejectUnauthorized: false };\n' });
  const fix = fixFor(await fixes(dir), 'disable-tls-verify');
  assert.ok(fix, 'fix produced');
  assert.equal(fix.autoApplicable, true);
  assert.ok(!/rejectUnauthorized/.test(fix.replacement), 'option removed');
});

test('yaml.load fix uses safe_load and drops the Loader kwarg (valid code)', async () => {
  const dir = await repo({ 'c.py': 'data = yaml.load(open("f"), Loader=yaml.Loader)\n' });
  const fix = fixFor(await fixes(dir), 'py-yaml-load');
  assert.ok(fix);
  assert.equal(fix.replacement.trim(), 'data = yaml.safe_load(open("f"))');
  assert.ok(!/Loader/.test(fix.replacement), 'safe_load must not carry a Loader arg');
});

test('debugger fix deletes the statement', async () => {
  const dir = await repo({ 'a.js': 'debugger;\n' });
  const fix = fixFor(await fixes(dir), 'debugger-stmt');
  assert.ok(fix && fix.autoApplicable);
  assert.ok(fix.strategy === 'delete-line' || (fix.replacement || '').trim() === '');
});

test('tx.origin fix rewrites to msg.sender', async () => {
  const dir = await repo({ 'V.sol': 'contract V { function a() public { require(tx.origin == owner); } }\n' });
  const fix = fixFor(await fixes(dir), 'tx-origin-auth');
  assert.ok(fix);
  assert.ok(/msg\.sender/.test(fix.replacement) && !/tx\.origin/.test(fix.replacement));
});

test('hardcoded secret fix moves value to process.env with a derived name', async () => {
  const dir = await repo({ 'a.js': 'const dbPassword = "sup3rSecretValue!";\n' });
  const fix = fixFor(await fixes(dir), 'hardcoded-password');
  assert.ok(fix, 'secret fix produced');
  assert.equal(fix.autoApplicable, false, 'secret replacement needs review (env must be set)');
  assert.ok(/process\.env\.DB_PASSWORD/.test(fix.replacement));
  assert.ok(/ROTATE/i.test(fix.note), 'note reminds to rotate');
});

test('missing-gitignore fix creates a .gitignore', async () => {
  const dir = await repo({ 'package.json': '{"name":"x","version":"1.0.0"}\n', 'a.js': 'const x=1;\n' });
  const fix = fixFor(await fixes(dir), 'missing-gitignore');
  assert.ok(fix && fix.strategy === 'create-file');
  assert.ok(/\.env/.test(fix.replacement));
});

test('every fix carries a unified-diff patch and a plain-language note', async () => {
  const dir = await repo({ 'a.js': 'const o = { rejectUnauthorized: false };\ndebugger;\n' });
  for (const f of (await fixes(dir)).filter((x) => x.fix)) {
    assert.ok(f.fix.note && f.fix.note.length > 8, `note for ${f.ruleId}`);
    assert.ok(typeof f.fix.patch === 'string', `patch for ${f.ruleId}`);
  }
});

test('applyFixes writes safe fixes and they clear on re-scan', async () => {
  const dir = await repo({
    'a.js': 'const o = { rejectUnauthorized: false };\ndebugger;\nconst keep = 1;\n',
    'c.py': 'import yaml\nx = yaml.load(f, Loader=yaml.Loader)\ny = requests.get(u, verify=False)\n',
  });
  const before = await scan({ root: dir });
  const beforeRules = new Set(before.findings.map((f) => f.ruleId));
  assert.ok(beforeRules.has('disable-tls-verify') && beforeRules.has('py-yaml-load'));

  const { applied } = await applyFixes(dir, before.findings, { minConfidence: 0.7 });
  assert.ok(applied.length >= 4, `applied ${applied.length} fixes`);

  const after = await scan({ root: dir });
  const afterRules = new Set(after.findings.map((f) => f.ruleId));
  for (const cleared of ['disable-tls-verify', 'debugger-stmt', 'py-yaml-load', 'py-requests-noverify']) {
    assert.ok(!afterRules.has(cleared), `${cleared} should be fixed and gone`);
  }
  // untouched code preserved
  const a = await fs.readFile(path.join(dir, 'a.js'), 'utf8');
  assert.ok(a.includes('const keep = 1;'), 'unrelated code preserved');
});

test('applyFixes dry-run does not modify files', async () => {
  const dir = await repo({ 'a.js': 'debugger;\nconst x=1;\n' });
  const before = await fs.readFile(path.join(dir, 'a.js'), 'utf8');
  const r = await scan({ root: dir });
  await applyFixes(dir, r.findings, { dryRun: true });
  const after = await fs.readFile(path.join(dir, 'a.js'), 'utf8');
  assert.equal(before, after, 'dry-run must not write');
});
