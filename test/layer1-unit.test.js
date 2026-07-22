// LAYER 1 — unit tests: the tests FOR the tester.
// Every core module and every probe is verified against ground-truth fixtures with
// KNOWN planted issues. If a probe stops catching its planted vuln, or starts flagging
// clean code, these fail.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/index.js';
import { Finding, SEVERITY, signatureOf, dedupeFindings, compareFindings } from '../src/core/finding.js';
import { ProbeRegistry, validateProbe } from '../src/core/probe.js';
import { detectLanguage } from '../src/core/lang.js';
import { walk } from '../src/core/walker.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VULN = path.join(__dirname, 'fixtures', 'vulnerable-app');
const CLEAN = path.join(__dirname, 'fixtures', 'clean-app');

// ---- core: Finding model ----
test('Finding requires mandatory fields', () => {
  assert.throws(() => new Finding({}), /probe/);
  assert.throws(() => new Finding({ probe: 'p' }), /ruleId/);
  assert.throws(() => new Finding({ probe: 'p', ruleId: 'r', severity: 'bogus', title: 't' }), /severity/);
  const f = new Finding({ probe: 'p', ruleId: 'r', severity: 'high', title: 't' });
  assert.equal(f.severityRank, SEVERITY.high);
  assert.ok(f.signature.includes('p::r'));
});

test('Finding.toRecord is a stable ML row', () => {
  const f = new Finding({ probe: 'p', ruleId: 'r', severity: 'low', title: 't', snippet: 'x', language: 'javascript' });
  const rec = f.toRecord();
  assert.equal(rec.probe, 'p');
  assert.equal(rec.severity, 'low');
  assert.ok('signature' in rec && 'confidence' in rec && 'tags' in rec);
});

test('signature collapses trivially-different snippets', () => {
  const a = signatureOf({ probe: 'x', ruleId: 'y', snippet: 'const key = "aaaa1111"' });
  const b = signatureOf({ probe: 'x', ruleId: 'y', snippet: 'const key = "bbbb2222"' });
  assert.equal(a, b, 'identifiers/strings/numbers should normalize to the same signature');
});

test('dedupeFindings + compareFindings order worst-first', () => {
  const mk = (sev, file, line) => new Finding({ probe: 'p', ruleId: 'r', severity: sev, title: 't', file, line });
  const list = [mk('low', 'a.js', 1), mk('critical', 'b.js', 2), mk('low', 'a.js', 1)];
  const sorted = dedupeFindings(list).sort(compareFindings);
  assert.equal(sorted.length, 2, 'duplicate (a.js:1) collapsed');
  assert.equal(sorted[0].severity, 'critical');
});

// ---- core: probe registry ----
test('ProbeRegistry validates and orders probes', () => {
  const reg = new ProbeRegistry();
  reg.register({ id: 'static/a', title: 'A', layer: 'static', order: 2, run() {} });
  reg.register({ id: 'meta/z', title: 'Z', layer: 'meta', run() {} });
  reg.register({ id: 'static/b', title: 'B', layer: 'static', order: 1, run() {} });
  const sel = reg.select();
  assert.deepEqual(sel.map((p) => p.id), ['static/b', 'static/a', 'meta/z'], 'layer then order');
  assert.throws(() => reg.register({ id: 'x', title: 'x', layer: 'nope', run() {} }), /layer/);
  assert.throws(() => validateProbe({ id: 'x', layer: 'static', title: 't' }), /run/);
});

// ---- core: language + walker ----
test('detectLanguage covers key languages', () => {
  assert.equal(detectLanguage('a/b.sol'), 'solidity');
  assert.equal(detectLanguage('x.tsx'), 'typescript');
  assert.equal(detectLanguage('Dockerfile'), 'dockerfile');
  assert.equal(detectLanguage('.env.production'), 'dotenv');
});

test('walker finds fixture files and skips ignored dirs', async () => {
  const files = await walk(VULN);
  const names = files.map((f) => f.path);
  assert.ok(names.includes('config.js'));
  assert.ok(names.includes('Vault.sol'));
  assert.ok(!names.some((n) => n.includes('node_modules')));
});

// ---- probes vs ground truth ----
// helper: rules that fired on the vulnerable fixture
async function vulnRules() {
  const r = await scan({ root: VULN });
  return new Set(r.findings.map((f) => f.ruleId));
}

test('secrets probe catches planted secrets', async () => {
  const rules = await vulnRules();
  for (const expected of ['aws-access-key', 'github-token', 'hardcoded-password', 'connection-string-creds']) {
    assert.ok(rules.has(expected), `expected secrets rule "${expected}" to fire`);
  }
});

test('secrets probe does NOT flag generated / env-sourced values', async () => {
  const r = await scan({ root: VULN });
  const hp = r.findings.filter((f) => f.ruleId === 'hardcoded-password');
  // config.js has exactly one real hardcoded password (dbPassword); apiKey/authSecret are excluded
  assert.ok(hp.every((f) => f.snippet.includes('dbPassword') || !f.snippet.includes('apiKey')), 'must not flag generated apiKey');
  assert.ok(!hp.some((f) => f.snippet.includes('process.env')), 'must not flag env-sourced secret');
});

test('dangerous-js probe catches injection patterns', async () => {
  const rules = await vulnRules();
  for (const expected of ['eval-use', 'child-process-concat', 'sql-concat', 'disable-tls-verify']) {
    assert.ok(rules.has(expected), `expected dangerous-js rule "${expected}" to fire`);
  }
});

test('dangerous-js does NOT flag parameterized queries', async () => {
  const r = await scan({ root: VULN });
  const sql = r.findings.filter((f) => f.ruleId === 'sql-concat');
  // exactly one real concat (the "'... " + userInput); the parameterized ones are skipped
  assert.equal(sql.length, 1, `expected exactly 1 sql-concat, got ${sql.length}: ${sql.map((f) => f.line)}`);
});

test('solidity probe catches contract vulns', async () => {
  const rules = await vulnRules();
  for (const expected of ['tx-origin-auth', 'blockhash-randomness', 'selfdestruct', 'floating-pragma', 'unchecked-low-level-call']) {
    assert.ok(rules.has(expected), `expected solidity rule "${expected}" to fire`);
  }
});

test('deps probe catches manifest risks', async () => {
  const rules = await vulnRules();
  for (const expected of ['wildcard-dependency', 'missing-lockfile', 'install-script-hook']) {
    assert.ok(rules.has(expected), `expected deps rule "${expected}" to fire`);
  }
});

test('fuzz/json-roundtrip catches malformed JSON', async () => {
  const rules = await vulnRules();
  assert.ok(rules.has('malformed-json'), 'expected malformed-json on data-broken.json');
});

// ---- the false-positive guard: clean code must be clean ----
test('clean fixture produces ZERO findings at/above low', async () => {
  const r = await scan({ root: CLEAN });
  const real = r.findings.filter((f) => f.severityRank >= SEVERITY.low);
  assert.equal(real.length, 0, `clean app should be clean, got: ${real.map((f) => f.ruleId + '@' + f.file + ':' + f.line).join(', ')}`);
});

// ---- probe isolation: a throwing probe must not kill the run ----
test('a crashing probe is isolated and reported, run still completes', async () => {
  const boom = { id: 'static/boom', title: 'Boom', layer: 'static', run() { throw new Error('kaboom'); } };
  const r = await scan({ root: CLEAN, extraProbes: [boom] });
  assert.ok(r.summary.probesErrored.includes('static/boom'), 'errored probe recorded');
  assert.ok(r.probeRuns.find((p) => p.id === 'static/boom').error.includes('kaboom'));
});
