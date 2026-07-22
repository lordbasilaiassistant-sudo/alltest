// CUSTOM RULES + RSI rule synthesis — extensible detection (no code) and the closed
// end of the self-improvement loop (learned signatures → reviewable rule drafts).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { scan } from '../src/index.js';
import { learnFromResult, promoteCandidates, synthesizeRuleProposals } from '../src/rsi/learn.js';
import { Finding } from '../src/core/finding.js';

async function repo(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'alltest-cr-'));
  for (const [n, c] of Object.entries(files)) {
    const p = path.join(dir, n);
    await fs.mkdir(path.dirname(p), { recursive: true });
    await fs.writeFile(p, c);
  }
  return dir;
}
const rules = (r) => new Set(r.findings.map((f) => f.ruleId));

test('custom rule from .alltest/rules.json is loaded and fires', async () => {
  const dir = await repo({
    '.alltest/rules.json': JSON.stringify([{ id: 'no-foo', pattern: 'FORBIDDEN_FN\\(', severity: 'high', title: 'Forbidden function', fixHint: 'Use the approved API.' }]),
    'a.js': 'FORBIDDEN_FN(x);\nconst ok = 1;\n',
  });
  const r = await scan({ root: dir });
  const f = r.findings.find((x) => x.ruleId === 'no-foo');
  assert.ok(f, 'custom rule fired');
  assert.equal(f.severity, 'high');
  assert.ok(f.tags.includes('custom'));
});

test('custom rule honors a language filter', async () => {
  const dir = await repo({
    '.alltest/rules.json': JSON.stringify([{ id: 'py-only', pattern: 'MARKER', severity: 'low', title: 'x', languages: ['python'] }]),
    'a.js': 'MARKER\n', 'b.py': 'MARKER\n',
  });
  const r = await scan({ root: dir });
  const hits = r.findings.filter((f) => f.ruleId === 'py-only');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].file, 'b.py');
});

test('a malformed rules file yields a finding, not a crash', async () => {
  const dir = await repo({ '.alltest/rules.json': '{ not valid json', 'a.js': 'const x=1;\n' });
  const r = await scan({ root: dir });
  assert.ok(rules(r).has('custom-rules-invalid'), 'reports invalid rules file');
});

test('a bad regex in a rule is reported, other rules still run', async () => {
  const dir = await repo({
    '.alltest/rules.json': JSON.stringify([
      { id: 'bad', pattern: '(', severity: 'low', title: 'bad regex' },
      { id: 'good', pattern: 'HITME', severity: 'medium', title: 'ok' },
    ]),
    'a.js': 'HITME\n',
  });
  const r = await scan({ root: dir });
  assert.ok(rules(r).has('custom-rule-bad-regex'), 'bad regex reported');
  assert.ok(rules(r).has('good'), 'good rule still ran');
});

test('rule schema is validated (missing pattern rejected)', async () => {
  const dir = await repo({ '.alltest/rules.json': JSON.stringify([{ id: 'x', severity: 'low', title: 't' }]), 'a.js': 'x\n' });
  const r = await scan({ root: dir });
  assert.ok(rules(r).has('custom-rules-invalid'));
});

// ---- RSI: learned signatures → rule proposals ----
test('RSI synthesizes reviewable rule proposals from repeated signatures', async () => {
  const kbPath = path.join(await fs.mkdtemp(path.join(os.tmpdir(), 'kb-')), 'kb.jsonl');
  const mk = () => ({ findings: [new Finding({ probe: 'static/x', ruleId: 'weird-call', severity: 'medium', title: 'weird', snippet: 'dangerousCall("literal", 42)', language: 'javascript', file: 'a.js', line: 1 })] });
  for (let i = 0; i < 3; i++) await learnFromResult(mk(), { kbPath });
  await promoteCandidates(3, { kbPath });
  const proposals = await synthesizeRuleProposals({ kbPath, minCount: 3 });
  assert.ok(proposals.length >= 1, 'at least one proposal');
  const p = proposals[0];
  assert.ok(p.id.startsWith('learned-'));
  assert.ok(p.pattern && p.pattern.length > 3, 'has a regex pattern');
  assert.ok(new RegExp(p.pattern), 'pattern compiles');
  assert.ok(p.title.includes('[learned]'));
  assert.ok(p._provenance && p._provenance.count >= 3, 'carries provenance for review');
});

test('proposals only come from patterns with a real literal anchor (no match-everything)', async () => {
  const kbPath = path.join(await fs.mkdtemp(path.join(os.tmpdir(), 'kb2-')), 'kb.jsonl');
  // a snippet that normalizes to only placeholders → no safe regex
  const mk = () => ({ findings: [new Finding({ probe: 'p', ruleId: 'nums', severity: 'low', title: 'n', snippet: '42 + 7', language: 'javascript', file: 'a.js', line: 1 })] });
  for (let i = 0; i < 4; i++) await learnFromResult(mk(), { kbPath });
  await promoteCandidates(3, { kbPath });
  const proposals = await synthesizeRuleProposals({ kbPath, minCount: 3 });
  assert.equal(proposals.length, 0, 'a placeholder-only pattern must not become a rule');
});
