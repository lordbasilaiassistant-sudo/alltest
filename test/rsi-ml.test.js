// RSI + ML pipeline tests. These verify the self-improvement loop actually learns
// (novel signatures get recorded, known ones bump counts, high-frequency ones get
// promoted to candidate rules) and that the ML corpus emits a stable, dedupable schema.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { learnFromResult, promoteCandidates, kbStats } from '../src/rsi/learn.js';
import { appendCorpus, toExample, dedupeCorpus, corpusStats } from '../src/ml/dataset.js';
import { Finding } from '../src/core/finding.js';

async function tmp(name) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'alltest-'));
  return path.join(dir, name);
}

function mkResult(findings) {
  return { root: '/x', startedAt: '2026-01-01T00:00:00Z', findings };
}
function mkFinding(ruleId, snippet, sev = 'medium') {
  return new Finding({ probe: 'static/x', ruleId, severity: sev, title: ruleId, snippet, language: 'javascript', file: 'a.js', line: 1 });
}

// ---- RSI ----
test('RSI learns novel signatures and bumps known ones', async () => {
  const kbPath = await tmp('kb.jsonl');
  const r1 = await learnFromResult(mkResult([mkFinding('r1', 'foo("a")'), mkFinding('r2', 'bar(1)')]), { kbPath });
  assert.equal(r1.novel, 2);
  assert.equal(r1.total, 2);
  // same signatures again → no new novelty, counts bump
  const r2 = await learnFromResult(mkResult([mkFinding('r1', 'foo("b")')]), { kbPath });
  assert.equal(r2.novel, 0, 'normalized signature already known');
  assert.equal(r2.updated, 1);
});

test('RSI promotes high-frequency signatures to candidate rules', async () => {
  const kbPath = await tmp('kb2.jsonl');
  for (let i = 0; i < 3; i++) {
    await learnFromResult(mkResult([mkFinding('hot', 'x(1)')]), { kbPath });
  }
  const promoted = await promoteCandidates(3, { kbPath });
  assert.equal(promoted.length, 1, 'a signature seen 3x becomes a candidate rule');
  assert.equal(promoted[0].status, 'candidate-rule');
  const stats = await kbStats({ kbPath });
  assert.equal(stats.byStatus['candidate-rule'], 1);
});

test('RSI knowledge base survives a corrupt line', async () => {
  const kbPath = await tmp('kb3.jsonl');
  await learnFromResult(mkResult([mkFinding('r1', 'a()')]), { kbPath });
  await fs.appendFile(kbPath, 'THIS IS NOT JSON\n');
  const r = await learnFromResult(mkResult([mkFinding('r2', 'b()')]), { kbPath });
  assert.ok(r.total >= 2, 'corrupt line skipped, learning continues');
});

// ---- ML corpus ----
test('toExample produces a stable training row', () => {
  const ex = toExample(mkFinding('secret', 'const k = "x"', 'high'), mkResult([]), { repo: 'demo' });
  assert.equal(ex.label, 'secret');
  assert.equal(ex.severity, 'high');
  assert.equal(ex.language, 'javascript');
  assert.equal(ex.schema_version, 1);
  assert.ok(ex.hash && ex.hash.length === 16);
  assert.equal(ex.source_repo, 'demo');
});

test('appendCorpus writes JSONL + manifest, dedupeCorpus collapses duplicates', async () => {
  const corpus = await tmp('c.jsonl');
  const result = mkResult([mkFinding('r1', 'dup()'), mkFinding('r1', 'dup()'), mkFinding('r2', 'other()')]);
  const n = await appendCorpus(corpus, result, { repo: 'demo' });
  assert.equal(n, 3);
  // append the same run again → duplicates on disk
  await appendCorpus(corpus, result, { repo: 'demo' });
  const before = await corpusStats(corpus);
  assert.equal(before.examples, 6);
  const { after } = await dedupeCorpus(corpus);
  const stats = await corpusStats(corpus);
  assert.ok(stats.examples < 6, 'dedupe removed duplicate rows');
  // manifest exists
  const manifest = JSON.parse(await fs.readFile(corpus.replace(/\.jsonl$/, '.manifest.json'), 'utf8'));
  assert.ok(manifest.runs >= 2);
});

test('corpus rows are valid JSONL (every line parses)', async () => {
  const corpus = await tmp('c2.jsonl');
  await appendCorpus(corpus, mkResult([mkFinding('a', 'x()'), mkFinding('b', 'y()')]), {});
  const text = await fs.readFile(corpus, 'utf8');
  for (const line of text.split('\n').filter(Boolean)) {
    assert.doesNotThrow(() => JSON.parse(line), `line must be valid JSON: ${line}`);
  }
});
