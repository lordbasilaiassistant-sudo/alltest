// LAYER 2 — the suite testing ITSELF.
// Run alltest against its own source and assert internal integrity. This is the probe
// that "tests the tests": if any probe violates the ProbeDef contract, or the Finding
// schema regresses, or the registry can't build, the meta/self-integrity probe reports it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, buildRegistry } from '../src/index.js';
import { runScan } from '../src/core/runner.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, '..');

test('meta/self-integrity passes on a healthy build (no meta findings)', async () => {
  const r = await scan({ root: REPO_ROOT, layers: ['meta'], probes: ['meta/self-integrity'] });
  const metaFindings = r.findings.filter((f) => f.probe === 'meta/self-integrity');
  assert.equal(metaFindings.length, 0, `self-integrity should be clean, got: ${metaFindings.map((f) => f.title).join('; ')}`);
});

test('every built-in probe satisfies the ProbeDef contract', () => {
  const reg = buildRegistry();
  assert.ok(reg.size >= 10, 'expected the full probe catalog');
  for (const p of reg.probes.values()) {
    assert.ok(typeof p.id === 'string' && p.id.includes('/'), `probe id shape: ${p.id}`);
    assert.ok(['static', 'dynamic', 'fuzz', 'meta'].includes(p.layer), `probe layer: ${p.id}`);
    assert.ok(typeof p.run === 'function', `probe run: ${p.id}`);
    assert.ok(p.title, `probe title: ${p.id}`);
  }
});

test('scanning the whole repo runs cleanly (dogfood: alltest on alltest)', async () => {
  // The full self-scan uses .alltestignore to exclude pattern-definition files.
  const r = await scan({ root: REPO_ROOT });
  // No probe may error out.
  assert.equal(r.summary.probesErrored.length, 0, `probes errored: ${r.summary.probesErrored.join(', ')}`);
  // No critical/high findings in our own shipped code.
  const bad = r.findings.filter((f) => f.severityRank >= 3);
  assert.equal(bad.length, 0, `alltest's own code should have no high/critical findings, got: ${bad.map((f) => f.ruleId + '@' + f.location).join(', ')}`);
});

test('runner is deterministic — two scans of the same tree agree', async () => {
  const a = await scan({ root: path.join(__dirname, 'fixtures', 'vulnerable-app') });
  const b = await scan({ root: path.join(__dirname, 'fixtures', 'vulnerable-app') });
  const sig = (r) => r.findings.map((f) => f.ruleId + '@' + f.file + ':' + f.line).sort().join('|');
  assert.equal(sig(a), sig(b), 'scan output must be deterministic');
});
