// SANDBOX — proves the hard-isolation guarantee that the in-process runner cannot make:
// a SYNCHRONOUSLY infinite-looping probe is actually killed by the worker supervisor.
// This is the real fix for the "a same-thread Promise race can't stop sync code" defect.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanSandboxed } from '../src/core/sandbox.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLEAN = path.join(__dirname, 'fixtures', 'clean-app');
const HANG = path.join(__dirname, 'fixtures', 'hanging-probe.mjs');

test('sandbox returns a normal result for a healthy scan', async () => {
  const sb = await scanSandboxed({ root: path.join(__dirname, 'fixtures', 'vulnerable-app') }, { hardTimeoutMs: 30000 });
  assert.equal(sb.timedOut, false, sb.error || '');
  assert.ok(sb.result, 'result returned');
  assert.ok(sb.result.findings.length > 0, 'findings came back across the worker boundary');
  // revived findings expose the getters reporters need
  assert.ok(typeof sb.result.findings[0].severityRank === 'number');
});

test('sandbox HARD-KILLS a synchronously-hanging probe (the critical guarantee)', async () => {
  const start = Date.now();
  const sb = await scanSandboxed(
    { root: CLEAN, probeModules: [HANG] },
    { hardTimeoutMs: 1500 }
  );
  const elapsed = Date.now() - start;
  assert.equal(sb.timedOut, true, 'a sync infinite loop must trip the hard timeout');
  assert.ok(/terminated|timeout/i.test(sb.error || ''), 'reports termination');
  assert.ok(elapsed < 6000, `must be killed promptly (was ${elapsed}ms) — not hang forever`);
});

test('sandbox loads probes by module path (serializable, worker-safe)', async () => {
  // A benign external probe loaded by path should run and report.
  const benign = path.join(__dirname, 'fixtures', 'benign-external-probe.mjs');
  const { promises: fs } = await import('node:fs');
  await fs.writeFile(benign, `export default {
    id: 'static/external-demo', title: 'demo', layer: 'static',
    run(ctx){ ctx.report({ ruleId:'demo-rule', severity:'low', title:'external probe ran', file:null, line:1, confidence:1 }); }
  };\n`);
  const sb = await scanSandboxed({ root: CLEAN, probeModules: [benign] }, { hardTimeoutMs: 20000 });
  assert.equal(sb.timedOut, false, sb.error || '');
  assert.ok(sb.result.findings.some((f) => f.ruleId === 'demo-rule'), 'externally-loaded probe produced a finding');
});
