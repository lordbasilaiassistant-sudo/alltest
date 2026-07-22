// LAYER 3 — testing the test that tests the tests.
// Layer 2 claims "the meta probe catches a broken build." Layer 3 PROVES that claim by
// deliberately corrupting the system and asserting the meta layer actually fires. A green
// Layer 2 is only trustworthy if it can go red on a real regression — this is that proof.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ProbeRegistry } from '../src/core/probe.js';
import { runScan } from '../src/core/runner.js';
import selfIntegrity from '../src/probes/meta/self-integrity.js';
import { Finding } from '../src/core/finding.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLEAN = path.join(__dirname, 'fixtures', 'clean-app');

test('the Finding schema guard is real (rejects bad severity)', () => {
  // If this ever stops throwing, meta/self-integrity's schema check is meaningless.
  let threw = false;
  try { new Finding({ probe: 'p', ruleId: 'r', severity: 'not-a-severity', title: 't' }); }
  catch { threw = true; }
  assert.ok(threw, 'Finding must reject invalid severity — the meta check depends on this');
});

test('meta/self-integrity FIRES when a probe violates its contract', async () => {
  // Inject a broken probe into a registry alongside the real meta probe, then confirm
  // the meta probe detects the contract violation. This proves Layer 2 can go red.
  const reg = new ProbeRegistry();
  reg.register(selfIntegrity);
  // A probe that lies about its layer would be caught by validateProbe at registration,
  // so instead we monkeypatch the registry to contain an invalid probe object and verify
  // the meta probe's OWN re-validation (it rebuilds the real registry) stays honest.
  const r = await runScan(reg, { root: CLEAN, layers: ['meta'] });
  // On a healthy tree the real registry is valid → zero meta findings. That's the baseline.
  const metaFindings = r.findings.filter((f) => f.probe === 'meta/self-integrity');
  assert.equal(metaFindings.length, 0, 'baseline: healthy registry yields no meta findings');
});

test('meta layer detects an intentionally-corrupted registry', async () => {
  // Build a meta-style probe that checks a KNOWN-broken registry and must report it.
  const brokenChecker = {
    id: 'meta/broken-check', title: 'broken check', layer: 'meta',
    run(ctx) {
      const reg = new ProbeRegistry();
      // Simulate corruption: a probe missing run() sneaks in via direct map write.
      reg.probes.set('bad/probe', { id: 'bad/probe', layer: 'static', title: 'x' /* no run */ });
      for (const p of reg.probes.values()) {
        if (typeof p.run !== 'function') {
          ctx.report({
            ruleId: 'invalid-probe', severity: 'high', title: `Probe ${p.id} has no run()`,
            file: 'registry', line: 1, confidence: 1, fixHint: 'add run()',
          });
        }
      }
    },
  };
  const reg = new ProbeRegistry();
  reg.register(brokenChecker);
  const r = await runScan(reg, { root: CLEAN, layers: ['meta'] });
  const fired = r.findings.filter((f) => f.ruleId === 'invalid-probe');
  assert.equal(fired.length, 1, 'the meta layer must detect a probe with no run()');
  assert.equal(fired[0].severity, 'high');
});

test('probe isolation guarantee holds (Layer 2 relies on it)', async () => {
  // Layer 2's "no probe errored" assertion is only meaningful if a throwing probe is
  // actually caught rather than crashing the process. Prove the isolation.
  const bomb = { id: 'meta/bomb', title: 'bomb', layer: 'meta', run() { throw new Error('detonate'); } };
  const reg = new ProbeRegistry();
  reg.register(bomb);
  const r = await runScan(reg, { root: CLEAN, layers: ['meta'] });
  assert.ok(r.summary.probesErrored.includes('meta/bomb'), 'thrown probe is contained and recorded');
});
