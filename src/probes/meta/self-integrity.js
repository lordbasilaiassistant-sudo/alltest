// meta/self-integrity.js — the meta layer: alltest testing itself while it runs.
// When the target IS alltest (or any project embedding it), this probe asserts internal
// invariants: every probe validates, every Finding schema holds, the registry is sane.
// This is one turtle in the stack — layered tests verify THIS probe in test/meta.test.js.

import { validateProbe, LAYERS } from '../../core/probe.js';
import { Finding, SEVERITY } from '../../core/finding.js';
// NB: buildRegistry is imported lazily inside run() to avoid a circular import
// (probes/index.js imports this probe; this probe inspecting the registry would
// otherwise create a top-level import cycle → temporal dead zone).

export default {
  id: 'meta/self-integrity',
  title: 'alltest self-integrity (meta)',
  layer: 'meta',
  languages: ['*'],
  order: 99,
  description: 'Asserts the probe registry, probe contracts, and Finding schema are internally consistent.',
  async run(ctx) {
    // Only run meaningfully when scanning a project that contains alltest itself,
    // or always as a cheap internal consistency gate (it does not touch ctx.files heavily).
    const isSelf = ctx.files.some((f) => f.path === 'src/core/finding.js' && ctx.files.some((g) => g.path === 'src/core/probe.js'))
      || ctx.options?.meta === true;

    // 1. The live registry must be internally valid regardless of target.
    let reg;
    try {
      const { buildRegistry } = await import('../index.js'); // lazy — breaks import cycle
      reg = buildRegistry();
    } catch (e) {
      ctx.report({
        ruleId: 'registry-build-failed', severity: 'critical',
        title: 'alltest probe registry failed to build',
        message: String(e && e.stack || e),
        file: 'src/probes/index.js', line: 1, confidence: 1,
        fixHint: 'A probe module is malformed; fix its default export to satisfy the ProbeDef contract.',
        tags: ['meta', 'self-test'],
      });
      return;
    }

    for (const probe of reg.probes.values()) {
      try {
        validateProbe(probe);
      } catch (e) {
        ctx.report({
          ruleId: 'invalid-probe', severity: 'high',
          title: `Probe fails its contract: ${probe.id || '(unknown)'}`,
          message: String(e.message),
          file: 'src/probes/index.js', line: 1, confidence: 1,
          fixHint: 'Ensure the probe has id, title, a valid layer, and a run() function.',
          tags: ['meta', 'self-test'],
        });
      }
      if (!LAYERS.includes(probe.layer)) {
        ctx.report({
          ruleId: 'bad-probe-layer', severity: 'medium',
          title: `Probe ${probe.id} declares unknown layer "${probe.layer}"`,
          message: `Layer must be one of ${LAYERS.join(', ')}.`,
          file: 'src/probes/index.js', line: 1, confidence: 1,
          fixHint: 'Set probe.layer to a known layer.', tags: ['meta'],
        });
      }
    }

    // 2. Finding schema invariants (constructor guards must hold).
    try {
      // valid finding must construct
      const ok = new Finding({ probe: 'meta', ruleId: 'x', severity: 'low', title: 't' });
      if (ok.severityRank !== SEVERITY.low) throw new Error('severityRank mismatch');
      // invalid severity must throw
      let threw = false;
      try { new Finding({ probe: 'm', ruleId: 'x', severity: 'nope', title: 't' }); } catch { threw = true; }
      if (!threw) throw new Error('Finding accepted an invalid severity');
    } catch (e) {
      ctx.report({
        ruleId: 'finding-schema-broken', severity: 'critical',
        title: 'Finding schema invariant violated',
        message: String(e.message),
        file: 'src/core/finding.js', line: 1, confidence: 1,
        fixHint: 'The Finding model regressed. Restore its validation guards.',
        tags: ['meta', 'self-test'],
      });
    }

    if (isSelf) {
      ctx.log(`meta: verified ${reg.size} probes and Finding schema — all internal invariants hold`);
    }
  },
};
