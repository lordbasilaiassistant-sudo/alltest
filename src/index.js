// index.js — public programmatic API for alltest.
// Lets any Node/agent embed the engine: `import { scan } from 'alltest'`.

import { buildRegistry } from './probes/index.js';
import { runScan } from './core/runner.js';
import { render } from './core/report.js';
export { Finding, SEVERITY, compareFindings } from './core/finding.js';
export { ProbeRegistry } from './core/probe.js';
export { buildRegistry } from './probes/index.js';
export { render } from './core/report.js';

/**
 * Run a full scan of a codebase.
 * @param {object} opts
 * @param {string} opts.root
 * @param {string[]} [opts.layers]
 * @param {string[]} [opts.probes]
 * @param {boolean} [opts.allowExec]
 * @param {import('./core/probe.js').ProbeDef[]} [opts.extraProbes]
 * @param {(ev:object)=>void} [opts.onEvent]
 * @returns {Promise<import('./core/runner.js').RunResult>}
 */
export async function scan(opts) {
  const registry = buildRegistry(opts.extraProbes || []);
  return runScan(registry, opts);
}

/** Convenience: scan + render in one call. */
export async function scanAndRender(opts, format = 'table') {
  const result = await scan(opts);
  return { result, output: render(result, format, opts) };
}
