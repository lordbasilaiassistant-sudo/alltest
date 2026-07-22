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
 * @param {import('./core/probe.js').ProbeDef[]} [opts.extraProbes] - in-process probe defs
 * @param {string[]} [opts.probeModules] - paths/URLs to probe modules to import (worker-safe)
 * @param {(ev:object)=>void} [opts.onEvent]
 * @returns {Promise<import('./core/runner.js').RunResult>}
 */
export async function scan(opts) {
  const extra = [...(opts.extraProbes || [])];
  // Serializable probe loading: import each module and take its default export (or all
  // exported probe-shaped objects). This is what lets the worker sandbox load probes.
  for (const mod of opts.probeModules || []) {
    const url = mod.startsWith('file:') || mod.includes('://') ? mod : pathToFileURL(mod).href;
    const imported = await import(url);
    const def = imported.default || imported.probe;
    if (def) extra.push(def);
  }
  const registry = buildRegistry(extra);
  return runScan(registry, opts);
}

import { pathToFileURL } from 'node:url';

/** Convenience: scan + render in one call. */
export async function scanAndRender(opts, format = 'table') {
  const result = await scan(opts);
  return { result, output: render(result, format, opts) };
}
