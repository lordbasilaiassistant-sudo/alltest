// runner.js — orchestrates a scan: walk → run probes layer by layer → collect findings.
// Isolated so a crashing probe can never take down the whole run (that isolation is
// itself a tested property — a bad probe is exactly the kind of 0-day we must survive).

import path from 'node:path';
import { walk, makeReader } from './walker.js';
import { exec } from './exec.js';
import { Finding, compareFindings, dedupeFindings, signatureOf, SEVERITY } from './finding.js';
import { summarizeLanguages } from './lang.js';
import { LAYERS } from './probe.js';
import { applyIgnores } from './ignore.js';

/**
 * @param {import('./probe.js').ProbeRegistry} registry
 * @param {object} opts
 * @param {string} opts.root
 * @param {string[]} [opts.layers]        - restrict to these layers
 * @param {string[]} [opts.probes]        - restrict to these probe ids
 * @param {boolean} [opts.allowExec=false]- permit dynamic probes to run project code
 * @param {(ev:object)=>void} [opts.onEvent]
 * @param {number} [opts.probeTimeout=120000]
 * @returns {Promise<RunResult>}
 */
export async function runScan(registry, opts) {
  const root = path.resolve(opts.root || '.');
  const onEvent = opts.onEvent || (() => {});
  const started = Date.now();

  onEvent({ type: 'walk:start', root });
  const files = await walk(root, { maxFiles: opts.maxFiles });
  onEvent({ type: 'walk:done', count: files.length, truncated: !!files.truncated });

  const languages = summarizeLanguages(files);
  const presentLangs = Object.keys(languages);
  const read = makeReader(root);

  let layers = opts.layers && opts.layers.length ? opts.layers : LAYERS.slice();
  // dynamic probes only run when execution is explicitly allowed
  if (!opts.allowExec) layers = layers.filter((l) => l !== 'dynamic');

  const selected = registry.select({
    layers,
    ids: opts.probes,
    languages: presentLangs,
  });

  /** @type {Finding[]} */
  const findings = [];
  /** @type {ProbeRunInfo[]} */
  const probeRuns = [];

  for (const def of selected) {
    const localSink = [];
    const ctx = {
      root,
      files,
      read,
      exec: (cmd, args, o) => exec(cmd, args, { cwd: root, ...o }),
      report: (init) => {
        const f = init instanceof Finding ? init : new Finding({ probe: def.id, ...init });
        localSink.push(f);
      },
      log: (msg) => onEvent({ type: 'probe:log', probe: def.id, msg }),
      options: opts,
      allowExec: !!opts.allowExec,
      languages,
    };

    const t0 = Date.now();
    onEvent({ type: 'probe:start', probe: def.id, title: def.title, layer: def.layer });
    let error = null;
    try {
      await withTimeout(
        Promise.resolve(def.run(ctx)),
        opts.probeTimeout ?? 120000,
        `probe ${def.id} timed out`
      );
    } catch (e) {
      error = String((e && e.stack) || e);
      onEvent({ type: 'probe:error', probe: def.id, error: String(e && e.message || e) });
    }
    const dt = Date.now() - t0;
    for (const f of localSink) findings.push(f);
    probeRuns.push({
      id: def.id,
      layer: def.layer,
      title: def.title,
      ms: dt,
      findings: localSink.length,
      error,
    });
    onEvent({ type: 'probe:done', probe: def.id, ms: dt, findings: localSink.length, error });
  }

  const { kept, suppressed } = await applyIgnores(root, findings);
  const deduped = dedupeFindings(kept).sort(compareFindings);

  const result = {
    root,
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    fileCount: files.length,
    truncated: !!files.truncated,
    languages,
    probeRuns,
    suppressed,
    findings: deduped,
    summary: summarize(deduped, probeRuns),
  };
  onEvent({ type: 'scan:done', summary: result.summary });
  return result;
}

/** @typedef {Object} ProbeRunInfo */
/** @typedef {Object} RunResult */

/**
 * Return a shallow result view containing only findings at/above `minSeverity`,
 * with a recomputed summary. The full result (incl. `info`) is preserved for the
 * ML corpus; this is purely for human display / issue-filing / CI gating.
 * @param {RunResult} result
 * @param {import('./finding.js').Severity} minSeverity
 */
export function filterResultView(result, minSeverity) {
  const minRank = SEVERITY[minSeverity] ?? SEVERITY.low;
  const findings = result.findings.filter((f) => f.severityRank >= minRank);
  return {
    ...result,
    findings,
    summary: summarize(findings, result.probeRuns),
    filteredFrom: result.findings.length,
    minSeverity,
  };
}

function summarize(findings, probeRuns) {
  const bySeverity = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const byProbe = {};
  const byRule = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byProbe[f.probe] = (byProbe[f.probe] || 0) + 1;
    byRule[f.ruleId] = (byRule[f.ruleId] || 0) + 1;
  }
  const errored = probeRuns.filter((p) => p.error).map((p) => p.id);
  return {
    total: findings.length,
    bySeverity,
    byProbe,
    byRule,
    probesRun: probeRuns.length,
    probesErrored: errored,
    // gate score: weighted severity total — used for CI exit codes
    riskScore: findings.reduce((n, f) => n + f.severityRank * (0.5 + f.confidence / 2), 0),
  };
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
