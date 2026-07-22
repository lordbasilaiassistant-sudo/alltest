// runner.js — orchestrates a scan: walk → run probes layer by layer → collect findings.
//
// Fault model (be precise, not aspirational):
//  - A probe that THROWS (sync or async) is caught and recorded; the run continues.
//  - A probe that AWAITS something that never resolves is bounded by `withTimeout`.
//  - A probe that SYNCHRONOUSLY blocks the event loop (infinite loop, catastrophic
//    regex) CANNOT be interrupted on this thread — no same-thread Promise race can.
//    Built-in probes are bounded (line-length caps + audited regexes). To run UNTRUSTED
//    or RSI-generated probes safely, use the worker sandbox (src/core/sandbox.js), whose
//    supervisor can worker.terminate() a synchronously-spinning probe. This mirrors how
//    ESLint/Prettier run plugins in-process by default.

import path from 'node:path';
import { promises as fs } from 'node:fs';
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
  let files = await walk(root, { maxFiles: opts.maxFiles });
  // Incremental scanning: restrict to an explicit file allowlist (e.g. git-changed files).
  if (opts.onlyFiles && opts.onlyFiles.length) {
    const allow = new Set(opts.onlyFiles.map((p) => p.replace(/\\/g, '/').replace(/^\.\//, '')));
    const truncated = files.truncated;
    files = files.filter((f) => allow.has(f.path));
    files.truncated = truncated;
  }
  onEvent({ type: 'walk:done', count: files.length, truncated: !!files.truncated });

  // When the target is a single file, file paths are relative to its parent dir — the
  // reader and ignore layer must resolve against that base, not the file itself.
  let readBase = root;
  try { if ((await fs.stat(root)).isFile()) readBase = path.dirname(root); } catch {}

  const languages = summarizeLanguages(files);
  const presentLangs = Object.keys(languages);
  const read = makeReader(readBase);

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

  const { kept, suppressed } = await applyIgnores(readBase, findings);
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
