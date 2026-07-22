// core/sandbox.js — run a scan inside a worker thread with a HARD, enforceable timeout.
//
// The in-process runner cannot interrupt a synchronously-blocking probe (infinite loop,
// catastrophic regex). A worker thread can: it has its own event loop, so the supervisor
// on the main thread stays responsive and can call worker.terminate() — which genuinely
// kills sync-spinning code. This is the correct isolation boundary for running UNTRUSTED
// or RSI-generated probes, and it gives every scan a real wall-clock ceiling.
//
// Only serializable options cross the boundary: root, layers, probes, allowExec,
// probeModules (paths — not function refs), maxFiles. Results come back as plain records.

import { Worker } from 'node:worker_threads';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WORKER = path.join(__dirname, 'sandbox-worker.js');

/**
 * @param {object} opts - scan options (must be serializable; extraProbes are ignored,
 *   use probeModules to load probes by path).
 * @param {object} [supervisor]
 * @param {number} [supervisor.hardTimeoutMs=60000] - kill the worker after this long.
 * @returns {Promise<{result?:object, timedOut:boolean, error?:string}>}
 */
export function scanSandboxed(opts, supervisor = {}) {
  const hardTimeoutMs = supervisor.hardTimeoutMs ?? 60000;
  const serializable = {
    root: opts.root,
    layers: opts.layers,
    probes: opts.probes,
    allowExec: !!opts.allowExec,
    probeModules: opts.probeModules || [],
    maxFiles: opts.maxFiles,
    version: opts.version,
    probeTimeout: opts.probeTimeout,
  };

  return new Promise((resolve) => {
    let settled = false;
    let worker;
    const done = (v) => { if (!settled) { settled = true; clearTimeout(timer); try { worker && worker.terminate(); } catch {} resolve(v); } };

    const timer = setTimeout(() => {
      // Hard kill — this works even if the worker is stuck in a synchronous loop.
      done({ timedOut: true, error: `scan exceeded hard timeout of ${hardTimeoutMs}ms and was terminated` });
    }, hardTimeoutMs);

    try {
      worker = new Worker(WORKER, { workerData: serializable });
    } catch (e) {
      done({ timedOut: false, error: `failed to start sandbox worker: ${String(e && e.message || e)}` });
      return;
    }

    worker.on('message', (msg) => {
      if (msg && msg.ok) done({ result: reviveResult(msg.result), timedOut: false });
      else done({ timedOut: false, error: (msg && msg.error) || 'unknown sandbox error' });
    });
    worker.on('error', (e) => done({ timedOut: false, error: String(e && e.message || e) }));
    worker.on('exit', (code) => {
      if (!settled && code !== 0) done({ timedOut: false, error: `sandbox worker exited with code ${code}` });
    });
  });
}

// The worker returns plain finding records; give them back the convenience getters the
// reporters rely on (severityRank, location) without importing the full Finding class.
function reviveResult(result) {
  if (!result || !Array.isArray(result.findings)) return result;
  const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  result.findings = result.findings.map((f) => ({
    ...f,
    severityRank: RANK[f.severity] ?? 0,
    location: f.file ? `${f.file}${f.line != null ? ':' + f.line : ''}` : '(project)',
    toRecord() { return f; },
  }));
  return result;
}
