// core/sandbox-worker.js — worker entry point for the sandboxed scan.
// Runs the normal scan in an isolated thread and posts the result back. If a probe here
// spins synchronously forever, the SUPERVISOR (sandbox.js) terminates this whole thread —
// which is exactly why the isolation is real rather than cooperative.

import { parentPort, workerData } from 'node:worker_threads';
import { scan } from '../index.js';

(async () => {
  try {
    const result = await scan(workerData);
    // Serialize findings to plain records (functions/getters don't cross the boundary).
    const plain = {
      root: result.root,
      startedAt: result.startedAt,
      durationMs: result.durationMs,
      fileCount: result.fileCount,
      truncated: result.truncated,
      languages: result.languages,
      probeRuns: result.probeRuns,
      suppressed: result.suppressed,
      summary: result.summary,
      findings: result.findings.map((f) => f.toRecord()),
    };
    parentPort.postMessage({ ok: true, result: plain });
  } catch (e) {
    parentPort.postMessage({ ok: false, error: String((e && e.stack) || e) });
  }
})();
