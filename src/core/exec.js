// exec.js — safe, promisified child process runner for dynamic probes.
// Never throws on non-zero exit; returns {code, stdout, stderr, timedOut}.

import { spawn } from 'node:child_process';

/**
 * @param {string} cmd
 * @param {string[]} args
 * @param {object} [opts]
 * @param {string} [opts.cwd]
 * @param {number} [opts.timeout=120000]
 * @param {object} [opts.env]
 * @param {number} [opts.maxBuffer=8_000_000]
 * @returns {Promise<{code:number,stdout:string,stderr:string,timedOut:boolean,error?:string}>}
 */
export function exec(cmd, args = [], opts = {}) {
  const timeout = opts.timeout ?? 120000;
  const maxBuffer = opts.maxBuffer ?? 8_000_000;
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, {
        cwd: opts.cwd || process.cwd(),
        env: { ...process.env, ...(opts.env || {}) },
        shell: process.platform === 'win32', // allow .cmd/.ps shims on Windows
        windowsHide: true,
      });
    } catch (e) {
      resolve({ code: -1, stdout: '', stderr: '', timedOut: false, error: String(e && e.message || e) });
      return;
    }

    let stdout = '';
    let stderr = '';
    let killed = false;
    let over = false;
    // Decode as UTF-8 at the stream boundary so multibyte chars aren't split across
    // chunks (raw Buffer concatenation produces mojibake).
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');

    const timer = setTimeout(() => {
      killed = true;
      try { child.kill('SIGKILL'); } catch {}
    }, timeout);

    child.stdout?.on('data', (d) => {
      if (over) return;
      stdout += d;
      if (stdout.length > maxBuffer) { stdout = stdout.slice(0, maxBuffer); over = true; }
    });
    child.stderr?.on('data', (d) => {
      if (stderr.length < maxBuffer) stderr += d;
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ code: -1, stdout, stderr, timedOut: killed, error: String(e && e.message || e) });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, stdout, stderr, timedOut: killed });
    });
  });
}

/** Detect whether a binary exists on PATH (cross-platform-ish). */
export async function which(bin) {
  const probe = process.platform === 'win32' ? 'where' : 'which';
  const r = await exec(probe, [bin], { timeout: 5000 });
  return r.code === 0 ? r.stdout.split(/\r?\n/)[0].trim() : null;
}
