// core/sweep.js — scan every repo/subproject under a directory.
// This is how alltest tests "all my projects": point it at ~/Desktop and it finds each
// project root (a dir with a manifest or a .git) and scans each independently.

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { scan } from '../index.js';
import { appendCorpus } from '../ml/dataset.js';
import { learnFromResult } from '../rsi/learn.js';

const PROJECT_MARKERS = ['package.json', '.git', 'Cargo.toml', 'go.mod', 'pyproject.toml', 'requirements.txt', 'foundry.toml', 'hardhat.config.js', 'hardhat.config.ts'];

/**
 * Discover project roots directly under `dir` (one level deep by default).
 * @returns {Promise<string[]>} absolute project paths
 */
export async function discoverProjects(dir, opts = {}) {
  const abs = path.resolve(dir);
  const depth = opts.depth ?? 1;
  const found = [];
  await visit(abs, 0);
  return found;

  async function visit(current, level) {
    let entries;
    try { entries = await fs.readdir(current, { withFileTypes: true }); } catch { return; }
    const names = new Set(entries.filter((e) => !e.isDirectory() || true).map((e) => e.name));
    const isProject = PROJECT_MARKERS.some((m) => names.has(m));
    if (isProject && current !== abs) { found.push(current); return; } // don't descend into a project
    if (level >= depth) {
      if (isProject) found.push(current);
      return;
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      if (e.name.startsWith('.') || SKIP.has(e.name)) continue;
      await visit(path.join(current, e.name), level + 1);
    }
  }
}

const SKIP = new Set(['node_modules', 'dist', 'build', 'coverage', '.git', 'vendor', 'target']);

/**
 * Sweep: scan each discovered project.
 * @param {string} dir
 * @param {object} [opts]
 * @param {boolean} [opts.allowExec]
 * @param {string} [opts.corpus]
 * @param {(name:string,result:object)=>void} [opts.onRepo]
 * @returns {Promise<Array<{repo:string, path:string, result:object}>>}
 */
export async function sweep(dir, opts = {}) {
  const projects = await discoverProjects(dir, { depth: opts.depth ?? 1 });
  const results = [];
  for (const proj of projects) {
    const name = path.basename(proj);
    let result;
    try {
      result = await scan({ root: proj, allowExec: !!opts.allowExec, version: opts.version });
    } catch (e) {
      result = { root: proj, findings: [], summary: { total: 0, bySeverity: {}, riskScore: 0, error: String(e.message) }, probeRuns: [] };
    }
    if (opts.corpus) {
      try { await appendCorpus(opts.corpus, result, { root: proj, repo: name }); } catch {}
    }
    if (opts.learn !== false) {
      try { await learnFromResult(result); } catch {}
    }
    if (opts.onRepo) opts.onRepo(name, result);
    results.push({ repo: name, path: proj, result });
  }
  // sort worst-first
  results.sort((a, b) => (b.result.summary.riskScore || 0) - (a.result.summary.riskScore || 0));
  return results;
}
