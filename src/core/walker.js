// walker.js — dependency-free recursive file discovery with sane ignore rules.
// Works on any repo without config. Respects .gitignore-style basics + hard caps
// so pointing it at a huge monorepo can't hang.

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { detectLanguage, isTextSource } from './lang.js';

/**
 * @typedef {Object} FileEntry
 * @property {string} path      - repo-relative, forward-slash
 * @property {string} abs       - absolute
 * @property {number} size      - bytes
 * @property {string} language
 */

const DEFAULT_IGNORE_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', 'coverage',
  '.next', '.nuxt', '.cache', '.turbo', 'vendor', 'target', '__pycache__',
  '.venv', 'venv', 'env', '.idea', '.vscode', 'artifacts', 'cache', 'typechain',
  'typechain-types', '.pnpm', 'bower_components', '.gradle', 'bin', 'obj',
  // tool state / agent scratch — copies of the repo, not the repo
  '.claude', 'worktrees', '.worktrees', '.svelte-kit', '.astro', '.parcel-cache',
  'broadcast', '.foundry', '.serena', '.output', '.vercel', '.wrangler',
  // vendored Solidity dependencies (Foundry `lib/<dep>`) — third-party code, not the user's
  'forge-std', 'ds-test', 'solmate', 'solady', 'permit2',
  'v4-core', 'v4-periphery', 'openzeppelin-contracts', 'openzeppelin-contracts-upgradeable',
  '@openzeppelin', 'openzeppelin', 'uniswap', 'v3-core', 'v3-periphery',
]);

const DEFAULT_IGNORE_FILE_RE = /\.(min\.js|map|lock|png|jpe?g|gif|webp|ico|svg|pdf|zip|tar|gz|exe|dll|so|dylib|woff2?|ttf|eot|mp4|mp3|wav|bin|wasm|node)$/i;

const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip files > 2MB (generated/data)

/**
 * @param {string} root
 * @param {object} [opts]
 * @param {number} [opts.maxFiles=20000]
 * @param {Set<string>} [opts.ignoreDirs]
 * @param {boolean} [opts.includeNonSource=false]
 * @returns {Promise<FileEntry[]>}
 */
export async function walk(root, opts = {}) {
  const absRoot = path.resolve(root);
  const maxFiles = opts.maxFiles ?? 20000;
  // COPY the ignore set — never mutate the shared module default (would cross-contaminate
  // sweeps, where every repo's .gitignore dirs would leak into later repos).
  const ignoreDirs = new Set(opts.ignoreDirs || DEFAULT_IGNORE_DIRS);
  const includeNonSource = opts.includeNonSource ?? false;

  // Handle a single-file target: scan just that file.
  let rootStat;
  try {
    rootStat = await fs.stat(absRoot);
  } catch {
    const empty = [];
    empty.truncated = false;
    empty.error = 'path not found';
    return empty;
  }
  if (rootStat.isFile()) {
    const rel = path.basename(absRoot);
    const out = rootStat.size <= MAX_FILE_BYTES
      ? [{ path: rel, abs: absRoot, size: rootStat.size, language: detectLanguage(rel) }]
      : [];
    out.truncated = false;
    return out;
  }

  const extra = await loadGitignoreDirs(absRoot);
  for (const d of extra) ignoreDirs.add(d);

  /** @type {FileEntry[]} */
  const out = [];
  const stack = [absRoot];
  let truncated = false;

  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable dir — skip
    }
    for (const ent of entries) {
      const abs = path.join(dir, ent.name);
      if (ent.isSymbolicLink()) continue; // avoid loops
      if (ent.isDirectory()) {
        if (ignoreDirs.has(ent.name)) continue;
        stack.push(abs);
      } else if (ent.isFile()) {
        if (DEFAULT_IGNORE_FILE_RE.test(ent.name)) continue;
        const rel = path.relative(absRoot, abs).replace(/\\/g, '/');
        if (!includeNonSource && !isTextSource(rel)) continue;
        let size = 0;
        try {
          const st = await fs.stat(abs);
          size = st.size;
        } catch {
          continue;
        }
        if (size > MAX_FILE_BYTES) continue;
        out.push({ path: rel, abs, size, language: detectLanguage(rel) });
        if (out.length >= maxFiles) {
          truncated = true;
          break;
        }
      }
    }
    if (truncated) break;
  }

  out.sort((a, b) => a.path.localeCompare(b.path));
  out.truncated = truncated;
  return out;
}

/** Very small .gitignore reader: only harvest top-level directory ignores (safe subset). */
async function loadGitignoreDirs(root) {
  const dirs = new Set();
  try {
    const txt = await fs.readFile(path.join(root, '.gitignore'), 'utf8');
    for (let line of txt.split(/\r?\n/)) {
      line = line.trim();
      if (!line || line.startsWith('#') || line.startsWith('!')) continue;
      // only take simple "dirname/" or "dirname" patterns without globs/slashes-in-middle
      const clean = line.replace(/^\/+/, '').replace(/\/+$/, '');
      if (clean && !clean.includes('/') && !clean.includes('*') && !clean.includes('.')) {
        dirs.add(clean);
      }
    }
  } catch {
    /* no gitignore — fine */
  }
  return dirs;
}

/** Convenience reader bound to a root. */
export function makeReader(root) {
  const absRoot = path.resolve(root);
  return async (rel) => fs.readFile(path.join(absRoot, rel), 'utf8');
}
