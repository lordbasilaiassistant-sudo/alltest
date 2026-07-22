// core/baseline.js — accept a codebase's existing findings once, then report only NEW ones.
// This is what makes alltest adoptable on a large legacy repo: you can't gate CI on 8,000
// pre-existing findings, but you CAN gate on the ones a change introduces. Findings match
// the baseline by (signature + file), not line number, so unrelated edits that shift lines
// don't resurface accepted debt as "new".

import { promises as fs } from 'node:fs';
import path from 'node:path';

/** Stable key for baseline matching: independent of line number (survives code moving). */
export function baselineKey(finding) {
  const rec = typeof finding.toRecord === 'function' ? finding.toRecord() : finding;
  const sig = rec.signature || finding.signature || `${rec.probe}::${rec.ruleId}`;
  return `${sig}@@${rec.file || ''}`;
}

/**
 * @param {string} file
 * @returns {Promise<{keys:Set<string>, count:number, createdAt?:string}|null>}
 */
export async function loadBaseline(file) {
  let raw;
  try { raw = await fs.readFile(path.resolve(file), 'utf8'); } catch { return null; }
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return null; }
  const keys = new Set(Array.isArray(parsed.keys) ? parsed.keys : []);
  return { keys, count: keys.size, createdAt: parsed.createdAt };
}

/**
 * Write the current findings as the accepted baseline.
 * @param {string} file
 * @param {import('./finding.js').Finding[]} findings
 * @param {object} [meta]
 * @returns {Promise<number>} number of keys written
 */
export async function writeBaseline(file, findings, meta = {}) {
  const abs = path.resolve(file);
  await fs.mkdir(path.dirname(abs), { recursive: true });
  const keys = [...new Set(findings.map(baselineKey))].sort();
  const body = {
    tool: 'alltest',
    createdAt: meta.createdAt || null, // stamped by caller (Date.* is avoided in core)
    root: meta.root || null,
    total: keys.length,
    // a human-readable index (not used for matching, just so diffs are reviewable)
    byRule: countBy(findings, (f) => f.ruleId),
    keys,
  };
  await fs.writeFile(abs, JSON.stringify(body, null, 2));
  return keys.length;
}

/**
 * Split findings into new vs baselined.
 * @param {import('./finding.js').Finding[]} findings
 * @param {{keys:Set<string>}} baseline
 */
export function diffAgainstBaseline(findings, baseline) {
  const isNew = [], baselined = [];
  for (const f of findings) {
    (baseline.keys.has(baselineKey(f)) ? baselined : isNew).push(f);
  }
  // fixed = baseline keys no longer present (resolved debt — worth celebrating in output)
  const present = new Set(findings.map(baselineKey));
  const fixed = [...baseline.keys].filter((k) => !present.has(k));
  return { isNew, baselined, fixedCount: fixed.length };
}

function countBy(arr, fn) {
  const o = {};
  for (const x of arr) { const k = fn(x); o[k] = (o[k] || 0) + 1; }
  return o;
}
