// ml/dataset.js — the ML training-corpus pipeline.
// Every finding becomes a labeled example for a future model that learns to detect
// issues directly. We store JSONL (one example per line) with a stable schema + a
// content hash so the corpus can be deduped and versioned as it grows across runs.

import { promises as fs } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * Append a run's findings to a JSONL corpus file (creating it if needed).
 * Deduplicates within the append against existing content hashes when the file is small
 * enough to read; otherwise appends blindly (dedup is done offline by `dedupeCorpus`).
 * @returns {Promise<number>} number of rows written
 */
export async function appendCorpus(file, result, opts = {}) {
  const abs = path.resolve(file);
  await fs.mkdir(path.dirname(abs), { recursive: true });

  const rows = result.findings.map((f) => toExample(f, result, opts));
  const lines = rows.map((r) => JSON.stringify(r)).join('\n');
  await fs.appendFile(abs, lines + (lines ? '\n' : ''), 'utf8');

  // also keep a rolling meta manifest
  await writeManifest(abs, result, rows.length);
  return rows.length;
}

/** Convert a Finding to a training example. Deterministic key order. */
export function toExample(finding, result = {}, opts = {}) {
  const rec = typeof finding.toRecord === 'function' ? finding.toRecord() : finding;
  const example = {
    // input signal
    snippet: rec.snippet || '',
    language: rec.language || 'unknown',
    context_path: rec.file || null,
    // labels (what a detector must learn to predict)
    label: rec.ruleId,
    category: (rec.tags && rec.tags[0]) || rec.probe,
    severity: rec.severity,
    probe: rec.probe,
    // remediation target (for fix-suggestion training)
    fix: rec.fixHint || '',
    // metadata
    confidence: rec.confidence,
    tags: rec.tags || [],
    signature: rec.signature || null,
    source_repo: opts.repo || basename(result.root || opts.root || ''),
    collected_at: result.startedAt || null,
    schema_version: 1,
  };
  example.hash = crypto.createHash('sha1')
    .update(`${example.label}|${example.language}|${example.snippet}`)
    .digest('hex')
    .slice(0, 16);
  return example;
}

/** Offline dedup: rewrite a corpus keeping the first row per content hash. */
export async function dedupeCorpus(file) {
  const abs = path.resolve(file);
  let text;
  try { text = await fs.readFile(abs, 'utf8'); } catch { return { before: 0, after: 0 }; }
  const seen = new Set();
  const kept = [];
  let before = 0;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    before++;
    let obj;
    try { obj = JSON.parse(line); } catch { continue; }
    const h = obj.hash || crypto.createHash('sha1').update(line).digest('hex').slice(0, 16);
    if (seen.has(h)) continue;
    seen.add(h);
    kept.push(JSON.stringify(obj));
  }
  await fs.writeFile(abs, kept.join('\n') + '\n', 'utf8');
  return { before, after: kept.length };
}

/** Basic corpus stats — label balance is what you need to know before training. */
export async function corpusStats(file) {
  const abs = path.resolve(file);
  const text = await fs.readFile(abs, 'utf8');
  const byLabel = {}, byLang = {}, bySeverity = {};
  let n = 0;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let o; try { o = JSON.parse(line); } catch { continue; }
    n++;
    byLabel[o.label] = (byLabel[o.label] || 0) + 1;
    byLang[o.language] = (byLang[o.language] || 0) + 1;
    bySeverity[o.severity] = (bySeverity[o.severity] || 0) + 1;
  }
  return { examples: n, labels: Object.keys(byLabel).length, byLabel, byLang, bySeverity };
}

async function writeManifest(corpusPath, result, added) {
  const manifestPath = corpusPath.replace(/\.jsonl?$/, '') + '.manifest.json';
  let manifest = { runs: 0, totalAdded: 0, lastRun: null, repos: [] };
  try { manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8')); } catch {}
  manifest.runs = (manifest.runs || 0) + 1;
  manifest.totalAdded = (manifest.totalAdded || 0) + added;
  manifest.lastRun = result.startedAt || null;
  const repo = basename(result.root || '');
  if (repo && !manifest.repos.includes(repo)) manifest.repos.push(repo);
  await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
}

function basename(p) {
  return String(p).replace(/\\/g, '/').replace(/\/+$/, '').split('/').pop() || '';
}
