// rsi/learn.js — the Recursive Self-Improvement loop.
// alltest gets better the more code it sees. Every finding's *signature* is checked
// against a persistent knowledge base. Novel signatures are recorded with their
// frequency, example, and a synthesizable rule template — so tomorrow's scan recognizes
// a pattern that was "0-day" (unknown to the tool) today. This is the closed learning loop.

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const KB_PATH = path.resolve(__dirname, '..', '..', 'knowledge', 'signatures.jsonl');

/**
 * Ingest a scan result: register novel signatures, bump counts on known ones.
 * @param {{findings: Array<{signature?:string, toRecord?:Function}>}} result
 * @param {object} [opts]
 * @param {string} [opts.kbPath]
 * @returns {Promise<{novel:number, updated:number, total:number}>}
 */
export async function learnFromResult(result, opts = {}) {
  const kbPath = opts.kbPath || KB_PATH;
  const kb = await loadKB(kbPath);

  let novel = 0, updated = 0;
  for (const f of result.findings) {
    const rec = typeof f.toRecord === 'function' ? f.toRecord() : f;
    const sig = rec.signature || f.signature;
    if (!sig) continue;
    const existing = kb.get(sig);
    if (existing) {
      existing.count += 1;
      existing.lastSeen = rec.collected_at || existing.lastSeen;
      if (!existing.examples.includes(rec.file) && existing.examples.length < 5 && rec.file) {
        existing.examples.push(rec.file);
      }
      updated++;
    } else {
      kb.set(sig, newEntry(sig, rec));
      novel++;
    }
  }

  await saveKB(kbPath, kb);
  return { novel, updated, total: kb.size };
}

/** A novel finding becomes a knowledge entry — including a rule template for future auto-detection. */
function newEntry(signature, rec) {
  return {
    signature,
    ruleId: rec.ruleId,
    probe: rec.probe,
    language: rec.language || 'any',
    severity: rec.severity,
    title: rec.title,
    tags: rec.tags || [],
    fixHint: rec.fixHint || '',
    // The normalized shape can seed a regex/AST rule; kept for a future rule-synthesizer.
    template: extractTemplate(rec.snippet || rec.title || ''),
    examples: rec.file ? [rec.file] : [],
    count: 1,
    firstSeen: rec.collected_at || null,
    lastSeen: rec.collected_at || null,
    status: 'observed', // observed → candidate-rule → promoted
  };
}

/**
 * Promote high-frequency observed signatures to candidate rules.
 * When a signature has been seen >= threshold times across scans, it's a real pattern
 * worth a dedicated detector — mark it for promotion. (The rule-synthesizer/human/agent
 * then turns `template` into a probe rule.)
 */
export async function promoteCandidates(threshold = 3, opts = {}) {
  const kbPath = opts.kbPath || KB_PATH;
  const kb = await loadKB(kbPath);
  const promoted = [];
  for (const entry of kb.values()) {
    if (entry.status === 'observed' && entry.count >= threshold) {
      entry.status = 'candidate-rule';
      promoted.push(entry);
    }
  }
  await saveKB(kbPath, kb);
  return promoted;
}

export async function kbStats(opts = {}) {
  const kb = await loadKB(opts.kbPath || KB_PATH);
  const byStatus = {}, byLang = {};
  for (const e of kb.values()) {
    byStatus[e.status] = (byStatus[e.status] || 0) + 1;
    byLang[e.language] = (byLang[e.language] || 0) + 1;
  }
  return { total: kb.size, byStatus, byLang };
}

async function loadKB(kbPath) {
  const kb = new Map();
  let text = '';
  try { text = await fs.readFile(kbPath, 'utf8'); } catch { return kb; }
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const e = JSON.parse(line);
      if (e.signature) kb.set(e.signature, e);
    } catch { /* skip corrupt line */ }
  }
  return kb;
}

async function saveKB(kbPath, kb) {
  await fs.mkdir(path.dirname(kbPath), { recursive: true });
  const lines = [...kb.values()].map((e) => JSON.stringify(e)).join('\n');
  await fs.writeFile(kbPath, lines + (lines ? '\n' : ''), 'utf8');
}

function extractTemplate(s) {
  return String(s)
    .replace(/["'`][^"'`]*["'`]/g, '<STR>')
    .replace(/\b0x[0-9a-fA-F]+\b/g, '<HEX>')
    .replace(/\b\d+\b/g, '<NUM>')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 160);
}
