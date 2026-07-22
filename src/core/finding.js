// finding.js — the central data model.
// A Finding is simultaneously: a human-readable result, a GitHub-issue payload,
// and one row of the ML training corpus. Keep this schema stable — everything keys off it.

/** Severity ordering. Higher number = worse. Used for sorting, gating, and exit codes. */
export const SEVERITY = Object.freeze({
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

export const SEVERITY_NAMES = Object.freeze(
  Object.keys(SEVERITY).sort((a, b) => SEVERITY[a] - SEVERITY[b])
);

/** @typedef {'info'|'low'|'medium'|'high'|'critical'} Severity */

/**
 * @typedef {Object} FindingInit
 * @property {string} probe       - id of the probe that produced this (e.g. "static/secrets")
 * @property {string} ruleId      - stable id of the specific rule (e.g. "aws-access-key")
 * @property {Severity} severity
 * @property {string} title       - one-line summary
 * @property {string} [message]   - longer human explanation
 * @property {string} [file]      - repo-relative path
 * @property {number} [line]      - 1-indexed
 * @property {number} [column]    - 1-indexed
 * @property {string} [snippet]   - the offending code (redacted for secrets)
 * @property {string} [language]  - detected language of `file`
 * @property {string} [fixHint]   - concrete, AI-actionable remediation
 * @property {number} [confidence]- 0..1 how sure we are (drives 0-day triage)
 * @property {string[]} [tags]    - freeform, e.g. ["security","owasp:a3","cwe-798"]
 * @property {Object} [meta]      - probe-specific extra data
 */

let _seq = 0;

export class Finding {
  /** @param {FindingInit} init */
  constructor(init) {
    if (!init || typeof init !== 'object') {
      throw new TypeError('Finding requires an init object');
    }
    const { probe, ruleId, severity, title } = init;
    if (!probe) throw new TypeError('Finding.probe is required');
    if (!ruleId) throw new TypeError('Finding.ruleId is required');
    if (!(severity in SEVERITY)) {
      throw new TypeError(`Finding.severity must be one of ${SEVERITY_NAMES.join(', ')}; got ${severity}`);
    }
    if (!title) throw new TypeError('Finding.title is required');

    this.id = `f${(++_seq).toString(36)}`;
    this.probe = probe;
    this.ruleId = ruleId;
    this.severity = severity;
    this.title = title;
    this.message = init.message || '';
    this.file = init.file || null;
    this.line = init.line ?? null;
    this.column = init.column ?? null;
    this.snippet = init.snippet ?? null;
    this.language = init.language ?? null;
    this.fixHint = init.fixHint || '';
    this.confidence = clamp01(init.confidence ?? 0.8);
    this.tags = Array.isArray(init.tags) ? [...init.tags] : [];
    this.meta = init.meta && typeof init.meta === 'object' ? init.meta : {};
    this.fix = init.fix || null; // concrete remediation, attached by the fix engine on demand
  }

  get severityRank() {
    return SEVERITY[this.severity];
  }

  /** A stable fingerprint for dedup + RSI novelty detection (independent of line noise). */
  get signature() {
    return signatureOf(this);
  }

  /** Location string for humans / clickable in editors. */
  get location() {
    if (!this.file) return '(project)';
    let loc = this.file;
    if (this.line != null) loc += `:${this.line}`;
    if (this.column != null) loc += `:${this.column}`;
    return loc;
  }

  /** One ML-corpus row. Deterministic key order for reproducible datasets. */
  toRecord() {
    return {
      probe: this.probe,
      ruleId: this.ruleId,
      severity: this.severity,
      title: this.title,
      message: this.message,
      file: this.file,
      line: this.line,
      column: this.column,
      snippet: this.snippet,
      language: this.language,
      fixHint: this.fixHint,
      confidence: this.confidence,
      tags: this.tags,
      signature: this.signature,
      fix: this.fix ? safeValue(this.fix) : null,
      meta: safeValue(this.meta),
    };
  }
}

/**
 * Make an arbitrary probe-supplied value JSON-safe: coerce BigInt to string, break
 * cycles, drop functions/symbols/undefined. A probe stashing an on-chain 123n amount or
 * a circular object in `meta` must never be able to crash the entire report.
 */
export function safeValue(v, seen = new WeakSet(), depth = 0) {
  if (v === null || v === undefined) return null;
  const t = typeof v;
  if (t === 'bigint') return v.toString();
  if (t === 'number') return Number.isFinite(v) ? v : String(v);
  if (t === 'string' || t === 'boolean') return v;
  if (t === 'function' || t === 'symbol') return undefined;
  if (depth > 6) return '[max-depth]';
  if (Array.isArray(v)) {
    if (seen.has(v)) return '[circular]';
    seen.add(v);
    return v.slice(0, 500).map((x) => safeValue(x, seen, depth + 1));
  }
  if (t === 'object') {
    if (seen.has(v)) return '[circular]';
    seen.add(v);
    const out = {};
    for (const k of Object.keys(v)) {
      const sv = safeValue(v[k], seen, depth + 1);
      if (sv !== undefined) out[k] = sv;
    }
    return out;
  }
  return String(v);
}

/**
 * Deterministic fingerprint: probe + rule + language + normalized snippet shape.
 * Deliberately excludes file/line so the same bug in two places (or after edits)
 * collapses to one signature — that's what lets RSI recognize "seen this class before".
 * @param {Finding|FindingInit} f
 */
export function signatureOf(f) {
  const norm = normalizeSnippet(f.snippet || f.title || '');
  return `${f.probe}::${f.ruleId}::${f.language || 'any'}::${norm}`;
}

/** Collapse identifiers/numbers/whitespace so trivially-different code shares a signature. */
export function normalizeSnippet(s) {
  return String(s)
    .replace(/["'`][^"'`]*["'`]/g, 'STR')   // string literals
    .replace(/\b0x[0-9a-fA-F]+\b/g, 'HEX')   // hex/addresses
    .replace(/\b\d+(\.\d+)?\b/g, 'NUM')      // numbers
    .replace(/[A-Za-z_$][A-Za-z0-9_$]{0,}/g, (w) => KEYWORDS.has(w) ? w : 'ID') // idents → ID, keep keywords
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200);
}

const KEYWORDS = new Set([
  'function', 'return', 'if', 'else', 'for', 'while', 'const', 'let', 'var',
  'require', 'import', 'export', 'eval', 'new', 'async', 'await', 'class',
  'public', 'private', 'external', 'internal', 'payable', 'call', 'delegatecall',
  'selfdestruct', 'transfer', 'send', 'assembly', 'tx', 'origin', 'msg', 'sender',
]);

function clamp01(n) {
  n = Number(n);
  if (Number.isNaN(n)) return 0.8;
  return Math.max(0, Math.min(1, n));
}

/** Compare for sort: worst severity first, then higher confidence, then file. */
export function compareFindings(a, b) {
  if (b.severityRank !== a.severityRank) return b.severityRank - a.severityRank;
  if (b.confidence !== a.confidence) return b.confidence - a.confidence;
  return String(a.file).localeCompare(String(b.file)) || (a.line ?? 0) - (b.line ?? 0);
}

/** Deduplicate a list of findings by (signature, file, line). */
export function dedupeFindings(findings) {
  const seen = new Map();
  for (const f of findings) {
    const key = `${f.signature}@@${f.file}:${f.line}`;
    if (!seen.has(key)) seen.set(key, f);
  }
  return [...seen.values()];
}
