// core/fix.js — the fix engine. Turns a finding into an ACTUAL remediation, not advice:
// the concrete before→after change, a unified-diff patch, and (when the change is
// mechanically safe) an auto-applicable flag. This is what lets `alltest fix --apply`
// remediate real issues, and what makes filed issues directly actionable by an AI.

import { promises as fs } from 'node:fs';
import path from 'node:path';

/**
 * @typedef {Object} Fix
 * @property {string} ruleId
 * @property {string} file
 * @property {number} line
 * @property {'replace-line'|'delete-line'|'edit-span'|'create-file'|'insert'|'manual'} strategy
 * @property {string|null} original     - current code (the line, or a description for create-file)
 * @property {string|null} replacement  - fixed code (null for manual)
 * @property {string} patch             - unified diff a human/agent can apply
 * @property {string} note              - the exact change, in plain terms
 * @property {boolean} autoApplicable   - mechanically safe + behavior-preserving-or-safer
 * @property {number} confidence
 */

// ── per-rule fix generators ─────────────────────────────────────────────────
// Each: (f: Finding, lines: string[]) => {strategy, replacement?, note, autoApplicable, confidence, extra?} | null

const FIXERS = {
  'debugger-stmt': (f, lines) => {
    const src = lines[f.line - 1] ?? '';
    // remove just the debugger statement, keep the rest of the line
    const replacement = src.replace(/(?<![\w."'`-])debugger\b\s*;?/, '').replace(/\s+$/, '');
    return { strategy: replacement.trim() ? 'replace-line' : 'delete-line', replacement: replacement.trim() ? replacement : null,
      note: 'Remove the leftover `debugger` statement.', autoApplicable: true, confidence: 0.95 };
  },

  'disable-tls-verify': (f, lines) => {
    const src = lines[f.line - 1] ?? '';
    // strip `rejectUnauthorized: false` (and a trailing comma) — restores default cert validation
    let r = src.replace(/,?\s*rejectUnauthorized\s*:\s*false\s*,?/, (m) => m.trim().startsWith(',') && m.trim().endsWith(',') ? ',' : '');
    if (r === src) return null;
    return { strategy: 'replace-line', replacement: r.replace(/\{\s*,/, '{').replace(/,\s*\}/, ' }'),
      note: 'Remove `rejectUnauthorized: false` so TLS certificates are validated again.', autoApplicable: true, confidence: 0.85 };
  },

  'py-requests-noverify': (f, lines) => {
    const src = lines[f.line - 1] ?? '';
    const r = src.replace(/,?\s*verify\s*=\s*False/, '');
    if (r === src) return null;
    return { strategy: 'replace-line', replacement: r, note: 'Drop `verify=False` to restore TLS certificate validation (or pass a CA bundle path).', autoApplicable: true, confidence: 0.8 };
  },

  'py-yaml-load': (f, lines) => {
    const src = lines[f.line - 1] ?? '';
    // yaml.load → yaml.safe_load, and drop any `, Loader=...` kwarg (safe_load takes none).
    // Done as two independent replacements so a nested `)` (e.g. open("f")) can't truncate it.
    let r = src.replace(/\byaml\.load\b/, 'yaml.safe_load').replace(/,\s*Loader\s*=\s*[\w.]+/, '');
    if (r === src) return null;
    return { strategy: 'replace-line', replacement: r, note: 'Use `yaml.safe_load()` — it will not execute arbitrary Python from the document (and takes no Loader).', autoApplicable: true, confidence: 0.9 };
  },

  'tx-origin-auth': (f, lines) => {
    const src = lines[f.line - 1] ?? '';
    const r = src.replace(/tx\.origin/g, 'msg.sender');
    if (r === src) return null;
    return { strategy: 'replace-line', replacement: r, note: 'Replace `tx.origin` with `msg.sender` for authorization (tx.origin is phishable).', autoApplicable: true, confidence: 0.85 };
  },

  'insecure-random-token': (f, lines) => {
    const src = lines[f.line - 1] ?? '';
    // Math.random()-based token → crypto.randomUUID(); leave a hint if not a clean swap.
    if (/Math\.random\(\)\s*\.toString\(\s*36\s*\)\s*\.slice\([^)]*\)/.test(src)) {
      const r = src.replace(/Math\.random\(\)\s*\.toString\(\s*36\s*\)\s*\.slice\([^)]*\)/, 'crypto.randomUUID()');
      return { strategy: 'replace-line', replacement: r, note: 'Use crypto.randomUUID() (import { randomUUID } from "node:crypto") for a secure value.', autoApplicable: false, confidence: 0.6 };
    }
    return { strategy: 'manual', replacement: null, note: 'Replace Math.random() with crypto.randomBytes(n).toString("hex") or crypto.randomUUID() for this security-sensitive value.', autoApplicable: false, confidence: 0.5 };
  },

  'missing-gitignore': (f) => ({
    strategy: 'create-file', original: '(no .gitignore)',
    replacement: DEFAULT_GITIGNORE, note: 'Create a .gitignore so build artifacts, dependencies and secrets are not committed.',
    autoApplicable: true, confidence: 0.8, extra: { createPath: '.gitignore' },
  }),

  'env-not-ignored': (f) => ({
    strategy: 'insert', original: '.gitignore (no .env rule)',
    replacement: '.env\n.env.*\n!.env.example', note: 'Add .env patterns to .gitignore so a real secrets file cannot be committed.',
    autoApplicable: true, confidence: 0.7, extra: { appendTo: '.gitignore', appendText: '\n# environment files\n.env\n.env.*\n!.env.example\n' },
  }),

  'committed-dotenv': (f) => ({
    strategy: 'manual', original: f.file, replacement: null,
    note: `Untrack and rotate: \`git rm --cached ${f.file}\`, add \`${f.file}\` to .gitignore, then ROTATE every secret it contained (git history keeps the old values).`,
    autoApplicable: false, confidence: 0.9,
  }),

  'key-file-committed': (f) => ({
    strategy: 'manual', original: f.file, replacement: null,
    note: `Remove and rotate: \`git rm --cached ${f.file}\`, add it to .gitignore, generate a NEW key, and treat the old one as compromised (it is in git history).`,
    autoApplicable: false, confidence: 0.9,
  }),

  'floating-pragma': (f, lines) => {
    const src = lines[f.line - 1] ?? '';
    const m = /pragma\s+solidity\s+\^(\d+\.\d+\.\d+)/.exec(src);
    if (!m) return null;
    const r = src.replace(/\^(\d+\.\d+\.\d+)/, '$1');
    return { strategy: 'replace-line', replacement: r, note: `Pin the compiler to exactly ${m[1]} (drop the ^) for reproducible bytecode.`, autoApplicable: true, confidence: 0.7 };
  },

  'catch-swallow': (f, lines) => {
    const src = lines[f.line - 1] ?? '';
    const indent = (src.match(/^\s*/) || [''])[0];
    const m = /catch\s*\(\s*([A-Za-z_$][\w$]*)?\s*\)/.exec(src);
    const errName = (m && m[1]) || 'err';
    const fixed = src.replace(/(catch\s*\(\s*)(\)|[A-Za-z_$][\w$]*\s*\))\s*\{\s*\}/,
      (full, pre, close) => `${pre.replace(/\($/, '(')}${m && m[1] ? '' : errName}${close.trim() === ')' ? ')' : close}`);
    return { strategy: 'replace-line',
      replacement: src.replace(/\{\s*\}/, `{ console.error(${errName}); }`),
      note: `Do not swallow the error silently — at minimum log it (console.error(${errName})) or handle it.`,
      autoApplicable: false, confidence: 0.6 };
  },

  // Generic secret → env-var replacement (covers hardcoded-password + all named vendor keys).
  __secret: (f, lines) => {
    const src = lines[f.line - 1] ?? '';
    // find the assigned variable and its quoted literal
    const am = /([A-Za-z_$][\w$]*)\s*([:=])\s*(["'`])(?:[^"'`\\]|\\.)*\3/.exec(src);
    if (!am) return null;
    const varName = am[1];
    const op = am[2];
    const envName = toEnvName(varName);
    const replacement = src.replace(/([:=])\s*(["'`])(?:[^"'`\\]|\\.)*\2/, `${op} process.env.${envName}`);
    return { strategy: 'replace-line', replacement,
      note: `Move this secret out of source: set ${envName} in your environment (and add ${envName}= to .env.example), then read it via process.env.${envName}. ROTATE the exposed value.`,
      autoApplicable: false, confidence: 0.65, extra: { envVar: envName } };
  },
};

const SECRET_RULES = new Set([
  'hardcoded-password', 'high-entropy-secret', 'aws-secret-key', 'anthropic-key', 'openai-key',
  'stripe-key', 'stripe-webhook', 'slack-token', 'npm-token', 'twilio-key', 'sendgrid-key',
  'google-api-key', 'google-oauth-secret', 'gitlab-token', 'github-token', 'telegram-bot-token',
  'digitalocean-token', 'eth-private-key', 'py-django-secret',
]);

const DEFAULT_GITIGNORE = `node_modules/
dist/
build/
coverage/
*.log
.DS_Store
.env
.env.*
!.env.example
`;

/** camelCase / snake / kebab → SCREAMING_SNAKE_CASE for an env var name. */
export function toEnvName(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[-.\s]+/g, '_')
    .toUpperCase()
    .replace(/^_+|_+$/g, '')
    .replace(/_{2,}/g, '_');
}

/** Build a one-hunk unified diff for a single-line replacement/deletion. */
function unifiedDiff(file, lineNo, before, after) {
  const b = before == null ? [] : [`-${before}`];
  const a = after == null ? [] : [`+${after}`];
  const oldCount = before == null ? 0 : 1;
  const newCount = after == null ? 0 : 1;
  return [`--- a/${file}`, `+++ b/${file}`, `@@ -${lineNo},${oldCount} +${lineNo},${newCount} @@`, ...b, ...a].join('\n');
}

/**
 * Compute a Fix for one finding, given the file's lines.
 * @returns {Fix|null}
 */
export function fixForFinding(finding, lines) {
  const gen = FIXERS[finding.ruleId] || (SECRET_RULES.has(finding.ruleId) ? FIXERS.__secret : null);
  if (!gen) return null;
  let r;
  try { r = gen(finding, lines); } catch { return null; }
  if (!r) return null;
  const original = r.original !== undefined ? r.original : (lines[finding.line - 1] ?? null);
  let patch = '';
  if (r.strategy === 'replace-line') patch = unifiedDiff(finding.file, finding.line, original, r.replacement);
  else if (r.strategy === 'delete-line') patch = unifiedDiff(finding.file, finding.line, original, null);
  else if (r.strategy === 'create-file') patch = `--- /dev/null\n+++ b/${r.extra.createPath}\n` + r.replacement.split('\n').map((l) => '+' + l).join('\n');
  else if (r.strategy === 'insert') patch = `# append to ${r.extra?.appendTo || finding.file}:\n` + (r.extra?.appendText || r.replacement);
  return {
    ruleId: finding.ruleId, file: finding.file, line: finding.line,
    strategy: r.strategy, original, replacement: r.replacement ?? null,
    patch, note: r.note, autoApplicable: !!r.autoApplicable, confidence: r.confidence ?? 0.5,
    extra: r.extra || null,
  };
}

/**
 * Compute fixes for all findings in a result (reads each file once).
 * @param {string} root
 * @param {import('./finding.js').Finding[]} findings
 * @returns {Promise<Map<string,Fix>>} keyed by finding.id
 */
export async function computeFixes(root, findings) {
  const byFile = new Map();
  for (const f of findings) {
    if (!f.file) continue;
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }
  const fixes = new Map();
  const fileCache = new Map();
  for (const [file, list] of byFile) {
    let lines = fileCache.get(file);
    if (!lines) {
      try { lines = (await fs.readFile(path.join(root, file), 'utf8')).split(/\r?\n/); }
      catch { lines = []; }
      fileCache.set(file, lines);
    }
    for (const f of list) {
      const fix = fixForFinding(f, lines);
      if (fix) fixes.set(f.id, fix);
    }
  }
  return fixes;
}

/**
 * Apply auto-applicable fixes to disk. Safe by design: one fix per (file,line), skips
 * overlapping edits, only touches autoApplicable fixes at/above minConfidence.
 * @returns {Promise<{applied:Fix[], skipped:Fix[]}>}
 */
export async function applyFixes(root, findings, opts = {}) {
  const minConfidence = opts.minConfidence ?? 0.7;
  const fixes = await computeFixes(root, findings);
  const applied = [], skipped = [];

  // group line edits by file; process create/append separately
  const lineEdits = new Map(); // file -> Map(lineNo -> fix)
  const creates = [], appends = [];
  for (const fix of fixes.values()) {
    if (!fix.autoApplicable || fix.confidence < minConfidence) { skipped.push(fix); continue; }
    if (fix.strategy === 'create-file') { creates.push(fix); continue; }
    if (fix.strategy === 'insert') { appends.push(fix); continue; }
    if (fix.strategy === 'replace-line' || fix.strategy === 'delete-line') {
      if (!lineEdits.has(fix.file)) lineEdits.set(fix.file, new Map());
      const m = lineEdits.get(fix.file);
      if (m.has(fix.line)) { skipped.push(fix); continue; } // avoid conflicting edits on one line
      m.set(fix.line, fix);
    } else { skipped.push(fix); }
  }

  for (const [file, edits] of lineEdits) {
    const abs = path.join(root, file);
    let content;
    try { content = await fs.readFile(abs, 'utf8'); } catch { for (const fx of edits.values()) skipped.push(fx); continue; }
    const eol = content.includes('\r\n') ? '\r\n' : '\n';
    const lines = content.split(/\r?\n/);
    for (const [lineNo, fix] of edits) {
      if (fix.strategy === 'delete-line') { lines[lineNo - 1] = ' DELETE '; }
      else { lines[lineNo - 1] = fix.replacement; }
      applied.push(fix);
    }
    const out = lines.filter((l) => l !== ' DELETE ').join(eol);
    if (!opts.dryRun) await fs.writeFile(abs, out);
  }

  for (const fix of creates) {
    const p = path.join(root, fix.extra.createPath);
    try { await fs.access(p); skipped.push(fix); } // don't overwrite an existing file
    catch { if (!opts.dryRun) await fs.writeFile(p, fix.replacement); applied.push(fix); }
  }
  for (const fix of appends) {
    const p = path.join(root, fix.extra.appendTo);
    try {
      const cur = await fs.readFile(p, 'utf8').catch(() => '');
      if (!opts.dryRun) await fs.writeFile(p, cur + fix.extra.appendText);
      applied.push(fix);
    } catch { skipped.push(fix); }
  }

  return { applied, skipped };
}
