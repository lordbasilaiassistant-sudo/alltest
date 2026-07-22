// static/custom-rules.js — user- and RSI-defined detection rules, loaded at scan time.
// A team (or an agent acting on an RSI rule proposal) can add detections WITHOUT writing
// code: drop a `.alltest/rules.json` in the repo. This is the extensibility surface that
// lets alltest learn new error types — the closed end of the RSI loop.
//
// .alltest/rules.json  (array, or { rules: [...] }):
//   [{
//     "id": "no-internal-token",
//     "pattern": "INT-[A-Z0-9]{24}",       // regex source (required)
//     "flags": "i",                          // optional
//     "severity": "high",                    // info|low|medium|high|critical
//     "title": "Internal service token committed",
//     "message": "…",                        // optional longer text
//     "languages": ["*"],                    // optional; "*" or a list of language ids
//     "fixHint": "Load INT_TOKEN from the environment; rotate this one.",
//     "tags": ["secret"],
//     "confidence": 0.8,
//     "skipTests": true                       // optional; down-weight in test dirs
//   }]

import { promises as fs } from 'node:fs';
import path from 'node:path';

const CANDIDATE_PATHS = [
  '.alltest/rules.json',
  '.alltestrules.json',
  '.alltest/rules.jsonc',
];
const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);
const MAX_RULES = 500;

export default {
  id: 'static/custom-rules',
  title: 'Custom & learned detection rules',
  layer: 'static',
  languages: ['*'],
  order: 10,
  description: 'Applies user/RSI-defined regex rules from .alltest/rules.json — extend detection with no code.',
  async run(ctx) {
    const { rules, error, source } = await loadRules(ctx.root);
    if (error) {
      ctx.report({
        ruleId: 'custom-rules-invalid', severity: 'low',
        title: `Custom rules file is invalid: ${source}`,
        message: error, file: source, line: 1, confidence: 0.9,
        fixHint: 'Fix the JSON / rule schema so your custom detection rules load.',
        tags: ['config'],
      });
      return;
    }
    if (!rules.length) return;

    // Pre-compile once; a bad regex becomes a finding, never a crash.
    const compiled = [];
    for (const r of rules) {
      try {
        compiled.push({ ...r, re: new RegExp(r.pattern, sanitizeFlags(r.flags)) });
      } catch (e) {
        ctx.report({
          ruleId: 'custom-rule-bad-regex', severity: 'low',
          title: `Custom rule "${r.id}" has an invalid regex`,
          message: `${e.message}`, file: source, line: 1, confidence: 0.9,
          fixHint: 'Correct the "pattern" for this rule.', tags: ['config'],
        });
      }
    }
    if (!compiled.length) return;

    for (const file of ctx.files) {
      let text;
      try { text = await ctx.read(file.path); } catch { continue; }
      const isTest = /(^|\/)(test|tests|__tests__|spec|fixtures?)\//.test(file.path) || /\.(test|spec)\./.test(file.path);
      const lines = text.split(/\r?\n/);
      for (const rule of compiled) {
        if (rule.languages && !rule.languages.includes('*') && !rule.languages.includes(file.language)) continue;
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.length > 2000) continue;
          const m = new RegExp(rule.re.source, rule.re.flags.replace('g', '')).exec(line);
          if (!m) continue;
          const conf = (rule.confidence ?? 0.7) * (isTest && rule.skipTests ? 0.4 : 1);
          ctx.report({
            ruleId: rule.id,
            severity: rule.severity,
            title: rule.title,
            message: rule.message || `${rule.title} at ${file.path}:${i + 1}.`,
            file: file.path, line: i + 1, column: line.indexOf(m[0]) + 1,
            snippet: line.trim().slice(0, 200),
            language: file.language,
            confidence: conf,
            fixHint: rule.fixHint || 'Review and remediate this custom-rule match.',
            tags: Array.isArray(rule.tags) ? ['custom', ...rule.tags] : ['custom'],
            meta: { custom: true, source },
          });
        }
      }
    }
  },
};

async function loadRules(root) {
  for (const rel of CANDIDATE_PATHS) {
    let raw;
    try { raw = await fs.readFile(path.join(root, rel), 'utf8'); } catch { continue; }
    let parsed;
    try {
      parsed = JSON.parse(raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1'));
    } catch (e) {
      return { rules: [], error: `JSON parse error: ${e.message}`, source: rel };
    }
    const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed.rules) ? parsed.rules : null;
    if (!list) return { rules: [], error: 'expected an array of rules, or { "rules": [...] }', source: rel };
    const { valid, error } = validateRules(list.slice(0, MAX_RULES));
    if (error) return { rules: [], error, source: rel };
    return { rules: valid, source: rel };
  }
  return { rules: [] };
}

function validateRules(list) {
  const valid = [];
  for (const [i, r] of list.entries()) {
    if (!r || typeof r !== 'object') return { valid, error: `rule #${i} is not an object` };
    if (!r.id || typeof r.id !== 'string') return { valid, error: `rule #${i} missing "id"` };
    if (!r.pattern || typeof r.pattern !== 'string') return { valid, error: `rule "${r.id}" missing "pattern"` };
    if (!SEVERITIES.has(r.severity)) return { valid, error: `rule "${r.id}" severity must be one of info|low|medium|high|critical` };
    if (!r.title) return { valid, error: `rule "${r.id}" missing "title"` };
    valid.push(r);
  }
  return { valid };
}

function sanitizeFlags(flags) {
  const allowed = new Set(['i', 'm', 's', 'u']);
  const f = String(flags || '').split('').filter((c) => allowed.has(c));
  return [...new Set(f)].join('');
}
