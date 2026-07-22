// static/entropy-secrets.js — 0-day secret detection via entropy.
// Known-pattern matching (static/secrets) can't catch a credential format it has never
// seen. This probe flags high-entropy strings that *look* like tokens but match no known
// pattern — the way you find a leaked secret whose vendor you don't have a rule for.

import { classifySecretCandidate, extractCandidates } from '../../core/entropy.js';

// var-name context: capture the identifier being assigned, if any.
const ASSIGN_RE = /([A-Za-z_$][\w$.]*)\s*[:=]\s*["'`]/;

export default {
  id: 'static/entropy-secrets',
  title: 'High-entropy secrets (unknown-format / 0-day)',
  layer: 'static',
  languages: ['*'],
  order: 2,
  description: 'Entropy analysis to catch credentials that match no known signature — leaked tokens of unknown vendor/format.',
  async run(ctx) {
    for (const file of ctx.files) {
      // Skip file types where high-entropy strings are expected and benign.
      if (/\.(lock|min\.js|map|svg|csv|tsv)$/i.test(file.path)) continue;
      const lang = file.language;
      if (lang === 'markdown') continue;

      let text;
      try { text = await ctx.read(file.path); } catch { continue; }
      if (text.length > 1_000_000) continue;

      const isTestOrExample = /(^|\/)(test|tests|__tests__|spec|fixtures?|mocks?|examples?)\//.test(file.path)
        || /\.(test|spec|example|sample)\./.test(file.path);

      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 800) continue; // minified/data line
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

        const varMatch = ASSIGN_RE.exec(line);
        const varName = varMatch ? varMatch[1] : '';

        const isDataFile = /\.(json|abi)$/i.test(file.path);
        for (const cand of extractCandidates(line)) {
          // JSON/ABI files are full of addresses, bytecode, and hashes — all high-entropy
          // hex that is never a secret. Skip hex candidates there entirely.
          if (isDataFile && /^(0x)?[0-9a-fA-F]+$/.test(cand.value.trim())) continue;
          const cls = classifySecretCandidate(cand.value, line, varName);
          if (!cls) continue;

          // Only report when the assignment CONTEXT looks credential-ish. A bare
          // high-entropy blob with no secret-ish name is overwhelmingly a contract
          // address / hash / bytecode / encoded asset — reporting those buries the
          // real signal. Named-but-unknown-format secrets are the 0-day value here.
          if (!cls.secretName) continue;

          let confidence = 0.65;
          if (isTestOrExample) confidence *= 0.5;
          if (confidence < 0.35) continue;

          ctx.report({
            ruleId: 'high-entropy-secret',
            severity: 'high',
            title: `Possible secret: ${cls.reason}`,
            message: `A ${cls.kind} string of length ${cls.length} with entropy ${cls.entropy} bits/char was found at ${file.path}:${i + 1}. It matches no known credential pattern but looks like a token — verify it is not a leaked secret.`,
            file: file.path,
            line: i + 1,
            column: cand.index + 1,
            snippet: redact(trimmed),
            language: lang,
            confidence,
            fixHint: 'If this is a credential, remove it from source, rotate it, and load from an environment variable. If it is a legitimate high-entropy constant (hash, id, encoded data), mark it with `// alltest-ignore high-entropy-secret`.',
            tags: ['secret', 'entropy', 'zero-day', 'cwe-798'],
            meta: { entropy: cls.entropy, length: cls.length, kind: cls.kind },
          });
        }
      }
    }
  },
};

/** Redact the high-entropy middle so we never echo a real secret into a report/corpus. */
function redact(line) {
  return line.replace(/["'`]([A-Za-z0-9+/=_-]{16,200})["'`]/g, (full, tok) => {
    const q = full[0];
    return `${q}${tok.slice(0, 4)}…[${tok.length} chars, redacted]…${tok.slice(-2)}${q}`;
  }).slice(0, 200);
}
