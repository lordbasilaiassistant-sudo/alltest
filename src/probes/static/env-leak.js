// static/env-leak.js — information-disclosure patterns.
// The ThryxEco audit found 25+ places leaking e.message to clients. Rules require the
// value to hang off an ERROR-ish variable (err/error/e/caughtError) so benign fields
// like `profile.message` or `user.stack` / `techStack` are not misflagged.

// error-ish variable: bare e/ex/err, or any identifier ending in err/error/exception.
const ERRVAR = String.raw`(?:e|ex|err|error|exception|\w*[eE]rr(?:or)?|\w*[eE]xception)`;

const RULES = [
  {
    id: 'error-message-to-response',
    re: new RegExp(String.raw`res(?:ponse)?\.(?:json|send|end|write|status\([^)]*\)\.(?:json|send))\s*\([^)]*\b${ERRVAR}\.(?:message|stack)\b`, 'i'),
    severity: 'medium', title: 'Raw error message/stack returned in HTTP response',
    confidence: 0.7, tags: ['info-disclosure', 'cwe-209'],
    fix: 'Return a generic error to clients and log details server-side. Leaking e.message/e.stack reveals internals to attackers.',
  },
  {
    id: 'stack-in-response',
    re: new RegExp(String.raw`\.(?:json|send|write|render)\s*\([^)]*\b${ERRVAR}\.stack\b|ctx\.body\s*=\s*[^;\n]*\b${ERRVAR}\.(?:stack|message)\b|reply\.send\s*\(\s*${ERRVAR}\b`, 'i'),
    severity: 'medium', title: 'Stack trace / raw error exposed to client (Express/Koa/Fastify)',
    confidence: 0.65, tags: ['info-disclosure', 'cwe-209'],
    fix: 'Never send stack traces to clients. Log them; return a generic message + request id.',
  },
  {
    id: 'render-error-object',
    re: new RegExp(String.raw`res\.render\s*\([^)]*\{[^}]*\b${ERRVAR}\b`, 'i'),
    severity: 'low', title: 'Error object passed to a template render',
    confidence: 0.4, tags: ['info-disclosure'],
    fix: 'Rendering the raw error into a template can leak internals. Pass a sanitized message.',
  },
  {
    id: 'env-dump',
    re: /(?:res(?:ponse)?\.(?:json|send)\s*\(\s*process\.env|JSON\.stringify\s*\(\s*process\.env|ctx\.body\s*=\s*process\.env)/,
    severity: 'high', title: 'process.env serialized/returned (secrets leak)',
    confidence: 0.85, tags: ['info-disclosure', 'secret'],
    fix: 'Never serialize process.env — it contains every secret. Expose only the specific, non-secret values you need.',
  },
  {
    id: 'cors-wildcard',
    re: /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]|\bcors\s*\(\s*\)/,
    severity: 'medium', title: 'CORS allows any origin (wildcard or default cors())',
    confidence: 0.55, tags: ['cors', 'cwe-942'],
    fix: 'A wildcard CORS origin lets any site call your API. Restrict to known origins, especially with credentials.',
  },
  {
    id: 'verbose-error-flag',
    // Require an error/stack CONTEXT so benign options like chart `{stack:true}` don't match.
    re: /\b(?:showStack|includeStack|exposeErrors?|stackTrace|verboseErrors?)\s*:\s*true|errors?\s*:\s*\{\s*[^}]*stack\s*:\s*true/i,
    severity: 'low', title: 'Verbose/stack error flag enabled',
    confidence: 0.45, tags: ['info-disclosure'],
    fix: 'Ensure verbose error output is off in production configs.',
  },
];

const IS_CODE = new Set(['javascript', 'typescript', 'python', 'go', 'ruby', 'php', 'java']);

export default {
  id: 'static/env-leak',
  title: 'Information disclosure (error/stack/env leaks)',
  layer: 'static',
  languages: ['javascript', 'typescript', 'python', 'go', 'ruby', 'php', 'java'],
  order: 6,
  description: 'Raw error messages/stacks in responses (Express/Koa/Fastify/render), process.env dumps, wildcard CORS.',
  async run(ctx) {
    for (const file of ctx.files) {
      if (!IS_CODE.has(file.language)) continue;
      let text;
      try { text = await ctx.read(file.path); } catch { continue; }
      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 2000) continue;
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) continue;
        for (const rule of RULES) {
          if (!rule.re.test(line)) continue;
          ctx.report({
            ruleId: rule.id,
            severity: rule.severity,
            title: rule.title,
            message: `${rule.title} at ${file.path}:${i + 1}.`,
            file: file.path, line: i + 1,
            snippet: trimmed.slice(0, 200),
            language: file.language,
            confidence: rule.confidence,
            fixHint: rule.fix,
            tags: rule.tags,
          });
        }
      }
    }
  },
};
