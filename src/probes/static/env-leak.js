// static/env-leak.js — information-disclosure patterns.
// The ThryxEco audit found 25+ places leaking e.message to clients. This probe targets
// that exact class: raw error/exception details, stack traces, and env dumps reaching
// responses or logs where an attacker can read them.

const RULES = [
  {
    id: 'error-message-to-response',
    re: /res(?:ponse)?\.(?:json|send|end|status\([^)]*\)\.(?:json|send))\s*\([^)]*(?:err|error|e)\.(?:message|stack)/,
    severity: 'medium', title: 'Raw error message/stack returned in HTTP response',
    confidence: 0.7, tags: ['info-disclosure', 'cwe-209'],
    fix: 'Return a generic error to clients and log details server-side. Leaking e.message/e.stack reveals internals to attackers.',
  },
  {
    id: 'stack-in-response',
    re: /\.(?:json|send)\s*\([^)]*\.stack\b/,
    severity: 'medium', title: 'Stack trace exposed to client',
    confidence: 0.7, tags: ['info-disclosure', 'cwe-209'],
    fix: 'Never send stack traces to clients. Log them; return a generic message + request id.',
  },
  {
    id: 'env-dump',
    re: /(?:res(?:ponse)?\.(?:json|send)\s*\(\s*process\.env|JSON\.stringify\s*\(\s*process\.env)/,
    severity: 'high', title: 'process.env serialized/returned (secrets leak)',
    confidence: 0.85, tags: ['info-disclosure', 'secret'],
    fix: 'Never serialize process.env — it contains every secret. Expose only the specific, non-secret values you need.',
  },
  {
    id: 'cors-wildcard-credentials',
    re: /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]/,
    severity: 'medium', title: "CORS allows any origin ('*')",
    confidence: 0.6, tags: ['cors', 'cwe-942'],
    fix: 'A wildcard CORS origin lets any site call your API. Restrict to known origins, especially with credentials.',
  },
  {
    id: 'verbose-error-flag',
    re: /(?:stack|showStack|includeStack|debug)\s*:\s*true/,
    severity: 'low', title: 'Verbose/stack error flag enabled',
    confidence: 0.4, tags: ['info-disclosure'],
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
  description: 'Raw error messages/stacks in responses, process.env dumps, wildcard CORS.',
  async run(ctx) {
    for (const file of ctx.files) {
      if (!IS_CODE.has(file.language)) continue;
      let text;
      try { text = await ctx.read(file.path); } catch { continue; }
      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 2000) continue;
        for (const rule of RULES) {
          if (!rule.re.test(line)) continue;
          ctx.report({
            ruleId: rule.id,
            severity: rule.severity,
            title: rule.title,
            message: `${rule.title} at ${file.path}:${i + 1}.`,
            file: file.path, line: i + 1,
            snippet: line.trim().slice(0, 200),
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
