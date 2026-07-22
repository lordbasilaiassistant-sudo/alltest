// static/dangerous-js.js — dangerous JS/TS patterns (injection, eval, unsafe I/O).
// Line-based heuristics — fast, no AST, works on partial/broken files (a real 0-day
// often lives in code that doesn't even parse).

const RULES = [
  {
    id: 'eval-use', re: /(?<![.\w])eval\s*\(/, severity: 'high',
    title: 'Use of eval()', confidence: 0.7, tags: ['injection', 'cwe-95'],
    fix: 'Avoid eval(). Parse JSON with JSON.parse, dispatch via a lookup table, or use a proper sandbox.',
  },
  {
    id: 'function-constructor', re: /new\s+Function\s*\(/, severity: 'high',
    title: 'Dynamic code via new Function()', confidence: 0.7, tags: ['injection', 'cwe-95'],
    fix: 'Dynamic code construction is an injection vector. Replace with explicit logic.',
  },
  {
    id: 'child-process-concat',
    re: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*[`"'][^`"']*\$\{|(?:exec|execSync)\s*\(\s*[^,)]*\+/,
    severity: 'critical', title: 'Shell command built from interpolation/concatenation',
    confidence: 0.75, tags: ['injection', 'cwe-78'],
    fix: 'Command injection risk. Use execFile/spawn with an argument array; never interpolate user input into a shell string.',
  },
  {
    id: 'sql-concat',
    // Require a real SQL statement shape (keyword + its mandatory clause) so English
    // strings like "Delete failed:" or "update property" don't match. Only true
    // concatenation ('...' + x) or template interpolation (${x}) counts as the risk —
    // NOT `? +` (that's arithmetic on a bound parameter in a parameterized query).
    re: /\b(SELECT\s+[\w*,\s.()]+\s+FROM|INSERT\s+INTO\s+\w|UPDATE\s+["'`\w.]+\s+SET|DELETE\s+FROM\s+\w|DROP\s+(?:TABLE|DATABASE)\s+\w)\b[^;]*(?:["'`]\s*\+\s*\w|\$\{)/i,
    severity: 'high', title: 'SQL built via string concatenation/interpolation',
    confidence: 0.55, tags: ['injection', 'cwe-89'],
    fix: 'Possible SQL injection. Use parameterized queries / prepared statements ($1, ? placeholders) instead of building the query string. If the interpolated value is a generated placeholder list (?,?,?) or a numeric coercion, this is safe — mark it with `// alltest-ignore sql-concat`.',
    // Skip the common SAFE patterns: numeric coercion and generated ?-placeholder lists.
    skip: (line) => /\$\{\s*(Number|parseInt|parseFloat|BigInt)\s*\(|\$\{\s*(placeholders?|qmarks?|marks|qs|phs?|params|questionMarks|binds?|inClause)\b/i.test(line),
  },
  {
    id: 'innerhtml', re: /\.innerHTML\s*=\s*(?!["'`]\s*["'`])/, severity: 'medium',
    title: 'Assignment to innerHTML', confidence: 0.5, tags: ['xss', 'cwe-79'],
    fix: 'Potential XSS. Use textContent, or sanitize (DOMPurify) before injecting HTML.',
  },
  {
    id: 'insecure-random-token',
    re: /Math\.random\(\)[^;]*(token|secret|password|nonce|salt|key|id)|(?:token|secret|nonce|salt)[^;=]*=\s*[^;]*Math\.random/i,
    severity: 'medium', title: 'Math.random() used for security-sensitive value',
    confidence: 0.55, tags: ['crypto', 'cwe-338'],
    fix: 'Math.random() is not cryptographically secure. Use crypto.randomBytes / crypto.randomUUID.',
  },
  {
    id: 'disable-tls-verify',
    re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/,
    severity: 'high', title: 'TLS certificate verification disabled',
    confidence: 0.85, tags: ['tls', 'cwe-295'],
    fix: 'Disabling TLS verification allows MITM. Remove rejectUnauthorized:false / restore cert validation.',
  },
  {
    id: 'catch-swallow',
    re: /catch\s*\([^)]*\)\s*\{\s*\}/, severity: 'low',
    title: 'Empty catch block swallows errors', confidence: 0.7, tags: ['reliability'],
    fix: 'Silently swallowing errors hides failures. At minimum log the error, or handle it explicitly.',
  },
  {
    id: 'await-in-loop-hint', re: /for\s*\([^)]*\)\s*\{[^}]*await\s/, severity: 'info',
    title: 'await inside a loop (possible serialization bottleneck)', confidence: 0.3, tags: ['performance'],
    fix: 'If iterations are independent, collect promises and await Promise.all for concurrency.',
  },
  {
    id: 'process-exit-in-lib', re: /process\.exit\s*\(/, severity: 'info', confidence: 0.3,
    title: 'process.exit() call', tags: ['reliability'],
    fix: 'process.exit() in library code prevents graceful shutdown and skips pending I/O. Prefer throwing / returning a code from main.',
  },
  {
    id: 'debugger-stmt', re: /(?<![.\w])debugger\s*;?/, severity: 'low',
    title: 'Leftover debugger statement', confidence: 0.85, tags: ['debug'],
    fix: 'Remove the debugger statement before shipping.',
  },
];

const IS_JS = new Set(['javascript', 'typescript', 'vue', 'svelte']);

export default {
  id: 'static/dangerous-js',
  title: 'Dangerous JavaScript/TypeScript patterns',
  layer: 'static',
  languages: ['javascript', 'typescript', 'vue', 'svelte'],
  order: 2,
  description: 'Injection, eval, unsafe child_process/SQL, disabled TLS, swallowed errors, weak randomness.',
  async run(ctx) {
    for (const file of ctx.files) {
      if (!IS_JS.has(file.language)) continue;
      if (/\.(test|spec)\.[jt]sx?$/.test(file.path)) {
        // still scan tests but downgrade confidence later — many patterns are intentional there
      }
      let text;
      try { text = await ctx.read(file.path); } catch { continue; }
      const isTest = /(^|\/)(test|tests|__tests__|spec)\//.test(file.path) || /\.(test|spec)\./.test(file.path);
      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 2000) continue;
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue; // skip comment lines
        for (const rule of RULES) {
          if (!rule.re.test(line)) continue;
          if (rule.skip && rule.skip(line, file.path)) continue;
          ctx.report({
            ruleId: rule.id,
            severity: rule.severity,
            title: rule.title,
            message: `${rule.title} at ${file.path}:${i + 1}.`,
            file: file.path,
            line: i + 1,
            column: 1,
            snippet: trimmed.slice(0, 200),
            language: file.language,
            confidence: rule.confidence * (isTest ? 0.5 : 1),
            fixHint: rule.fix,
            tags: rule.tags,
          });
        }
      }
    }
  },
};
