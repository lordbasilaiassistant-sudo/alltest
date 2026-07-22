// static/dangerous-js.js — dangerous JS/TS patterns (injection, eval, unsafe I/O).
// Line-based heuristics with explicit word boundaries and lookbehinds so method calls
// (regex.exec, db.exec), identifiers (gridSize, debuggerAttached), and object fields
// (profile.message) don't produce false positives. Multiline rules (marked `multiline`)
// scan the whole file so common formatting (empty catch on two lines) is still caught.

const RULES = [
  {
    id: 'eval-use', re: /(?<![.\w])eval\s*\(/, severity: 'high',
    title: 'Use of eval()', confidence: 0.7, tags: ['injection', 'cwe-95'],
    fix: 'Avoid eval(). Parse JSON with JSON.parse, dispatch via a lookup table, or use a proper sandbox.',
  },
  {
    id: 'indirect-eval', re: /\(\s*0\s*,\s*eval\s*\)|(?:window|globalThis|self|global)\s*\[\s*["'`]eval["'`]\s*\]/,
    severity: 'high', title: 'Indirect/aliased eval', confidence: 0.75, tags: ['injection', 'cwe-95'],
    fix: 'Indirect eval ((0,eval) / window["eval"]) executes arbitrary code in global scope. Remove it.',
  },
  {
    id: 'function-constructor', re: /new\s+Function\s*\(|(?<![.\w])Function\s*\(\s*["'`]/, severity: 'high',
    title: 'Dynamic code via the Function constructor', confidence: 0.7, tags: ['injection', 'cwe-95'],
    fix: 'Function()/new Function() build code from strings — an injection vector. Replace with explicit logic.',
  },
  {
    id: 'string-arg-timer', re: /\b(?:setTimeout|setInterval)\s*\(\s*["'`]/, severity: 'medium',
    title: 'String argument to setTimeout/setInterval (eval-equivalent)', confidence: 0.7, tags: ['injection', 'cwe-95'],
    fix: 'A string first-arg is eval-ed. Pass a function reference instead.',
  },
  {
    id: 'child-process-concat',
    // Unambiguous child_process names (execSync/spawnSync/execFileSync) are matched even
    // when dotted (child_process.execSync). Ambiguous `exec`/`spawn`/`execFile` require a
    // non-method position (lookbehind) so `regex.exec(a+b)` / `db.exec(...)` don't match.
    re: new RegExp(
      '(?:\\b(?:execSync|spawnSync|execFileSync)\\s*\\(|(?<![.\\w])(?:exec|spawn|execFile)\\s*\\()' +
      '\\s*(?:[`"\'][^`"\']*\\$\\{|[^,)]*["\'`]\\s*\\+|[^,)]*\\+\\s*[A-Za-z_$])'
    ),
    severity: 'critical', title: 'Shell command built from interpolation/concatenation',
    confidence: 0.75, tags: ['injection', 'cwe-78'],
    fix: 'Command injection risk. Use execFile/spawn with an argument array; never interpolate user input into a shell string.',
  },
  {
    id: 'sql-concat',
    re: /\b(SELECT\s+[\w*,\s.()]+\s+FROM|INSERT\s+INTO\s+\w|UPDATE\s+["'`\w.]+\s+SET|DELETE\s+FROM\s+\w|DROP\s+(?:TABLE|DATABASE)\s+\w)\b[^;]*(?:["'`]\s*\+\s*\w|\$\{)/i,
    severity: 'high', title: 'SQL built via string concatenation/interpolation',
    confidence: 0.55, tags: ['injection', 'cwe-89'],
    fix: 'Possible SQL injection. Use parameterized queries / prepared statements ($1, ? placeholders). If the interpolated value is a generated placeholder list (?,?,?) or a numeric coercion, mark it with `// alltest-ignore sql-concat`.',
    skip: (line) => /\$\{\s*(Number|parseInt|parseFloat|BigInt)\s*\(|\$\{\s*(placeholders?|qmarks?|marks|qs|phs?|params|questionMarks|binds?|inClause)\b/i.test(line),
  },
  {
    id: 'dom-xss-sink',
    // innerHTML/outerHTML =, +=, and the other HTML-injection sinks.
    re: /\.(innerHTML|outerHTML)\s*\+?=|\.insertAdjacentHTML\s*\(|(?<![.\w])document\.write(?:ln)?\s*\(|\.html\s*\(\s*[^)]*(?:\$\{|\+|req\.|user)/,
    severity: 'medium', title: 'HTML injection sink (innerHTML/outerHTML/document.write)', confidence: 0.5, tags: ['xss', 'cwe-79'],
    fix: 'Potential XSS. Use textContent, or sanitize (DOMPurify) before injecting HTML.',
    // Safe when sanitized, or when the RHS is a pure string literal (no interpolation/concat/variable).
    skip: (line) => /DOMPurify|sanitize|escapeHtml|\.textContent/.test(line)
      || /\.(innerHTML|outerHTML)\s*\+?=\s*(?:`[^`$]*`|"[^"\\]*"|'[^'\\]*')\s*;?\s*$/.test(line),
  },
  {
    id: 'insecure-random-token',
    // Word-boundaried keywords so `gridSize` (id), `keyboard` (key), `provider` (id) don't match.
    re: /Math\.random\(\)[^;\n]*\b(token|secret|password|passwd|nonce|salt|session|otp|apikey|api_key|privateKey)\b|\b(token|secret|nonce|salt|session|otp|apiKey)\b[^;=\n]{0,40}=\s*[^;\n]*Math\.random/i,
    severity: 'medium', title: 'Math.random() used for a security-sensitive value',
    confidence: 0.6, tags: ['crypto', 'cwe-338'],
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
    id: 'jwt-none-alg',
    re: /algorithms?\s*:\s*\[?\s*["'`]none["'`]|["'`]alg["'`]\s*:\s*["'`]none["'`]/i,
    severity: 'high', title: 'JWT "none" algorithm accepted', confidence: 0.8, tags: ['auth', 'cwe-347'],
    fix: 'Accepting alg:none lets anyone forge tokens. Pin to a specific algorithm (e.g. RS256/HS256).',
  },
  {
    id: 'catch-swallow',
    re: /catch\s*\([^)]*\)\s*\{\s*\}/, multiline: true, severity: 'low',
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
    id: 'debugger-stmt', re: /(?<![\w."'`-])debugger\b(?![\w-])/, severity: 'low',
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
  description: 'Injection, eval (incl. indirect), unsafe child_process/SQL, DOM XSS, disabled TLS, JWT none, weak randomness.',
  async run(ctx) {
    const perLine = RULES.filter((r) => !r.multiline);
    const multiline = RULES.filter((r) => r.multiline);

    for (const file of ctx.files) {
      if (!IS_JS.has(file.language)) continue;
      let text;
      try { text = await ctx.read(file.path); } catch { continue; }
      const isTest = /(^|\/)(test|tests|__tests__|spec)\//.test(file.path) || /\.(test|spec)\./.test(file.path);
      const lines = text.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 2000) continue;
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue; // skip comment lines
        for (const rule of perLine) {
          if (!rule.re.test(line)) continue;
          if (rule.skip && rule.skip(line, file.path)) continue;
          report(ctx, rule, file, i + 1, trimmed, isTest);
        }
      }

      // multiline rules (e.g. empty catch spanning two lines)
      for (const rule of multiline) {
        const re = new RegExp(rule.re.source, 'g');
        let m;
        while ((m = re.exec(text)) !== null) {
          const lineNo = text.slice(0, m.index).split(/\r?\n/).length;
          report(ctx, rule, file, lineNo, (lines[lineNo - 1] || '').trim(), isTest);
          if (m.index === re.lastIndex) re.lastIndex++;
        }
      }
    }
  },
};

function report(ctx, rule, file, line, snippet, isTest) {
  ctx.report({
    ruleId: rule.id,
    severity: rule.severity,
    title: rule.title,
    message: `${rule.title} at ${file.path}:${line}.`,
    file: file.path,
    line,
    column: 1,
    snippet: snippet.slice(0, 200),
    language: file.language,
    confidence: rule.confidence * (isTest ? 0.5 : 1),
    fixHint: rule.fix,
    tags: rule.tags,
  });
}
