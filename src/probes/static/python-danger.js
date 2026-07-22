// static/python-danger.js — dangerous Python patterns.
// Covers the Python side of Anthony's stack (ML projects, scrapers, agent runtimes).

const RULES = [
  { id: 'py-eval-exec', re: /(?<![.\w])(eval|exec)\s*\(/, severity: 'high', title: 'Python eval()/exec()', confidence: 0.65, tags: ['injection', 'cwe-95'], fix: 'Avoid eval/exec on dynamic input. Use ast.literal_eval for data, or explicit dispatch.' },
  { id: 'py-pickle-load', re: /pickle\.loads?\s*\(|cPickle\.loads?\s*\(/, severity: 'high', title: 'Untrusted pickle deserialization', confidence: 0.6, tags: ['deserialization', 'cwe-502'], fix: 'pickle executes arbitrary code on load. Use JSON or a safe schema for untrusted data.' },
  { id: 'py-yaml-load', re: /yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.(Safe|CSafe))/, severity: 'high', title: 'yaml.load without SafeLoader', confidence: 0.75, tags: ['deserialization', 'cwe-502'], fix: 'Use yaml.safe_load() — plain yaml.load can execute arbitrary Python.' },
  { id: 'py-subprocess-shell', re: /subprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/, severity: 'high', title: 'subprocess with shell=True', confidence: 0.7, tags: ['injection', 'cwe-78'], fix: 'shell=True + string command is injection-prone. Pass an argument list and shell=False.' },
  { id: 'py-os-system', re: /os\.system\s*\(/, severity: 'medium', title: 'os.system() call', confidence: 0.6, tags: ['injection', 'cwe-78'], fix: 'Prefer subprocess with an argument list over os.system (which runs a shell).' },
  { id: 'py-assert-auth', re: /assert\s+.*(auth|admin|permission|is_authenticated|role)/i, severity: 'medium', title: 'Security check via assert (stripped with -O)', confidence: 0.45, tags: ['auth', 'cwe-617'], fix: 'assert statements are removed when Python runs with -O. Use explicit if/raise for security checks.' },
  { id: 'py-requests-noverify', re: /requests\.(get|post|put|delete|patch|head|request)\s*\([^)]*verify\s*=\s*False/, severity: 'high', title: 'requests with TLS verify=False', confidence: 0.85, tags: ['tls', 'cwe-295'], fix: 'verify=False disables TLS validation (MITM). Provide a CA bundle or fix the cert.' },
  { id: 'py-flask-debug', re: /app\.run\s*\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True/, severity: 'medium', title: 'Flask/Django debug mode enabled', confidence: 0.5, tags: ['info-disclosure'], fix: 'Debug mode exposes the interactive debugger / stack traces. Disable it in production.' },
  { id: 'py-mktemp', re: /tempfile\.mktemp\s*\(/, severity: 'low', title: 'Insecure tempfile.mktemp()', confidence: 0.7, tags: ['race', 'cwe-377'], fix: 'mktemp is race-prone. Use tempfile.mkstemp() or NamedTemporaryFile.' },
  { id: 'py-bare-except', re: /except\s*:/, severity: 'low', title: 'Bare except: clause', confidence: 0.6, tags: ['reliability'], fix: 'Bare except catches everything incl. KeyboardInterrupt/SystemExit. Catch specific exceptions.' },
];

export default {
  id: 'static/python-danger',
  title: 'Dangerous Python patterns',
  layer: 'static',
  languages: ['python'],
  order: 3,
  description: 'eval/exec, pickle/yaml deserialization, shell=True, verify=False, assert-auth, debug mode.',
  async run(ctx) {
    for (const file of ctx.files) {
      if (file.language !== 'python') continue;
      let text;
      try { text = await ctx.read(file.path); } catch { continue; }
      const isTest = /(^|\/)(tests?|__tests__)\//.test(file.path) || /(^|\/)test_.*\.py$|_test\.py$/.test(file.path);
      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        if (trimmed.startsWith('#')) continue;
        for (const rule of RULES) {
          if (!rule.re.test(line)) continue;
          ctx.report({
            ruleId: rule.id, severity: rule.severity, title: rule.title,
            message: `${rule.title} at ${file.path}:${i + 1}.`,
            file: file.path, line: i + 1, snippet: trimmed.slice(0, 200),
            language: 'python', confidence: rule.confidence * (isTest ? 0.5 : 1),
            fixHint: rule.fix, tags: rule.tags,
          });
        }
      }
    }
  },
};
