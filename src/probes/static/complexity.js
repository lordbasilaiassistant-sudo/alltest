// static/complexity.js — complexity & size anomalies.
// Bugs concentrate where code is hard to reason about: long functions, deep nesting,
// high cyclomatic complexity. This probe surfaces those hot-spots — not "a bug" but
// "here is where an unknown bug most likely lives", which is the honest form of 0-day
// triage a scanner can offer without executing anything.

const BRACE_LANGS = new Set(['javascript', 'typescript', 'solidity', 'go', 'java', 'c', 'cpp', 'csharp', 'rust', 'php', 'kotlin', 'vue', 'svelte']);

// Cyclomatic-complexity decision tokens (approximate; counts branch points).
const DECISION_RE = /\b(if|for|while|case|catch|switch)\b|&&|\|\||\?[^.:]|(?<=\W)\?(?=\s)/g;

// Complexity/maintainability findings never exceed `medium` — they signal risk hot-spots,
// not security/correctness bugs, and shouldn't inflate the high/critical count.
const THRESHOLDS = {
  fnLines: { medium: 150, low: 80 },
  complexity: { medium: 30, low: 18 },
  nesting: { medium: 7, low: 5 },
  fileLines: { low: 1500, info: 800 },
};

export default {
  id: 'static/complexity',
  title: 'Complexity & size anomalies',
  layer: 'static',
  languages: ['javascript', 'typescript', 'solidity', 'go', 'java', 'c', 'cpp', 'csharp', 'rust', 'php', 'python'],
  order: 9,
  description: 'Long functions, deep nesting, high cyclomatic complexity, oversized files — where latent bugs hide.',
  async run(ctx) {
    for (const file of ctx.files) {
      const lang = file.language;
      const isBrace = BRACE_LANGS.has(lang);
      if (!isBrace && lang !== 'python') continue;
      let text;
      try { text = await ctx.read(file.path); } catch { continue; }
      const lines = text.split(/\r?\n/);
      if (lines.some((l) => l.length > 5000)) continue; // minified/generated — skip

      // whole-file size anomaly
      if (lines.length >= THRESHOLDS.fileLines.low) {
        ctx.report(fileFinding(file, lines.length, 'low'));
      } else if (lines.length >= THRESHOLDS.fileLines.info) {
        ctx.report(fileFinding(file, lines.length, 'info'));
      }

      const fns = isBrace ? analyzeBrace(lines) : analyzePython(lines);
      for (const fn of fns) {
        // complexity (capped at medium — this is maintainability risk, not a security bug)
        const c = fn.complexity;
        let sev = null;
        if (c >= THRESHOLDS.complexity.medium) sev = 'medium';
        else if (c >= THRESHOLDS.complexity.low) sev = 'low';
        if (sev) {
          ctx.report({
            ruleId: 'high-cyclomatic-complexity', severity: sev,
            title: `High cyclomatic complexity (~${c}) in ${fn.name}`,
            message: `${file.path}:${fn.startLine} — function "${fn.name}" has ~${c} decision points across ${fn.lines} lines. High complexity correlates strongly with defect density and makes the function hard to test fully.`,
            file: file.path, line: fn.startLine, snippet: fn.signature.slice(0, 160),
            language: lang, confidence: 0.6,
            fixHint: `Decompose "${fn.name}" into smaller functions; extract nested branches and early-return to reduce branching.`,
            tags: ['complexity', 'maintainability', 'bug-risk'],
            meta: { complexity: c, lines: fn.lines, nesting: fn.maxNesting },
          });
        }
        // very long function
        if (fn.lines >= THRESHOLDS.fnLines.medium) {
          ctx.report(fnLenFinding(file, fn, 'medium', lang));
        } else if (fn.lines >= THRESHOLDS.fnLines.low && !sev) {
          ctx.report(fnLenFinding(file, fn, 'info', lang));
        }
        // deep nesting
        if (fn.maxNesting >= THRESHOLDS.nesting.medium) {
          ctx.report({
            ruleId: 'deep-nesting', severity: 'low',
            title: `Deep nesting (${fn.maxNesting} levels) in ${fn.name}`,
            message: `${file.path}:${fn.startLine} — nesting reaches ${fn.maxNesting} levels. Deeply nested code is error-prone and hard to follow.`,
            file: file.path, line: fn.startLine, language: lang, confidence: 0.5,
            fixHint: 'Flatten with early returns / guard clauses, or extract inner blocks into helpers.',
            tags: ['complexity', 'maintainability'], meta: { nesting: fn.maxNesting },
          });
        }
      }
    }
  },
};

function fileFinding(file, n, sev) {
  return {
    ruleId: 'oversized-file', severity: sev,
    title: `Oversized file (${n} lines)`,
    message: `${file.path} has ${n} lines. Very large files tend to accumulate coupling and hide bugs; consider splitting by responsibility.`,
    file: file.path, line: 1, language: file.language, confidence: 0.5,
    fixHint: 'Split the file into cohesive modules by responsibility.',
    tags: ['maintainability'], meta: { lines: n },
  };
}

function fnLenFinding(file, fn, sev, lang) {
  return {
    ruleId: 'long-function', severity: sev,
    title: `Long function (${fn.lines} lines): ${fn.name}`,
    message: `${file.path}:${fn.startLine} — "${fn.name}" spans ${fn.lines} lines. Long functions are harder to test and reason about.`,
    file: file.path, line: fn.startLine, language: lang, confidence: 0.5,
    fixHint: `Break "${fn.name}" into smaller, single-purpose functions.`,
    tags: ['maintainability'], meta: { lines: fn.lines },
  };
}

// --- brace-based analyzer (C-family) ---
const FN_START_RE = /\b(?:function\s+([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)\s*(?:=|:)\s*(?:async\s+)?function|([A-Za-z_$][\w$]*)\s*(?:=|:)\s*(?:async\s*)?\([^)]*\)\s*=>|(?:function|func)\s*\*?\s*([A-Za-z_$][\w$]*)?|(?:public|private|external|internal|def)\s+([A-Za-z_$][\w$]*)\s*\()/;

/** Blank out string/regex literal *contents* so keywords inside them don't parse as code. */
function stripLiterals(line) {
  return line
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/`(?:[^`\\]|\\.)*`/g, '``')
    .replace(/\/(?:[^/\\\n]|\\.){2,}\//g, '/RE/'); // regex literals (heuristic)
}

function analyzeBrace(lines) {
  const fns = [];
  const stripped = lines.map(stripLiterals);
  let i = 0;
  while (i < lines.length) {
    const line = stripped[i];
    const m = detectFnStart(line);
    if (m && line.includes('{') || (m && findOpenBraceAhead(stripped, i))) {
      const start = i;
      // Structural analysis runs on the literal-stripped lines so braces/operators
      // inside strings & regexes don't skew depth or complexity.
      let depth = 0, started = false, maxNesting = 0, body = '';
      let j = i;
      for (; j < lines.length && j < i + 1200; j++) {
        const l = stripped[j];
        body += l + '\n';
        for (const ch of l) {
          if (ch === '{') { depth++; started = true; maxNesting = Math.max(maxNesting, depth); }
          else if (ch === '}') { depth--; }
        }
        if (started && depth <= 0) break;
      }
      const decisions = (body.match(DECISION_RE) || []).length;
      const complexity = 1 + decisions;
      fns.push({
        name: m || '(anonymous)',
        startLine: start + 1,
        lines: j - start + 1,
        complexity,
        maxNesting,
        signature: lines[start].trim(),
      });
      i = j + 1;
    } else {
      i++;
    }
  }
  return fns;
}

function detectFnStart(line) {
  const m = FN_START_RE.exec(line);
  if (!m) return null;
  const name = m[1] || m[2] || m[3] || m[4] || m[5];
  // avoid matching control keywords like if/for/while/switch/catch as "functions"
  if (name && /^(if|for|while|switch|catch|return|typeof|function)$/.test(name)) return null;
  return name || '(anonymous)';
}

function findOpenBraceAhead(lines, i) {
  for (let k = i; k < Math.min(i + 3, lines.length); k++) {
    if (lines[k].includes('{')) return true;
  }
  return false;
}

// --- indentation-based analyzer (Python) ---
function analyzePython(lines) {
  const fns = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)def\s+([A-Za-z_]\w*)\s*\(/.exec(lines[i]);
    if (!m) continue;
    const indent = m[1].length;
    const name = m[2];
    let body = lines[i] + '\n';
    let maxNesting = 0;
    let j = i + 1;
    for (; j < lines.length; j++) {
      const l = lines[j];
      if (l.trim() === '') { body += '\n'; continue; }
      const curIndent = l.length - l.trimStart().length;
      if (curIndent <= indent) break; // dedent → function ended
      body += l + '\n';
      maxNesting = Math.max(maxNesting, Math.floor((curIndent - indent) / 4));
    }
    const decisions = (body.match(/\b(if|elif|for|while|except|and|or)\b/g) || []).length;
    fns.push({
      name, startLine: i + 1, lines: j - i,
      complexity: 1 + decisions, maxNesting, signature: lines[i].trim(),
    });
  }
  return fns;
}
