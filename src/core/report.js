// report.js — turn a RunResult into human & machine formats.
// Formats: table (terminal), json, jsonl (ML corpus rows), markdown, sarif (CI/GitHub).

import { SEVERITY_NAMES } from './finding.js';

const COLOR = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  critical: '\x1b[41m\x1b[97m', high: '\x1b[31m', medium: '\x1b[33m',
  low: '\x1b[36m', info: '\x1b[90m', green: '\x1b[32m',
};
const SEV_ICON = { critical: '⛔', high: '✗', medium: '▲', low: '•', info: '·' };

function useColor(opts) {
  if (opts && opts.color === false) return false;
  return process.stdout.isTTY && !process.env.NO_COLOR;
}

export function renderTable(result, opts = {}) {
  const color = useColor(opts);
  const c = (name, s) => (color ? COLOR[name] + s + COLOR.reset : s);
  const out = [];
  const s = result.summary;

  out.push('');
  out.push(c('bold', `  alltest — ${result.root}`));
  out.push(c('dim', `  ${result.fileCount} files · ${Object.keys(result.languages).length} languages · ${result.probeRuns.length} probes · ${result.durationMs}ms`));
  out.push('');

  if (s.total === 0) {
    out.push('  ' + c('green', '✓ No findings. Clean scan.'));
    out.push('');
    return out.join('\n');
  }

  // group by file for readability
  const byFile = new Map();
  for (const f of result.findings) {
    const k = f.file || '(project)';
    if (!byFile.has(k)) byFile.set(k, []);
    byFile.get(k).push(f);
  }

  const maxFindings = opts.limit ?? 200;
  let shown = 0;
  for (const [file, findings] of byFile) {
    if (shown >= maxFindings) break;
    out.push('  ' + c('bold', file));
    for (const f of findings) {
      if (shown++ >= maxFindings) { out.push(c('dim', `  … and more (use --format json for all)`)); break; }
      const icon = SEV_ICON[f.severity] || '•';
      const sev = c(f.severity, `${icon} ${f.severity.toUpperCase().padEnd(8)}`);
      const loc = f.line != null ? c('dim', `:${f.line}`) : '';
      out.push(`    ${sev} ${f.title}${loc}`);
      if (f.fixHint && opts.verbose !== false) out.push(c('dim', `        ↳ ${f.fixHint}`));
    }
    out.push('');
  }

  // summary line
  const parts = SEVERITY_NAMES.slice().reverse()
    .filter((sv) => s.bySeverity[sv])
    .map((sv) => c(sv, `${s.bySeverity[sv]} ${sv}`));
  out.push('  ' + c('bold', 'Summary: ') + parts.join(c('dim', ' · ')));
  out.push(c('dim', `  risk score ${s.riskScore.toFixed(1)} · ${s.total} findings across ${byFile.size} files`));
  if (s.probesErrored.length) out.push(c('medium', `  ⚠ probes errored: ${s.probesErrored.join(', ')}`));
  out.push('');
  return out.join('\n');
}

export function renderJson(result, opts = {}) {
  return JSON.stringify(
    {
      tool: 'alltest',
      version: opts.version || '0.1.0',
      root: result.root,
      startedAt: result.startedAt,
      durationMs: result.durationMs,
      fileCount: result.fileCount,
      truncated: result.truncated,
      languages: result.languages,
      summary: result.summary,
      probeRuns: result.probeRuns,
      findings: result.findings.map((f) => f.toRecord()),
    },
    null,
    2
  );
}

/** JSONL: one finding per line — the ML training corpus format. */
export function renderJsonl(result) {
  return result.findings.map((f) => JSON.stringify(f.toRecord())).join('\n');
}

export function renderMarkdown(result, opts = {}) {
  const s = result.summary;
  const out = [];
  out.push(`# alltest report`);
  out.push('');
  out.push(`**Target:** \`${result.root}\`  `);
  out.push(`**Scanned:** ${result.fileCount} files · ${result.probeRuns.length} probes · ${result.durationMs}ms  `);
  out.push(`**Findings:** ${s.total} (risk score ${s.riskScore.toFixed(1)})`);
  out.push('');
  out.push('| Severity | Count |');
  out.push('|---|---|');
  for (const sv of SEVERITY_NAMES.slice().reverse()) {
    if (s.bySeverity[sv]) out.push(`| ${sv} | ${s.bySeverity[sv]} |`);
  }
  out.push('');
  if (s.total === 0) { out.push('✅ No findings.'); return out.join('\n'); }
  out.push('## Findings');
  out.push('');
  for (const f of result.findings) {
    out.push(`### ${sevBadge(f.severity)} ${f.title}`);
    out.push('');
    out.push(`- **Location:** \`${f.location}\``);
    out.push(`- **Probe/rule:** \`${f.probe}\` / \`${f.ruleId}\``);
    out.push(`- **Confidence:** ${(f.confidence * 100).toFixed(0)}%`);
    if (f.snippet) out.push(`- **Code:** \`${f.snippet.replace(/`/g, "'")}\``);
    if (f.message) out.push(`- **Detail:** ${f.message.split('\n')[0]}`);
    if (f.fixHint) out.push(`- **Fix:** ${f.fixHint}`);
    out.push('');
  }
  return out.join('\n');
}

function sevBadge(sev) {
  return { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' }[sev] || '⚪';
}

/** SARIF 2.1.0 — consumable by GitHub code scanning and most CI. */
export function renderSarif(result, opts = {}) {
  const rules = new Map();
  const results = result.findings.map((f) => {
    if (!rules.has(f.ruleId)) {
      rules.set(f.ruleId, {
        id: f.ruleId,
        name: f.ruleId,
        shortDescription: { text: f.title },
        defaultConfiguration: { level: sarifLevel(f.severity) },
        properties: { tags: f.tags, probe: f.probe },
      });
    }
    return {
      ruleId: f.ruleId,
      level: sarifLevel(f.severity),
      message: { text: `${f.title}${f.fixHint ? ' — ' + f.fixHint : ''}` },
      locations: f.file
        ? [{
            physicalLocation: {
              artifactLocation: { uri: f.file },
              region: { startLine: f.line || 1, startColumn: f.column || 1 },
            },
          }]
        : [],
      properties: { severity: f.severity, confidence: f.confidence, probe: f.probe },
    };
  });
  return JSON.stringify({
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'alltest', version: opts.version || '0.1.0', rules: [...rules.values()] } },
      results,
    }],
  }, null, 2);
}

function sarifLevel(sev) {
  return { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' }[sev] || 'note';
}

export function render(result, format, opts = {}) {
  switch (format) {
    case 'json': return renderJson(result, opts);
    case 'jsonl': return renderJsonl(result);
    case 'markdown': case 'md': return renderMarkdown(result, opts);
    case 'sarif': return renderSarif(result, opts);
    case 'table': default: return renderTable(result, opts);
  }
}
