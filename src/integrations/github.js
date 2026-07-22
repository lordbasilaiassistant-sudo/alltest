// integrations/github.js — file findings as AI-fixable GitHub issues via the `gh` CLI.
// Issue bodies are written FOR an AI agent to act on: exact location, severity, the
// offending snippet, a concrete fix, and a machine-readable block. Deduped by a
// signature marker so re-scans don't spam duplicate issues.

import { exec, which } from '../core/exec.js';

const MARKER = 'alltest-sig:'; // hidden fingerprint we search existing issues for

/**
 * @param {string} repo  "owner/name"
 * @param {import('../core/runner.js').RunResult} result
 * @param {object} [opts]
 * @param {boolean} [opts.dryRun=true]
 * @param {string} [opts.minSeverity='medium']
 * @param {number} [opts.max=25]  safety cap on issues per run
 * @returns {Promise<{created:object[], planned:object[], skipped:object[]}>}
 */
export async function fileIssues(repo, result, opts = {}) {
  const dryRun = opts.dryRun !== false;
  const minRank = rankOf(opts.minSeverity || 'medium');
  const max = opts.max ?? 25;

  const candidates = result.findings
    .filter((f) => f.severityRank >= minRank)
    .slice(0, max);

  const planned = candidates.map((f) => ({
    title: issueTitle(f),
    labels: issueLabels(f),
    signature: f.signature,
    body: issueBody(f, repo),
    finding: f.location,
  }));

  if (dryRun) return { created: [], planned, skipped: [] };

  const gh = await which('gh');
  if (!gh) {
    throw new Error('`gh` (GitHub CLI) not found on PATH. Install it and run `gh auth login` to file issues.');
  }

  // fetch existing alltest issue signatures to avoid duplicates
  const existing = await existingSignatures(repo);

  const created = [], skipped = [];
  for (const item of planned) {
    if (existing.has(item.signature)) { skipped.push(item); continue; }
    const args = ['issue', 'create', '--repo', repo, '--title', item.title, '--body', item.body];
    for (const l of item.labels) args.push('--label', l);
    const r = await exec(gh, args, { timeout: 30000 });
    if (r.code === 0) {
      created.push({ ...item, url: r.stdout.trim() });
      existing.add(item.signature);
    } else {
      // label may not exist — retry without labels
      const r2 = await exec(gh, ['issue', 'create', '--repo', repo, '--title', item.title, '--body', item.body], { timeout: 30000 });
      if (r2.code === 0) created.push({ ...item, url: r2.stdout.trim() });
      else skipped.push({ ...item, error: r.stderr || r2.stderr });
    }
  }
  return { created, planned, skipped };
}

async function existingSignatures(repo) {
  const set = new Set();
  const gh = await which('gh');
  if (!gh) return set;
  const r = await exec(gh, ['issue', 'list', '--repo', repo, '--state', 'all', '--limit', '400', '--search', MARKER, '--json', 'body'], { timeout: 30000 });
  if (r.code !== 0) return set;
  try {
    for (const issue of JSON.parse(r.stdout)) {
      const m = new RegExp(MARKER + '([^\\s`]+)').exec(issue.body || '');
      if (m) set.add(m[1]);
    }
  } catch {}
  return set;
}

function issueTitle(f) {
  const sev = f.severity.toUpperCase();
  const loc = f.file ? ` in ${f.file}` : '';
  return `[alltest/${sev}] ${f.title}${loc}`.slice(0, 240);
}

function issueLabels(f) {
  const labels = ['alltest', `severity:${f.severity}`];
  if (f.tags && f.tags[0]) labels.push(f.tags[0].slice(0, 40));
  return labels;
}

/** The body is written to be directly actionable by an AI coding agent. */
function issueBody(f, repo) {
  const rec = f.toRecord ? f.toRecord() : f;
  return `> Reported automatically by **alltest** — the layered code-testing engine.

## What
${f.title}

**Severity:** \`${f.severity}\` · **Confidence:** ${(f.confidence * 100).toFixed(0)}% · **Probe:** \`${f.probe}\` · **Rule:** \`${f.ruleId}\`

## Where
\`${f.location}\`
${f.snippet ? '\n```\n' + f.snippet.replace(/```/g, "'''") + '\n```\n' : ''}
## Why it matters
${f.message || f.title}

## How to fix (for an AI agent or human)
${f.fixHint || 'Review and remediate the pattern above.'}

## Acceptance criteria
- [ ] The pattern at \`${f.location}\` is removed or made safe.
- [ ] A re-run of \`npx alltest scan .\` no longer reports rule \`${f.ruleId}\` here.
${f.tags?.length ? `\n**Tags:** ${f.tags.map((t) => '`' + t + '`').join(', ')}` : ''}

<sub>${MARKER}${f.signature}</sub>`;
}

function rankOf(sev) {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[sev] ?? 2;
}
