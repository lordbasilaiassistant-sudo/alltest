#!/usr/bin/env node
// alltest CLI — run every layer of tests against any codebase.
//
//   alltest scan [path]          scan a codebase (default: cwd)
//   alltest scan . --exec        also run dynamic probes (build/tests)
//   alltest scan . --format json|jsonl|markdown|sarif|table
//   alltest scan . --corpus out.jsonl   append findings to the ML corpus
//   alltest report [path] --github OWNER/REPO   file findings as GitHub issues
//   alltest learn <report.json>  feed findings back into the RSI knowledge base
//   alltest probes               list all probes
//   alltest sweep <dir>          scan every subdirectory/repo under <dir>
//   alltest version

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/index.js';
import { render } from '../src/core/report.js';
import { filterResultView } from '../src/core/runner.js';
import { scanSandboxed } from '../src/core/sandbox.js';
import { applyFixes } from '../src/core/fix.js';
import { loadBaseline, writeBaseline, diffAgainstBaseline } from '../src/core/baseline.js';
import { exec } from '../src/core/exec.js';
import { buildRegistry } from '../src/probes/index.js';
import { appendCorpus } from '../src/ml/dataset.js';
import { learnFromResult } from '../src/rsi/learn.js';
import { fileIssues } from '../src/integrations/github.js';
import { sweep } from '../src/core/sweep.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_VERSION = await readVersion();

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const rest = argv.slice(1);

  switch (cmd) {
    case 'scan': return cmdScan(rest);
    case 'baseline': return cmdBaseline(rest);
    case 'sweep': return cmdSweep(rest);
    case 'report': return cmdReport(rest);
    case 'fix': return cmdFix(rest);
    case 'learn': return cmdLearn(rest);
    case 'propose-rules': return cmdProposeRules(rest);
    case 'probes': return cmdProbes(rest);
    case 'version': case '--version': case '-v':
      console.log(`alltest ${PKG_VERSION}`); return;
    case 'help': case '--help': case '-h': case undefined:
      return printHelp();
    default:
      console.error(`Unknown command: ${cmd}\n`); printHelp(); process.exitCode = 2;
  }
}

function parseFlags(args) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith('--')) { flags[key] = next; i++; }
      else flags[key] = true;
    } else positional.push(a);
  }
  return { flags, positional };
}

async function cmdScan(args) {
  const { flags, positional } = parseFlags(args);
  const root = path.resolve(positional[0] || '.');
  // Fail loudly on a bad path — a typo'd path must not silently report "clean".
  try {
    await fs.stat(root);
  } catch {
    console.error(`alltest: path not found: ${positional[0] || root}`);
    process.exitCode = 2;
    return;
  }
  const format = flags.format || 'table';
  const layers = flags.layers ? String(flags.layers).split(',') : undefined;
  const probes = flags.probes ? String(flags.probes).split(',') : undefined;
  const allowExec = !!flags.exec;
  const quiet = !!flags.quiet;

  // Incremental: restrict the scan to git-changed files (fast PR checks).
  let onlyFiles;
  if (flags.changed || flags.since) {
    const ref = flags.since ? String(flags.since) : (flags.changed !== true ? String(flags.changed) : null);
    onlyFiles = await gitChangedFiles(root, ref);
    if (!onlyFiles) { console.error('alltest: --changed needs a git repository.'); process.exitCode = 2; return; }
    if (!onlyFiles.length) { console.error('alltest: no changed files to scan.'); return; }
  }

  const spin = quiet || format !== 'table' ? null : makeProgress();
  let result;
  if (flags.sandbox || flags.timeout) {
    // Hard-isolated scan: enforce a real wall-clock even against synchronously-hanging probes.
    const hardTimeoutMs = flags.timeout ? Number(flags.timeout) * 1000 : 120000;
    const probeModules = flags['probe-module'] ? [].concat(flags['probe-module']).map((p) => path.resolve(String(p))) : [];
    const sb = await scanSandboxed({ root, layers, probes, allowExec, version: PKG_VERSION, probeModules }, { hardTimeoutMs });
    if (spin) spin.done();
    if (sb.timedOut || !sb.result) {
      console.error(`alltest: ${sb.error || 'sandboxed scan failed'}`);
      process.exitCode = 1;
      return;
    }
    result = sb.result;
  } else {
    result = await scan({
      root, layers, probes, allowExec, version: PKG_VERSION,
      withFixes: !!flags.fix, onlyFiles,
      onEvent: spin ? spin.onEvent : undefined,
    });
    if (spin) spin.done();
  }

  // Corpus + RSI get the FULL finding set (info included — valuable training signal).
  if (flags.corpus) {
    const n = await appendCorpus(String(flags.corpus), result, { root });
    console.error(`Appended ${n} findings to ML corpus ${flags.corpus}`);
  }
  if (flags.learn) {
    const learned = await learnFromResult(result);
    console.error(`RSI: ${learned.novel} novel signatures learned (${learned.total} known)`);
  }

  // Baseline: report only findings NOT in the accepted baseline (new debt introduced).
  let baselineNote = '';
  if (flags.baseline) {
    const bl = await loadBaseline(String(flags.baseline));
    if (!bl) {
      console.error(`No baseline at ${flags.baseline}. Create one with: alltest baseline ${positional[0] || '.'} --out ${flags.baseline}`);
    } else {
      const { isNew, fixedCount } = diffAgainstBaseline(result.findings, bl);
      baselineNote = `baseline: ${bl.count} accepted · ${isNew.length} new · ${fixedCount} fixed`;
      result = { ...result, findings: isNew, summary: { ...result.summary, total: isNew.length }, baselineNote };
    }
  }

  // Display / issue-filing / CI use a severity floor (default: low — hides `info` noise).
  const minSev = flags.min || (format === 'jsonl' || format === 'json' ? 'info' : 'low');
  const view = filterResultView(result, minSev);
  if (baselineNote && format === 'table') console.error('  ' + baselineNote);
  const output = render(view, format, { version: PKG_VERSION });
  if (flags.out) {
    await fs.writeFile(path.resolve(String(flags.out)), output);
    console.error(`Wrote ${format} report to ${flags.out}`);
  } else {
    process.stdout.write(output + '\n');
  }

  // exit code for CI: fail on findings at/above threshold
  const failOn = flags['fail-on'];
  if (failOn) {
    const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[failOn] ?? 3;
    const bad = result.findings.filter((f) => f.severityRank >= rank);
    if (bad.length) process.exitCode = 1;
  }
}

async function cmdBaseline(args) {
  const { flags, positional } = parseFlags(args);
  const root = path.resolve(positional[0] || '.');
  try { await fs.stat(root); } catch { console.error(`alltest: path not found: ${positional[0] || root}`); process.exitCode = 2; return; }
  const out = String(flags.out || '.alltest/baseline.json');
  const result = await scan({ root, allowExec: !!flags.exec, version: PKG_VERSION });
  const n = await writeBaseline(out, result.findings, { root });
  console.error(`Accepted ${n} existing findings as the baseline → ${out}`);
  console.error(`Now \`alltest scan ${positional[0] || '.'} --baseline ${out} --fail-on high\` reports only NEW findings.`);
}

async function cmdSweep(args) {
  const { flags, positional } = parseFlags(args);
  const dir = path.resolve(positional[0] || '.');
  const format = flags.format || 'summary';
  console.error(`Sweeping repos under ${dir} …`);
  const results = await sweep(dir, {
    allowExec: !!flags.exec,
    version: PKG_VERSION,
    corpus: flags.corpus ? String(flags.corpus) : null,
    onRepo: (name, res) => {
      const s = res.summary;
      console.error(`  ${padStatus(s)} ${name}  (${s.total} findings, risk ${s.riskScore.toFixed(0)})`);
    },
  });
  if (format === 'json') {
    process.stdout.write(JSON.stringify(results.map((r) => ({ repo: r.repo, summary: r.result.summary })), null, 2) + '\n');
  } else {
    const totals = results.reduce((n, r) => n + r.result.summary.total, 0);
    console.error(`\nSwept ${results.length} repos — ${totals} total findings.`);
    if (flags.out) {
      await fs.writeFile(path.resolve(String(flags.out)), JSON.stringify(results.map((r) => ({ repo: r.repo, summary: r.result.summary, findings: r.result.findings.map((f) => f.toRecord()) })), null, 2));
      console.error(`Full sweep report → ${flags.out}`);
    }
  }
}

async function cmdFix(args) {
  const { flags, positional } = parseFlags(args);
  const root = path.resolve(positional[0] || '.');
  try { await fs.stat(root); } catch { console.error(`alltest: path not found: ${positional[0] || root}`); process.exitCode = 2; return; }

  const result = await scan({ root, version: PKG_VERSION, withFixes: true });
  const withFix = result.findings.filter((f) => f.fix);
  const auto = withFix.filter((f) => f.fix.autoApplicable && f.fix.confidence >= (flags['min-confidence'] ? Number(flags['min-confidence']) : 0.7));
  const suggestions = withFix.filter((f) => !auto.includes(f));

  const apply = !!flags.apply;
  const C = process.stdout.isTTY && !process.env.NO_COLOR;
  const c = (col, s) => C ? `\x1b[${col}m${s}\x1b[0m` : s;

  console.log('');
  console.log(c('1', `  alltest fix — ${root}`));
  console.log(c('2', `  ${withFix.length} fixable of ${result.findings.length} findings · ${auto.length} auto-applicable · ${suggestions.length} need review`));
  console.log('');

  if (apply) {
    const { applied, skipped } = await applyFixes(root, result.findings, { minConfidence: flags['min-confidence'] ? Number(flags['min-confidence']) : 0.7, dryRun: !!flags['dry-run'] });
    for (const fx of applied) console.log('  ' + c('32', (flags['dry-run'] ? 'would fix ' : 'fixed ')) + c('2', fx.file + ':' + fx.line) + '  ' + fx.ruleId);
    console.log('');
    console.log(c('1', `  ${flags['dry-run'] ? 'Would apply' : 'Applied'} ${applied.length} auto-fixes.`) + c('2', ` ${suggestions.length} findings need a reviewed change (see below).`));
  } else {
    console.log(c('2', '  (dry run — showing fixes. Re-run `alltest fix . --apply` to write the safe ones.)'));
  }
  console.log('');

  // show concrete diffs for everything fixable
  const show = flags.all ? withFix : withFix.slice(0, flags.limit ? Number(flags.limit) : 40);
  for (const f of show) {
    const badge = f.fix.autoApplicable ? c('32', '● auto') : c('33', '○ review');
    console.log(`  ${badge} ${c('1', f.ruleId)} ${c('2', f.location)}`);
    console.log(c('2', `     ${f.fix.note}`));
    if (f.fix.strategy === 'replace-line' && f.fix.original != null) {
      console.log('     ' + c('31', '- ' + f.fix.original.trim()));
      if (f.fix.replacement != null) console.log('     ' + c('32', '+ ' + f.fix.replacement.trim()));
    } else if (f.fix.strategy === 'delete-line') {
      console.log('     ' + c('31', '- ' + (f.fix.original || '').trim()) + c('2', '   (remove)'));
    } else if (f.fix.strategy === 'create-file') {
      console.log('     ' + c('32', '+ create ' + f.fix.extra.createPath));
    } else if (f.fix.strategy === 'insert') {
      console.log('     ' + c('32', '+ ' + (f.fix.replacement || '').split('\n').join(' / ')));
    }
    console.log('');
  }
  if (!flags.all && withFix.length > show.length) console.log(c('2', `  … and ${withFix.length - show.length} more (use --all)`));
}

async function cmdReport(args) {
  const { flags, positional } = parseFlags(args);
  const root = path.resolve(positional[0] || '.');
  const result = await scan({ root, allowExec: !!flags.exec, version: PKG_VERSION, withFixes: true });
  if (flags.github) {
    const dry = !flags.confirm; // filing issues is outward-facing → require --confirm
    const r = await fileIssues(String(flags.github), result, { dryRun: dry, minSeverity: flags['min-severity'] || 'medium' });
    if (dry) {
      console.error(`DRY RUN — would file ${r.planned.length} issues to ${flags.github}. Re-run with --confirm to actually create them.`);
      console.log(JSON.stringify(r.planned, null, 2));
    } else {
      console.error(`Filed ${r.created.length} issues to ${flags.github}.`);
    }
  } else {
    process.stdout.write(render(result, flags.format || 'markdown', { version: PKG_VERSION }) + '\n');
  }
}

async function cmdLearn(args) {
  const { positional } = parseFlags(args);
  const file = positional[0];
  if (!file) { console.error('Usage: alltest learn <report.json>'); process.exitCode = 2; return; }
  const raw = await fs.readFile(path.resolve(file), 'utf8');
  const parsed = JSON.parse(raw);
  const result = { findings: (parsed.findings || []).map((r) => ({ ...r, signature: r.signature, toRecord: () => r, severityRank: 0 })) };
  const learned = await learnFromResult(result);
  console.error(`RSI: ${learned.novel} novel signatures learned; knowledge base now ${learned.total}.`);
}

async function cmdProposeRules(args) {
  const { flags } = parseFlags(args);
  const { synthesizeRuleProposals, promoteCandidates } = await import('../src/rsi/learn.js');
  await promoteCandidates(flags['min-count'] ? Number(flags['min-count']) : 3);
  const proposals = await synthesizeRuleProposals({ minCount: flags['min-count'] ? Number(flags['min-count']) : 3 });
  if (!proposals.length) {
    console.error('No rule proposals yet. Scan more code with --learn so the RSI knowledge base accumulates repeated patterns.');
    return;
  }
  if (flags.out) {
    // strip provenance for a ready-to-use .alltest/rules.json
    const clean = proposals.map(({ _provenance, ...r }) => r);
    await fs.writeFile(path.resolve(String(flags.out)), JSON.stringify(clean, null, 2));
    console.error(`Wrote ${clean.length} proposed rules to ${flags.out}. REVIEW each before enabling — a learned regex will flag other code.`);
  } else {
    console.error(`${proposals.length} rule proposal(s) from the RSI knowledge base (review before adding to .alltest/rules.json):\n`);
    console.log(JSON.stringify(proposals, null, 2));
  }
}

async function cmdProbes() {
  const reg = buildRegistry();
  const list = reg.select();
  const byLayer = {};
  for (const p of list) (byLayer[p.layer] ||= []).push(p);
  for (const layer of Object.keys(byLayer)) {
    console.log(`\n${layer.toUpperCase()}`);
    for (const p of byLayer[layer]) {
      console.log(`  ${p.id.padEnd(28)} ${p.description || p.title}`);
    }
  }
  console.log(`\n${list.length} probes total.`);
}

function makeProgress() {
  let current = '';
  const isTty = process.stderr.isTTY;
  return {
    onEvent(ev) {
      if (!isTty) return;
      if (ev.type === 'probe:start') { current = ev.probe; process.stderr.write(`\r\x1b[2K  running ${ev.probe} …`); }
      if (ev.type === 'walk:done') process.stderr.write(`\r\x1b[2K  walked ${ev.count} files`);
    },
    done() { if (isTty) process.stderr.write('\r\x1b[2K'); },
  };
}

function padStatus(s) {
  if (s.bySeverity.critical) return '⛔';
  if (s.bySeverity.high) return '✗ ';
  if (s.total) return '▲ ';
  return '✓ ';
}

function printHelp() {
  console.log(`
alltest ${PKG_VERSION} — the layered code-testing engine

USAGE
  alltest scan [path]                 Scan a codebase (default: current dir)
  alltest fix [path] [--apply]        Show/apply concrete before→after fixes
  alltest baseline [path] [--out f]   Accept current findings; scan --baseline reports only new
  alltest sweep <dir>                 Scan every repo/subproject under <dir>
  alltest report [path] --github O/R  Scan and file AI-fixable GitHub issues (with fixes)
  alltest learn <report.json>         Feed findings into the RSI knowledge base
  alltest propose-rules [--out f]     Draft custom rules from learned patterns (review first)
  alltest probes                      List all probes
  alltest version

  Custom rules: drop a .alltest/rules.json in any repo to add detections (no code).

FIX OPTIONS
  --apply               Write the auto-applicable fixes to disk (default: dry run)
  --dry-run             With --apply: show what would change without writing
  --min-confidence <n>  Only auto-apply fixes at/above this confidence (default 0.7)
  --all                 Show every fix, not just the first 40

SCAN OPTIONS
  --exec                Run dynamic probes (build/tests) — executes project code
  --format <fmt>        table | json | jsonl | markdown | sarif   (default: table)
  --layers <a,b>        Restrict layers: static,dynamic,fuzz,meta
  --probes <ids>        Restrict to specific probe ids
  --fix                 Attach a concrete fix (before→after) to each finding
  --baseline <file>     Report only findings NOT in the baseline (new debt only)
  --changed [ref]       Scan only git-changed files (fast PR checks)
  --since <ref>         Scan only files changed vs a git ref (e.g. origin/main)
  --corpus <file.jsonl> Append findings to the ML training corpus
  --learn               Learn novel finding signatures (RSI)
  --out <file>          Write report to a file instead of stdout
  --fail-on <sev>       Exit non-zero if a finding >= sev exists (CI gate)

EXAMPLES
  npx alltest scan .
  npx alltest scan ./my-app --exec --format sarif --out report.sarif
  npx alltest sweep ~/Desktop --corpus dataset/findings.jsonl
  npx alltest report . --github lordbasilaiassistant-sudo/my-app --confirm

Runs on free GLM for AI-assisted triage → get the z.ai Coding Plan:
  https://z.ai/subscribe?ic=BWTG6TRYYQ  (referral — funds development)
`);
}

/**
 * Repo-relative paths changed in git. With `ref`, diff against it (great for PRs:
 * `--since origin/main`); otherwise the working set (staged + unstaged + untracked).
 * @returns {Promise<string[]|null>} null if not a git repo
 */
async function gitChangedFiles(root, ref) {
  const isRepo = await exec('git', ['rev-parse', '--is-inside-work-tree'], { cwd: root, timeout: 8000 });
  if (isRepo.code !== 0) return null;
  const paths = new Set();
  const add = (out) => out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).forEach((p) => paths.add(p));
  if (ref) {
    const r = await exec('git', ['diff', '--name-only', `${ref}...HEAD`], { cwd: root, timeout: 15000 });
    if (r.code === 0) add(r.stdout);
    // also include working-tree changes on top of the ref diff
    const w = await exec('git', ['diff', '--name-only', ref], { cwd: root, timeout: 15000 });
    if (w.code === 0) add(w.stdout);
  } else {
    for (const args of [['diff', '--name-only'], ['diff', '--name-only', '--cached']]) {
      const r = await exec('git', args, { cwd: root, timeout: 15000 });
      if (r.code === 0) add(r.stdout);
    }
    const u = await exec('git', ['ls-files', '--others', '--exclude-standard'], { cwd: root, timeout: 15000 });
    if (u.code === 0) add(u.stdout);
  }
  return [...paths];
}

async function readVersion() {
  try {
    const pkg = JSON.parse(await fs.readFile(path.join(__dirname, '..', 'package.json'), 'utf8'));
    return pkg.version;
  } catch { return '0.0.0'; }
}

main().catch((e) => {
  console.error('alltest fatal:', e && e.stack || e);
  process.exit(1);
});
