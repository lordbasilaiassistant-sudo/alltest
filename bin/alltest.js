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
    case 'sweep': return cmdSweep(rest);
    case 'report': return cmdReport(rest);
    case 'learn': return cmdLearn(rest);
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
  const format = flags.format || 'table';
  const layers = flags.layers ? String(flags.layers).split(',') : undefined;
  const probes = flags.probes ? String(flags.probes).split(',') : undefined;
  const allowExec = !!flags.exec;
  const quiet = !!flags.quiet;

  const spin = quiet || format !== 'table' ? null : makeProgress();
  const result = await scan({
    root, layers, probes, allowExec, version: PKG_VERSION,
    onEvent: spin ? spin.onEvent : undefined,
  });
  if (spin) spin.done();

  // Corpus + RSI get the FULL finding set (info included — valuable training signal).
  if (flags.corpus) {
    const n = await appendCorpus(String(flags.corpus), result, { root });
    console.error(`Appended ${n} findings to ML corpus ${flags.corpus}`);
  }
  if (flags.learn) {
    const learned = await learnFromResult(result);
    console.error(`RSI: ${learned.novel} novel signatures learned (${learned.total} known)`);
  }

  // Display / issue-filing / CI use a severity floor (default: low — hides `info` noise).
  const minSev = flags.min || (format === 'jsonl' || format === 'json' ? 'info' : 'low');
  const view = filterResultView(result, minSev);
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

async function cmdReport(args) {
  const { flags, positional } = parseFlags(args);
  const root = path.resolve(positional[0] || '.');
  const result = await scan({ root, allowExec: !!flags.exec, version: PKG_VERSION });
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
  alltest sweep <dir>                 Scan every repo/subproject under <dir>
  alltest report [path] --github O/R  Scan and file AI-fixable GitHub issues
  alltest learn <report.json>         Feed findings into the RSI knowledge base
  alltest probes                      List all probes
  alltest version

SCAN OPTIONS
  --exec                Run dynamic probes (build/tests) — executes project code
  --format <fmt>        table | json | jsonl | markdown | sarif   (default: table)
  --layers <a,b>        Restrict layers: static,dynamic,fuzz,meta
  --probes <ids>        Restrict to specific probe ids
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
