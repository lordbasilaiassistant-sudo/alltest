#!/usr/bin/env node
// run-layers.js — execute the test layers IN ORDER and narrate the turtles-all-the-way-down
// structure. Each layer only "counts" if the layer beneath it is green.
//
//   Layer 0  the tool runs at all (imports resolve, registry builds)
//   Layer 1  unit tests — the tests FOR the tester (probes vs ground-truth fixtures)
//   Layer 2  the suite testing ITSELF (alltest scans alltest; self-integrity)
//   Layer 3  the test that proves Layer 2 can go red (inject a regression)
//   Layer 4  RSI + ML pipelines learn/emit correctly
//   Layer 5  ignore + reporter contracts

import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');

const LAYERS = [
  { n: 0, name: 'Bootstrap (registry builds, probes load)', file: null, cmd: ['bin/alltest.js', 'probes'] },
  { n: 1, name: 'Unit — tests FOR the tester', file: 'test/layer1-unit.test.js' },
  { n: 2, name: 'Meta — the suite tests ITSELF', file: 'test/layer2-meta.test.js' },
  { n: 3, name: 'Meta-meta — proves Layer 2 can go red', file: 'test/layer3-metameta.test.js' },
  { n: 4, name: 'RSI + ML pipelines', file: 'test/rsi-ml.test.js' },
  { n: 5, name: 'Ignore + reporter contracts', file: 'test/ignore-report.test.js' },
];

let allGreen = true;
console.log('\n  alltest — layered self-verification\n  ' + '─'.repeat(50));

for (const layer of LAYERS) {
  const args = layer.cmd ? layer.cmd : ['--test', layer.file];
  const bin = layer.cmd ? 'node' : 'node';
  const finalArgs = layer.cmd ? layer.cmd : ['--test', layer.file];
  const res = spawnSync('node', finalArgs, { cwd: root, encoding: 'utf8' });
  const ok = res.status === 0;
  if (!ok) allGreen = false;
  const tag = ok ? '\x1b[32m✓ PASS\x1b[0m' : '\x1b[31m✗ FAIL\x1b[0m';
  const counts = layer.file ? summarize(res.stdout) : '';
  console.log(`  ${tag}  Layer ${layer.n}: ${layer.name}${counts ? '  ' + counts : ''}`);
  if (!ok && layer.file) {
    // show the failing assertion lines
    const fails = (res.stdout + res.stderr).split('\n').filter((l) => /AssertionError|Error:|✖/.test(l)).slice(0, 6);
    for (const f of fails) console.log('        ' + f.trim());
  }
  // A broken lower layer invalidates the ones above it (short-circuit like a real proof chain).
  if (!ok && layer.n <= 2) {
    console.log('  ' + '─'.repeat(50));
    console.log(`  \x1b[31mLayer ${layer.n} is red — layers above it are unverifiable. Stopping.\x1b[0m\n`);
    process.exit(1);
  }
}

console.log('  ' + '─'.repeat(50));
console.log(allGreen
  ? '  \x1b[32mAll layers green. The tester, and the tests that test it, hold.\x1b[0m\n'
  : '  \x1b[31mSome layers failed.\x1b[0m\n');
process.exit(allGreen ? 0 : 1);

function summarize(stdout) {
  const pass = /ℹ pass (\d+)/.exec(stdout);
  const fail = /ℹ fail (\d+)/.exec(stdout);
  if (!pass) return '';
  return `\x1b[2m(${pass[1]} pass${fail && fail[1] !== '0' ? ', ' + fail[1] + ' fail' : ''})\x1b[0m`;
}
