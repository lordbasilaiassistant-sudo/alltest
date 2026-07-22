# alltest

**The layered code-testing engine.** Point it at *any* codebase and it runs layer upon
layer of probes — static analysis, dynamic build/test execution, fuzzing, and meta
self-checks — to surface bugs, security holes, hardcoded secrets, smart-contract flaws,
and quality issues. Then it files **AI-fixable** reports, **learns** new issue patterns as
it goes (RSI), and streams a **labeled ML training corpus** for a future issue-detection model.

Built for AI agents to test anyone's code, thoroughly, in one command.

```bash
npx alltest scan .
```

```
  alltest — /your/project
  418 files · 6 languages · 13 probes · 210ms

  server/db/users.js
    ✗ HIGH     SQL built via string concatenation/interpolation:88
        ↳ Possible SQL injection. Use parameterized queries instead of building the query string.
  .env
    ✗ HIGH     Environment file committed: .env:1
        ↳ Remove the .env (git rm --cached), add it to .gitignore, and rotate anything it contained.
  contracts/Vault.sol
    ⛔ CRITICAL Authorization via tx.origin:42
        ↳ tx.origin auth is phishable. Use msg.sender for authorization checks.

  Summary: 1 critical · 2 high
```

---

## Why alltest

Most scanners do one thing. alltest is an **engine of layers**, designed so coverage grows
over time instead of going stale:

- **Layers upon layers.** `static → dynamic → fuzz → meta`. Each probe is a tiny pluggable
  unit, so the catalog keeps expanding — and the RSI loop can propose new ones.
- **It tests itself.** The suite runs *on itself*, a meta probe verifies its own integrity,
  and a meta-**meta** test proves the self-test can actually go red on a regression.
  Turtles all the way down (`npm run test:layers`).
- **Findings are fixes-in-waiting.** Every finding carries an exact `file:line`, a redacted
  snippet, why it matters, a concrete remediation, and acceptance criteria — ready for an
  AI agent (or human) to act on, or to file as a GitHub issue.
- **It gets smarter.** Novel finding signatures are learned into a knowledge base; recurring
  ones get promoted to candidate detection rules. Every finding is also emitted as a labeled
  training example — the seed corpus for a model that learns to find issues directly.
- **Zero-friction.** Dependency-light, no build step, runs on Node ≥ 18, works on any repo
  with no config.

## Install

```bash
# one-off
npx alltest scan .

# or install
npm i -g alltest        # global CLI
npm i -D alltest        # dev dependency + programmatic API
```

## Usage

### Scan a codebase
```bash
alltest scan <path>                     # static probes (safe, no code execution)
alltest scan . --exec                    # also build + run the test suite
alltest scan . --format sarif --out report.sarif   # CI / GitHub code scanning
alltest scan . --format json             # machine-readable (for agents)
alltest scan . --min medium              # severity floor
alltest scan . --fail-on high            # exit non-zero → CI gate
alltest scan . --corpus data/findings.jsonl --learn   # feed ML corpus + RSI
```

### Test every project under a directory
```bash
alltest sweep ~/code --corpus data/findings.jsonl --out sweep.json
```
Finds each project root and scans them all — "check all my repos" in one command.

### File AI-fixable GitHub issues
```bash
alltest report . --github owner/repo --min-severity high            # dry run
alltest report . --github owner/repo --min-severity high --confirm  # create them
```
Deduped by signature so re-runs never spam. Requires the [`gh`](https://cli.github.com) CLI.

### Programmatic API
```js
import { scan, render } from 'alltest';

const result = await scan({ root: './my-app', allowExec: false });
console.log(render(result, 'markdown'));
for (const f of result.findings) {
  console.log(f.severity, f.ruleId, f.location, '→', f.fixHint);
}
```

## What it catches — 15 probes across 4 layers

| Layer | Probe | Examples |
|---|---|---|
| static | secrets | private keys (incl. EVM `Wallet()`), 40+ vendor patterns (AWS, GitHub, GitLab, OpenAI, Anthropic, Stripe, Slack, npm, Twilio, SendGrid, Google OAuth, Telegram…), DB/credential URLs, credential assignments |
| static | **entropy-secrets** | **0-day secrets**: high-entropy tokens of *unknown* vendor/format that match no signature (found real hardcoded `ADMIN_KEY`s in testing) |
| static | dangerous-js | eval (incl. indirect `(0,eval)`), `Function()`, string-arg `setTimeout`, command & SQL injection, DOM-XSS (`innerHTML +=`), disabled TLS, JWT `none`, weak randomness |
| static | python-danger | eval/exec, pickle/yaml/torch/joblib deserialization (RCE), `shell=True`, `verify=False`, SSTI, Django secret, assert-auth |
| static | solidity | tx.origin auth, unchecked/low-level calls, delegatecall, selfdestruct, block-var randomness, range pragma, unbounded loops, zero-address setters |
| static | deps | wildcard/unbounded versions, missing lockfile, `curl\|bash` in scripts, install hooks, optional/peer deps, invalid manifest |
| static | config-hygiene | committed `.env`, **private-key files** (`.key`/`.pem`/`id_rsa`, content-aware vs public certs), `.env` not gitignored |
| static | env-leak | error/stack leaks (Express/Koa/Fastify/render), `process.env` dumps, wildcard CORS |
| static | ci-docker | `:latest` images, `curl \| bash`, ADD-from-URL, root containers, unpinned Actions, `pull_request_target` |
| static | complexity | high cyclomatic complexity, long functions, deep nesting, oversized files — where latent bugs hide |
| fuzz | json-roundtrip | malformed JSON/config that crashes at load |
| dynamic | build / tests | build failures, failing or absent test suites (`--exec`) |
| meta | self-integrity | alltest's own registry + Finding-schema invariants |

Run `alltest probes` for the live list.

## Hard isolation for untrusted probes

Probes run in-process by default (fast, like ESLint plugins). To scan with untrusted or
RSI-generated probes — or to enforce a real wall-clock — use the worker **sandbox**, whose
supervisor can `terminate()` a probe stuck in a *synchronous* infinite loop (something no
same-thread timeout can do):

```bash
alltest scan . --sandbox --timeout 60          # hard 60s ceiling, killable
alltest scan . --sandbox --probe-module ./my-probe.mjs
```

## Suppressing false positives
```js
const y = eval(trusted);   // alltest-ignore
const z = eval(trusted);   // alltest-disable-line eval-use
```
```
# .alltestignore
vendor/
**/generated/*.js
```

## The layered self-test

```
Layer 0  Bootstrap — the engine loads, the registry builds
Layer 1  Unit — the tests FOR the tester (probes vs ground-truth fixtures)
Layer 2  Meta — the suite tests ITSELF (alltest scans alltest)
Layer 3  Meta-meta — proves Layer 2 can go red on a real regression
Layer 4  Mutation — deliberately breaks detection to prove the tests have teeth
Layer 5  Robustness — hostile & degenerate inputs never crash the engine
Layer 6  Sandbox — proves a synchronously-hanging probe is actually killed
Layer 7  Regressions — every adversarial-review finding locked forever
Layer 8  RSI + ML pipelines learn and emit correctly
Layer 9  Probe coverage + reporter/ignore contracts (SARIF/JSONL/JSON)
```
```bash
npm test            # 100 tests, all layers
npm run test:layers # narrated, layer by layer
```

Every detection rule was adversarially reviewed; each confirmed false-positive and
false-negative is now a locked regression test (`test/regressions.test.js`).

## Roadmap
- More probes (Rust/Go/Java depth, taint-tracking, AST-level analysis).
- A code-level fuzz engine (property generation against exported functions).
- Rule synthesis: auto-generate probes from promoted RSI signatures.
- Train the first issue-detection model on the collected corpus.

## License
MIT

---

<sub>alltest can use free GLM for optional AI-assisted triage. If you want a coding plan
that runs models like this, the **[z.ai Coding Plan](https://z.ai/subscribe?ic=BWTG6TRYYQ)**
link is a referral — it helps fund alltest's development. (Disclosed referral, not a discount.)</sub>
