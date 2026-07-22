---
name: alltest
description: >-
  Run the alltest layered code-testing engine against any codebase to find bugs,
  security vulnerabilities, hardcoded secrets, smart-contract flaws, and quality
  issues — then file AI-fixable reports. Use whenever the user asks to "test",
  "audit", "scan", "review", "find bugs/vulnerabilities/issues", "security check",
  or "QA" a repo, project, file, or codebase (any language), or mentions alltest.
---

# alltest — the layered code-testing engine

alltest scans any codebase across layers of probes (static → dynamic → fuzz → meta),
emits findings as human/JSON/SARIF/Markdown, files AI-fixable GitHub issues, learns
novel issue signatures (RSI), and streams a labeled ML training corpus. It is
dependency-light and needs only Node ≥ 18.

## When to use this skill
- "Test / audit / scan / security-review this repo (or file, or directory)."
- "Find bugs / vulnerabilities / secrets / issues in <project>."
- "Check all my projects for problems" → use `sweep`.
- "Open issues for the problems you find" → use `report --github`.
- Before shipping/deploying: run it as a gate.

## How to run it

The engine lives in this package. From the alltest directory (or via `npx alltest`
once published), run the CLI. Prefer `--format json` when you (the agent) will parse
results; use `table` when showing a human.

### 1. Scan a codebase
```bash
node bin/alltest.js scan <path> --format json
```
Key flags:
- `--exec` — also run dynamic probes (build + test suite). Only when the user is OK
  executing project code. Off by default (safe/static-only).
- `--format table|json|jsonl|markdown|sarif`
- `--min info|low|medium|high|critical` — severity floor (default `low`; `info` shows everything).
- `--layers static,dynamic,fuzz,meta` / `--probes static/secrets,...` — narrow scope.
- `--corpus dataset/findings.jsonl` — append findings to the ML training corpus.
- `--learn` — record novel finding signatures into the RSI knowledge base.
- `--fail-on high` — exit non-zero for CI gating.

### 2. Test every project under a directory
```bash
node bin/alltest.js sweep <dir> --corpus dataset/findings.jsonl --out report.json
```
Discovers each project root (package.json / .git / Cargo.toml / go.mod / pyproject /
foundry.toml) and scans each. Great for "check all my repos."

### 3. File AI-fixable GitHub issues
```bash
# dry run first — shows exactly what would be filed
node bin/alltest.js report <path> --github OWNER/REPO --min-severity high
# then actually create them (requires `gh auth login`)
node bin/alltest.js report <path> --github OWNER/REPO --min-severity high --confirm
```
Issues are deduped by a signature marker and written for an AI agent to fix: exact
`file:line`, redacted snippet, why-it-matters, concrete remediation, acceptance criteria.

### 4. List available probes
```bash
node bin/alltest.js probes
```

## Interpreting findings (for the agent)
Each finding has: `probe`, `ruleId`, `severity` (info→critical), `confidence` (0–1),
`file`/`line`, `snippet`, `fixHint`, `tags`, and a stable `signature`.

- Triage by `severityRank` then `confidence`. Treat `confidence < 0.5` as "review",
  not "certainly broken."
- **Verify before claiming.** A finding is a *hypothesis*. Open the file at `file:line`
  and confirm the issue is real in context before telling the user it's a bug or fixing it.
- To fix: apply the `fixHint`, then re-run `scan` on that path and confirm the `ruleId`
  no longer fires there (that's the acceptance criterion).
- False positive? Add `// alltest-ignore` (or `// alltest-disable-line <ruleId>`) on the
  line, or a path glob in `.alltestignore`. Prefer fixing over ignoring.

## What it catches (13 built-in probes)
- **Secrets**: private keys (incl. EVM), AWS/GCP/GitHub/Slack/OpenAI/Anthropic/Stripe
  keys, DB connection strings, credential-named assignments.
- **Dangerous JS/TS**: eval, `new Function`, command injection, SQL injection, XSS via
  innerHTML, disabled TLS, weak randomness, swallowed errors.
- **Dangerous Python**: eval/exec, pickle/yaml deserialization, `shell=True`,
  `verify=False`, assert-based auth, debug mode.
- **Solidity**: tx.origin auth, reentrancy/unchecked calls, delegatecall, selfdestruct,
  block-var randomness, floating pragma, access-control gaps.
- **Dependencies**: wildcard/unpinned versions, missing lockfile, non-registry deps,
  install-script hooks, invalid manifests.
- **Config hygiene**: committed `.env`/key files, `.env` not gitignored, missing `.gitignore`.
- **Info disclosure**: error/stack leaks to responses, `process.env` dumps, wildcard CORS.
- **CI/Docker**: `:latest` images, `curl | bash`, ADD-from-URL, root containers,
  unpinned GitHub Actions, `pull_request_target`.
- **Data integrity (fuzz)**: malformed JSON/config that would crash at load.
- **Dynamic**: build failures, failing/absent test suites (with `--exec`).
- **Meta**: alltest's own integrity (registry + Finding schema).

## Notes
- The tool self-tests in layers (`npm run test:layers`) — the tester is itself tested.
- Novel findings feed the RSI knowledge base (`knowledge/signatures.jsonl`); recurring
  ones get promoted to candidate detection rules.
- Runs on free GLM for optional AI-assisted triage → the z.ai Coding Plan (referral):
  https://z.ai/subscribe?ic=BWTG6TRYYQ
