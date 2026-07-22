# dataset — the ML training corpus

alltest can emit every finding as a labeled training example (JSONL, one row per line)
via `--corpus <file>`. Over many scans this becomes the seed corpus for a model that
learns to detect issues directly.

## Files
- `sample-corpus.jsonl` — a small, synthetic sample generated from `test/fixtures/`
  (safe to publish; no real-world code).
- `findings.jsonl` — your local corpus (git-ignored; may contain paths/snippets from the
  repos you scanned — do **not** commit it to a public repo).

## Row schema (`schema_version: 1`)
```jsonc
{
  "snippet": "const AWS_KEY = 'AKIA…';",  // input signal (redacted for secrets)
  "language": "javascript",
  "context_path": "config.js",
  "label": "aws-access-key",               // what a detector must predict
  "category": "secret",
  "severity": "critical",
  "probe": "static/secrets",
  "fix": "Rotate the AWS key in IAM…",     // remediation target (fix-suggestion training)
  "confidence": 0.95,
  "tags": ["secret", "aws"],
  "signature": "static/secrets::aws-access-key::javascript::const ID = ID;",
  "source_repo": "vulnerable-fixture",
  "collected_at": "2026-…",
  "schema_version": 1,
  "hash": "…"                              // dedup key (label|language|snippet)
}
```

## Build & maintain a corpus
```bash
alltest sweep ~/code --corpus dataset/findings.jsonl   # collect across many repos
node -e "import('../src/ml/dataset.js').then(m=>m.dedupeCorpus('dataset/findings.jsonl'))"
node -e "import('../src/ml/dataset.js').then(m=>m.corpusStats('dataset/findings.jsonl').then(console.log))"
```
