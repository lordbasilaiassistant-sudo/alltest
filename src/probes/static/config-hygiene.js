// static/config-hygiene.js — repo/config hygiene that prevents whole *classes* of leaks.
// The single highest-leverage check for Anthony: is a real .env committed, or missing
// from .gitignore? (His secrets rule is "keys never on OneDrive/in source" — this enforces it.)

export default {
  id: 'static/config-hygiene',
  title: 'Repository & config hygiene',
  layer: 'static',
  languages: ['*'],
  order: 7,
  description: 'Committed .env files, .env not gitignored, world-readable key files, missing .gitignore.',
  async run(ctx) {
    const paths = ctx.files.map((f) => f.path);
    const has = (re) => paths.some((p) => re.test(p));

    // A real .env committed (not .example/.sample/.template)
    for (const f of ctx.files) {
      const base = f.path.split('/').pop();
      if (/^\.env(\.\w+)?$/.test(base) && !/\.(example|sample|template|dist)$/.test(base)) {
        ctx.report({
          ruleId: 'committed-dotenv', severity: 'high',
          title: `Environment file committed: ${f.path}`,
          message: `${f.path} looks like a real environment file inside the repo. .env files typically hold live secrets and must never be committed.`,
          file: f.path, line: 1, language: 'dotenv', confidence: 0.75,
          fixHint: 'Remove the .env from the repo (git rm --cached), add it to .gitignore, and rotate anything it contained.',
          tags: ['secret', 'config'],
        });
      }
      // key material files
      if (/\.(pem|key|p12|pfx|keystore)$/.test(base) || base === 'id_rsa' || base === '.wallet-key') {
        ctx.report({
          ruleId: 'key-file-committed', severity: 'critical',
          title: `Key/credential file committed: ${f.path}`,
          message: `${f.path} appears to be private key material committed to the repo.`,
          file: f.path, line: 1, confidence: 0.7,
          fixHint: 'Remove and rotate immediately. Key files belong in a secret store, never in git.',
          tags: ['secret', 'config'],
        });
      }
    }

    // .env present but not gitignored
    const gitignore = ctx.files.find((f) => f.path === '.gitignore');
    const hasEnvFile = has(/(^|\/)\.env(\.|$)/);
    if (hasEnvFile) {
      let ignoresEnv = false;
      if (gitignore) {
        try {
          const gi = await ctx.read('.gitignore');
          ignoresEnv = /(^|\n)\s*\.?\*?\.env/.test(gi) || /(^|\n)\s*\.env/.test(gi);
        } catch {}
      }
      if (!ignoresEnv) {
        ctx.report({
          ruleId: 'env-not-ignored', severity: 'medium',
          title: '.env files are not covered by .gitignore',
          message: 'An .env-style file exists but .gitignore does not ignore .env — a real secrets file could be committed by accident.',
          file: gitignore ? '.gitignore' : '(repo root)', line: 1, confidence: 0.6,
          fixHint: 'Add ".env" and ".env.*" (except .env.example) to .gitignore.',
          tags: ['config'],
        });
      }
    }

    // No .gitignore at all in a code project
    if (!gitignore && ctx.files.some((f) => /package\.json$|requirements\.txt$|Cargo\.toml$|go\.mod$/.test(f.path))) {
      ctx.report({
        ruleId: 'missing-gitignore', severity: 'low',
        title: 'No .gitignore in a code project',
        message: 'This project has a manifest but no .gitignore — build artifacts, secrets, and dependencies risk being committed.',
        file: '(repo root)', line: 1, confidence: 0.6,
        fixHint: 'Add a .gitignore appropriate to the stack (node_modules, .env, dist, etc.).',
        tags: ['config'],
      });
    }
  },
};
