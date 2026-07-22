// static/deps.js — dependency & manifest hygiene (static; the audit runner is dynamic).
// Flags risky version ranges, missing lockfiles, and known-bad install scripts without
// needing network access.

const RISKY_INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'];

export default {
  id: 'static/deps',
  title: 'Dependency & manifest hygiene',
  layer: 'static',
  languages: ['*'],
  order: 4,
  description: 'package.json risks: wildcard versions, missing lockfile, git/url deps, install-script hooks.',
  async run(ctx) {
    const pkgFiles = ctx.files.filter((f) => /(^|\/)package\.json$/.test(f.path));
    for (const file of pkgFiles) {
      let raw;
      try { raw = await ctx.read(file.path); } catch { continue; }
      let pkg;
      try {
        pkg = JSON.parse(raw);
      } catch (e) {
        ctx.report({
          ruleId: 'invalid-package-json', severity: 'high',
          title: 'package.json is not valid JSON',
          message: `Failed to parse ${file.path}: ${e.message}`,
          file: file.path, line: 1, language: 'json', confidence: 0.99,
          fixHint: 'Fix the JSON syntax; a broken manifest breaks installs and tooling.',
          tags: ['manifest'],
        });
        continue;
      }

      const dir = file.path.replace(/package\.json$/, '');
      const hasLock = ctx.files.some((f) =>
        f.path === dir + 'package-lock.json' ||
        f.path === dir + 'pnpm-lock.yaml' ||
        f.path === dir + 'yarn.lock' ||
        f.path === dir + 'bun.lockb'
      );
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      const depCount = Object.keys(deps).length;

      if (!hasLock && depCount > 0 && !pkg.workspaces) {
        ctx.report({
          ruleId: 'missing-lockfile', severity: 'medium',
          title: 'No lockfile alongside package.json',
          message: `${file.path} declares ${depCount} dependencies but has no lockfile — installs are non-reproducible and vulnerable to dependency drift.`,
          file: file.path, line: 1, language: 'json', confidence: 0.7,
          fixHint: 'Commit a lockfile (npm install → package-lock.json) for reproducible, auditable installs.',
          tags: ['supply-chain'],
        });
      }

      for (const [name, range] of Object.entries(deps)) {
        if (typeof range !== 'string') continue;
        if (range === '*' || range === 'latest' || range === '') {
          ctx.report({
            ruleId: 'wildcard-dependency', severity: 'medium',
            title: `Unpinned dependency: ${name}@${range || '(empty)'}`,
            message: `${name} uses an unbounded version range ("${range}") — any future (possibly malicious) release will be pulled in.`,
            file: file.path, line: lineOf(raw, name), language: 'json', confidence: 0.8,
            fixHint: `Pin ${name} to a specific version or a bounded caret/tilde range.`,
            tags: ['supply-chain'],
          });
        }
        if (/^(git\+|https?:|github:|file:)/.test(range)) {
          ctx.report({
            ruleId: 'nonregistry-dependency', severity: 'low',
            title: `Non-registry dependency: ${name}`,
            message: `${name} resolves from "${range}" rather than the npm registry — not integrity-checked by the lockfile the same way.`,
            file: file.path, line: lineOf(raw, name), language: 'json', confidence: 0.6,
            fixHint: 'Prefer registry-published, version-pinned dependencies where possible.',
            tags: ['supply-chain'],
          });
        }
      }

      const scripts = pkg.scripts || {};
      for (const hook of RISKY_INSTALL_HOOKS) {
        if (scripts[hook]) {
          ctx.report({
            ruleId: 'install-script-hook', severity: 'low',
            title: `Lifecycle install hook present: ${hook}`,
            message: `${file.path} runs a "${hook}" script on install: ${String(scripts[hook]).slice(0, 120)}`,
            file: file.path, line: lineOf(raw, `"${hook}"`), language: 'json', confidence: 0.5,
            fixHint: 'Install hooks run arbitrary code on npm install. Verify it is necessary and safe.',
            tags: ['supply-chain'],
          });
        }
      }
    }
  },
};

function lineOf(raw, needle) {
  const idx = raw.indexOf(needle);
  if (idx < 0) return 1;
  return raw.slice(0, idx).split(/\r?\n/).length;
}
