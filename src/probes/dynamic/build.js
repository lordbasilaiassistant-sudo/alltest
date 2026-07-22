// dynamic/build.js — does the project actually build? (only runs with --exec)
// A build that fails is the most objective 0-day of all: the code doesn't work.

export default {
  id: 'dynamic/build',
  title: 'Project build',
  layer: 'dynamic',
  languages: ['*'],
  order: 1,
  description: 'Runs the project build (npm run build / tsc / cargo build / go build) and reports failures.',
  async run(ctx) {
    if (!ctx.allowExec) return;
    const pkgFile = ctx.files.find((f) => f.path === 'package.json');

    if (pkgFile) {
      let pkg;
      try { pkg = JSON.parse(await ctx.read('package.json')); } catch { return; }
      const scripts = pkg.scripts || {};
      if (scripts.build) {
        ctx.log('running: npm run build');
        const r = await ctx.exec('npm', ['run', 'build'], { timeout: 300000 });
        if (r.code !== 0) {
          ctx.report({
            ruleId: 'build-failed', severity: 'high',
            title: 'npm run build failed',
            message: `The build script exited with code ${r.code}.\n\n${tail(r.stderr || r.stdout)}`,
            file: 'package.json', line: 1, confidence: 0.95,
            fixHint: 'Fix the build errors shown. A failing build means the project cannot ship in its current state.',
            tags: ['build'],
            meta: { exitCode: r.code, timedOut: r.timedOut },
          });
        }
        return;
      }
      // TypeScript typecheck as a fallback if tsc config exists
      const hasTs = ctx.files.some((f) => f.path === 'tsconfig.json');
      if (hasTs) {
        ctx.log('running: npx tsc --noEmit');
        const r = await ctx.exec('npx', ['tsc', '--noEmit'], { timeout: 300000 });
        if (r.code !== 0) {
          ctx.report({
            ruleId: 'typecheck-failed', severity: 'high',
            title: 'TypeScript typecheck (tsc --noEmit) failed',
            message: tail(r.stdout || r.stderr),
            file: 'tsconfig.json', line: 1, confidence: 0.9,
            fixHint: 'Resolve the reported type errors.',
            tags: ['build', 'types'], meta: { exitCode: r.code },
          });
        }
      }
      return;
    }

    // Rust
    if (ctx.files.some((f) => f.path === 'Cargo.toml')) {
      ctx.log('running: cargo build');
      const r = await ctx.exec('cargo', ['build'], { timeout: 300000 });
      if (r.code !== 0) {
        ctx.report({
          ruleId: 'cargo-build-failed', severity: 'high', title: 'cargo build failed',
          message: tail(r.stderr), file: 'Cargo.toml', line: 1, confidence: 0.9,
          fixHint: 'Fix the Rust compile errors shown.', tags: ['build'], meta: { exitCode: r.code },
        });
      }
      return;
    }

    // Go
    if (ctx.files.some((f) => f.path === 'go.mod')) {
      ctx.log('running: go build ./...');
      const r = await ctx.exec('go', ['build', './...'], { timeout: 300000 });
      if (r.code !== 0) {
        ctx.report({
          ruleId: 'go-build-failed', severity: 'high', title: 'go build failed',
          message: tail(r.stderr), file: 'go.mod', line: 1, confidence: 0.9,
          fixHint: 'Fix the Go compile errors shown.', tags: ['build'], meta: { exitCode: r.code },
        });
      }
    }
  },
};

function tail(s, n = 3000) {
  s = String(s || '');
  return s.length > n ? '…' + s.slice(-n) : s;
}
