// dynamic/tests.js — run the project's own test suite (only with --exec).
// Also reports the *absence* of any tests, which is itself a finding for a shippable repo.

export default {
  id: 'dynamic/tests',
  title: 'Project test suite',
  layer: 'dynamic',
  languages: ['*'],
  order: 2,
  description: 'Runs the project test script and reports failures; flags projects with no tests at all.',
  async run(ctx) {
    const pkgFile = ctx.files.find((f) => f.path === 'package.json');
    const testFiles = ctx.files.filter((f) =>
      /(\.(test|spec)\.[jt]sx?$)|((^|\/)(test|tests|__tests__|spec)\/)/.test(f.path)
    );

    if (pkgFile) {
      let pkg;
      try { pkg = JSON.parse(await ctx.read('package.json')); } catch { return; }
      const scripts = pkg.scripts || {};
      const testScript = scripts.test;
      const isPlaceholder = testScript && /no test specified|echo\s+["']?Error/i.test(testScript);

      if (!testScript || isPlaceholder) {
        if (testFiles.length === 0) {
          ctx.report({
            ruleId: 'no-tests', severity: 'medium',
            title: 'Project has no test suite',
            message: 'No test script and no test files were found. Untested code has no automated safety net against regressions.',
            file: 'package.json', line: 1, confidence: 0.7,
            fixHint: 'Add tests (node --test, vitest, jest) and a "test" script. Start with the critical path.',
            tags: ['test-coverage'],
          });
        }
        return;
      }

      if (!ctx.allowExec) return;
      ctx.log('running: npm test');
      const r = await ctx.exec('npm', ['test'], { timeout: 300000, env: { CI: 'true' } });
      if (r.code !== 0) {
        ctx.report({
          ruleId: 'tests-failed', severity: 'high',
          title: 'npm test failed',
          message: `The test script exited with code ${r.code}.\n\n${tail(r.stdout || r.stderr)}`,
          file: 'package.json', line: 1, confidence: 0.9,
          fixHint: 'Investigate and fix the failing tests; a red suite means known-broken behavior.',
          tags: ['test-coverage'], meta: { exitCode: r.code, timedOut: r.timedOut },
        });
      }
      return;
    }

    // Python
    if (ctx.files.some((f) => /requirements\.txt$|pyproject\.toml$|setup\.py$/.test(f.path))) {
      if (testFiles.length === 0 && !ctx.files.some((f) => /test_.*\.py$|_test\.py$/.test(f.path))) {
        ctx.report({
          ruleId: 'no-tests', severity: 'medium', title: 'Python project has no tests',
          message: 'No pytest/unittest files found.', file: '(repo root)', line: 1, confidence: 0.6,
          fixHint: 'Add pytest tests covering the main modules.', tags: ['test-coverage'],
        });
      }
    }
  },
};

function tail(s, n = 3000) {
  s = String(s || '');
  return s.length > n ? '…' + s.slice(-n) : s;
}
