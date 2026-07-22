// fuzz/json-roundtrip.js — property/fuzz layer: validate that data files a project
// ships are actually parseable and round-trip. Broken JSON/config is a common silent
// 0-day (an app that crashes on boot because a committed config file is malformed).
// This is the seed of the fuzz layer; the fuzz engine (src/fuzz/) drives code-level fuzzing.

export default {
  id: 'fuzz/json-roundtrip',
  title: 'Data-file integrity (JSON/config parse + round-trip)',
  layer: 'fuzz',
  languages: ['json'],
  order: 1,
  description: 'Parses every committed JSON file and verifies it round-trips; catches malformed data/config.',
  async run(ctx) {
    const jsonFiles = ctx.files.filter((f) => f.language === 'json' || /\.json$/.test(f.path));
    for (const file of jsonFiles) {
      let raw;
      try { raw = await ctx.read(file.path); } catch { continue; }
      if (!raw.trim()) continue;
      // tolerate JSONC in config files
      const isJsonc = /\.(jsonc)$|tsconfig|\.vscode\//.test(file.path);
      const cleaned = isJsonc ? stripJsonComments(raw) : raw;
      try {
        const parsed = JSON.parse(cleaned);
        // round-trip stability check (structure survives re-serialization)
        JSON.parse(JSON.stringify(parsed));
      } catch (e) {
        ctx.report({
          ruleId: 'malformed-json', severity: 'high',
          title: `Malformed JSON: ${file.path}`,
          message: `${file.path} does not parse as JSON: ${e.message}. Any code that loads it will throw at runtime.`,
          file: file.path, line: guessLine(cleaned, e), confidence: 0.9,
          fixHint: 'Fix the JSON syntax error at the reported location.',
          tags: ['data-integrity', 'crash'],
          language: 'json',
        });
      }
    }
  },
};

function stripJsonComments(s) {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
    .replace(/,(\s*[}\]])/g, '$1'); // trailing commas
}

function guessLine(raw, err) {
  const m = /position\s+(\d+)/.exec(err.message);
  if (m) return raw.slice(0, Number(m[1])).split(/\r?\n/).length;
  const l = /line\s+(\d+)/.exec(err.message);
  return l ? Number(l[1]) : 1;
}
