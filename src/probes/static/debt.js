// static/debt.js — technical-debt & correctness-smell markers.
// Low severity on their own, but they're the highest-signal *training labels* for the
// ML corpus (paired "here's a known-rough spot" examples), and clusters flag hot files.

const MARKERS = [
  { id: 'todo', re: /\b(TODO|FIXME|HACK|XXX|BUG|REFACTOR|OPTIMIZE)\b[:\s]/, severity: 'info', tags: ['debt'] },
  { id: 'not-implemented', re: /throw\s+new\s+Error\s*\(\s*["'`](not implemented|unimplemented|todo|TODO)/i, severity: 'low', tags: ['debt'] },
  { id: 'console-log', re: /console\.(log|debug|info)\s*\(/, severity: 'info', tags: ['debug'] },
  { id: 'ts-ignore', re: /@ts-(ignore|nocheck|expect-error)/, severity: 'low', tags: ['types'] },
  { id: 'any-cast', re: /\bas\s+any\b|:\s*any\b/, severity: 'info', tags: ['types'] },
  { id: 'nonnull-assert', re: /\w!\.\w|\w!\)/, severity: 'info', tags: ['types'] },
];

export default {
  id: 'static/debt',
  title: 'Technical-debt & correctness markers',
  layer: 'static',
  languages: ['javascript', 'typescript', 'python', 'solidity', 'go', 'rust', 'java', 'c', 'cpp'],
  order: 5,
  description: 'TODO/FIXME/HACK, not-implemented stubs, stray console.log, @ts-ignore, loose any.',
  async run(ctx) {
    const clusters = {}; // file -> count, to flag debt hot-spots
    for (const file of ctx.files) {
      if (file.language === 'unknown' || file.language === 'markdown') continue;
      let text;
      try { text = await ctx.read(file.path); } catch { continue; }
      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 1000) continue;
        for (const m of MARKERS) {
          if (!m.re.test(line)) continue;
          clusters[file.path] = (clusters[file.path] || 0) + 1;
          ctx.report({
            ruleId: m.id,
            severity: m.severity,
            title: `${m.id.replace(/-/g, ' ')} marker`,
            message: `${file.path}:${i + 1} — ${line.trim().slice(0, 160)}`,
            file: file.path, line: i + 1,
            snippet: line.trim().slice(0, 200),
            language: file.language,
            confidence: 0.6,
            fixHint: 'Address or ticket this marker; unresolved debt markers accumulate into hidden risk.',
            tags: m.tags,
          });
        }
      }
    }
  },
};
