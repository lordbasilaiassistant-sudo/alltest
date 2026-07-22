// static/ci-docker.js — CI/CD & container hygiene.
// Deploy configs are code too, and they're a favorite supply-chain foothold: an
// unpinned action, a curl|bash, a container running as root.

const DOCKER_RULES = [
  { id: 'docker-latest-tag', re: /^\s*FROM\s+\S+:latest\b|^\s*FROM\s+[^:@\s]+\s*$/im, severity: 'low', title: 'Docker base image uses :latest (or no tag)', confidence: 0.7, tags: ['supply-chain'], fix: 'Pin the base image to a specific version/digest for reproducible, auditable builds.' },
  { id: 'docker-add-remote', re: /^\s*ADD\s+https?:\/\//im, severity: 'medium', title: 'Dockerfile ADD from a URL', confidence: 0.7, tags: ['supply-chain'], fix: 'Prefer COPY of vendored files, or curl with a checksum; ADD-from-URL is unverified.' },
  { id: 'docker-curl-bash', re: /curl\s+[^|]*\|\s*(sudo\s+)?(sh|bash)/i, severity: 'high', title: 'Piping curl into a shell', confidence: 0.8, tags: ['supply-chain', 'cwe-494'], fix: 'curl | bash runs unverified remote code. Download, verify a checksum/signature, then execute.' },
  { id: 'docker-root', re: /^\s*USER\s+root\b/im, severity: 'low', title: 'Container explicitly runs as root', confidence: 0.5, tags: ['hardening'], fix: 'Add a non-root USER for the runtime stage to limit blast radius.' },
];

const CI_RULES = [
  { id: 'ci-unpinned-action', re: /uses:\s*[\w.-]+\/[\w.-]+@(main|master|v?\d+)\s*$/im, severity: 'low', title: 'GitHub Action pinned to a moving ref (branch/major tag)', confidence: 0.55, tags: ['supply-chain'], fix: 'Pin third-party actions to a full commit SHA to prevent supply-chain tampering.' },
  { id: 'ci-pull-request-target', re: /on:\s*[\s\S]{0,80}pull_request_target/i, severity: 'medium', title: 'Workflow triggers on pull_request_target', confidence: 0.6, tags: ['supply-chain', 'cwe-269'], fix: 'pull_request_target runs with repo secrets on fork PRs. Avoid checking out/executing PR code here.' },
  { id: 'ci-curl-bash', re: /curl\s+[^|]*\|\s*(sudo\s+)?(sh|bash)/i, severity: 'high', title: 'CI step pipes curl into a shell', confidence: 0.8, tags: ['supply-chain'], fix: 'Download + verify before executing remote scripts in CI.' },
];

export default {
  id: 'static/ci-docker',
  title: 'CI/CD & container hygiene',
  layer: 'static',
  languages: ['*'],
  order: 8,
  description: 'Dockerfile (latest tags, ADD-from-URL, curl|bash, root) and GitHub Actions (unpinned actions, pull_request_target).',
  async run(ctx) {
    for (const file of ctx.files) {
      const base = file.path.split('/').pop().toLowerCase();
      const isDocker = base === 'dockerfile' || base.endsWith('.dockerfile') || base.startsWith('dockerfile.');
      const isCI = /(^|\/)\.github\/workflows\/.*\.ya?ml$/.test(file.path) || /(^|\/)\.gitlab-ci\.yml$/.test(file.path) || /(^|\/)(\.circleci|\.woodpecker)\//.test(file.path);
      if (!isDocker && !isCI) continue;
      let text;
      try { text = await ctx.read(file.path); } catch { continue; }
      const rules = isDocker ? DOCKER_RULES : CI_RULES;
      const lines = text.split(/\r?\n/);
      for (const rule of rules) {
        // some rules are multiline (search whole text), most are per-line
        if (rule.id === 'ci-pull-request-target') {
          if (rule.re.test(text)) {
            ctx.report({ ruleId: rule.id, severity: rule.severity, title: rule.title, message: `${rule.title} in ${file.path}.`, file: file.path, line: lineOf(text, 'pull_request_target'), confidence: rule.confidence, fixHint: rule.fix, tags: rule.tags, language: file.language });
          }
          continue;
        }
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (!new RegExp(rule.re.source, rule.re.flags.replace('m', '')).test(line)) continue;
          if (line.trim().startsWith('#')) continue;
          ctx.report({
            ruleId: rule.id, severity: rule.severity, title: rule.title,
            message: `${rule.title} at ${file.path}:${i + 1}.`,
            file: file.path, line: i + 1, snippet: line.trim().slice(0, 200),
            confidence: rule.confidence, fixHint: rule.fix, tags: rule.tags, language: file.language,
          });
        }
      }
    }
  },
};

function lineOf(text, needle) {
  const idx = text.indexOf(needle);
  return idx < 0 ? 1 : text.slice(0, idx).split(/\r?\n/).length;
}
