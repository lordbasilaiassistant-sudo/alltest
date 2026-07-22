// static/secrets.js — hardcoded credential / secret detection.
// High-value on Anthony's repos specifically (ThryxEco shipped a live DB password,
// auth secret, and admin key in source — this probe is built to catch exactly that).

const RULES = [
  // --- Private keys / key material (critical) ---
  {
    id: 'private-key-pem',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    severity: 'critical', title: 'Private key committed in source',
    tags: ['secret', 'cwe-798'], confidence: 0.98,
    fix: 'Remove the key from source, rotate it immediately, and load from an env var or secret manager.',
  },
  {
    id: 'eth-private-key',
    // 64 hex chars, standalone, typically after = : or as a string. Avoid matching tx hashes in prose by requiring assignment-ish context.
    re: /(?:private[_-]?key|priv[_-]?key|PK|WALLET_KEY|DEPLOYER_KEY)\s*[:=]\s*["']?(0x)?[0-9a-fA-F]{64}["']?/i,
    severity: 'critical', title: 'Ethereum/EVM private key hardcoded',
    tags: ['secret', 'crypto', 'cwe-798'], confidence: 0.9,
    fix: 'A 64-hex-char private key is exposed. Rotate the wallet, move any funds, and load the key from process.env only.',
  },
  {
    id: 'eth-private-key-loose',
    re: /["'](0x)?[0-9a-fA-F]{64}["']/,
    severity: 'low', title: 'Bare 64-hex string literal (possible private key / seed)',
    tags: ['secret', 'crypto'], confidence: 0.35,
    fix: 'If this 64-hex value is a private key or seed, remove and rotate it. If it is a tx hash, merkle root, or public constant, ignore.',
    // Suppress the overwhelmingly-common non-secret cases: hashes, roots, ABIs, arrays of hex.
    skip: (line, file) => /\.(json|md|sol|abi)$/i.test(file) ||
      /\b(hash|root|proof|commit|topic|selector|digest|blockhash|txhash|merkle|sighash|domainseparator|bytes32)\b/i.test(line) ||
      (line.match(/[0-9a-fA-F]{64}/g) || []).length > 1,
  },

  // --- Cloud / provider keys ---
  { id: 'aws-access-key', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/, severity: 'critical', title: 'AWS access key id', tags: ['secret', 'aws'], confidence: 0.95, fix: 'Rotate the AWS key in IAM and remove it from source.' },
  { id: 'aws-secret-key', re: /aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/i, severity: 'critical', title: 'AWS secret access key', tags: ['secret', 'aws'], confidence: 0.9, fix: 'Rotate immediately in IAM; never store in source.' },
  { id: 'gcp-key', re: /"type"\s*:\s*"service_account"/, severity: 'high', title: 'Google Cloud service-account JSON', tags: ['secret', 'gcp'], confidence: 0.6, fix: 'Service-account key material must not be committed; revoke and regenerate.' },
  { id: 'github-token', re: /\b(ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b/, severity: 'critical', title: 'GitHub token', tags: ['secret', 'github'], confidence: 0.95, fix: 'Revoke the token at github.com/settings/tokens and remove from source.' },
  { id: 'slack-token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, severity: 'high', title: 'Slack token', tags: ['secret', 'slack'], confidence: 0.9, fix: 'Rotate the Slack token in your app settings.' },
  { id: 'openai-key', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/, severity: 'high', title: 'OpenAI-style API key (sk-...)', tags: ['secret', 'ai'], confidence: 0.75, fix: 'Rotate the API key and load from env.' },
  { id: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/, severity: 'high', title: 'Anthropic API key', tags: ['secret', 'ai'], confidence: 0.9, fix: 'Rotate at console.anthropic.com and load from env.' },
  { id: 'stripe-key', re: /\b(sk|rk)_(live|test)_[0-9A-Za-z]{20,}\b/, severity: 'critical', title: 'Stripe secret key', tags: ['secret', 'payments'], confidence: 0.9, fix: 'Roll the key in the Stripe dashboard immediately.' },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: 'high', title: 'Google API key', tags: ['secret', 'gcp'], confidence: 0.8, fix: 'Restrict/rotate the key in the Google Cloud console.' },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, severity: 'medium', title: 'Hardcoded JWT', tags: ['secret', 'auth'], confidence: 0.5, fix: 'If this JWT carries real claims/secrets, rotate the signing key.' },

  // --- Generic assigned secrets (the ThryxEco class) ---
  {
    id: 'hardcoded-password',
    re: /\b(password|passwd|pwd|db[_-]?pass(?:word)?|admin[_-]?key|auth[_-]?secret|secret[_-]?key|api[_-]?key|access[_-]?token|private[_-]?token)\s*[:=]\s*["'][^"'\n]{6,}["']/i,
    severity: 'high', title: 'Hardcoded secret assigned to a credential-named variable',
    tags: ['secret', 'cwe-798'], confidence: 0.55,
    fix: 'Move this value into an environment variable / secret store and load via process.env. Rotate the current value.',
    // Not actually a hardcoded secret when the value is *generated* or read from env,
    // or when it's a string prefix being concatenated (`'thryx_' + randomBytes(...)`).
    skip: (line) =>
      /(crypto\.)?randomBytes|randomUUID|Math\.random|uuid|nanoid|generate\w*|process\.env|\.env\b|getenv|from_env|os\.environ|import\.meta\.env/i.test(line) ||
      /["'][^"'\n]{1,40}["']\s*\+/.test(line),   // string literal immediately concatenated → it's a fragment
  },
  {
    id: 'connection-string-creds',
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:'"@]+:[^\s:'"@]+@/i,
    severity: 'high', title: 'Database connection string with inline credentials',
    tags: ['secret', 'database'], confidence: 0.85,
    fix: 'Move the DB URL (with its embedded user:pass) to an env var; rotate the password.',
  },
];

// Contexts where a "secret" is almost certainly a placeholder/example, not real.
const PLACEHOLDER_RE = /\b(example|placeholder|your[_-]?|xxx+|todo|changeme|dummy|sample|test[_-]?key|<[^>]+>|\.\.\.|redacted|fake|foobar|0{16,}|1234567890)\b/i;

export default {
  id: 'static/secrets',
  title: 'Hardcoded secrets & credentials',
  layer: 'static',
  languages: ['*'],
  order: 1,
  description: 'Scans every text file for private keys, cloud/API tokens, and credential-named assignments.',
  async run(ctx) {
    for (const file of ctx.files) {
      // skip lockfiles and obvious data dumps by size already handled in walker
      let text;
      try {
        text = await ctx.read(file.path);
      } catch {
        continue;
      }
      if (text.length > 1_500_000) continue;
      const lines = text.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 2000) continue; // minified/data line
        for (const rule of RULES) {
          const m = rule.re.exec(line);
          if (!m) continue;
          const matched = m[0];
          if (rule.skip && rule.skip(line, file.path)) continue;
          // Suppress obvious placeholders / examples (esp. in .env.example, README, tests).
          const isExampleFile = /(\.example$|\.sample$|\.template$|readme|\.md$)/i.test(file.path);
          const isTestFile = /(^|\/)(test|tests|__tests__|spec|fixtures?|mocks?)\//.test(file.path) || /\.(test|spec)\./.test(file.path);
          if (PLACEHOLDER_RE.test(line) || (isExampleFile && rule.confidence < 0.9)) continue;
          // Test fixtures routinely contain fake keys — keep only high-certainty rules, downweighted.
          if (isTestFile && rule.confidence < 0.9) continue;
          const confMult = (isExampleFile ? 0.6 : 1) * (isTestFile ? 0.5 : 1);

          ctx.report({
            ruleId: rule.id,
            severity: rule.severity,
            title: rule.title,
            message: `${rule.title} detected in ${file.path}:${i + 1}. Secrets in source are exposed to anyone with repo access and to git history forever.`,
            file: file.path,
            line: i + 1,
            column: line.indexOf(matched) + 1,
            snippet: redact(line.trim(), matched),
            language: file.language,
            confidence: rule.confidence * confMult,
            fixHint: rule.fix,
            tags: rule.tags,
          });
        }
      }
    }
  },
};

/** Redact the sensitive middle of a match so we don't re-leak it into reports/datasets. */
function redact(line, matched) {
  if (!matched || matched.length < 8) return line;
  const keep = 4;
  const masked = matched.slice(0, keep) + '…' + '*'.repeat(Math.min(6, matched.length - keep * 2)) + '…' + matched.slice(-keep);
  return line.split(matched).join(masked);
}
