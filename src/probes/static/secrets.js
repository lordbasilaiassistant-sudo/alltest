// static/secrets.js — hardcoded credential / secret detection.
// High-value on Anthony's repos specifically (ThryxEco shipped a live DB password,
// auth secret, and admin key in source). Rules use explicit word boundaries so
// identifiers like `epk`, `gridSize`, `author` don't produce false "secret" hits.

import { tokenizeIdentifier } from '../../core/entropy.js';

const RULES = [
  // --- Private keys / key material (critical) ---
  {
    id: 'private-key-pem',
    // Any PEM private-key header (RSA/EC/DSA/OPENSSH/PGP/ENCRYPTED/PKCS8) + PuTTY keys.
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----|PuTTY-User-Key-File-\d/,
    severity: 'critical', title: 'Private key committed in source',
    tags: ['secret', 'cwe-798'], confidence: 0.98,
    fix: 'Remove the key from source, rotate it immediately, and load from an env var or secret manager.',
  },
  {
    id: 'eth-private-key',
    // 64 hex assigned to a key-named variable. Keyword group is \b-anchored so `epk`,
    // `spk`, `GROUP_PK` do NOT match the bare `PK` alternative.
    re: /\b(?:private[_-]?key|priv[_-]?key|wallet[_-]?key|deployer[_-]?key|signing[_-]?key|secret[_-]?key|PK|mnemonic|seed[_-]?phrase)\b\s*[:=]\s*["'`]?(0x)?[0-9a-fA-F]{64}["'`]?/i,
    severity: 'critical', title: 'Ethereum/EVM private key hardcoded',
    tags: ['secret', 'crypto', 'cwe-798'], confidence: 0.9,
    fix: 'A 64-hex-char private key is exposed. Rotate the wallet, move any funds, and load the key from process.env only.',
  },
  {
    id: 'eth-wallet-literal',
    re: /new\s+(?:ethers\.)?Wallet\s*\(\s*["'`](0x)?[0-9a-fA-F]{64}["'`]/,
    severity: 'critical', title: 'Hardcoded private key passed to Wallet()',
    tags: ['secret', 'crypto', 'cwe-798'], confidence: 0.92,
    fix: 'The private key handed to new Wallet(...) is committed. Rotate the wallet and load the key from process.env.',
  },
  {
    id: 'eth-private-key-loose',
    re: /["'`](0x)?[0-9a-fA-F]{64}["'`]/,
    severity: 'low', title: 'Bare 64-hex string literal (possible private key / seed)',
    tags: ['secret', 'crypto'], confidence: 0.35,
    fix: 'If this 64-hex value is a private key or seed, remove and rotate it. If it is a tx hash, merkle root, or public constant, ignore.',
    // Suppress the common non-secret cases. Uses tokenizeIdentifier so camelCase names like
    // `merkleRoot` / `contentHash` are correctly recognized as hash-ish, not secrets.
    skip: (line, file) => /\.(json|md|sol|abi)$/i.test(file) ||
      /\b(hash|root|proof|commit|topic|selector|digest|blockhash|txhash|merkle|sighash|domain|separator|bytes32|checksum|sha)\b/i.test(tokenizeIdentifier(line)) ||
      (line.match(/[0-9a-fA-F]{64}/g) || []).length > 1,
  },

  // --- Cloud / provider keys ---
  { id: 'aws-access-key', re: /\b(AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/, severity: 'critical', title: 'AWS access key id', tags: ['secret', 'aws'], confidence: 0.95, fix: 'Rotate the AWS key in IAM and remove it from source.' },
  { id: 'aws-secret-key', re: /\b(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)\b\s*[:=]\s*["'`]?[A-Za-z0-9/+=]{40}["'`]?/i, severity: 'critical', title: 'AWS secret access key', tags: ['secret', 'aws'], confidence: 0.9, fix: 'Rotate immediately in IAM; never store in source.' },
  { id: 'gcp-key', re: /"type"\s*:\s*"service_account"/, severity: 'high', title: 'Google Cloud service-account JSON', tags: ['secret', 'gcp'], confidence: 0.6, fix: 'Service-account key material must not be committed; revoke and regenerate.' },
  { id: 'google-oauth-secret', re: /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/, severity: 'high', title: 'Google OAuth client secret', tags: ['secret', 'gcp'], confidence: 0.9, fix: 'Rotate the OAuth client secret in the Google Cloud console.' },
  { id: 'github-token', re: /\b(ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b/, severity: 'critical', title: 'GitHub token', tags: ['secret', 'github'], confidence: 0.95, fix: 'Revoke the token at github.com/settings/tokens and remove from source.' },
  { id: 'gitlab-token', re: /\bglpat-[0-9A-Za-z_-]{20,}\b/, severity: 'critical', title: 'GitLab personal access token', tags: ['secret', 'gitlab'], confidence: 0.9, fix: 'Revoke the token in GitLab settings.' },
  { id: 'slack-token', re: /\bxox[baprse]-[0-9A-Za-z-]{10,}\b|\bxapp-\d-[A-Za-z0-9-]{10,}\b/, severity: 'high', title: 'Slack token', tags: ['secret', 'slack'], confidence: 0.9, fix: 'Rotate the Slack token in your app settings.' },
  { id: 'npm-token', re: /\bnpm_[A-Za-z0-9]{36}\b|_authToken\s*=\s*["'`]?[A-Za-z0-9_-]{20,}/, severity: 'high', title: 'npm access token', tags: ['secret', 'npm'], confidence: 0.85, fix: 'Revoke the npm token (npm token revoke) and remove from source/.npmrc.' },
  { id: 'openai-key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b/, severity: 'high', title: 'OpenAI-style API key (sk-...)', tags: ['secret', 'ai'], confidence: 0.7, fix: 'Rotate the API key and load from env.', skip: (line) => /https?:\/\/|\.(com|org|io|co|net)\b|slug|url|href|path/i.test(line) && !/\bsk-(proj|svcacct|admin)-/.test(line) },
  { id: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/, severity: 'high', title: 'Anthropic API key', tags: ['secret', 'ai'], confidence: 0.9, fix: 'Rotate at console.anthropic.com and load from env.' },
  { id: 'stripe-key', re: /\b(sk|rk)_(live|test)_[0-9A-Za-z]{20,}\b/, severity: 'critical', title: 'Stripe secret key', tags: ['secret', 'payments'], confidence: 0.9, fix: 'Roll the key in the Stripe dashboard immediately.' },
  { id: 'stripe-webhook', re: /\bwhsec_[A-Za-z0-9]{20,}\b/, severity: 'high', title: 'Stripe webhook signing secret', tags: ['secret', 'payments'], confidence: 0.85, fix: 'Roll the webhook signing secret in the Stripe dashboard.' },
  { id: 'twilio-key', re: /\bSK[0-9a-fA-F]{32}\b|\bAC[0-9a-fA-F]{32}\b/, severity: 'high', title: 'Twilio API key / Account SID', tags: ['secret', 'twilio'], confidence: 0.7, fix: 'Rotate the Twilio credential in the console.' },
  { id: 'sendgrid-key', re: /\bSG\.[\w-]{20,}\.[\w-]{20,}\b/, severity: 'high', title: 'SendGrid API key', tags: ['secret', 'sendgrid'], confidence: 0.9, fix: 'Rotate the SendGrid key.' },
  { id: 'telegram-bot-token', re: /\b\d{6,}:AA[A-Za-z0-9_-]{30,}\b/, severity: 'high', title: 'Telegram bot token', tags: ['secret', 'telegram'], confidence: 0.85, fix: 'Revoke the bot token via @BotFather.' },
  { id: 'digitalocean-token', re: /\bdop_v1_[a-f0-9]{40,}\b/, severity: 'high', title: 'DigitalOcean access token', tags: ['secret', 'digitalocean'], confidence: 0.9, fix: 'Regenerate the DigitalOcean token.' },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: 'high', title: 'Google API key', tags: ['secret', 'gcp'], confidence: 0.8, fix: 'Restrict/rotate the key in the Google Cloud console.' },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, severity: 'medium', title: 'Hardcoded JWT', tags: ['secret', 'auth'], confidence: 0.5, fix: 'If this JWT carries real claims/secrets, rotate the signing key.' },

  // --- Generic assigned secrets (the ThryxEco class) ---
  {
    id: 'hardcoded-password',
    // Now also matches template literals (backticks) and bare token/secret/pass names.
    re: /\b(password|passwd|pwd|db[_-]?pass(?:word)?|admin[_-]?key|auth[_-]?secret|secret[_-]?key|secret|api[_-]?key|api[_-]?token|access[_-]?token|private[_-]?token|bearer[_-]?token|session[_-]?secret|client[_-]?secret|encryption[_-]?key)\b\s*[:=]\s*["'`][^"'`\n]{6,}["'`]/i,
    severity: 'high', title: 'Hardcoded secret assigned to a credential-named variable',
    tags: ['secret', 'cwe-798'], confidence: 0.55,
    fix: 'Move this value into an environment variable / secret store and load via process.env. Rotate the current value.',
    // Not a hardcoded secret when the value is generated / env-sourced, is a filesystem
    // path (e.g. `pwd = "/var/www"`), or is a fragment being concatenated.
    skip: (line) =>
      /(crypto\.)?randomBytes|randomUUID|Math\.random|uuid|nanoid|generate\w*|process\.env|\.env\b|getenv|from_env|os\.environ|import\.meta\.env|readFileSync|require\(/i.test(line) ||
      /["'`][^"'`\n]{1,40}["'`]\s*\+/.test(line) ||
      /\bpwd\b\s*[:=]\s*["'`][./~\\]/.test(line),  // pwd = "/path" is a directory, not a password
  },
  {
    id: 'connection-string-creds',
    re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|ftp|ftps|sftp|https?|ldaps?|smtps?|mssql|clickhouse|cassandra):\/\/[^\s:'"@/]+:[^\s:'"@/]+@/i,
    severity: 'high', title: 'Connection string / URL with inline credentials',
    tags: ['secret', 'database'], confidence: 0.8,
    fix: 'Move the URL (with its embedded user:pass) to an env var; rotate the password.',
    skip: (line) => /:(pass(word)?|user|username|host|placeholder|example|xxx+|changeme)@/i.test(line),
  },
];

// Contexts where a "secret" is almost certainly a placeholder/example, not real.
const PLACEHOLDER_RE = /\b(example|placeholder|your[_-]?|xxx+|todo|changeme|dummy|sample|test[_-]?key|redacted|fake|foobar|password|hunter2|s3cr3t|secret123|deadbeef)\b|<[^>]+>|\.\.\.|0{16,}|1234567890/i;

export default {
  id: 'static/secrets',
  title: 'Hardcoded secrets & credentials',
  layer: 'static',
  languages: ['*'],
  order: 1,
  description: 'Scans every text file for private keys, cloud/API tokens, and credential-named assignments.',
  async run(ctx) {
    for (const file of ctx.files) {
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
          const isExampleFile = /(\.example$|\.sample$|\.template$|readme|\.md$)/i.test(file.path);
          const isTestFile = /(^|\/)(test|tests|__tests__|spec|fixtures?|mocks?)\//.test(file.path) || /\.(test|spec)\./.test(file.path);
          if (PLACEHOLDER_RE.test(line) || (isExampleFile && rule.confidence < 0.9)) continue;
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
