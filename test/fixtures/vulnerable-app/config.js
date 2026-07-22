// FIXTURE: intentionally vulnerable. Each line below is a KNOWN planted finding
// that the corresponding probe MUST catch. Do not "fix" these — the tests assert them.

// PLANT: aws-access-key (critical) — valid format, no placeholder trigger words
const AWS_KEY = 'AKIAQZ7W2E9R4T6Y8UOP';

// PLANT: github-token (critical)
const GH = 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';

// PLANT: hardcoded-password (high) — a real literal, not generated
const dbPassword = 'sup3rSecretDbPass!';

// PLANT: connection-string-creds (high)
const DB_URL = 'postgres://admin:hunter2@db.internal:5432/prod';

// NOT a finding: generated value (skip rule must suppress)
const apiKey = 'prefix_' + require('crypto').randomBytes(24).toString('hex');

// NOT a finding: pulled from env
const authSecret = process.env.AUTH_SECRET;

module.exports = { AWS_KEY, GH, dbPassword, DB_URL, apiKey, authSecret };
