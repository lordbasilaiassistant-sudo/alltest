// core/entropy.js — Shannon entropy + token extraction.
// The basis for catching *unknown* secrets: a credential you've never seen a pattern
// for still looks like high-entropy noise assigned to a variable. This is how alltest
// finds 0-day secrets that signature lists miss.

/** Shannon entropy in bits/char of a string. */
export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let H = 0;
  const n = str.length;
  for (const count of freq.values()) {
    const p = count / n;
    H -= p * Math.log2(p);
  }
  return H;
}

/** Fraction of characters that are letters+digits (token-likeness). */
export function alnumRatio(str) {
  if (!str) return 0;
  let a = 0;
  for (const ch of str) if (/[A-Za-z0-9]/.test(ch)) a++;
  return a / str.length;
}

/** Does the charset look like a secret token (base64/hex/base58)? */
export function looksLikeToken(str) {
  return /^[A-Za-z0-9+/=_-]{16,}$/.test(str) && alnumRatio(str) > 0.85;
}

/**
 * Classify a candidate high-entropy string. Returns null if it's probably benign,
 * or {kind, entropy, reason} if it plausibly is a secret.
 * Tuned to suppress the usual high-entropy-but-not-secret cases: hashes, UUIDs,
 * base64 image/data blobs, integrity hashes, git SHAs, and CSS.
 */
/** Split camelCase / snake_case / kebab so "apiToken" → "api Token" for word matching. */
export function tokenizeIdentifier(s) {
  return String(s)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_\-.]+/g, ' ');
}

export function classifySecretCandidate(value, contextLine = '', varName = '') {
  let v = value.trim();
  const had0x = /^0x/i.test(v);
  if (had0x) v = v.slice(2); // strip 0x so hex length/entropy is measured on the payload
  const len = v.length;
  if (len < 20 || len > 200) return null;
  if (!looksLikeToken(v)) return null;

  // An 0x-prefixed 40-hex value is an Ethereum ADDRESS — public, never a secret.
  if (had0x && /^[0-9a-fA-F]{40}$/.test(v)) return null;
  // 20-byte (40 hex) values generally are addresses/hashes-of-address, not secrets.
  if (/^[0-9a-fA-F]{40}$/.test(v)) return null;
  // kebab/snake slugs with several word segments are URLs/ids/blog slugs, not tokens
  // (e.g. "why-your-api-key-matters-2026"). Real tokens aren't dictionary-word-hyphenated.
  if (/^[a-z0-9]+([-_][a-z0-9]+){3,}$/i.test(v)) return null;

  // normalize identifier context so camelCase/snake names match \bword\b patterns
  const ctx = tokenizeIdentifier(varName) + ' ' + tokenizeIdentifier(contextLine);

  const H = shannonEntropy(v);
  const isHex = /^[0-9a-fA-F]+$/.test(v);
  const isBase64ish = /^[A-Za-z0-9+/]+=*$/.test(v);

  // thresholds: hex strings pack fewer bits/char than base64, so use different floors
  const threshold = isHex ? 3.0 : 4.0;
  if (H < threshold) return null;

  // Benign high-entropy patterns to suppress:
  // - UUIDs (handled by shape) — but UUIDs have dashes; our token regex allowed - so guard:
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return null;
  // - obvious hashes / integrity by var name or context
  if (/\b(hash|sha\d*|md5|checksum|digest|integrity|etag|commit|revision|sri|subresource|blockhash|txhash|merkle|root|nonce|iv|salt|uuid|guid)\b/i.test(ctx)) return null;
  // - data/base64 blobs (images, fonts)
  if (/data:|base64,|\.(png|jpe?g|gif|woff|ttf|svg)\b/i.test(contextLine)) return null;

  // Positive signal boosts confidence: a secret-ish variable name.
  const secretName = /\b(key|secret|token|password|passwd|pwd|auth|api|access|credential|cred|bearer|session|cookie|private)\b/i.test(ctx);

  // - a git SHA-1 (40 hex) or SHA-256 (64 hex) with no secret-ish var name is usually a ref
  if (isHex && (len === 40 || len === 64) && !secretName) return null;

  return {
    kind: isHex ? 'hex' : isBase64ish ? 'base64' : 'token',
    entropy: Number(H.toFixed(2)),
    length: len,
    secretName,
    reason: `high-entropy ${isHex ? 'hex' : 'token'} string (H=${H.toFixed(2)} bits/char, len ${len})`,
  };
}

/** Extract quoted string literals and assignment RHS values from a code line. */
export function extractCandidates(line) {
  const out = [];
  // quoted strings
  const strRe = /["'`]([^"'`\n]{16,200})["'`]/g;
  let m;
  while ((m = strRe.exec(line))) out.push({ value: m[1], index: m.index });
  return out;
}
