// lang.js — cheap, dependency-free language detection by extension + a few filenames.

const BY_EXT = {
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.py': 'python', '.pyi': 'python',
  '.sol': 'solidity',
  '.rs': 'rust',
  '.go': 'go',
  '.java': 'java', '.kt': 'kotlin',
  '.rb': 'ruby',
  '.php': 'php',
  '.c': 'c', '.h': 'c',
  '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
  '.cs': 'csharp',
  '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell',
  '.ps1': 'powershell',
  '.json': 'json', '.jsonc': 'json',
  '.yaml': 'yaml', '.yml': 'yaml',
  '.toml': 'toml',
  '.md': 'markdown', '.mdx': 'markdown',
  '.html': 'html', '.htm': 'html',
  '.css': 'css', '.scss': 'css', '.sass': 'css',
  '.sql': 'sql',
  '.vue': 'vue',
  '.svelte': 'svelte',
  '.env': 'dotenv',
};

const BY_NAME = {
  'dockerfile': 'dockerfile',
  'makefile': 'makefile',
  '.gitignore': 'gitignore',
  '.npmrc': 'ini',
  '.env': 'dotenv',
};

export function extname(path) {
  const base = path.replace(/\\/g, '/').split('/').pop() || '';
  const dot = base.lastIndexOf('.');
  if (dot <= 0) return '';
  return base.slice(dot).toLowerCase();
}

export function basename(path) {
  return (path.replace(/\\/g, '/').split('/').pop() || '').toLowerCase();
}

/** @returns {string} language id or 'unknown' */
export function detectLanguage(path) {
  const name = basename(path);
  if (BY_NAME[name]) return BY_NAME[name];
  if (name.startsWith('.env')) return 'dotenv';
  const ext = extname(path);
  return BY_EXT[ext] || 'unknown';
}

// Security-relevant files that carry NO recognized source language but MUST be scanned
// (private keys, credential stores). Without this, the scanner is blind to the single
// most important thing it claims to catch: committed key material.
const SECURITY_FILE_RE = /(^|[\\/])(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.wallet-key|\.netrc|_netrc|\.pgpass|\.htpasswd|\.pypirc|credentials|\.npmrc)$/i;
const SECURITY_EXT_RE = /\.(pem|key|p12|pfx|pkcs12|keystore|jks|der|ppk|crt|cer|asc|gpg|kdbx|ovpn)$/i;

/** True for files worth reading (skip images/binaries; always include key/credential files). */
export function isTextSource(path) {
  const lang = detectLanguage(path);
  if (lang !== 'unknown') return true;
  if (SECURITY_FILE_RE.test(path) || SECURITY_EXT_RE.test(path)) return true;
  return /\.(txt|cfg|conf|ini|properties|gradle|lock|xml|graphql|proto|env|tfstate|tfvars)$/i.test(path);
}

/** Is this a private-key / credential-bearing file by name or extension? */
export function isSecurityFile(path) {
  return SECURITY_FILE_RE.test(path) || SECURITY_EXT_RE.test(path);
}

export function summarizeLanguages(files) {
  const counts = {};
  for (const f of files) {
    const l = f.language || detectLanguage(f.path);
    counts[l] = (counts[l] || 0) + 1;
  }
  return counts;
}
