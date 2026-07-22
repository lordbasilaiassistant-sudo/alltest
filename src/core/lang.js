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

/** True for files worth reading as source (skip images/binaries/etc). */
export function isTextSource(path) {
  const lang = detectLanguage(path);
  return lang !== 'unknown' || /\.(txt|cfg|conf|ini|properties|gradle|lock|xml|graphql|proto)$/i.test(path);
}

export function summarizeLanguages(files) {
  const counts = {};
  for (const f of files) {
    const l = f.language || detectLanguage(f.path);
    counts[l] = (counts[l] || 0) + 1;
  }
  return counts;
}
