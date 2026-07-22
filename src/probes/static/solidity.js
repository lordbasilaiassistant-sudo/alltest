// static/solidity.js — Solidity smart-contract vulnerability heuristics.
// Anthony's ecosystem is mostly on-chain (Diamonds, factories, LP lockers) where a
// single missed access-control or reentrancy bug drains real money. Line-level heuristics
// catch the classic classes without needing a full compiler.

const RULES = [
  {
    id: 'tx-origin-auth',
    re: /require\s*\(\s*tx\.origin\s*[!=]=|tx\.origin\s*[!=]=\s*(owner|msg\.sender|admin)/,
    severity: 'high', title: 'Authorization via tx.origin', confidence: 0.85,
    tags: ['access-control', 'swc-115'],
    fix: 'tx.origin auth is phishable. Use msg.sender for authorization checks.',
  },
  {
    id: 'unchecked-low-level-call',
    re: /\.call\{[^}]*\}\s*\(|\.call\s*\(|\.delegatecall\s*\(/,
    severity: 'medium', title: 'Low-level call — verify return value is checked',
    confidence: 0.4, tags: ['reentrancy', 'swc-104'],
    fix: 'Check the boolean success return of .call/.delegatecall; unchecked calls fail silently. Ensure reentrancy guards on state after external calls.',
  },
  {
    id: 'delegatecall',
    re: /\.delegatecall\s*\(/,
    severity: 'high', title: 'delegatecall present — storage/context risk',
    confidence: 0.5, tags: ['delegatecall', 'swc-112'],
    fix: 'delegatecall runs foreign code against this contract\'s storage. Ensure the target is trusted/immutable and storage layout matches.',
  },
  {
    id: 'selfdestruct',
    re: /selfdestruct\s*\(|suicide\s*\(/,
    severity: 'high', title: 'selfdestruct present', confidence: 0.7,
    tags: ['swc-106'],
    fix: 'selfdestruct can permanently disable the contract and force-send ETH. Gate it behind strong access control or remove it.',
  },
  {
    id: 'block-timestamp-logic',
    re: /(block\.timestamp|now)\s*[<>=]/,
    severity: 'low', title: 'block.timestamp used in comparison logic', confidence: 0.4,
    tags: ['swc-116'],
    fix: 'Miners/sequencers can nudge block.timestamp (~seconds). Do not use it for randomness or tight timing/financial gates.',
  },
  {
    id: 'blockhash-randomness',
    // keccak over block vars, OR direct use of blockhash/prevrandao/difficulty in arithmetic/modulo.
    re: /keccak256\s*\([^)]*(block\.(timestamp|difficulty|prevrandao|number)|blockhash)|\b(blockhash\s*\([^)]*\)|block\.(prevrandao|difficulty))\s*[%*/+]|[%*/+]\s*(blockhash\s*\(|block\.(prevrandao|difficulty|timestamp))/,
    severity: 'high', title: 'On-chain pseudo-randomness from block variables', confidence: 0.7,
    tags: ['randomness', 'swc-120'],
    fix: 'block.* / blockhash values are predictable/manipulable. Use a VRF (e.g. Chainlink) or commit-reveal for randomness.',
  },
  {
    id: 'floating-pragma-range',
    re: /pragma\s+solidity\s+(>=|>|<=|<)/,
    severity: 'low', title: 'Unbounded/range pragma — pin the compiler', confidence: 0.7,
    tags: ['swc-103'],
    fix: 'A range pragma (>=, <) lets the contract compile under many versions. Pin an exact version for reproducible bytecode.',
  },
  {
    id: 'unbounded-loop',
    re: /for\s*\([^;]*;\s*[^;]*<\s*\w+\.length\s*;[^)]*\)/,
    severity: 'low', title: 'Loop over a dynamic array (possible gas DoS)', confidence: 0.35,
    tags: ['dos', 'swc-128'],
    fix: 'A loop bounded by a growable array length can exceed the block gas limit as it grows. Cap iterations or use pull-based patterns.',
  },
  {
    id: 'missing-zero-address-check',
    re: /function\s+(setOwner|transferOwnership|setAdmin|changeOwner|setBeneficiary|setRecipient|setTreasury)\s*\(\s*address\s+\w+/,
    severity: 'low', title: 'Ownership/recipient setter — confirm a zero-address check', confidence: 0.3,
    tags: ['access-control'],
    fix: 'Setters that assign a critical address should require(newAddr != address(0)) to avoid bricking the contract.',
    postFilter: (line, text) => true,
  },
  {
    id: 'unprotected-selfmint-or-transfer',
    re: /function\s+(mint|burn|withdraw|setOwner|transferOwnership|upgrade|initialize)\b[^;{]*\{/,
    severity: 'medium', title: 'Powerful function — confirm access control',
    confidence: 0.3, tags: ['access-control'],
    fix: 'Verify this state-changing/admin function has onlyOwner / role checks and (for initialize) an initializer guard.',
    postFilter: (line) => !/only[A-Z]\w*|onlyOwner|require\s*\(\s*msg\.sender|_checkRole|initializer/.test(line),
  },
  {
    id: 'floating-pragma',
    re: /pragma\s+solidity\s+\^/,
    severity: 'low', title: 'Floating pragma (^) — pin the compiler', confidence: 0.8,
    tags: ['swc-103'],
    fix: 'Pin an exact compiler version (e.g. pragma solidity 0.8.24;) so deployed bytecode is reproducible.',
  },
  {
    id: 'unsafe-erc20-transfer',
    re: /\.transfer\s*\(|\.transferFrom\s*\(|\.approve\s*\(/,
    severity: 'low', title: 'Raw ERC20 transfer/approve — return value may be ignored',
    confidence: 0.25, tags: ['erc20'],
    fix: 'Some tokens (USDT) don\'t return a bool. Use SafeERC20 (safeTransfer/safeApprove) to be safe.',
  },
  {
    id: 'assembly-block',
    re: /\bassembly\s*\{/,
    severity: 'info', title: 'Inline assembly block — manual review advised', confidence: 0.4,
    tags: ['assembly'],
    fix: 'Inline assembly bypasses Solidity safety checks. Confirm memory/storage handling is correct.',
  },
];

export default {
  id: 'static/solidity',
  title: 'Solidity smart-contract vulnerabilities',
  layer: 'static',
  languages: ['solidity'],
  order: 3,
  description: 'Reentrancy/low-level calls, tx.origin auth, weak randomness, selfdestruct, floating pragma, access-control gaps.',
  async run(ctx) {
    for (const file of ctx.files) {
      if (file.language !== 'solidity') continue;
      let text;
      try { text = await ctx.read(file.path); } catch { continue; }
      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;
        for (const rule of RULES) {
          if (!rule.re.test(line)) continue;
          if (rule.postFilter && !rule.postFilter(line)) continue;
          ctx.report({
            ruleId: rule.id,
            severity: rule.severity,
            title: rule.title,
            message: `${rule.title} at ${file.path}:${i + 1}.`,
            file: file.path,
            line: i + 1,
            column: 1,
            snippet: trimmed.slice(0, 200),
            language: 'solidity',
            confidence: rule.confidence,
            fixHint: rule.fix,
            tags: rule.tags,
          });
        }
      }
    }
  },
};
