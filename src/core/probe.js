// probe.js — the pluggable unit of testing.
// Every layer of the suite (static rule, dynamic runner, fuzzer, meta-check) is a Probe.
// A probe is intentionally tiny to implement so the RSI loop can *generate* new ones.

import { Finding } from './finding.js';

/**
 * @typedef {Object} ProbeContext
 * @property {string} root                 - absolute path of the target codebase
 * @property {import('./walker.js').FileEntry[]} files - discovered files (post-ignore)
 * @property {(rel:string)=>Promise<string>} read     - read a file's text by repo-relative path
 * @property {(cmd:string,args:string[],opts?:object)=>Promise<{code:number,stdout:string,stderr:string}>} exec
 * @property {(f:import('./finding.js').FindingInit)=>void} report - emit a finding
 * @property {(msg:string)=>void} log
 * @property {Object} options              - CLI/run options
 * @property {boolean} allowExec           - dynamic probes may run project code
 */

/**
 * @typedef {Object} ProbeDef
 * @property {string} id            - e.g. "static/secrets"
 * @property {string} title
 * @property {'static'|'dynamic'|'fuzz'|'meta'} layer
 * @property {string} [description]
 * @property {string[]} [languages] - languages this probe is relevant to ("*" = all)
 * @property {number} [order]       - lower runs earlier within its layer
 * @property {(ctx:ProbeContext)=>Promise<void>|void} run
 */

export const LAYERS = Object.freeze(['static', 'dynamic', 'fuzz', 'meta']);

export class ProbeRegistry {
  constructor() {
    /** @type {Map<string, ProbeDef>} */
    this.probes = new Map();
  }

  /** @param {ProbeDef} def */
  register(def) {
    validateProbe(def);
    if (this.probes.has(def.id)) {
      throw new Error(`Duplicate probe id: ${def.id}`);
    }
    this.probes.set(def.id, def);
    return this;
  }

  registerAll(defs) {
    for (const d of defs) this.register(d);
    return this;
  }

  get(id) {
    return this.probes.get(id);
  }

  /** @param {{layers?:string[], ids?:string[], languages?:string[]}} [filter] */
  select(filter = {}) {
    let list = [...this.probes.values()];
    if (filter.ids && filter.ids.length) {
      const set = new Set(filter.ids);
      list = list.filter((p) => set.has(p.id));
    }
    if (filter.layers && filter.layers.length) {
      const set = new Set(filter.layers);
      list = list.filter((p) => set.has(p.layer));
    }
    if (filter.languages && filter.languages.length) {
      const set = new Set(filter.languages);
      list = list.filter(
        (p) => !p.languages || p.languages.includes('*') || p.languages.some((l) => set.has(l))
      );
    }
    // Order by layer sequence, then per-probe order, then id for determinism.
    return list.sort((a, b) => {
      const la = LAYERS.indexOf(a.layer);
      const lb = LAYERS.indexOf(b.layer);
      if (la !== lb) return la - lb;
      if ((a.order ?? 100) !== (b.order ?? 100)) return (a.order ?? 100) - (b.order ?? 100);
      return a.id.localeCompare(b.id);
    });
  }

  get size() {
    return this.probes.size;
  }
}

export function validateProbe(def) {
  if (!def || typeof def !== 'object') throw new TypeError('probe def must be an object');
  if (!def.id || typeof def.id !== 'string') throw new TypeError('probe.id required');
  if (!LAYERS.includes(def.layer)) {
    throw new TypeError(`probe.layer must be one of ${LAYERS.join(', ')}; got ${def.layer} (${def.id})`);
  }
  if (typeof def.run !== 'function') throw new TypeError(`probe.run must be a function (${def.id})`);
  if (!def.title) throw new TypeError(`probe.title required (${def.id})`);
  return true;
}

/** Helper for probe authors: build a Finding, tagging it with the probe id automatically. */
export function makeReporter(probeId, sink) {
  return (init) => {
    const f = init instanceof Finding ? init : new Finding({ probe: probeId, ...init });
    sink.push(f);
    return f;
  };
}
