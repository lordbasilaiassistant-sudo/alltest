// probes/index.js — the built-in probe catalog. Import all probes and expose a
// factory that builds a registry. New probes (including RSI-generated ones) get
// registered here or loaded dynamically from a knowledge directory.

import { ProbeRegistry } from '../core/probe.js';

import secrets from './static/secrets.js';
import dangerousJs from './static/dangerous-js.js';
import pythonDanger from './static/python-danger.js';
import solidity from './static/solidity.js';
import deps from './static/deps.js';
import debt from './static/debt.js';
import envLeak from './static/env-leak.js';
import configHygiene from './static/config-hygiene.js';
import ciDocker from './static/ci-docker.js';
import buildProbe from './dynamic/build.js';
import testsProbe from './dynamic/tests.js';
import fuzzJson from './fuzz/json-roundtrip.js';
import selfIntegrity from './meta/self-integrity.js';

export const BUILTIN_PROBES = [
  secrets,
  dangerousJs,
  pythonDanger,
  solidity,
  deps,
  debt,
  envLeak,
  configHygiene,
  ciDocker,
  buildProbe,
  testsProbe,
  fuzzJson,
  selfIntegrity,
];

/** @returns {ProbeRegistry} */
export function buildRegistry(extraProbes = []) {
  const reg = new ProbeRegistry();
  reg.registerAll(BUILTIN_PROBES);
  if (extraProbes.length) reg.registerAll(extraProbes);
  return reg;
}
