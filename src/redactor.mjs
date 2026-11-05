import { randomUUID } from 'node:crypto';

import { resolveRedactionLimits } from './redaction-limits.mjs';
import { collectExactIpv4, isDocumentationAddress, replaceAddresses } from './scan/ip.mjs';
import { scanString } from './scan/scan.mjs';
import { applySpans } from './scan/spans.mjs';
import { transformJsonText } from './scan/traverse.mjs';
import { RESTORABLE_MARKER_SOURCE } from './sensitive-texts.mjs';

const POOL_PREFIXES = [
  '192.0.2',
  '198.51.100',
  '203.0.113',
];
const STATE_VERSION = 3;
const RESTORABLE_MARKER = new RegExp(RESTORABLE_MARKER_SOURCE, 'g');
const EXACT_MARKER = new RegExp(`^${RESTORABLE_MARKER_SOURCE}$`);
const EXACT_IP_MARKER = /^\[REDACTED_IP_[a-f0-9]{32}\]$/;
const SECRET_TYPES = new Set(['API_KEY', 'JWT', 'PRIVATE_KEY', 'PASSWORD', 'TEXT']);
const SECRET_CAPACITY = 10000;
export const POOL_SIZE = POOL_PREFIXES.length * 254;

export class MappingCapacityError extends Error {
  constructor() {
    super('IPv4 mapping capacity exhausted');
    this.code = 'MAPPING_CAPACITY_EXHAUSTED';
  }
}

function fakeAddressAt(index) {
  if (!Number.isInteger(index) || index < 0 || index >= POOL_SIZE) return null;
  const prefix = POOL_PREFIXES[Math.floor(index / 254)];
  return `${prefix}.${(index % 254) + 1}`;
}

export function emptyState() {
  return { version: STATE_VERSION, nextIndex: 0, mappings: [], secretMappings: [] };
}

export function validateState(state) {
  if (
    !state
    || ![1, 2, STATE_VERSION].includes(state.version)
    || !Number.isInteger(state.nextIndex)
    || state.nextIndex < 0
    || state.nextIndex > POOL_SIZE
    || !Array.isArray(state.mappings)
    || state.mappings.length > POOL_SIZE
  ) {
    throw new Error('Invalid mapping state');
  }
  if (state.mappings.length !== state.nextIndex) throw new Error('Invalid mapping state');
  const fakeValues = validateIpMappings(state);
  if (state.version === STATE_VERSION) validateSecretMappings(state.secretMappings, fakeValues);
}

function validateIpMappings(state) {
  const realValues = new Set();
  const fakeValues = new Set();
  for (const [index, mapping] of state.mappings.entries()) {
    if (
      !mapping
      || typeof mapping.real !== 'string'
      || typeof mapping.fake !== 'string'
      || collectExactIpv4(mapping.real) !== mapping.real
      || isDocumentationAddress(mapping.real)
      || realValues.has(mapping.real)
      || fakeValues.has(mapping.fake)
      || (state.version === 1 && mapping.legacyFake !== undefined)
    ) {
      throw new Error('Invalid mapping state');
    }
    realValues.add(mapping.real);
    fakeValues.add(mapping.fake);
    const expectedLegacy = fakeAddressAt(index);
    if (state.version === 1) {
      if (mapping.fake !== expectedLegacy) throw new Error('Invalid mapping state');
    } else if (!EXACT_IP_MARKER.test(mapping.fake)
      || (mapping.legacyFake !== undefined && mapping.legacyFake !== expectedLegacy)) {
      throw new Error('Invalid mapping state');
    }
  }
  return fakeValues;
}

function validateSecretMappings(mappings, fakeValues) {
  if (!Array.isArray(mappings) || mappings.length > SECRET_CAPACITY) throw new Error('Invalid mapping state');
  const seen = new Set();
  for (const mapping of mappings) {
    if (!mapping || !SECRET_TYPES.has(mapping.type) || typeof mapping.real !== 'string' || mapping.real === ''
      || typeof mapping.fake !== 'string' || !new RegExp(`^\\[REDACTED_${mapping.type}_[a-f0-9]{32}\\]$`).test(mapping.fake)
      || fakeValues.has(mapping.fake) || seen.has(JSON.stringify([mapping.type, mapping.real]))) {
      throw new Error('Invalid mapping state');
    }
    fakeValues.add(mapping.fake);
    seen.add(JSON.stringify([mapping.type, mapping.real]));
  }
}

function newMarker(type = 'IP') {
  return `[REDACTED_${type}_${randomUUID().replaceAll('-', '')}]`;
}

// Replaces sensitive text with persistent markers and restores them, for one
// state snapshot. redact() mutates the snapshot; check changed before saving.
export class Redactor {
  #migrated = false;
  #mappingCount;
  #secretCount;

  constructor(state, customText = () => []) {
    this.customText = customText;
    this.#load(state);
    // Migration keeps every IP mapping and legacy states have no secret mappings.
    this.#mappingCount = state.mappings.length;
    this.#secretCount = state.secretMappings?.length ?? 0;
  }

  get changed() {
    return this.#migrated || this.state.mappings.length !== this.#mappingCount
      || this.state.secretMappings.length !== this.#secretCount;
  }

  #load(state) {
    this.state = state;
    this.realToFake = new Map(state.mappings.map((mapping) => [mapping.real, mapping.fake]));
    this.fakeToReal = new Map(state.mappings.map((mapping) => [mapping.fake, mapping.real]));
    for (const mapping of state.mappings) {
      if (mapping.legacyFake) this.fakeToReal.set(mapping.legacyFake, mapping.real);
    }
    this.secretToFake = new Map((state.secretMappings ?? []).map((mapping) => [JSON.stringify([mapping.type, mapping.real]), mapping.fake]));
    for (const mapping of state.secretMappings ?? []) this.fakeToReal.set(mapping.fake, mapping.real);
  }

  // Older states are read as they are and only upgraded before a write.
  #migrate() {
    if (this.state.version !== STATE_VERSION) {
      this.#load({ ...this.state, version: STATE_VERSION, secretMappings: [],
        mappings: this.state.version === 1 ? this.state.mappings.map((mapping) => ({
          real: mapping.real, fake: newMarker(), legacyFake: mapping.fake,
        })) : this.state.mappings,
      });
      this.#migrated = true;
    }
  }

  #allocateSecret(type, real) {
    if (this.fakeToReal.has(real) && EXACT_MARKER.test(real)) return real;
    real = real.replace(RESTORABLE_MARKER, (marker) => this.fakeToReal.get(marker) ?? marker);
    const key = JSON.stringify([type, real]);
    if (this.secretToFake.has(key)) return this.secretToFake.get(key);
    if (this.state.secretMappings.length >= SECRET_CAPACITY) {
      throw Object.assign(new Error('Sensitive text mapping capacity exhausted'), { code: 'SECRET_MAPPING_CAPACITY_EXHAUSTED' });
    }
    let fake;
    do { fake = newMarker(type); } while (this.fakeToReal.has(fake));
    this.state.secretMappings.push({ type, real, fake });
    this.secretToFake.set(key, fake);
    this.fakeToReal.set(fake, real);
    return fake;
  }

  #allocateIp(ip) {
    if (isDocumentationAddress(ip)) return ip;
    if (this.realToFake.has(ip)) return this.realToFake.get(ip);
    if (this.state.nextIndex >= POOL_SIZE) throw new MappingCapacityError();
    let fake;
    do { fake = newMarker(); } while (this.fakeToReal.has(fake));
    this.state.mappings.push({ real: ip, fake });
    this.state.nextIndex += 1;
    this.realToFake.set(ip, fake);
    this.fakeToReal.set(fake, ip);
    return fake;
  }

  // One scan per decoded string; IPs use the address pool, the rest secret
  // markers. Without secrets, only IPv4 addresses are replaced.
  redact(text, { secrets = false, mode = 'paranoic', redactionLimits } = {}) {
    this.#migrate();
    const options = { limits: resolveRedactionLimits(redactionLimits), mode, secrets, customText: this.customText };
    let ipCount = 0;
    let secretCount = 0;
    const { body } = transformJsonText(text, (value) => {
      const spans = scanString(value, options);
      const replaced = applySpans(value, spans, (type, real) => {
        if (type === 'IP') {
          ipCount += 1;
          return this.#allocateIp(real.replaceAll('-', '.'));
        }
        secretCount += 1;
        return this.#allocateSecret(type, real);
      });
      return { body: replaced, count: spans.length };
    });
    return { body, count: ipCount, secretCount };
  }

  #restoreValue(value) {
    const legacy = replaceAddresses(value, (ip) => this.fakeToReal.get(ip));
    let count = legacy.count;
    const body = legacy.body.replace(RESTORABLE_MARKER, (marker, offset, input) => {
      const real = this.fakeToReal.get(marker);
      if (!real) return marker;
      count += 1;
      const aws = marker.startsWith('[REDACTED_IP_') && /\bip-$/i.test(input.slice(0, offset));
      return aws ? real.replaceAll('.', '-') : real;
    });
    return { body, count };
  }

  restore(text) {
    return transformJsonText(text, (value) => this.#restoreValue(value));
  }
}
