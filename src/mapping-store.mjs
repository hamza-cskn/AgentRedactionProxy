import { randomUUID } from 'node:crypto';
import { chmod, mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { transformJsonText } from './json-text.mjs';
import { redactSecrets } from './secret-redaction.mjs';
import { RESTORABLE_MARKER_SOURCE, replaceSensitiveTexts, validateSensitiveTexts } from './sensitive-texts.mjs';
import { decryptText, encryptText } from './encrypted-storage.mjs';

const DOCUMENTATION_PREFIXES = new Set([
  '192.0.2',
  '198.51.100',
  '203.0.113',
]);
const POOL_PREFIXES = [
  '192.0.2',
  '198.51.100',
  '203.0.113',
];
const OCTET = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
const IPV4_PATTERN = new RegExp(`(^|[^0-9.]|(?<![0-9])\\.)(${OCTET}(?:\\.${OCTET}){3})(?!\\.?[0-9])`, 'g');
const AWS_IPV4_PATTERN = new RegExp(`\\b(ip-)(${OCTET}(?:-${OCTET}){3})(?=\\.(?:ec2|[a-z0-9-]+\\.compute)\\.internal\\b)`, 'gi');
const STATE_VERSION = 3;
const IP_MARKER = new RegExp(RESTORABLE_MARKER_SOURCE, 'g');
const EXACT_IP_MARKER = /^\[REDACTED_IP_[a-f0-9]{32}\]$/;
const SECRET_TYPES = new Set(['API_KEY', 'JWT', 'PRIVATE_KEY', 'PASSWORD', 'TEXT']);
const SECRET_CAPACITY = 10000;
const POOL_SIZE = POOL_PREFIXES.length * 254;
const LOCK_WAIT_MS = 5_000;

export class TransformedBodyLimitError extends Error {
  constructor() {
    super('Transformed body exceeds configured limit');
    this.code = 'TRANSFORMED_BODY_TOO_LARGE';
  }
}

export class MappingCapacityError extends Error {
  constructor() {
    super('IPv4 mapping capacity exhausted');
    this.code = 'MAPPING_CAPACITY_EXHAUSTED';
  }
}

export function defaultStatePath() {
  return path.join(os.homedir(), '.local', 'share', 'opencode-ipv4-proxy', 'redaction_mapping.json');
}

function isDocumentationAddress(ip) {
  return DOCUMENTATION_PREFIXES.has(ip.slice(0, ip.lastIndexOf('.')));
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

  const realValues = new Set();
  const fakeValues = new Set();
  for (const mapping of state.mappings) {
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
  }

  if (state.mappings.length !== state.nextIndex) {
    throw new Error('Invalid mapping state');
  }
  for (let index = 0; index < state.mappings.length; index += 1) {
    const mapping = state.mappings[index];
    if (state.version === 1 ? mapping.fake !== fakeAddressAt(index)
      : !EXACT_IP_MARKER.test(mapping.fake)
        || (mapping.legacyFake !== undefined && mapping.legacyFake !== fakeAddressAt(index))) {
      throw new Error('Invalid mapping state');
    }
  }
  if (state.version === STATE_VERSION) {
    if (!Array.isArray(state.secretMappings) || state.secretMappings.length > SECRET_CAPACITY) throw new Error('Invalid mapping state');
    const seen = new Set();
    for (const mapping of state.secretMappings) {
      if (!mapping || !SECRET_TYPES.has(mapping.type) || typeof mapping.real !== 'string' || mapping.real === ''
        || typeof mapping.fake !== 'string' || !new RegExp(`^\\[REDACTED_${mapping.type}_[a-f0-9]{32}\\]$`).test(mapping.fake)
        || fakeValues.has(mapping.fake) || seen.has(JSON.stringify([mapping.type, mapping.real]))) throw new Error('Invalid mapping state');
      fakeValues.add(mapping.fake);
      seen.add(JSON.stringify([mapping.type, mapping.real]));
    }
  }
}

function newMarker(type = 'IP') {
  return `[REDACTED_${type}_${randomUUID().replaceAll('-', '')}]`;
}

function collectExactIpv4(value) {
  IPV4_PATTERN.lastIndex = 0;
  const match = IPV4_PATTERN.exec(value);
  return match && match[0] === value ? match[2] : null;
}

async function readState(statePath, encryptionKey) {
  try {
    const text = await readFile(statePath, 'utf8');
    const state = JSON.parse(encryptionKey ? decryptText(text, encryptionKey, 'redaction-mapping') : text);
    validateState(state);
    return state;
  } catch (error) {
    if (error.code === 'ENOENT') return emptyState();
    if (error instanceof SyntaxError) throw new Error('Invalid mapping state');
    throw error;
  }
}

async function saveState(statePath, state, encryptionKey) {
  const directory = path.dirname(statePath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = `${statePath}.${process.pid}.${Date.now()}.tmp`;
  const handle = await open(temporaryPath, 'wx', 0o600);
  try {
    const text = `${JSON.stringify(state, null, 2)}\n`;
    await handle.writeFile(encryptionKey ? encryptText(text, encryptionKey, 'redaction-mapping') : text, 'utf8');
    await handle.sync();
  } catch (error) {
    await handle.close();
    await unlink(temporaryPath).catch(() => {});
    throw error;
  }
  await handle.close();

  try {
    await rename(temporaryPath, statePath);
  } catch (error) {
    await unlink(temporaryPath).catch(() => {});
    throw error;
  }
}

async function syncStateDirectory(statePath) {
  try {
    const directoryHandle = await open(path.dirname(statePath), 'r');
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  } catch (cause) {
    throw Object.assign(new Error('Mapping state durability check failed', { cause }), {
      code: 'MAPPING_DURABILITY_FAILED',
    });
  }
}

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function acquireLock(lockPath) {
  const deadline = Date.now() + LOCK_WAIT_MS;
  const token = `${process.pid}:${randomUUID()}`;

  while (Date.now() <= deadline) {
    try {
      const handle = await open(lockPath, 'wx', 0o600);
      try {
        await handle.writeFile(token, 'utf8');
        await handle.sync();
      } catch (error) {
        // This process exclusively created the lock; no other writer owns it.
        await unlink(lockPath);
        throw error;
      } finally {
        await handle.close();
      }

      return async () => {
        try {
          if (await readFile(lockPath, 'utf8') === token) {
            await unlink(lockPath);
          }
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
      };
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      await delay(25);
    }
  }

  throw new Error('Timed out waiting for mapping state lock');
}

function replaceAddresses(text, lookup, fallback = null) {
  let count = 0;
  let body = text;
  for (const [pattern, hyphenated] of [[IPV4_PATTERN, false], [AWS_IPV4_PATTERN, true]]) {
    pattern.lastIndex = 0;
    body = body.replace(pattern, (match, prefix, address) => {
      const ip = hyphenated ? address.replaceAll('-', '.') : address;
      const replacement = lookup(ip);
      if (replacement === ip) return match;
      if (replacement === null || replacement === undefined) {
        return fallback === null ? match : `${prefix}${fallback}`;
      }
      count += 1;
      return `${prefix}${hyphenated ? replacement.replaceAll('.', '-') : replacement}`;
    });
  }
  return { body, count };
}

// A failed store may be bypassed only for text with no real address. Use the
// same JSON decoding and address patterns as obfuscation, without state access.
export function containsSensitiveIpv4(text) {
  return transformJsonText(text, (value) => replaceAddresses(value, (ip) => (
    isDocumentationAddress(ip) ? ip : '[redacted-ipv4]'
  ))).count > 0;
}

export class MappingStore {
  static async status(statePath = defaultStatePath(), { encryptionKey } = {}) {
    const state = await readState(statePath, encryptionKey);
    return { used: state.nextIndex, capacity: POOL_SIZE, remaining: POOL_SIZE - state.nextIndex };
  }

  static async open(statePath = defaultStatePath(), { sensitiveTexts = [], encryptionKey, storageGuard } = {}) {
    const state = await readState(statePath, encryptionKey);
    await mkdir(path.dirname(statePath), { recursive: true, mode: 0o700 });
    await chmod(path.dirname(statePath), 0o700).catch(() => {});
    await chmod(statePath, 0o600).catch((error) => {
      if (error.code !== 'ENOENT') throw error;
    });
    return new MappingStore(statePath, state, sensitiveTexts, encryptionKey, storageGuard);
  }

  constructor(statePath, state, sensitiveTexts = [], encryptionKey, storageGuard) {
    this.statePath = statePath;
    this.lockPath = `${statePath}.lock`;
    this.encryptionKey = encryptionKey;
    this.storageGuard = storageGuard;
    this.sensitiveTexts = validateSensitiveTexts(sensitiveTexts).sort((a, b) => b.length - a.length);
    this.#applyState(state);
    this.queue = Promise.resolve();
  }

  #applyState(state) {
    this.state = state;
    this.realToFake = new Map(state.mappings.map((mapping) => [mapping.real, mapping.fake]));
    this.fakeToReal = new Map(state.mappings.map((mapping) => [mapping.fake, mapping.real]));
    for (const mapping of state.mappings) {
      if (mapping.legacyFake) this.fakeToReal.set(mapping.legacyFake, mapping.real);
    }
    this.secretToFake = new Map((state.secretMappings ?? []).map((mapping) => [JSON.stringify([mapping.type, mapping.real]), mapping.fake]));
    for (const mapping of state.secretMappings ?? []) this.fakeToReal.set(mapping.fake, mapping.real);
  }

  obfuscate(text, options = {}) {
    const operation = this.queue.then(() => this.#obfuscate(text, options));
    this.queue = operation.catch(() => {});
    return operation;
  }

  obfuscateRequest(text, options = {}) {
    return this.obfuscate(text, { ...options, redact: true });
  }

  containsSensitiveTexts(text) {
    return replaceSensitiveTexts(text, this.sensitiveTexts, () => '[sensitive]').count > 0;
  }

  async #obfuscate(text, options = {}) {
    const release = await acquireLock(this.lockPath);
    try {
      await this.storageGuard?.();
      this.#applyState(await readState(this.statePath, this.encryptionKey));
      return await this.#obfuscateLocked(text, options);
    } finally {
      await release();
    }
  }

  async #obfuscateLocked(text, { maxBytes = Number.POSITIVE_INFINITY, redact = false, mode = 'paranoic', redactionLimits } = {}) {
    const originalState = this.state;
    const migrating = this.state.version !== STATE_VERSION;
    if (migrating) {
      this.#applyState({ ...this.state, version: STATE_VERSION, secretMappings: [],
        mappings: this.state.version === 1 ? this.state.mappings.map((mapping) => ({
          real: mapping.real, fake: newMarker(), legacyFake: mapping.fake,
        })) : this.state.mappings,
      });
    }
    const originalLength = this.state.mappings.length;
    const originalNextIndex = this.state.nextIndex;
    const originalSecretLength = this.state.secretMappings.length;
    const newMappings = [];

    try {
      let secretCount = 0;
      const allocateSecret = (type, real) => {
        if (this.fakeToReal.has(real) && new RegExp(`^${RESTORABLE_MARKER_SOURCE}$`).test(real)) return real;
        real = real.replace(IP_MARKER, (marker) => this.fakeToReal.get(marker) ?? marker);
        const key = JSON.stringify([type, real]);
        if (this.secretToFake.has(key)) return this.secretToFake.get(key);
        if (this.state.secretMappings.length >= SECRET_CAPACITY) throw Object.assign(new Error('Sensitive text mapping capacity exhausted'), { code: 'SECRET_MAPPING_CAPACITY_EXHAUSTED' });
        let fake;
        do { fake = newMarker(type); } while (this.fakeToReal.has(fake));
        this.state.secretMappings.push({ type, real, fake });
        this.secretToFake.set(key, fake);
        this.fakeToReal.set(fake, real);
        return fake;
      };
      if (redact) {
        const secrets = redactSecrets(text, redactionLimits, mode, allocateSecret);
        text = secrets.body;
        secretCount = secrets.count;
        // Expand known secret spans in configured values into their markers so
        // whole literal phrases still match when they overlap a built-in key.
        const patterns = this.sensitiveTexts.flatMap((value) => {
          try {
            const matched = redactSecrets(value, redactionLimits, mode, (type, real) => (
              this.secretToFake.get(JSON.stringify([type, real])) ?? real
            )).body;
            return matched === value ? [value] : [matched, value];
          } catch {
            // A malformed-looking configured literal must not reject unrelated
            // requests. The actual request already passed credential checks.
            return [value];
          }
        });
        const custom = replaceSensitiveTexts(text, patterns, (value) => allocateSecret('TEXT', value.replace(IP_MARKER, (marker) => this.fakeToReal.get(marker) ?? marker)));
        text = custom.body;
        secretCount += custom.count;
      }
      const transformed = transformJsonText(text, (value) => replaceAddresses(value, (ip) => {
        if (isDocumentationAddress(ip)) return ip;
        if (this.realToFake.has(ip)) return this.realToFake.get(ip);
        if (this.state.nextIndex >= POOL_SIZE) throw new MappingCapacityError();
        let fake;
        do { fake = newMarker(); } while (this.fakeToReal.has(fake));
        const mapping = { real: ip, fake };
        this.state.mappings.push(mapping);
        this.state.nextIndex += 1;
        this.realToFake.set(ip, fake);
        this.fakeToReal.set(fake, ip);
        newMappings.push(mapping);
        return fake;
      }));

      if (Buffer.byteLength(transformed.body, 'utf8') > maxBytes) {
        throw new TransformedBodyLimitError();
      }
      if (migrating || newMappings.length > 0 || this.state.secretMappings.length !== originalSecretLength) await saveState(this.statePath, this.state, this.encryptionKey);
      // Also retry durability for existing mappings after a previous sync failure.
      await syncStateDirectory(this.statePath);
      return redact ? { ...transformed, secretCount } : transformed;
    } catch (error) {
      // The rename is already committed when directory syncing fails.
      if (error.code === 'MAPPING_DURABILITY_FAILED') throw error;
      this.state.mappings.length = originalLength;
      this.state.nextIndex = originalNextIndex;
      for (const mapping of newMappings) {
        this.realToFake.delete(mapping.real);
        this.fakeToReal.delete(mapping.fake);
      }
      if (migrating) this.#applyState(originalState);
      else {
        this.state.secretMappings.length = originalSecretLength;
        this.#applyState(this.state);
      }
      throw error;
    }
  }

  deobfuscate(text) {
    return this.deobfuscateMany([text]).then(([result]) => result);
  }

  deobfuscateMany(texts) {
    const operation = this.queue.then(async () => {
      const release = await acquireLock(this.lockPath);
      try {
        await this.storageGuard?.();
        this.#applyState(await readState(this.statePath, this.encryptionKey));
        return texts.map((text) => transformJsonText(text, (value) => {
          const legacy = replaceAddresses(value, (ip) => this.fakeToReal.get(ip));
          let count = legacy.count;
          const body = legacy.body.replace(IP_MARKER, (marker, offset, input) => {
            const real = this.fakeToReal.get(marker);
            if (!real) return marker;
            count += 1;
            const aws = marker.startsWith('[REDACTED_IP_') && /\bip-$/i.test(input.slice(0, offset))
              && /^\.(?:ec2|[a-z0-9-]+\.compute)\.internal\b/i.test(input.slice(offset + marker.length));
            return aws ? real.replaceAll('.', '-') : real;
          });
          return { body, count };
        }));
      } finally {
        await release();
      }
    });
    this.queue = operation.catch(() => {});
    return operation;
  }
}
