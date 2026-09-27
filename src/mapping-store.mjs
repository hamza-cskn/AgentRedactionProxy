import { randomUUID } from 'node:crypto';
import { chmod, mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { transformJsonText } from './json-text.mjs';

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
const STATE_VERSION = 1;
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
  return path.join(os.homedir(), '.local', 'share', 'opencode-ipv4-proxy', 'mappings.json');
}

function isDocumentationAddress(ip) {
  return DOCUMENTATION_PREFIXES.has(ip.slice(0, ip.lastIndexOf('.')));
}

function fakeAddressAt(index) {
  if (!Number.isInteger(index) || index < 0 || index >= POOL_SIZE) return null;
  const prefix = POOL_PREFIXES[Math.floor(index / 254)];
  return `${prefix}.${(index % 254) + 1}`;
}

function emptyState() {
  return { version: STATE_VERSION, nextIndex: 0, mappings: [] };
}

function validateState(state) {
  if (
    !state
    || state.version !== STATE_VERSION
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
    if (state.mappings[index].fake !== fakeAddressAt(index)) {
      throw new Error('Invalid mapping state');
    }
  }
}

function collectExactIpv4(value) {
  IPV4_PATTERN.lastIndex = 0;
  const match = IPV4_PATTERN.exec(value);
  return match && match[0] === value ? match[2] : null;
}

async function readState(statePath) {
  try {
    const state = JSON.parse(await readFile(statePath, 'utf8'));
    validateState(state);
    return state;
  } catch (error) {
    if (error.code === 'ENOENT') return emptyState();
    if (error instanceof SyntaxError) throw new Error('Invalid mapping state');
    throw error;
  }
}

async function saveState(statePath, state) {
  const directory = path.dirname(statePath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = `${statePath}.${process.pid}.${Date.now()}.tmp`;
  const handle = await open(temporaryPath, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(state, null, 2)}\n`, 'utf8');
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
  IPV4_PATTERN.lastIndex = 0;
  const body = text.replace(IPV4_PATTERN, (match, prefix, ip) => {
    const replacement = lookup(ip);
    if (replacement === ip) return match;
    if (replacement === null || replacement === undefined) {
      return fallback === null ? match : `${prefix}${fallback}`;
    }
    count += 1;
    return `${prefix}${replacement}`;
  });
  return { body, count };
}

export class MappingStore {
  static async status(statePath = defaultStatePath()) {
    const state = await readState(statePath);
    return { used: state.nextIndex, capacity: POOL_SIZE, remaining: POOL_SIZE - state.nextIndex };
  }

  static async open(statePath = defaultStatePath()) {
    const state = await readState(statePath);
    await mkdir(path.dirname(statePath), { recursive: true, mode: 0o700 });
    await chmod(path.dirname(statePath), 0o700).catch(() => {});
    await chmod(statePath, 0o600).catch((error) => {
      if (error.code !== 'ENOENT') throw error;
    });
    return new MappingStore(statePath, state);
  }

  constructor(statePath, state) {
    this.statePath = statePath;
    this.lockPath = `${statePath}.lock`;
    this.#applyState(state);
    this.queue = Promise.resolve();
  }

  #applyState(state) {
    this.state = state;
    this.realToFake = new Map(state.mappings.map((mapping) => [mapping.real, mapping.fake]));
    this.fakeToReal = new Map(state.mappings.map((mapping) => [mapping.fake, mapping.real]));
  }

  obfuscate(text, options = {}) {
    const operation = this.queue.then(() => this.#obfuscate(text, options));
    this.queue = operation.catch(() => {});
    return operation;
  }

  async #obfuscate(text, { maxBytes = Number.POSITIVE_INFINITY } = {}) {
    const release = await acquireLock(this.lockPath);
    try {
      this.#applyState(await readState(this.statePath));
      return await this.#obfuscateLocked(text, maxBytes);
    } finally {
      await release();
    }
  }

  async #obfuscateLocked(text, maxBytes) {
    const originalLength = this.state.mappings.length;
    const originalNextIndex = this.state.nextIndex;
    const newMappings = [];

    try {
      const transformed = transformJsonText(text, (value) => replaceAddresses(value, (ip) => {
        if (isDocumentationAddress(ip)) return ip;
        if (this.realToFake.has(ip)) return this.realToFake.get(ip);
        const fake = fakeAddressAt(this.state.nextIndex);
        if (fake === null) throw new MappingCapacityError();
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
      if (newMappings.length > 0) await saveState(this.statePath, this.state);
      // Also retry durability for existing mappings after a previous sync failure.
      await syncStateDirectory(this.statePath);
      return transformed;
    } catch (error) {
      // The rename is already committed when directory syncing fails.
      if (error.code === 'MAPPING_DURABILITY_FAILED') throw error;
      this.state.mappings.length = originalLength;
      this.state.nextIndex = originalNextIndex;
      for (const mapping of newMappings) {
        this.realToFake.delete(mapping.real);
        this.fakeToReal.delete(mapping.fake);
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
        this.#applyState(await readState(this.statePath));
        return texts.map((text) => transformJsonText(text, (value) => (
          replaceAddresses(value, (ip) => this.fakeToReal.get(ip))
        )));
      } finally {
        await release();
      }
    });
    this.queue = operation.catch(() => {});
    return operation;
  }
}
