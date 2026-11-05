import { randomUUID } from 'node:crypto';
import { chmod, mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { decryptText, encryptText } from './encrypted-storage.mjs';
import { emptyState, validateState } from './redactor.mjs';

const LOCK_WAIT_MS = 5_000;

export function defaultStatePath() {
  return path.join(os.homedir(), '.local', 'share', 'opencode-ipv4-proxy', 'redaction_mapping.json');
}

export async function readState(statePath, encryptionKey) {
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

// The mapping state file, shared by every proxy process. Each operation runs
// under an in-process queue and a cross-process lock, on a fresh read.
export class StateStore {
  static async open(statePath = defaultStatePath(), { encryptionKey, storageGuard } = {}) {
    const state = await readState(statePath, encryptionKey);
    await mkdir(path.dirname(statePath), { recursive: true, mode: 0o700 });
    await chmod(path.dirname(statePath), 0o700).catch(() => {});
    await chmod(statePath, 0o600).catch((error) => {
      if (error.code !== 'ENOENT') throw error;
    });
    return { store: new StateStore(statePath, encryptionKey, storageGuard), state };
  }

  constructor(statePath, encryptionKey, storageGuard) {
    this.statePath = statePath;
    this.lockPath = `${statePath}.lock`;
    this.encryptionKey = encryptionKey;
    this.storageGuard = storageGuard;
    this.queue = Promise.resolve();
  }

  #locked(fn) {
    const operation = this.queue.then(async () => {
      const release = await acquireLock(this.lockPath);
      try {
        await this.storageGuard?.();
        return await fn(await readState(this.statePath, this.encryptionKey));
      } finally {
        await release();
      }
    });
    this.queue = operation.catch(() => {});
    return operation;
  }

  read(fn) {
    return this.#locked(fn);
  }

  // fn returns { value, state }; a non-null state is saved before value is returned.
  update(fn) {
    return this.#locked(async (current) => {
      const { value, state } = await fn(current);
      if (state) await saveState(this.statePath, state, this.encryptionKey);
      // Also retry durability for existing mappings after a previous sync failure.
      await syncStateDirectory(this.statePath);
      return value;
    });
  }
}
