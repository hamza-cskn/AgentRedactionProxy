#!/usr/bin/env node
import { link, mkdir, mkdtemp, open, readFile, rm, unlink } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Writable } from 'node:stream';
import { createInterface } from 'node:readline/promises';
import { decryptText, encryptText, exists, parseMasterKey, storagePaths } from '../src/encrypted-storage.mjs';
import { defaultStatePath, emptyState, validateState } from '../src/mapping-store.mjs';
import { loadSensitiveTexts } from '../src/sensitive-texts.mjs';

async function writePrivate(file, text) {
  const handle = await open(file, 'wx', 0o600);
  try { await handle.writeFile(text); await handle.sync(); } catch (error) {
    await unlink(file);
    throw error;
  } finally { await handle.close(); }
}

async function syncDirectory(directory) {
  // Windows does not expose POSIX directory fsync through Node. File sync and
  // same-directory rename remain in use; Docker runs the Linux implementation.
  if (process.platform === 'win32') return;
  const handle = await open(directory, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
}

export async function encryptStorage(directory, masterKeyText) {
  const key = parseMasterKey(masterKeyText);
  directory = path.resolve(directory);
  const files = storagePaths(directory);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const locks = [];
  const published = [];
  let stage;
  let committed = false;
  try {
    for (const file of [files.conversionLock, `${files.plainMapping}.lock`, `${files.encryptedMapping}.lock`]) {
      await writePrivate(file, `${process.pid}\n`);
      locks.push(file);
    }
    for (const file of [files.masterKey, files.encryptedMapping, files.encryptedSecrets]) {
      if (await exists(file)) throw new Error('Encrypted outputs or master-key file already exist; refusing to overwrite');
    }
    if (await exists(path.join(directory, 'mappings.json'))) throw new Error('Rename legacy mappings.json to redaction_mapping.json before conversion');
    const originals = [];
    let mapping = JSON.stringify(emptyState());
    if (await exists(files.plainMapping)) {
      mapping = await readFile(files.plainMapping, 'utf8');
      originals.push(files.plainMapping);
    }
    try { validateState(JSON.parse(mapping)); } catch { throw new Error('Invalid plaintext redaction-mapping'); }
    let secrets = '[]';
    if (await exists(files.plainSecrets)) {
      await loadSensitiveTexts(files.plainSecrets);
      secrets = await readFile(files.plainSecrets, 'utf8');
      originals.push(files.plainSecrets);
    }
    stage = await mkdtemp(path.join(directory, '.encrypt-'));
    for (const [target, plaintext, purpose] of [[files.encryptedMapping, mapping, 'redaction-mapping'],
      [files.encryptedSecrets, secrets, 'user-defined-secrets']]) {
      const staged = path.join(stage, path.basename(target));
      await writePrivate(staged, encryptText(plaintext, key, purpose));
      if (decryptText(await readFile(staged, 'utf8'), key, purpose) !== plaintext) throw new Error('Encrypted output verification failed');
      // Exclusive creation never overwrites an unrelated pre-existing output.
      await writePrivate(target, await readFile(staged, 'utf8'));
      published.push(target);
    }
    await syncDirectory(directory);
    const stagedKey = path.join(stage, 'master_key_secret');
    await writePrivate(stagedKey, `${key.toString('base64')}\n`);
    // Publishing a complete hard link is atomic and refuses an existing key.
    await link(stagedKey, files.masterKey);
    committed = true;
    await syncDirectory(directory);
    const leftovers = [];
    for (const file of originals) {
      try { await unlink(file); } catch { leftovers.push(path.basename(file)); }
    }
    await syncDirectory(directory);
    return { leftovers };
  } catch (cause) {
    if (!committed) {
      const cleanupFailed = [];
      for (const file of published.reverse()) {
        try { await unlink(file); } catch { cleanupFailed.push(path.basename(file)); }
      }
      const suffix = cleanupFailed.length ? `; remove incomplete encrypted outputs: ${cleanupFailed.join(', ')}` : '';
      throw new Error(`Conversion failed; plaintext originals were preserved${suffix}`, { cause });
    }
    throw new Error('Encrypted mode is active, but cleanup/durability failed; inspect plaintext leftovers before restarting', { cause });
  } finally {
    key.fill(0);
    if (stage) await rm(stage, { recursive: true, force: true });
    for (const file of locks.reverse()) await unlink(file);
  }
}

async function promptKey() {
  if (!process.stdin.isTTY) throw new Error('Run conversion interactively in a terminal; never pass the master key as an argument or environment variable');
  let muted = false;
  const output = new Writable({ write(chunk, encoding, done) {
    if (!muted) process.stderr.write(chunk, encoding);
    done();
  } });
  const prompt = createInterface({ input: process.stdin, output, terminal: true });
  try {
    process.stderr.write('Stop all proxy instances before conversion.\nMaster key (base64, 32 random bytes; input hidden): ');
    muted = true;
    return await prompt.question('');
  } finally { muted = false; prompt.close(); process.stderr.write('\n'); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length > 3) throw new Error('Usage: node scripts/encrypt-storage.mjs [data-directory]');
    const directory = process.argv[2] || process.env.ARP_DATA_DIR || path.dirname(defaultStatePath());
    const result = await encryptStorage(directory, await promptKey());
    if (result.leftovers.length) {
      process.stderr.write(`Encrypted mode active; plaintext cleanup failed: ${result.leftovers.join(', ')}\n`);
      process.exitCode = 1;
    } else process.stdout.write('Encrypted mode activated. Plaintext originals removed. Protect master_key_secret and its backup.\n');
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
