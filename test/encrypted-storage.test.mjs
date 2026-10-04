import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs, { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import test from 'node:test';
import { decryptText, encryptText, exists, loadStorage, parseMasterKey, storagePaths } from '../src/encrypted-storage.mjs';
import { MappingStore } from '../src/mapping-store.mjs';
import { loadConfig } from '../src/config.mjs';
import { encryptStorage } from '../scripts/encrypt-storage.mjs';

const exec = promisify(execFile);
const key = randomBytes(32);
const keyText = key.toString('base64');
const custom = 'private-project-unique-name';
const token = `ghp_${'Ab12'.repeat(9)}`;

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'arp-encryption-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const files = storagePaths(directory);
  await writeFile(files.plainSecrets, JSON.stringify([custom]));
  const store = await MappingStore.open(files.plainMapping, { sensitiveTexts: [custom] });
  const masked = (await store.obfuscateRequest(`${custom} ${token} 10.20.30.40`)).body;
  return { directory, files, masked };
}

test('AES-GCM roundtrip uses fresh nonces, authenticates file purpose and rejects tampering', () => {
  const a = encryptText(custom, key, 'redaction-mapping');
  const b = encryptText(custom, key, 'redaction-mapping');
  assert.notEqual(JSON.parse(a).nonce, JSON.parse(b).nonce);
  assert.equal(a.includes(custom), false);
  assert.equal(decryptText(a, key, 'redaction-mapping'), custom);
  for (const [candidate, candidateKey, purpose] of [[a, randomBytes(32), 'redaction-mapping'],
    [a, key, 'user-defined-secrets'], [custom, key, 'redaction-mapping']]) {
    assert.throws(() => decryptText(candidate, candidateKey, purpose), /Cannot decrypt storage/);
  }
  for (const field of ['tag', 'nonce', 'ciphertext', 'version', 'format', 'purpose']) {
    const envelope = JSON.parse(a);
    envelope[field] = field === 'version' ? 2 : 'AAAA';
    assert.throws(() => decryptText(JSON.stringify(envelope), key, 'redaction-mapping'), /Cannot decrypt storage/);
  }
  for (const value of ['password', '', keyText.slice(0, -1), keyText + '=']) assert.throws(() => parseMasterKey(value));
  assert.deepEqual(parseMasterKey(`${keyText}\n`), key);
});

test('conversion encrypts both files, keeps UUIDs, deletes plaintext and persists subsequent allocations encrypted', async (t) => {
  const { directory, files, masked } = await fixture(t);
  const config = path.join(directory, 'config.json');
  await writeFile(config, JSON.stringify({ mode: 'paranoic' }));
  assert.deepEqual(await encryptStorage(directory, keyText), { leftovers: [] });
  for (const file of [files.plainSecrets, files.plainMapping, files.conversionLock]) assert.equal(await exists(file), false);
  const storage = await loadStorage(directory);
  assert.equal(storage.statePath, files.encryptedMapping);
  const loaded = await loadConfig(config, storage);
  assert.deepEqual(loaded.sensitiveTexts, [custom]);
  const store = await MappingStore.open(storage.statePath, { ...storage, sensitiveTexts: loaded.sensitiveTexts });
  assert.equal((await store.deobfuscate(masked)).body, `${custom} ${token} 10.20.30.40`);
  const another = await store.obfuscateRequest(`${custom} 10.20.30.41`);
  const reopened = await MappingStore.open(storage.statePath, storage);
  assert.equal((await reopened.deobfuscate(another.body)).body, `${custom} 10.20.30.41`);
  const before = await readFile(files.encryptedMapping, 'utf8');
  assert.equal((await MappingStore.status(storage.statePath, storage)).used, 2);
  assert.equal(await readFile(files.encryptedMapping, 'utf8'), before, 'status is read-only');
  for (const file of [files.encryptedMapping, files.encryptedSecrets]) {
    const body = await readFile(file, 'utf8');
    for (const sensitive of [custom, token, '10.20.30.40']) assert.equal(body.includes(sensitive), false);
    if (process.platform !== 'win32') assert.equal((await stat(file)).mode & 0o777, 0o600);
  }
  if (process.platform !== 'win32') assert.equal((await stat(files.masterKey)).mode & 0o777, 0o600);
  assert.equal((await readdir(directory)).some((name) => name.startsWith('.encrypt-') || name.endsWith('.lock')), false);
});

test('mode is selected only by key-file presence; mismatch and wrong keys never auto-convert', async (t) => {
  const { directory, files } = await fixture(t);
  assert.equal((await loadStorage(directory)).encryptionKey, undefined);
  const original = await readFile(files.plainMapping, 'utf8');
  await writeFile(files.masterKey, `${keyText}\n`);
  await assert.rejects(loadStorage(directory), /mode mismatch/);
  assert.equal(await readFile(files.plainMapping, 'utf8'), original);
  await rm(files.masterKey);
  await encryptStorage(directory, keyText);
  const ciphertext = await readFile(files.encryptedMapping, 'utf8');
  await writeFile(files.masterKey, randomBytes(32).toString('base64'));
  const wrong = await loadStorage(directory);
  await assert.rejects(MappingStore.open(wrong.statePath, wrong), /Cannot decrypt storage/);
  await assert.rejects(loadConfig(new URL('../config.json', import.meta.url), wrong), /Cannot load sensitive texts/);
  assert.equal(await readFile(files.encryptedMapping, 'utf8'), ciphertext);
  await rm(files.masterKey);
  await assert.rejects(loadStorage(directory), /mode mismatch/);
  await writeFile(files.masterKey, 'invalid-sensitive-key');
  await assert.rejects(loadStorage(directory), (error) => !error.message.includes('invalid-sensitive-key'));
});

test('mounted Docker key file selects encrypted storage without a key in the data volume', async (t) => {
  const { directory, files } = await fixture(t);
  await encryptStorage(directory, keyText);
  const external = path.join(directory, 'external-key');
  await fs.rename(files.masterKey, external);
  const storage = await loadStorage(directory, external);
  assert.equal(storage.statePath, files.encryptedMapping);
  await MappingStore.open(storage.statePath, storage);
});

test('invalid plaintext input or existing encrypted output leaves originals and existing files intact', async (t) => {
  const { directory, files } = await fixture(t);
  const mapping = await readFile(files.plainMapping, 'utf8');
  await writeFile(files.plainSecrets, 'bad-sensitive-json');
  await assert.rejects(encryptStorage(directory, keyText), /plaintext originals were preserved/);
  assert.equal(await readFile(files.plainMapping, 'utf8'), mapping);
  assert.equal(await readFile(files.plainSecrets, 'utf8'), 'bad-sensitive-json');
  assert.equal(await exists(files.masterKey), false);
  await writeFile(files.encryptedMapping, 'existing-do-not-overwrite');
  await assert.rejects(encryptStorage(directory, keyText), /plaintext originals were preserved/);
  assert.equal(await readFile(files.encryptedMapping, 'utf8'), 'existing-do-not-overwrite');
});

test('failure publishing master key rolls back encrypted outputs and preserves both plaintext files', async (t) => {
  const { directory, files } = await fixture(t);
  const originals = await Promise.all([files.plainMapping, files.plainSecrets].map((file) => readFile(file, 'utf8')));
  t.mock.method(fs, 'link', async () => { throw Object.assign(new Error('injected'), { code: 'EIO' }); });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  await assert.rejects(encryptStorage(directory, keyText), /plaintext originals were preserved/);
  assert.deepEqual(await Promise.all([files.plainMapping, files.plainSecrets].map((file) => readFile(file, 'utf8'))), originals);
  assert.deepEqual((await readdir(directory)).sort(), ['redaction_mapping.json', 'user_defined_secrets.json']);
});

for (const operation of ['writeFile', 'sync']) {
  test(`failure during second encrypted output ${operation} preserves originals and removes partial output`, async (t) => {
    const { directory, files } = await fixture(t);
    const originals = await Promise.all([files.plainMapping, files.plainSecrets].map((file) => readFile(file, 'utf8')));
    const originalOpen = fs.open;
    t.mock.method(fs, 'open', async (...args) => {
      const handle = await originalOpen(...args);
      if (args[0] === files.encryptedSecrets && args[1] === 'wx') {
        t.mock.method(handle, operation, async () => { throw Object.assign(new Error('injected'), { code: 'EIO' }); });
      }
      return handle;
    });
    syncBuiltinESMExports();
    t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
    await assert.rejects(encryptStorage(directory, keyText), /plaintext originals were preserved/);
    assert.deepEqual(await Promise.all([files.plainMapping, files.plainSecrets].map((file) => readFile(file, 'utf8'))), originals);
    assert.deepEqual((await readdir(directory)).sort(), ['redaction_mapping.json', 'user_defined_secrets.json']);
  });
}

test('storage guard stops a running store from recreating plaintext after conversion', async (t) => {
  const { directory, files } = await fixture(t);
  const store = await MappingStore.open(files.plainMapping, { storageGuard: async () => {
    if (await exists(files.masterKey) || await exists(files.conversionLock)) throw new Error('Restart required');
  } });
  await encryptStorage(directory, keyText);
  await assert.rejects(store.obfuscateRequest('10.20.30.41'), /Restart required/);
  await assert.rejects(store.deobfuscate('ordinary text'), /Restart required/);
  assert.equal(await exists(files.plainMapping), false);
});

test('post-activation cleanup failure reports leftovers and keeps encrypted mode usable', async (t) => {
  const { directory, files, masked } = await fixture(t);
  const unlink = fs.unlink;
  t.mock.method(fs, 'unlink', async (file) => {
    if (file === files.plainSecrets) throw Object.assign(new Error('injected'), { code: 'EACCES' });
    return unlink(file);
  });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  assert.deepEqual(await encryptStorage(directory, keyText), { leftovers: ['user_defined_secrets.json'] });
  assert.equal(await exists(files.plainSecrets), true);
  const storage = await loadStorage(directory);
  const store = await MappingStore.open(storage.statePath, storage);
  assert.equal((await store.deobfuscate(masked)).body, `${custom} ${token} 10.20.30.40`);
});

test('conversion lock blocks startup and cannot be removed by a competing conversion', async (t) => {
  const { directory, files } = await fixture(t);
  await writeFile(files.conversionLock, 'owned-by-another-process');
  await assert.rejects(loadStorage(directory), /conversion is in progress/);
  await assert.rejects(encryptStorage(directory, keyText), /plaintext originals were preserved/);
  assert.equal(await readFile(files.conversionLock, 'utf8'), 'owned-by-another-process');
});

test('status CLI reads both modes and wrong-key startup errors do not expose secrets', async (t) => {
  const { directory, files } = await fixture(t);
  const env = { ...process.env, ARP_DATA_DIR: directory, ARP_MASTER_KEY_FILE: files.masterKey };
  for (const encrypted of [false, true]) {
    if (encrypted) await encryptStorage(directory, keyText);
    const { stdout } = await exec(process.execPath, ['src/main.mjs', 'status'], { env });
    assert.equal(JSON.parse(stdout).used, 1);
  }
  await writeFile(files.masterKey, randomBytes(32).toString('base64'));
  await assert.rejects(exec(process.execPath, ['src/main.mjs'], { env }), (error) => {
    assert.match(error.stderr, /Cannot decrypt storage|Cannot load sensitive texts/);
    for (const value of [custom, token, keyText]) assert.equal(error.stderr.includes(value), false);
    return true;
  });
});
