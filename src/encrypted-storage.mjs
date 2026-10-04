import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { open, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const FORMAT = 'agent-redaction-proxy/aes-256-gcm';
const PURPOSES = new Set(['redaction-mapping', 'user-defined-secrets']);

export function parseMasterKey(value) {
  const text = value.trim();
  const key = Buffer.from(text, 'base64');
  if (key.length !== 32 || key.toString('base64') !== text) {
    throw new Error('Master key must be a base64-encoded random 32-byte key');
  }
  return key;
}

export function encryptText(text, key, purpose) {
  if (!PURPOSES.has(purpose) || !Buffer.isBuffer(key) || key.length !== 32) throw new Error('Invalid encryption settings');
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(`${FORMAT}:1:${purpose}`));
  const ciphertext = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return JSON.stringify({ format: FORMAT, version: 1, purpose,
    nonce: nonce.toString('base64'), tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64') }) + '\n';
}

export function decryptText(text, key, purpose) {
  try {
    const envelope = JSON.parse(text);
    if (!PURPOSES.has(purpose) || envelope.format !== FORMAT || envelope.version !== 1 || envelope.purpose !== purpose) throw new Error();
    const decode = (value, size) => {
      if (typeof value !== 'string') throw new Error();
      const bytes = Buffer.from(value, 'base64');
      if (bytes.toString('base64') !== value || (size !== undefined && bytes.length !== size)) throw new Error();
      return bytes;
    };
    const decipher = createDecipheriv('aes-256-gcm', key, decode(envelope.nonce, 12), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(`${FORMAT}:1:${purpose}`));
    decipher.setAuthTag(decode(envelope.tag, 16));
    const plaintext = Buffer.concat([decipher.update(decode(envelope.ciphertext)), decipher.final()]);
    return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
  } catch {
    throw new Error('Cannot decrypt storage: wrong master key, corrupt file or incompatible format');
  }
}

export async function exists(file) {
  try { await stat(file); return true; } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

export function storagePaths(directory) {
  return {
    plainMapping: path.join(directory, 'redaction_mapping.json'),
    plainSecrets: path.join(directory, 'user_defined_secrets.json'),
    encryptedMapping: path.join(directory, 'redaction_mapping.secret.json'),
    encryptedSecrets: path.join(directory, 'user_defined_secrets.secret.json'),
    masterKey: path.join(directory, 'master_key_secret'),
    conversionLock: path.join(directory, '.encryption-conversion.lock'),
  };
}

export async function loadStorage(directory, masterKeyFile = storagePaths(directory).masterKey) {
  const files = storagePaths(directory);
  if (await exists(files.conversionLock)) throw new Error('Encryption conversion is in progress; stop the proxy until conversion finishes');
  let encryptionKey;
  let handle;
  try {
    handle = await open(masterKeyFile, 'r');
    if ((await handle.stat()).size > 128) throw new Error('Invalid master-key file');
    encryptionKey = parseMasterKey(await handle.readFile('utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw new Error('Cannot load master-key file: require a base64-encoded random 32-byte key');
  } finally { await handle?.close(); }
  const statePath = encryptionKey ? files.encryptedMapping : files.plainMapping;
  const sensitiveTextsFile = encryptionKey ? files.encryptedSecrets : files.plainSecrets;
  for (const [selected, alternate] of [[statePath, encryptionKey ? files.plainMapping : files.encryptedMapping],
    [sensitiveTextsFile, encryptionKey ? files.plainSecrets : files.encryptedSecrets]]) {
    if (!await exists(selected) && await exists(alternate)) throw new Error('Storage mode mismatch; use the explicit conversion script, not automatic conversion');
  }
  return { statePath, encryptionKey, sensitiveTextsFile: await exists(sensitiveTextsFile) ? sensitiveTextsFile : undefined };
}
