import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { encryptText } from '../src/encrypted-storage.mjs';
import { loadSensitiveTexts, validateSensitiveTexts } from '../src/sensitive-texts.mjs';

const exec = promisify(execFile);

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'arp-short-entries-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test('every single ASCII character is rejected, including punctuation and controls', () => {
  for (let code = 0; code <= 127; code++) {
    assert.throws(() => validateSensitiveTexts([String.fromCharCode(code)]), /Sensitive texts/, `ASCII ${code}`);
  }
  for (const value of ['', ' ', '\t\n', '   ']) assert.throws(() => validateSensitiveTexts([value]));
});

test('two-character ASCII and single non-ASCII entries remain valid with exact whitespace', () => {
  const values = ['ab', '[R', 'é', '🔒', ' a ', 'a\n', '\0a', 'ab  cd', 'abcde'];
  assert.deepEqual(validateSensitiveTexts([...values, 'ab']), values);
});

for (const encrypted of [false, true]) {
  test(`${encrypted ? 'encrypted' : 'plaintext'} input rejects single ASCII entries without altering the source`, async (t) => {
    const directory = await fixture(t);
    const file = path.join(directory, 'input.json');
    const key = encrypted ? randomBytes(32) : undefined;
    const text = JSON.stringify(['sensitive-private-example', 'A']);
    const source = key ? encryptText(text, key, 'user-defined-secrets') : text;
    await writeFile(file, source);
    await assert.rejects(loadSensitiveTexts(file, key), (error) => {
      assert.match(error.message, /single-character ASCII/);
      assert.equal(error.message.includes('sensitive-private-example'), false);
      return true;
    });
    assert.equal(await readFile(file, 'utf8'), source);
  });

  test(`${encrypted ? 'encrypted' : 'plaintext'} startup warns for lengths below five without logging values`, async (t) => {
    const directory = await fixture(t);
    const values = ['Q2', 'z9x', 'r4t8', 'abcde', 'é', '🔒', ' a ', 'a\n'];
    const key = encrypted ? randomBytes(32) : undefined;
    const secrets = JSON.stringify([...values, 'Q2']);
    await writeFile(path.join(directory, key ? 'user_defined_secrets.secret.json' : 'user_defined_secrets.json'),
      key ? encryptText(secrets, key, 'user-defined-secrets') : secrets);
    if (key) await writeFile(path.join(directory, 'master_key_secret'), key.toString('base64'));
    // Stop after logging, before any listeners bind, using invalid mapping state.
    await writeFile(path.join(directory, key ? 'redaction_mapping.secret.json' : 'redaction_mapping.json'),
      key ? encryptText('{}', key, 'redaction-mapping') : '{}');
    const config = path.join(directory, 'config.json');
    await writeFile(config, JSON.stringify({ mode: 'paranoic' }));
    await assert.rejects(exec(process.execPath, ['src/main.mjs'], { env: {
      ...process.env, ARP_DATA_DIR: directory, ARP_CONFIG_FILE: config,
      ARP_MASTER_KEY_FILE: path.join(directory, 'master_key_secret'),
    } }), (error) => {
      const warnings = error.stderr.split('\n').filter((line) => line.startsWith('{')).map((line) => JSON.parse(line));
      assert.deepEqual(warnings.map(({ entryIndex, length }) => [entryIndex, length]),
        [[1, 2], [2, 3], [3, 4], [5, 1], [6, 1], [7, 3], [8, 2]]);
      for (const warning of warnings) {
        assert.equal(warning.event, 'short-user-defined-secret');
        assert.equal(warning.level, 'warning');
        assert.equal('value' in warning, false);
        assert.equal('secret' in warning, false);
      }
      for (const value of ['Q2', 'z9x', 'r4t8', 'abcde', 'é', '🔒']) assert.equal(error.stderr.includes(value), false);
      assert.match(error.stderr, /Invalid mapping state/);
      return true;
    });
  });
}
