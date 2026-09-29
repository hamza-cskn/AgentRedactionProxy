import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { loadConfig } from '../src/config.mjs';
import { createProxy } from '../src/proxy.mjs';
import { DEFAULT_REDACTION_LIMITS, resolveRedactionLimits } from '../src/redaction-limits.mjs';
import { redactSecrets } from '../src/secret-redaction.mjs';

const header = Buffer.from('{"alg":"HS256"}').toString('base64url');
const cases = [
  ['maxApiTokenChars', 64, (size) => `ghp_${'A'.repeat(size - 4)}`, '[REDACTED_API_KEY]'],
  ['maxJwtChars', 64, (size) => `${header}.e30.${'A'.repeat(size - header.length - 5)}`, '[REDACTED_JWT]'],
  ['maxJwtHeaderBytes', 64, (size) => `${Buffer.from(`{"alg":"HS256"}${' '.repeat(size - 15)}`).toString('base64url')}.e30.signature`, '[REDACTED_JWT]'],
  ['maxBase64Chars', 64, (size) => 'A'.repeat(size), null],
];

for (const [name, limit, make, marker] of cases) {
  test(`${name}: exact boundary, oversized, and raised limit`, () => {
    for (const size of [limit - 1, limit]) {
      assert.equal(redactSecrets(make(size), { [name]: limit }).body, marker ?? make(size));
    }
    for (const wrap of [(text) => text, (text) => JSON.stringify({ arguments: JSON.stringify({ content: text }) })]) {
      assert.throws(() => redactSecrets(wrap(make(limit + 1)), { [name]: limit }), {
        message: 'Redaction candidate exceeds configured limit',
      });
    }
    assert.equal(redactSecrets(make(limit + 1), { [name]: limit + 1 }).body, marker ?? make(limit + 1));
  });

  for (const mode of ['default', 'paranoic']) {
    test(`${mode}: ${name} fails closed across every HTTP byte split`, async () => {
      let forwarded = false;
      const logs = [];
      const proxy = createProxy({ mode, redactionLimits: { [name]: limit }, store: {
        obfuscate() { throw new Error('Oversized input reached mapping'); },
      }, logger: (line) => logs.push(line), fetchImpl: async () => {
        forwarded = true;
        return new Response('{}');
      } });
      const bytes = Buffer.from(JSON.stringify({ input: make(limit + 1) }));
      for (let cut = 0; cut <= bytes.length; cut += 1) {
        const request = Object.assign(Readable.from([bytes.subarray(0, cut), bytes.subarray(cut)]), {
          method: 'POST', url: '/v1/responses', headers: {},
        });
        const response = Object.assign(new EventEmitter(), {
          writableFinished: false, setHeader() {},
          writeHead(status) { this.statusCode = status; },
          end(body) { this.body = body; this.writableFinished = true; },
        });
        await proxy.listeners('request')[0](request, response);
        assert.equal(response.statusCode, 502);
        assert.equal(response.body.includes(make(limit + 1)), false);
      }
      assert.equal(forwarded, false);
      assert.equal(logs.join('').includes(make(limit + 1)), false);
    });
  }
}

test('base64 size guard covers standard and URL-safe alphabets, padding, data URLs and JSON escapes', () => {
  for (const blob of ['+/AB'.repeat(17), '-_AB'.repeat(17), `${'A'.repeat(63)}==`]) {
    for (const input of [blob, `data:image/png;base64,${blob}`, JSON.stringify({ data: blob })]) {
      assert.throws(() => redactSecrets(input, { maxBase64Chars: 64 }), /configured limit/);
    }
  }
  assert.throws(() => redactSecrets(`"${'\\u0041'.repeat(65)}"`, { maxBase64Chars: 64 }), /configured limit/);
  assert.equal(redactSecrets('A'.repeat(64), { maxBase64Chars: 64 }).count, 0);
});

test('default limits reject extreme candidates without decoding arbitrary blobs', () => {
  assert.throws(() => redactSecrets(`ghp_${'A'.repeat(5000)}`), /configured limit/);
  assert.throws(() => redactSecrets('A'.repeat(65537)), /configured limit/);
  assert.equal(redactSecrets(Buffer.from('10.20.30.40').toString('base64')).count, 0);
});

test('JWT/JWE and malformed-header candidates are bounded before validation', () => {
  const malformedHeader = Buffer.from(`{${'A'.repeat(64)}`).toString('base64url');
  assert.throws(() => redactSecrets(`${malformedHeader}.e30.signature`, { maxJwtHeaderBytes: 64 }), /configured limit/);
  const jwe = `${header}.key.iv.${'A'.repeat(80)}.tag`;
  assert.throws(() => redactSecrets(jwe, { maxJwtChars: jwe.length - 1 }), /configured limit/);
  assert.equal(redactSecrets(jwe, { maxJwtChars: jwe.length }).body, '[REDACTED_JWT]');
  const unicodeHeader = Buffer.from(JSON.stringify({ alg: 'HS256', note: '密碼' }));
  const jwt = `${unicodeHeader.toString('base64url')}.e30.signature`;
  assert.throws(() => redactSecrets(jwt, { maxJwtHeaderBytes: unicodeHeader.length - 1 }), /configured limit/);
  assert.equal(redactSecrets(jwt, { maxJwtHeaderBytes: unicodeHeader.length }).body, '[REDACTED_JWT]');
});

test('long dotted code paths are not JWT candidates without a JSON-object header', () => {
  const input = `root.${Array(4000).fill('field').join('.')}`;
  assert.deepEqual(redactSecrets(input), { body: input, count: 0 });
  assert.deepEqual(redactSecrets(JSON.stringify({ input })), { body: JSON.stringify({ input }), count: 0 });
});

test('leading JSON whitespace cannot bypass JWT header limits', () => {
  for (const spaces of [0, 1, 64, 4096]) {
    const bytes = Buffer.from(`${' '.repeat(spaces)}{"alg":"HS256"}`);
    const jwt = `${bytes.toString('base64url')}.e30.signature`;
    assert.throws(() => redactSecrets(jwt, { maxJwtHeaderBytes: bytes.length - 1 }), /configured limit/);
    assert.equal(redactSecrets(jwt, { maxJwtHeaderBytes: bytes.length }).body, '[REDACTED_JWT]');
  }
});

test('config merges partial overrides and rejects invalid limit settings', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'redaction-limits-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'config.json');
  await writeFile(file, JSON.stringify({ mode: 'default', redactionLimits: { maxJwtChars: 32000 } }));
  assert.deepEqual((await loadConfig(file)).redactionLimits, { ...DEFAULT_REDACTION_LIMITS, maxJwtChars: 32000 });
  for (const value of [0, -1, 1.5, '4096', null, 67108865]) {
    await writeFile(file, JSON.stringify({ mode: 'paranoic', redactionLimits: { maxApiTokenChars: value } }));
    await assert.rejects(loadConfig(file), /Redaction limits/);
  }
  for (const value of [null, [], 'bad', { maxTokenChars: 10 }]) {
    assert.throws(() => resolveRedactionLimits(value));
  }
});
