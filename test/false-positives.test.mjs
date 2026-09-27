import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';

import { MappingStore } from '../src/mapping-store.mjs';
import { createProxy } from '../src/proxy.mjs';
import { redactSecrets } from '../src/secret-redaction.mjs';

const benign = [
  '[local](http://localhost:3000)',
  'Visit http://localhost:3000.',
  'Visit http://localhost:3000!',
  '[local](http://localhost:3000!)',
  'https://example.com:8080, then run tests.',
  'const url = `http://${host}:${port}`;',
  'http://localhost:${PORT:-3000}/api',
  'http://localhost:%s/api',
  'http://host:port/path',
  'http://localhost:PORT',
  'http://[::1]:$PORT/api',
  'http://example.com is the endpoint: use GET.',
  'http://example.com https://other.example:8080',
  'let token;token=lexer.next();return token;',
  'const host = config.host; const token = lexer.next(); return token;',
  'Edit pypi-package-release-automation.yaml',
  'Edit npm_package_configuration_defaults.json',
  'auto &token=lexer.current();',
  'ready?token=next():token=null;',
  'host=config.host; token=lexer.next();',
  'Read https://host/?token=secret and then explain the output.',
  'host=db.example password="secret words',
  "Server=db;Pwd='secret",
];
const npmToken = `npm_${'aB12'.repeat(9)}`;
const pypiToken = `pypi-${'aB12_-'.repeat(15)}`;
const protectedTexts = [
  ['http://alice:port@host/path', 'http://alice:REDACTED_PASSWORD@host/path'],
  ['http://alice:PORT@host/path', 'http://alice:REDACTED_PASSWORD@host/path'],
  ['http://alice:${PORT:-3000}@host/path', 'http://alice:REDACTED_PASSWORD@host/path'],
  ['[link](http://alice:3000.)@host/path)', '[link](http://alice:REDACTED_PASSWORD@host/path)'],
  ['http://alice:3000`@host/path', 'http://alice:REDACTED_PASSWORD@host/path'],
  ['http://alice:3000!@host/path', 'http://alice:REDACTED_PASSWORD@host/path'],
  ['http://alice:3000! @host/path', 'http://alice:REDACTED_PASSWORD @host/path'],
  ['http://alice:3000!)@host/path', 'http://alice:REDACTED_PASSWORD@host/path'],
  ['host=db.example password=secret', 'host=db.example password=secret'],
  ['host=db.example password="two secret words"', 'host=db.example password="two secret words"'],
  ['host=db.example password=two secret words', 'host=db.example password=two secret words'],
  ['password=secret host=db.example', 'password=secret host=db.example'],
  ['const dsn = "host=db.example password=secret";', 'const dsn = "host=db.example password=secret";'],
  ['Server=db.example;Pwd=secret;', 'Server=db.example;Pwd=secret;'],
  ['jdbc:sqlserver://db.example;password=secret;', 'jdbc:sqlserver://db.example;password=secret;'],
  ['jdbc:sqlserver : / / db.example;password=secret;', 'jdbc:sqlserver : / / db.example;password=secret;'],
  ['https://host/?token=secret&mode=read', 'https://host/?token=secret&mode=read'],
  ['aws_secret_access_key=secret', 'aws_secret_access_key=secret'],
  [`./${npmToken}.txt`, './[REDACTED_API_KEY].txt'],
  [`./${pypiToken}.txt`, './[REDACTED_API_KEY].txt'],
  [`${npmToken}_old`, '[REDACTED_API_KEY]'],
  [`MY_${npmToken}`, 'MY_[REDACTED_API_KEY]'],
  [`pypi-${'a'.repeat(85)}`, '[REDACTED_API_KEY]'],
];

// Field names never determine sensitivity. A recognizable value is protected
// under any name; an opaque value is not classified by its surrounding label.
for (const name of ['password', 'token', 'secret', 'api_key', 'access_token', 'aws_secret_access_key', 'aws_session_token', 'ordinary']) {
  const token = `ghp_${'Ab12'.repeat(9)}`;
  for (const wrap of [
    (value) => `https://host/?${name}=${value}&mode=read`,
    (value) => `host=db.example;${name}=${value};`,
    (value) => `${name}=${value}`,
    (value) => `${name}: ${value}`,
    (value) => JSON.stringify({ [name]: value }),
  ]) {
    benign.push(wrap('opaqueValue123'));
    protectedTexts.push([wrap(token), wrap('[REDACTED_API_KEY]')]);
  }
}

for (const input of [
  'http://alice:3000.) word@host/path',
  'http://alice:3000! word@host/path',
  'http://alice:PORT word@host/path',
  'http://alice:secret/word@host/path',
  'http://alice smith:secret@host/path',
  'http://alice smith:secret/word@host/path',
  'http://alice smith:secret?word@host/path',
  'http://alice:secret',
]) {
  test(`false-positive fixes still reject malformed credentials: ${input}`, () => {
    assert.throws(() => redactSecrets(input), /Unsafe credential URL/);
  });
}

for (const [input, expected] of [...benign.map((text) => [text, text]), ...protectedTexts]) {
  test(`literal false-positive boundary: ${input}`, () => {
    assert.equal(redactSecrets(input).body, expected);
    const nested = JSON.stringify({ arguments: JSON.stringify({ content: input }) });
    assert.equal(JSON.parse(JSON.parse(redactSecrets(nested).body).arguments).content, expected);
  });
}

for (const mode of ['default', 'paranoic']) {
  test(`${mode}: false-positive fixes preserve initial and history requests without exposing credentials or IPs`, async (context) => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'redaction-false-positives-'));
    context.after(() => rm(directory, { recursive: true, force: true }));
    const store = await MappingStore.open(path.join(directory, 'mappings.json'));
    let forwarded;
    const proxy = createProxy({ mode, store, logger: () => {}, fetchImpl: async (_url, init) => {
      forwarded = JSON.parse(init.body.toString());
      return new Response('{}');
    } });
    for (const [input, expected] of [...benign.map((text) => [text, text]), ...protectedTexts]) {
      for (const history of [false, true]) {
        const messages = [{ role: 'user', content: `${input}\n10.20.30.40` }];
        if (history) messages.push({ role: 'assistant', content: 'OK' }, { role: 'user', content: 'Continue' });
        const request = Object.assign(Readable.from([Buffer.from(JSON.stringify({ messages }))]), {
          method: 'POST', url: '/v1/responses', headers: {},
        });
        const response = Object.assign(new EventEmitter(), {
          writableFinished: false,
          setHeader() {},
          writeHead(status) { this.statusCode = status; },
          end() { this.writableFinished = true; },
        });
        forwarded = undefined;
        await proxy.listeners('request')[0](request, response);
        assert.equal(response.statusCode, 200, `${input}, history=${history}`);
        assert.equal(forwarded.messages[0].content, `${expected}\n192.0.2.1`, input);
      }
    }
  });
}
