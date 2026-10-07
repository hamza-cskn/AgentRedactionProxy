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

const schemes = [
  'http', 'https', 'ws', 'wss', 'mongodb', 'mongodb+srv', 'postgres', 'postgresql',
  'mysql', 'mariadb', 'redis', 'rediss', 'amqp', 'amqps', 'ssh', 'sftp', 'ftp', 'ftps',
  'sqlserver', 'jdbc:sqlserver', 'jdbc:postgresql', 'custom+db.v2',
];
const preserved = [
  'http://grafana.example:80${2}',
  'HTTPS://grafana.example:443${path}',
  'ws://localhost:8080$2',
  'wss://localhost:443${2}${3}/socket',
  '[Grafana](http://grafana.example:80${2})',
  'mongodb://db1:${PORT1},db2:${PORT2}/app',
  'mongodb://[::1]:${PORT},[::2]:27017/app',
  'mongodb+srv://cluster.example/app',
  'postgresql://db1:$PORT,db2:$OTHER/app',
  'postgres://db1:5432,db2:${PORT}/app',
  'jdbc:postgresql://db1:${PORT},db2:5432/app',
  'jdbc:sqlserver://db.example:${PORT};databaseName=app;encrypt=true',
  'sqlserver://db.example:$PORT;databaseName=app;',
];
const template = '{{ define "monitoring.link" }}{{ reReplaceAll "^https?://(localhost|127[.]0[.]0[.]1):3000(/|$)" "http://grafana.seyirmobil.com:80${2}" . }}{{ end }}';

for (const mode of ['default', 'paranoic']) {
  test(`${mode}: common scheme syntax and the Grafana replacement remain intact`, () => {
    for (const input of [...preserved, template]) {
      for (const text of [input, JSON.stringify({ arguments: JSON.stringify({ content: input }) })]) {
        assert.deepEqual(redactSecrets(text, undefined, mode), { body: text, count: 0 }, input);
      }
    }
  });

  test(`${mode}: credentials take precedence over scheme-specific port notation`, () => {
    for (const scheme of schemes) {
      for (const password of ['secret', '80secret', '80${2}', '80$2', '443${path}', '${PORT},db2:27017', '$PORT;encrypt=true']) {
        for (const space of ['', ' ', '\t']) {
          const input = `${scheme}://alice:${password}${space}@host.example/path`;
          const expected = `${scheme}://alice:REDACTED_PASSWORD${space}@host.example/path`;
          assert.deepEqual(redactSecrets(input, undefined, mode), { body: expected, count: 1 }, input);
        }
      }
    }
    for (const scheme of ['redis', 'rediss', 'amqp', 'amqps']) {
      const input = `${scheme}://:secret@host.example/0`;
      assert.equal(redactSecrets(input, undefined, mode).body, `${scheme}://:REDACTED_PASSWORD@host.example/0`);
    }
  });

  test(`${mode}: scheme spelling mistakes never disable credential protection`, () => {
    const spellings = new Set(['mongdb', 'htps', 'redsi', 'postgress']);
    for (const scheme of schemes.filter((name) => !name.includes(':'))) {
      for (let index = 0; index < scheme.length; index += 1) {
        spellings.add(scheme.slice(0, index) + scheme.slice(index + 1));
        spellings.add(scheme.slice(0, index) + 'x' + scheme.slice(index));
        spellings.add(scheme.slice(0, index) + 'x' + scheme.slice(index + 1));
        if (index + 1 < scheme.length) {
          spellings.add(scheme.slice(0, index) + scheme[index + 1] + scheme[index] + scheme.slice(index + 2));
        }
      }
    }
    for (const scheme of spellings) {
      const input = `${scheme.toUpperCase()} : / / alice : 80secret @ host.example/path`;
      assert.equal(redactSecrets(input, undefined, mode).body,
        input.replace('80secret', 'REDACTED_PASSWORD'), input);
    }
  });

  test(`${mode}: malformed delimiters and ambiguous new port forms fail closed`, () => {
    const unsafe = [
      'http://alice:80${2}secret',
      'http://alice:80${2} word@host',
      'http://alice:80${2}/secret@host',
      'http://alice:80${2}?secret@host',
      'http://alice:80${2}#secret@host',
      'http://alice:80${2}%40host',
      'http://alice:80${2}@host@other',
      'mongodb://alice:${PORT},db2:${PORT2} word@host',
      'mongodb://alice:${PORT},db2:${PORT2}/secret@host',
      'sqlserver://alice:${PORT};encrypt=true word@host',
      'sqlserver://alice:${PORT};encrypt=true/secret@host',
      'htps://host:80${2}',
    ];
    for (const scheme of ['http', 'https', 'mongodb', 'mongdb', 'redis', 'custom+db.v2']) {
      for (const separator of [':/', ':///', ':://', '//']) {
        unsafe.push(`${scheme}${separator}alice:80secret@host`);
      }
    }
    for (const input of unsafe) {
      assert.throws(() => redactSecrets(input, undefined, mode), /Unsafe credential URL/, input);
      const nested = JSON.stringify({ arguments: JSON.stringify({ content: input }) });
      assert.throws(() => redactSecrets(nested, undefined, mode), /Unsafe credential URL/, input);
    }
  });

  test(`${mode}: the affected template can be sent again as history while credentials stay protected`, async (context) => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'url-schemes-'));
    context.after(() => rm(directory, { recursive: true, force: true }));
    const store = await MappingStore.open(path.join(directory, 'mappings.json'));
    const captured = [];
    const logs = [];
    const proxy = createProxy({
      mode, store, logger: (line) => logs.push(line),
      fetchImpl: async (_url, { body }) => {
        captured.push(JSON.parse(body.toString()));
        return new Response('{}');
      },
    });
    for (const history of [false, true]) {
      const messages = [{ role: 'user', content: `${template}\n10.20.30.40\nmongdb://alice:80secret@db.example/app` }];
      if (history) messages.push({ role: 'assistant', content: 'OK' }, { role: 'user', content: 'Continue' });
      const request = Object.assign(Readable.from([Buffer.from(JSON.stringify({ messages }))]), {
        method: 'POST', url: '/v1/responses', headers: {},
      });
      const response = Object.assign(new EventEmitter(), {
        writableFinished: false, setHeader() {},
        writeHead(status) { this.statusCode = status; },
        end() { this.writableFinished = true; },
      });
      await proxy.listeners('request')[0](request, response);
      assert.equal(response.statusCode, 200);
    }
    assert.equal(captured.length, 2);
    assert.equal(captured[0].messages[0].content, captured[1].messages[0].content);
    for (const { messages } of captured) {
      assert.ok(messages[0].content.includes(template));
      assert.ok(!messages[0].content.includes('80secret'));
      assert.ok(!messages[0].content.includes('10.20.30.40'));
      assert.match(messages[0].content, /\[REDACTED_PASSWORD_[a-f0-9]{32}\]/);
      assert.match(messages[0].content, /\[REDACTED_IP_[a-f0-9]{32}\]/);
    }
    assert.ok(!logs.join('').includes('80secret'));
  });
}
