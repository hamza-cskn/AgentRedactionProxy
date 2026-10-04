import assert from 'node:assert/strict';
import { redactedText } from './helpers/mapping-fixtures.mjs';
import { EventEmitter } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { MappingStore } from '../src/mapping-store.mjs';
import { createProxy } from '../src/proxy.mjs';
import { redactSecrets } from '../src/secret-redaction.mjs';

// Deliberate conservative policies, not unresolved desired-behavior TODOs.
const cases = [
  { name: 'HF filename policy', input: 'hf_model_configuration_defaults.json', output: '[REDACTED_API_KEY].json', filename: true },
  { name: 'sk filename policy', input: 'sk-test-production-deployment.yaml', output: '[REDACTED_API_KEY].yaml', filename: true },
  // Conservative behavior explicitly left for policy decisions or out of scope.
  { name: 'PEM marker documentation', input: 'Use the marker -----BEGIN PRIVATE KEY----- to recognize PEM files.', error: 'Unsafe private key' },
  { name: 'PuTTY marker in code', input: 'const signature = "PuTTY-User-Key-File-3:";', error: 'Unsafe private key' },
  { name: 'long ordinary string hits base64 guard', input: 'A'.repeat(65537), error: 'Redaction candidate exceeds configured limit' },
];

for (const fixture of cases) {
  for (const [shape, wrap] of [
    ['plain', (text) => text],
    ['nested JSON', (text) => JSON.stringify({ arguments: JSON.stringify({ content: text }) })],
  ]) {
    test(`KNOWN LIMITATION (${shape}): ${fixture.name}`, () => {
      if (fixture.error) {
        assert.throws(() => redactSecrets(wrap(fixture.input)), { message: fixture.error });
      } else {
        assert.equal(redactSecrets(wrap(fixture.input)).body, wrap(fixture.output));
      }
    });
  }
}

for (const mode of ['default', 'paranoic']) {
  test(`${mode}: known false positives reproduce in initial and history requests`, async (context) => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'redaction-known-fp-'));
    context.after(() => rm(directory, { recursive: true, force: true }));
    const store = await MappingStore.open(path.join(directory, 'mappings.json'));
    let forwarded;
    const proxy = createProxy({ mode, store, logger: () => {}, fetchImpl: async (_url, init) => {
      forwarded = JSON.parse(init.body.toString());
      return new Response('{}');
    } });
    for (const fixture of cases) {
      for (const history of [false, true]) {
        const messages = [{ role: 'user', content: `${fixture.input}\n10.20.30.40` }];
        if (history) messages.push({ role: 'assistant', content: 'OK' }, { role: 'user', content: 'Continue' });
        const request = Object.assign(Readable.from([Buffer.from(JSON.stringify({ messages }))]), {
          method: 'POST', url: '/v1/responses', headers: {},
        });
        const response = Object.assign(new EventEmitter(), {
          writableFinished: false, setHeader() {},
          writeHead(status) { this.statusCode = status; },
          end(body) { this.body = body; this.writableFinished = true; },
        });
        forwarded = undefined;
        await proxy.listeners('request')[0](request, response);
        const label = `${fixture.name}, history=${history}`;
        assert.equal(response.statusCode, fixture.error ? 502 : 200, label);
        if (fixture.error) {
          assert.equal(forwarded, undefined, label);
          assert.equal(response.body.includes(fixture.input), false, label);
        } else {
          const expected = fixture.filename && mode === 'default' ? fixture.input : fixture.output;
          assert.equal(redactedText(store, forwarded.messages[0].content), `${expected}\n${store.realToFake.get('10.20.30.40')}`, label);
        }
      }
    }
  });
}

test('literal documentation IPs do not collide with fresh markers', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'redaction-documentation-collision-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const store = await MappingStore.open(path.join(directory, 'mappings.json'));
  assert.match((await store.obfuscate('10.20.30.40')).body, /^\[REDACTED_IP_[a-f0-9]{32}\]$/);
  for (const text of ['Use 192.0.2.1 as a documentation example.', JSON.stringify({ arguments: '{"host":"192.0.2.1"}' })]) {
    assert.deepEqual(await store.obfuscate(text), { body: text, count: 0 });
    assert.equal((await store.deobfuscate(text)).body, text);
  }
});
