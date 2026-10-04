import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { MappingStore } from '../src/mapping-store.mjs';
import { loadConfig } from '../src/config.mjs';
import { createProxy } from '../src/proxy.mjs';
import { deobfuscateSse } from '../src/sse-transform.mjs';

const token = `ghp_${'Ab12'.repeat(9)}`;
const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJleGFtcGxlIn0.signature';
const pem = '-----BEGIN PRIVATE KEY-----\nQUJDREVGRw==\n-----END PRIVATE KEY-----';
const custom = ['private-service', 'private-service-production', 'line one\nline two', 'literal.*$value'];

async function fixture(t, values = custom) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'reversible-texts-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'mappings.json');
  return { file, directory, store: await MappingStore.open(file, { sensitiveTexts: values }) };
}

test('all secret types and literal texts round-trip with persistent distinct markers', async (t) => {
  const { file, store } = await fixture(t);
  const input = `${token}\n${jwt}\n${pem}\nhttp://alice:password@10.20.30.40/api\n${custom.join('\n')}\nPRIVATE-SERVICE`;
  const first = await store.obfuscateRequest(input, { mode: 'paranoic' });
  for (const value of [token, jwt, pem, 'password', '10.20.30.40', ...custom]) assert.equal(first.body.includes(value), false, value);
  for (const type of ['API_KEY', 'JWT', 'PRIVATE_KEY', 'PASSWORD', 'IP', 'TEXT']) assert.match(first.body, new RegExp(`\\[REDACTED_${type}_[a-f0-9]{32}\\]`));
  assert.equal(first.body.includes('PRIVATE-SERVICE'), true);
  assert.equal((await store.deobfuscate(first.body)).body, input);
  const reopened = await MappingStore.open(file, { sensitiveTexts: custom });
  assert.equal((await reopened.obfuscateRequest(input)).body, first.body);
  const withoutList = await MappingStore.open(file);
  assert.equal((await withoutList.deobfuscate(first.body)).body, input, 'removing the source list does not erase history restoration');
  assert.equal((await stat(file)).mode & 0o777, 0o600);
});

test('custom overlap, JSON escapes, and listed API-key/password values restore exactly', async (t) => {
  const { store } = await fixture(t, [...custom, token, 'password']);
  const content = `${custom[1]} ${custom[2]} ${custom[3]} ${token} http://alice:password@host`;
  const input = JSON.stringify({ arguments: JSON.stringify({ content, n: 42 }) });
  const masked = await store.obfuscateRequest(input);
  assert.equal(masked.body.includes('-production'), false, 'longest match wins');
  assert.equal((await store.deobfuscate(masked.body)).body, input);
  assert.equal((await store.obfuscateRequest(masked.body)).body, masked.body, 'markers must not be recursively masked');
});

test('oversized transformation rolls back both secret and IP mappings', async (t) => {
  const { file, store } = await fixture(t);
  await assert.rejects(store.obfuscateRequest(`${token} 10.20.30.40`, { maxBytes: 1 }), { code: 'TRANSFORMED_BODY_TOO_LARGE' });
  await assert.rejects(readFile(file), { code: 'ENOENT' });
  const masked = await store.obfuscateRequest(`${token} 10.20.30.40`);
  assert.equal((await store.deobfuscate(masked.body)).body, `${token} 10.20.30.40`);
});

test('whole phrases containing credentials and short literals preserve marker integrity', async (t) => {
  const phrase = `private phrase ${token} end`;
  const { store } = await fixture(t, [phrase, '[R', 'IP', 'REDACTED']);
  const input = `${phrase} [R IP REDACTED 10.20.30.40`;
  const masked = (await store.obfuscateRequest(input)).body;
  assert.equal(masked.includes('private phrase'), false);
  assert.equal((await store.deobfuscate(masked)).body, input);
  assert.equal((await store.obfuscateRequest(masked)).body, masked);
});

test('version-2 migration keeps existing IP markers and read-only status leaves state untouched', async (t) => {
  const { file } = await fixture(t);
  const fake = `[REDACTED_IP_${'a'.repeat(32)}]`;
  const original = JSON.stringify({ version: 2, nextIndex: 1, mappings: [{ real: '10.20.30.40', fake }] });
  await writeFile(file, original);
  const store = await MappingStore.open(file);
  await MappingStore.status(file);
  assert.equal(await readFile(file, 'utf8'), original);
  const masked = await store.obfuscateRequest(`10.20.30.40 ${token}`);
  assert.equal(masked.body.startsWith(fake), true);
  assert.equal(JSON.parse(await readFile(file, 'utf8')).version, 3);
  assert.equal((await store.deobfuscate(masked.body)).body, `10.20.30.40 ${token}`);
});

test('default mode blocks custom mapping failures and suppresses literal endpoint logs', async (t) => {
  const { store } = await fixture(t);
  store.obfuscateRequest = async () => { throw new Error('storage failure'); };
  const logs = [];
  let forwarded = false;
  const proxy = createProxy({ mode: 'default', store, protectAllPostBodies: true,
    logger: (line) => logs.push(line), fetchImpl: async () => { forwarded = true; return new Response('{}'); } });
  const request = Object.assign(Readable.from(['private-service']), {
    method: 'POST', url: '/v1/private%2Dservice', headers: {},
  });
  const response = Object.assign(new EventEmitter(), { setHeader() {},
    writeHead(status) { this.status = status; }, end() { this.writableFinished = true; } });
  await proxy.listeners('request')[0](request, response);
  assert.equal(response.status, 502);
  assert.equal(forwarded, false);
  assert.equal(logs.join('').includes('private'), false);
});

test('config loads a relative JSON text list and rejects bad files without echoing secrets', async (t) => {
  const { directory } = await fixture(t);
  const config = path.join(directory, 'config.json');
  const valuesFile = path.join(directory, 'sensitive-texts.json');
  await writeFile(config, JSON.stringify({ mode: 'default', sensitiveTextsFile: 'sensitive-texts.json' }));
  await writeFile(valuesFile, JSON.stringify(custom));
  assert.deepEqual((await loadConfig(config)).sensitiveTexts, custom);
  for (const invalid of [JSON.stringify([token, '']), JSON.stringify({ secret: token }), `${token} bad JSON`, JSON.stringify(['[REDACTED_TEXT_abc]'])]) {
    await writeFile(valuesFile, invalid);
    await assert.rejects(loadConfig(config), (error) => !error.message.includes(token));
  }
});

for (const mode of ['default', 'paranoic']) {
  test(`${mode}: proxy hides values upstream, restores the echo, and never logs them`, async (t) => {
    const { store } = await fixture(t);
    const content = `${token} private-service-production 10.20.30.40`;
    let captured;
    const logs = [];
    const proxy = createProxy({ mode, store, logger: (line) => logs.push(line), fetchImpl: async (_, { body }) => {
      captured = JSON.parse(body.toString());
      return new Response(JSON.stringify(captured));
    } });
    const request = Object.assign(Readable.from([Buffer.from(JSON.stringify({ content }))]), { method: 'POST', url: '/v1/responses', headers: {} });
    const response = Object.assign(new EventEmitter(), { writableFinished: false, setHeader() {}, writeHead(status) { this.status = status; }, end(body) { this.body = body; this.writableFinished = true; } });
    await proxy.listeners('request')[0](request, response);
    assert.equal(response.statusCode, 200);
    for (const value of [token, custom[1], '10.20.30.40']) {
      assert.equal(captured.content.includes(value), false);
      assert.equal(logs.join('').includes(value), false);
    }
    assert.equal(JSON.parse(response.body).content, content);
  });
}

for (const protocol of ['responses', 'chat-completions', 'anthropic', 'gemini']) {
test(`${protocol}: every SSE split restores secret and custom markers`, async (t) => {
  const { store } = await fixture(t);
  const input = JSON.stringify({ value: `${token} ${custom[1]}` });
  const masked = (await store.obfuscateRequest(input)).body;
  const encode = (text) => {
    if (protocol === 'responses') return { type: 'response.function_call_arguments.delta', item_id: 'call_1', delta: text };
    if (protocol === 'chat-completions') return { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: text } }] } }] };
    if (protocol === 'anthropic') return { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: text } };
    return { candidates: [{ index: 0, content: { parts: [{ text }] } }] };
  };
  const extract = (event) => event.delta?.partial_json ?? event.delta ?? event.choices?.[0].delta.tool_calls[0].function.arguments ?? event.candidates[0].content.parts[0].text;
  for (let cut = 0; cut <= masked.length; cut++) {
    const sse = [masked.slice(0, cut), masked.slice(cut)].map((text) => `data: ${JSON.stringify(encode(text))}\n\n`).join('');
    const output = await deobfuscateSse(sse, protocol, store);
    const text = output.body.trim().split('\n\n').map((block) => extract(JSON.parse(block.slice(6)))).join('');
    assert.equal(text, input, `split ${cut}`);
  }
});
}
