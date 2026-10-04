import assert from 'node:assert/strict';
import { legacyStore, mappedText, redactedText } from './helpers/mapping-fixtures.mjs';
import { EventEmitter } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';

import { MappingStore } from '../src/mapping-store.mjs';
import { createProxy } from '../src/proxy.mjs';
import { deobfuscateSse } from '../src/sse-transform.mjs';

async function storeFor(context, legacyAddresses) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'redaction-split-test-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'mappings.json');
  return legacyAddresses ? legacyStore(file, legacyAddresses) : MappingStore.open(file);
}

// Invoke the real handler with explicit Buffer chunks. This avoids the OS
// coalescing writes and accidentally turning a split test into one large read.
async function deliver(proxy, chunks, endpoint = '/v1/responses') {
  const request = Readable.from(chunks);
  Object.assign(request, { method: 'POST', url: endpoint, headers: {} });
  const response = Object.assign(new EventEmitter(), {
    headers: {},
    writableFinished: false,
    setHeader(name, value) { this.headers[name] = value; },
    writeHead(status, headers) { this.statusCode = status; Object.assign(this.headers, headers); },
    end(body) { this.body = Buffer.from(body); this.writableFinished = true; },
  });
  await proxy.listeners('request')[0](request, response);
  return response;
}

const token = 'ghp_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78';
const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJleGFtcGxlIn0.abcdefghijklmnopqrstuvwx';
const textCases = [
  ['API token', `😀 ${token}`, '😀 [REDACTED_API_KEY]'],
  ['IPv4', '😀 10.20.30.40', '😀 192.0.2.1'],
  ['AWS hostname', 'ip-10-20-30-40.ec2.internal', 'ip-192-0-2-1.ec2.internal'],
  ['URL password', 'mongo://alice:密碼@10.20.30.40/app', 'mongo://alice:REDACTED_PASSWORD@192.0.2.1/app'],
  ['JWT', jwt, '[REDACTED_JWT]'],
  ['private key', '-----BEGIN PRIVATE KEY-----\nQUJDREVGRw==\n-----END PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]'],
];

for (const mode of ['paranoic', 'default']) {
  for (const [name, input, expected] of textCases) {
    test(`${mode}: ${name} survives no HTTP byte split unredacted`, async (context) => {
      const store = await storeFor(context);
      let captured;
      const proxy = createProxy({
        mode, store, logger: () => {},
        fetchImpl: async (_url, { body }) => {
          captured = body.toString('utf8');
          return new Response('{}');
        },
      });
      const bytes = Buffer.from(JSON.stringify({ input }));
      const wanted = JSON.stringify({ input: expected });
      for (let cut = 0; cut <= bytes.length; cut += 1) {
        captured = undefined;
        const response = await deliver(proxy, [bytes.subarray(0, cut), bytes.subarray(cut)]);
        assert.equal(response.statusCode, 200, `byte split ${cut}`);
        assert.equal(redactedText(store, captured), mappedText(store, wanted), `byte split ${cut}`);
      }
      captured = undefined;
      const response = await deliver(proxy, [...bytes].map((byte) => Buffer.from([byte])));
      assert.equal(response.statusCode, 200);
      assert.equal(redactedText(store, captured), mappedText(store, wanted), 'one byte per chunk, including inside UTF-8 sequences');
    });
  }
}

const formats = [
  ['responses', (delta) => ({ type: 'response.output_text.delta', item_id: 'message_1', output_index: 0, content_index: 0, delta }), (event) => event.delta],
  ['anthropic', (text) => ({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } }), (event) => event.delta.text],
  ['chat-completions', (content) => ({ choices: [{ index: 0, delta: { content } }] }), (event) => event.choices[0].delta.content],
  ['gemini', (text) => ({ candidates: [{ index: 0, content: { parts: [{ text }] } }] }), (event) => event.candidates[0].content.parts[0].text],
];

const encodeSse = (events) => events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join('');
const decodeSse = (text) => text.trim().split('\n\n').map((block) => JSON.parse(block.slice(6)));

for (const [protocol, encode, decode] of formats) {
  test(`${protocol}: every SSE split restores complete IPs without matching their prefixes`, async (context) => {
    const store = await storeFor(context, Array.from({ length: 10 }, (_, i) => `10.20.30.${40 + i}`));
    const input = '😀192.0.2.1 / 192.0.2.10 / 192.0.2.1999 / ip-192-0-2-1.ec2.internal';
    const expected = '😀10.20.30.40 / 10.20.30.49 / 192.0.2.1999 / ip-10-20-30-40.ec2.internal';
    for (let cut = 0; cut <= input.length; cut += 1) {
      const events = [input.slice(0, cut), input.slice(cut)].map(encode);
      const output = await deobfuscateSse(encodeSse(events), protocol, store);
      assert.equal(decodeSse(output.body).map(decode).join(''), expected, `SSE split ${cut}`);
      assert.equal(output.count, 3, `SSE split ${cut}`);
    }
    const output = await deobfuscateSse(encodeSse(input.split('').map(encode)), protocol, store);
    assert.equal(decodeSse(output.body).map(decode).join(''), expected, 'one UTF-16 code unit per event');
  });
}

test('every upstream HTTP byte split preserves SSE parsing and restoration', async (context) => {
  const store = await storeFor(context);
  const marker = (await store.obfuscate('10.20.30.40')).body;
  const [, encode, decode] = formats[0];
  const bytes = Buffer.from(encodeSse([`😀${marker.slice(0, 17)}`, marker.slice(17)].map(encode)));
  for (let cut = 0; cut <= bytes.length; cut += 1) {
    const proxy = createProxy({
      mode: 'paranoic', store, logger: () => {},
      fetchImpl: async () => new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(bytes.subarray(0, cut));
          controller.enqueue(bytes.subarray(cut));
          controller.close();
        },
      }), { headers: { 'content-type': 'text/event-stream' } }),
    });
    const response = await deliver(proxy, [Buffer.from('{}')]);
    assert.equal(response.statusCode, 200, `upstream byte split ${cut}`);
    assert.equal(response.headers['x-ipv4-proxy-warning'], undefined);
    assert.equal(decodeSse(response.body.toString('utf8')).map(decode).join(''), '😀10.20.30.40', `upstream byte split ${cut}`);
  }
});

// SSE clients concatenate these fragments into one field. Restoring a prefix
// independently must not change the resulting address.
for (const [name, endpoint, events, extract] of [
  ['tool arguments missing item_id', '/v1/responses', [
    { type: 'response.function_call_arguments.delta', output_index: 0, delta: '{"host":"192.0.2.1' },
    { type: 'response.function_call_arguments.delta', output_index: 0, delta: '0"}' },
  ], (items) => JSON.parse(items.map((item) => item.delta).join('')).host],
  ['initial Anthropic text followed by a delta', '/v1/messages', [
    { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '192.0.2.1' } },
    { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: '0' } },
  ], (items) => items.map((item) => item.content_block?.text ?? item.delta.text).join('')],
]) {
  test(`SSE must not restore an address prefix across ${name}`, async (context) => {
    const store = await storeFor(context, ['10.20.30.4']);
    const proxy = createProxy({
      mode: 'paranoic', store, logger: () => {},
      fetchImpl: async () => new Response(encodeSse(events), {
        headers: { 'content-type': 'text/event-stream' },
      }),
    });
    const response = await deliver(proxy, [Buffer.from('{}')], endpoint);
    assert.equal(response.statusCode, 200);
    assert.equal(extract(decodeSse(response.body.toString('utf8'))), '192.0.2.10', 'unmapped full address must not become the real prefix plus a suffix');
    if (endpoint === '/v1/responses') {
      assert.equal(response.body.toString('utf8'), encodeSse(events));
      assert.equal(response.headers['x-ipv4-proxy-warning'], 'inbound-deobfuscation-failed-fake-response-returned');
    } else {
      assert.equal(response.headers['x-ipv4-proxy-warning'], undefined);
    }
  });
}

for (const field of ['text', 'thinking']) {
  test(`Anthropic initial ${field} and interleaved deltas restore only complete addresses`, async (context) => {
    const store = await storeFor(context, Array.from({ length: 10 }, (_, i) => `10.20.30.${40 + i}`));
    const input = '192.0.2.10';
    for (let cut = 0; cut <= input.length; cut += 1) {
      const events = [
        { type: 'content_block_start', index: 0, content_block: { type: field, [field]: input.slice(0, cut) } },
        { type: 'content_block_start', index: 1, content_block: { type: field, [field]: '192.0.2.1' } },
        { type: 'content_block_delta', index: 0, delta: { type: `${field}_delta`, [field]: input.slice(cut) } },
        { type: 'content_block_delta', index: 1, delta: { type: `${field}_delta`, [field]: '999' } },
      ];
      const result = await deobfuscateSse(encodeSse(events), 'anthropic', store);
      const restored = decodeSse(result.body);
      const content = (index) => restored.filter((event) => event.index === index)
        .map((event) => (event.content_block ?? event.delta)[field]).join('');
      assert.equal(content(0), '10.20.30.49', `split ${cut}`);
      assert.equal(content(1), '192.0.2.1999', `split ${cut}`);
      assert.equal(result.count, 1);
    }
  });
}
