import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { MappingStore } from '../src/mapping-store.mjs';
import { deobfuscateSse, protocolForPath } from '../src/sse-transform.mjs';

async function mappedStore() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'opencode-ipv4-sse-'));
  const store = await MappingStore.open(path.join(directory, 'mappings.json'));
  await store.obfuscate('10.123.45.67');
  return store;
}

function encodeSse(values) {
  return `${values.map((value) => `data: ${JSON.stringify(value)}\n\n`).join('')}data: [DONE]\n\n`;
}

function decodeSse(text) {
  return text
    .split(/\r?\n\r?\n/)
    .map((block) => block.split(/\r?\n/).find((line) => line.startsWith('data:')))
    .filter((line) => line && line.slice(5).trim() !== '[DONE]')
    .map((line) => JSON.parse(line.slice(5).trim()));
}

test('reassembles split Chat Completions content and tool arguments', async () => {
  const input = encodeSse([
    {
      choices: [{
        index: 0,
        delta: {
          content: '192',
          tool_calls: [{ index: 0, function: { arguments: '{"host":"192' } }],
        },
      }],
    },
    {
      choices: [{
        index: 0,
        delta: {
          content: '.0.2',
          tool_calls: [{ index: 0, function: { arguments: '.0.2' } }],
        },
      }],
    },
    {
      choices: [{
        index: 0,
        delta: {
          content: '.1',
          tool_calls: [{ index: 0, function: { arguments: '.1"}' } }],
        },
      }],
    },
  ]);

  const transformed = await deobfuscateSse(input, 'chat-completions', await mappedStore());
  const events = decodeSse(transformed.body);
  const content = events.map((event) => event.choices[0].delta.content).join('');
  const argumentsText = events
    .map((event) => event.choices[0].delta.tool_calls[0].function.arguments)
    .join('');

  assert.equal(content, '10.123.45.67');
  assert.equal(argumentsText, '{"host":"10.123.45.67"}');
  assert.equal(events.length, 3);
  assert.equal(transformed.count, 2);
});

test('reassembles split OpenAI Responses deltas', async () => {
  const input = encodeSse([
    { type: 'response.output_text.delta', item_id: 'item_1', output_index: 0, content_index: 0, delta: '192' },
    { type: 'response.output_text.delta', item_id: 'item_1', output_index: 0, content_index: 0, delta: '.0.2' },
    { type: 'response.output_text.delta', item_id: 'item_1', output_index: 0, content_index: 0, delta: '.1' },
  ]);

  const transformed = await deobfuscateSse(input, 'responses', await mappedStore());
  const events = decodeSse(transformed.body);
  assert.equal(events.map((event) => event.delta).join(''), '10.123.45.67');
  assert.equal(events.length, 3);
  assert.equal(transformed.count, 1);
});

test('reassembles split Anthropic text deltas', async () => {
  const input = encodeSse([
    { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: '192' } },
    { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: '.0.2' } },
    { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: '.1' } },
  ]);

  const transformed = await deobfuscateSse(input, 'anthropic', await mappedStore());
  const events = decodeSse(transformed.body);
  assert.equal(events.map((event) => event.delta.text).join(''), '10.123.45.67');
  assert.equal(events.length, 3);
  assert.equal(transformed.count, 1);
});

test('reassembles split Gemini candidate text parts', async () => {
  const input = encodeSse([
    { candidates: [{ index: 0, content: { parts: [{ text: '192' }] } }] },
    { candidates: [{ index: 0, content: { parts: [{ text: '.0.2' }] } }] },
    { candidates: [{ index: 0, content: { parts: [{ text: '.1' }] } }] },
  ]);

  const transformed = await deobfuscateSse(input, 'gemini', await mappedStore());
  const events = decodeSse(transformed.body);
  const text = events.map((event) => event.candidates[0].content.parts[0].text).join('');
  assert.equal(text, '10.123.45.67');
  assert.equal(events.length, 3);
  assert.equal(transformed.count, 1);
});

test('keeps Gemini thought and visible text in separate channels', async () => {
  const input = encodeSse([
    { candidates: [{ index: 0, content: { parts: [{ text: '192', thought: true }] } }] },
    { candidates: [{ index: 0, content: { parts: [{ text: '192' }] } }] },
    { candidates: [{ index: 0, content: { parts: [{ text: '.0.2', thought: true }] } }] },
    { candidates: [{ index: 0, content: { parts: [{ text: '.0.2' }] } }] },
    { candidates: [{ index: 0, content: { parts: [{ text: '.1', thought: true }] } }] },
    { candidates: [{ index: 0, content: { parts: [{ text: '.1' }] } }] },
  ]);

  const transformed = await deobfuscateSse(input, 'gemini', await mappedStore());
  const events = decodeSse(transformed.body);
  const thought = events
    .filter((event) => event.candidates[0].content.parts[0].thought)
    .map((event) => event.candidates[0].content.parts[0].text)
    .join('');
  const visible = events
    .filter((event) => !event.candidates[0].content.parts[0].thought)
    .map((event) => event.candidates[0].content.parts[0].text)
    .join('');

  assert.equal(thought, '10.123.45.67');
  assert.equal(visible, '10.123.45.67');
});

test('keeps two interleaved Responses items separate by item_id', async () => {
  const store = await mappedStore(); // registers 10.123.45.67 -> 192.0.2.1
  const fake2 = (await store.obfuscate('172.16.0.9')).body; // registers -> 192.0.2.2

  const input = encodeSse([
    { type: 'response.function_call_arguments.delta', item_id: 'call_1', output_index: 0, delta: '192' },
    { type: 'response.function_call_arguments.delta', item_id: 'call_2', output_index: 1, delta: fake2.slice(0, 6) },
    { type: 'response.function_call_arguments.delta', item_id: 'call_1', output_index: 0, delta: '.0.2' },
    { type: 'response.function_call_arguments.delta', item_id: 'call_2', output_index: 1, delta: fake2.slice(6) },
    { type: 'response.function_call_arguments.delta', item_id: 'call_1', output_index: 0, delta: '.1' },
  ]);

  const transformed = await deobfuscateSse(input, 'responses', store);
  const events = decodeSse(transformed.body);
  const call1 = events.filter((event) => event.item_id === 'call_1').map((event) => event.delta).join('');
  const call2 = events.filter((event) => event.item_id === 'call_2').map((event) => event.delta).join('');

  assert.equal(call1, '10.123.45.67');
  assert.equal(call2, '172.16.0.9');
});

test('rejects restoration of unidentified deltas even when they look complete', async () => {
  const store = await mappedStore(); // registers 10.123.45.67 -> 192.0.2.1
  const fake2 = (await store.obfuscate('172.16.0.9')).body;

  const input = encodeSse([
    { type: 'response.function_call_arguments.delta', delta: `ping 192.0.2.1` },
    { type: 'response.function_call_arguments.delta', delta: `curl ${fake2}` },
  ]);

  await assert.rejects(deobfuscateSse(input, 'responses', store), /unidentified SSE delta/);
});

test('never leaks a fragment of one real address into an unrelated stream when both are missing item_id', async () => {
  // Pathological input: the IPv4 bytes are themselves split across events
  // and neither event carries an identifier, so the two fragmented streams
  // cannot be safely told apart. The transform must not guess -- it must
  // not let a byte of either address end up misattributed to the other
  // stream's output.
  const store = await mappedStore(); // registers 10.123.45.67 -> 192.0.2.1
  const fake2 = (await store.obfuscate('172.16.0.9')).body;

  const input = encodeSse([
    { type: 'response.function_call_arguments.delta', delta: `ping ${'192.0.2.1'.slice(0, 4)}` },
    { type: 'response.function_call_arguments.delta', delta: `curl ${fake2.slice(0, 4)}` },
    { type: 'response.function_call_arguments.delta', delta: '192.0.2.1'.slice(4) },
    { type: 'response.function_call_arguments.delta', delta: fake2.slice(4) },
  ]);

  await assert.rejects(deobfuscateSse(input, 'responses', store), /unidentified SSE delta/);
});

test('does not split Unicode surrogate pairs during redistribution', async () => {
  const input = encodeSse([
    { choices: [{ index: 0, delta: { content: '😀192' } }] },
    { choices: [{ index: 0, delta: { content: '.0.2' } }] },
    { choices: [{ index: 0, delta: { content: '.1' } }] },
  ]);

  const transformed = await deobfuscateSse(input, 'chat-completions', await mappedStore());
  const chunks = decodeSse(transformed.body).map((event) => event.choices[0].delta.content);
  assert.equal(chunks.join(''), '😀10.123.45.67');
  for (const chunk of chunks) {
    assert.equal(new TextDecoder('utf-8', { fatal: true }).decode(new TextEncoder().encode(chunk)), chunk);
  }
});

test('classifies prefixed and unprefixed inference routes identically', () => {
  for (const [route, protocol] of [
    ['/responses', 'responses'],
    ['/messages', 'anthropic'],
    ['/chat/completions', 'chat-completions'],
    ['/models/gemini:generateContent', 'gemini'],
    ['/models/gemini:streamGenerateContent', 'gemini'],
  ]) {
    assert.equal(protocolForPath(route), protocol);
    assert.equal(protocolForPath(`/v1${route}`), protocol);
    assert.equal(protocolForPath(`/v10${route}`), null);
  }
});

for (const suffix of ['0', '999']) {
  test(`does not restore a mapped prefix inside a longer streamed address (${suffix})`, async () => {
    const store = await mappedStore();
    const formats = [
      ['chat-completions', (text) => ({ choices: [{ index: 0, delta: { content: text } }] }),
        (event) => event.choices[0].delta.content],
      ['responses', (delta) => ({ type: 'response.output_text.delta', item_id: 'item_1', output_index: 0, content_index: 0, delta }),
        (event) => event.delta],
      ['anthropic', (text) => ({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } }),
        (event) => event.delta.text],
      ['gemini', (text) => ({ candidates: [{ index: 0, content: { parts: [{ text }] } }] }),
        (event) => event.candidates[0].content.parts[0].text],
    ];
    for (const [protocol, encode, decode] of formats) {
      const input = encodeSse(['192.0.2.1', suffix].map(encode));
      const transformed = await deobfuscateSse(input, protocol, store);
      assert.equal(decodeSse(transformed.body).map(decode).join(''), `192.0.2.1${suffix}`, protocol);
      assert.equal(transformed.count, 0, protocol);
    }
  });
}

test('preserves unmapped tool targets and restores complete non-streamed fields', async () => {
  const input = encodeSse([
    { type: 'response.function_call_arguments.delta', item_id: 'call_1', output_index: 0, delta: '{"host":"192.0.2.1' },
    { type: 'response.function_call_arguments.delta', item_id: 'call_1', output_index: 0, delta: '0"}' },
    { type: 'response.function_call_arguments.done', item_id: 'call_1', output_index: 0, arguments: '{"host":"192.0.2.10"}' },
    { type: 'response.completed', response: { output: [{ content: [{ text: 'Known host 192.0.2.1' }] }] } },
  ]);
  const transformed = await deobfuscateSse(input, 'responses', await mappedStore());
  const events = decodeSse(transformed.body);
  const args = events.slice(0, 2).map((event) => event.delta).join('');
  assert.equal(JSON.parse(args).host, '192.0.2.10');
  assert.equal(args, events[2].arguments);
  assert.equal(events[3].response.output[0].content[0].text, 'Known host 10.123.45.67');
  assert.equal(transformed.count, 1);
});

test('restores the full mapped address rather than its mapped prefix in a chunk', async () => {
  const store = await mappedStore();
  const addresses = Array.from({ length: 9 }, (_, index) => `172.16.0.${index + 1}`);
  await store.obfuscate(addresses.join(' '));
  const input = encodeSse([
    { choices: [{ index: 0, delta: { content: '192.0.2.1' } }] },
    { choices: [{ index: 0, delta: { content: '0' } }] },
  ]);
  const transformed = await deobfuscateSse(input, 'chat-completions', store);
  assert.equal(decodeSse(transformed.body).map((event) => event.choices[0].delta.content).join(''), '172.16.0.9');
  assert.equal(transformed.count, 1);
});
