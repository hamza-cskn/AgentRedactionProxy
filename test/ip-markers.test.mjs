import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { MappingStore } from '../src/mapping-store.mjs';
import { deobfuscateSse } from '../src/sse-transform.mjs';

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ip-markers-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return path.join(directory, 'mappings.json');
}

test('markers are persistent, exact and do not restore documentation addresses', async (t) => {
  const file = await fixture(t);
  const store = await MappingStore.open(file);
  const marker = (await store.obfuscate('10.20.30.40')).body;
  assert.match(marker, /^\[REDACTED_IP_[a-f0-9]{32}\]$/);
  const reopened = await MappingStore.open(file);
  assert.equal((await reopened.obfuscate('10.20.30.40')).body, marker);
  assert.equal((await reopened.deobfuscate(marker)).body, '10.20.30.40');
  const literals = `192.0.2.1 198.51.100.1 203.0.113.1 ${marker.slice(0, -1)} ${marker.replace('IP_', 'IP_x')} [REDACTED_IP_${'0'.repeat(32)}]`;
  assert.equal((await reopened.deobfuscate(literals)).body, literals);
  const text = '10.20.30.40 ip-10-20-30-40.ec2.internal';
  assert.equal((await reopened.obfuscate(text)).body, `${marker} ip-${marker}.ec2.internal`);
  assert.equal((await reopened.deobfuscate(`${marker} ip-${marker}.ec2.internal`)).body, text);
  const args = JSON.stringify({ arguments: JSON.stringify({ host: marker, example: '192.0.2.1' }) });
  assert.equal(JSON.parse(JSON.parse((await reopened.deobfuscate(args)).body).arguments).host, '10.20.30.40');
});

test('legacy migration preserves old aliases but sends markers for all real IPs', async (t) => {
  const file = await fixture(t);
  const legacy = { version: 1, nextIndex: 1, mappings: [{ real: '10.20.30.40', fake: '192.0.2.1' }] };
  await writeFile(file, JSON.stringify(legacy));
  await MappingStore.status(file);
  assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), legacy, 'status is read-only');
  const store = await MappingStore.open(file);
  assert.equal((await store.deobfuscate('192.0.2.1')).body, '10.20.30.40');
  const marker = (await store.obfuscate('10.20.30.40')).body;
  assert.match(marker, /^\[REDACTED_IP_[a-f0-9]{32}\]$/);
  const state = JSON.parse(await readFile(file, 'utf8'));
  assert.equal(state.version, 2);
  assert.equal(state.mappings[0].legacyFake, '192.0.2.1');
  const reopened = await MappingStore.open(file);
  assert.equal((await reopened.deobfuscate(`192.0.2.1 ${marker}`)).body, '10.20.30.40 10.20.30.40');
  assert.equal((await reopened.obfuscate('10.20.30.40')).body, marker);
});

test('oversized migration rolls back without changing the legacy file', async (t) => {
  const file = await fixture(t);
  const original = JSON.stringify({ version: 1, nextIndex: 1, mappings: [{ real: '10.20.30.40', fake: '192.0.2.1' }] });
  await writeFile(file, original);
  const store = await MappingStore.open(file);
  await assert.rejects(store.obfuscate('10.20.30.40', { maxBytes: 1 }), { code: 'TRANSFORMED_BODY_TOO_LARGE' });
  assert.equal(await readFile(file, 'utf8'), original);
  assert.equal(store.state.version, 1);
  assert.equal((await store.deobfuscate('192.0.2.1')).body, '10.20.30.40');
  assert.match((await store.obfuscate('10.20.30.40')).body, /^\[REDACTED_IP_[a-f0-9]{32}\]$/);
});

test('concurrent legacy migrations persist the same marker', async (t) => {
  const file = await fixture(t);
  await writeFile(file, JSON.stringify({ version: 1, nextIndex: 1, mappings: [{ real: '10.20.30.40', fake: '192.0.2.1' }] }));
  const first = await MappingStore.open(file);
  const second = await MappingStore.open(file);
  const results = await Promise.all([first.obfuscate('10.20.30.40'), second.obfuscate('10.20.30.40')]);
  assert.equal(results[0].body, results[1].body);
  const reopened = await MappingStore.open(file);
  assert.equal((await reopened.obfuscate('10.20.30.40')).body, results[0].body);
  assert.equal((await reopened.deobfuscate('192.0.2.1')).body, '10.20.30.40');
});

test('corrupt marker states fail closed', async (t) => {
  const file = await fixture(t);
  for (const mapping of [
    { real: '10.20.30.40', fake: '192.0.2.1' },
    { real: '10.20.30.40', fake: '[REDACTED_IP_short]' },
    { real: '10.20.30.40', fake: `[REDACTED_IP_${'a'.repeat(32)}]`, legacyFake: '192.0.2.2' },
    { real: '192.0.2.1', fake: `[REDACTED_IP_${'a'.repeat(32)}]` },
  ]) {
    await writeFile(file, JSON.stringify({ version: 2, nextIndex: 1, mappings: [mapping] }));
    await assert.rejects(MappingStore.open(file), /Invalid mapping state/);
  }
});

for (const protocol of ['responses', 'chat-completions', 'anthropic', 'gemini']) {
  test(`${protocol}: every marker split restores tool/text channels exactly`, async (t) => {
    const store = await MappingStore.open(await fixture(t));
    const marker = (await store.obfuscate('10.20.30.40')).body;
    const encode = (text) => {
      if (protocol === 'responses') return { type: 'response.function_call_arguments.delta', item_id: 'call_1', delta: text };
      if (protocol === 'chat-completions') return { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: text } }] } }] };
      if (protocol === 'anthropic') return { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: text } };
      return { candidates: [{ index: 0, content: { parts: [{ text }] } }] };
    };
    const extract = (event) => event.delta?.partial_json ?? event.delta ?? event.choices?.[0].delta.tool_calls[0].function.arguments ?? event.candidates[0].content.parts[0].text;
    const input = JSON.stringify({ host: marker, example: '192.0.2.1' });
    for (let cut = 0; cut <= input.length; cut++) {
      const sse = [input.slice(0, cut), input.slice(cut)].map((text) => `data: ${JSON.stringify(encode(text))}\n\n`).join('');
      const output = await deobfuscateSse(sse, protocol, store);
      const restored = output.body.trim().split('\n\n').map((block) => extract(JSON.parse(block.slice(6)))).join('');
      assert.equal(restored, JSON.stringify({ host: '10.20.30.40', example: '192.0.2.1' }), `split ${cut}`);
    }
  });
}
