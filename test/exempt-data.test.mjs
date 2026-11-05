import assert from 'node:assert/strict';
import test from 'node:test';
import { MODES, assertNoLeak, entropy, proxyHarness } from './helpers/harness.mjs';

// A user-defined sensitive text that happens to occur inside opaque base64.
const CUSTOM = entropy(16, 7);
const DATA = `iVBORw0KGgo${CUSTOM}AAAA`;
const NOTE = `note ${CUSTOM}`;

// [shape, path, body, pick the exempt string, pick the neighbouring text]
const SHAPES = [
  ['Responses input_image', '/v1/responses',
    { input: [{ role: 'user', content: [
      { type: 'input_image', image_url: `data:image/png;base64,${DATA}` },
      { type: 'input_text', text: NOTE },
    ] }] },
    (body) => body.input[0].content[0].image_url, (body) => body.input[0].content[1].text,
    `data:image/png;base64,${DATA}`],
  ['Messages image', '/v1/messages',
    { messages: [{ role: 'user', content: [
      { type: 'image', source: { type: 'base64', media_type: 'image/png', data: DATA } },
      { type: 'text', text: NOTE },
    ] }] },
    (body) => body.messages[0].content[0].source.data, (body) => body.messages[0].content[1].text, DATA],
  ['Messages tool_result image', '/v1/messages',
    { messages: [{ role: 'user', content: [
      { type: 'tool_result', tool_use_id: 't1', content: [{ type: 'image', source: { type: 'base64', media_type: 'image/png', data: DATA } }] },
      { type: 'text', text: NOTE },
    ] }] },
    (body) => body.messages[0].content[0].content[0].source.data, (body) => body.messages[0].content[1].text, DATA],
  ['Messages thinking signature', '/v1/messages',
    { messages: [{ role: 'assistant', content: [{ type: 'thinking', thinking: NOTE, signature: DATA }] }] },
    (body) => body.messages[0].content[0].signature, (body) => body.messages[0].content[0].thinking, DATA],
  ['Messages redacted_thinking data', '/v1/messages',
    { messages: [{ role: 'assistant', content: [{ type: 'redacted_thinking', data: DATA }, { type: 'text', text: NOTE }] }] },
    (body) => body.messages[0].content[0].data, (body) => body.messages[0].content[1].text, DATA],
];

for (const mode of MODES) {
  for (const [shape, path, body, exempt, neighbour, expected] of SHAPES) {
    test(`proxy (${mode}, ${shape}): user-defined text inside exempt base64 stays byte-identical`, async (t) => {
      const h = await proxyHarness(t, { mode, sensitiveTexts: [CUSTOM] });

      await h.send(body, { path });

      const forwarded = JSON.parse(h.upstream[0].body);
      assert.equal(exempt(forwarded), expected);
      assertNoLeak(neighbour(forwarded), CUSTOM, 'neighbouring text');
    });
  }
}
