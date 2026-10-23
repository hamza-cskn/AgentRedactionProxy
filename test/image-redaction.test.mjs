import assert from 'node:assert/strict';
import test from 'node:test';
import { redactSecrets } from '../src/secret-redaction.mjs';

const image = `data:image/png;base64,iVBORw0KGgo${'A'.repeat(263869)}`;
const imagePart = { type: 'input_image', image_url: image };
const request = (part) => ({ input: [{ role: 'user', content: [part] }] });

for (const mode of ['default', 'paranoic']) {
  test(`${mode}: preserves Responses image data and redacts neighboring text`, () => {
    const body = JSON.stringify({ input: [{ role: 'user', content: [
      imagePart, { type: 'input_text', text: `ghp_${'A'.repeat(36)}` },
    ] }] });
    const result = redactSecrets(body, undefined, mode);
    const parsed = JSON.parse(result.body);
    assert.equal(parsed.input[0].content[0].image_url, image);
    assert.equal(parsed.input[0].content[1].text, '[REDACTED_API_KEY]');
    assert.equal(result.count, 1);
  });
}

test('image-shaped text, tool arguments and other paths still hit the size guard', () => {
  for (const value of [
    image,
    JSON.stringify(imagePart),
    JSON.stringify({ messages: [{ content: [imagePart] }] }),
    JSON.stringify(request({ ...imagePart, type: 'input_text' })),
    JSON.stringify(request({ type: 'input_text', text: image })),
    JSON.stringify({ arguments: JSON.stringify(request(imagePart)) }),
    JSON.stringify(request({ ...imagePart, image_url: image.replace('image/png', 'text/plain') })),
    JSON.stringify(request({ ...imagePart, image_url: `${image} ghp_${'A'.repeat(36)}` })),
  ]) {
    assert.throws(() => redactSecrets(value), /configured limit/);
  }
});

test('normal image URLs still redact credentials', () => {
  const body = JSON.stringify(request({ ...imagePart, image_url: 'https://alice:password@example.com/image.png' }));
  const result = redactSecrets(body);
  assert.equal(JSON.parse(result.body).input[0].content[0].image_url, 'https://alice:REDACTED_PASSWORD@example.com/image.png');
});

test('preserves JSON formatting, escaped image strings and numeric literals', () => {
  const body = ` { "large": 9007199254740993, "input": [{"content": [{"image_url": ${JSON.stringify(image).replace('png', '\\u0070ng')}, "type": "input_image"}]}] } `;
  assert.deepEqual(redactSecrets(body), { body, count: 0 });
});

test('duplicate JSON keys do not crash traversal or exempt a final text part', () => {
  assert.throws(() => redactSecrets(`{"input":[{"content":[{"type":"input_image","image_url":${JSON.stringify(image)},"type":"input_text"}]}]}`), /configured limit/);
  assert.deepEqual(redactSecrets('{"input":{"content":null},"input":null}'), {
    body: '{"input":{"content":null},"input":null}', count: 0,
  });
});

const data = `iVBORw0KGgo${'A'.repeat(263869)}`;
const imageBlock = { type: 'image', source: { type: 'base64', media_type: 'image/png', data } };
const messages = (...content) => ({ messages: [{ role: 'user', content }] });
const toolResult = (...content) => ({ type: 'tool_result', tool_use_id: 'toolu_1', content });

for (const mode of ['default', 'paranoic']) {
  test(`${mode}: preserves Messages image data and redacts neighboring text`, () => {
    const body = JSON.stringify(messages(
      imageBlock,
      toolResult(imageBlock, { type: 'text', text: `ghp_${'A'.repeat(36)}` }),
    ));
    const result = redactSecrets(body, undefined, mode);
    const parsed = JSON.parse(result.body);
    assert.equal(parsed.messages[0].content[0].source.data, data);
    assert.equal(parsed.messages[0].content[1].content[0].source.data, data);
    assert.equal(parsed.messages[0].content[1].content[1].text, '[REDACTED_API_KEY]');
    assert.equal(result.count, 1);
  });
}

test('Messages image-shaped data on other shapes still hits the size guard', () => {
  const source = imageBlock.source;
  for (const value of [
    JSON.stringify(imageBlock),
    JSON.stringify({ input: [{ content: [imageBlock] }] }),
    JSON.stringify(messages({ ...imageBlock, type: 'text' })),
    JSON.stringify(messages({ type: 'text', text: data })),
    JSON.stringify(messages({ ...imageBlock, source: { ...source, type: 'url' } })),
    JSON.stringify(messages({ ...imageBlock, source: { ...source, media_type: 'text/plain' } })),
    JSON.stringify(messages({ ...imageBlock, source: { ...source, data: `${data} ghp_${'A'.repeat(36)}` } })),
    JSON.stringify(messages({ type: 'text', content: [imageBlock] })),
    JSON.stringify(messages(toolResult(toolResult(imageBlock)))),
    JSON.stringify({ arguments: JSON.stringify(messages(imageBlock)) }),
    `{"messages":[{"content":[{"type":"image","source":${JSON.stringify(source)},"type":"text"}]}]}`,
  ]) {
    assert.throws(() => redactSecrets(value), /configured limit/);
  }
});
