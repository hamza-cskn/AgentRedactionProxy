import assert from 'node:assert/strict';
import test from 'node:test';
import { redactSecrets } from '../src/secret-redaction.mjs';

const blob = `CAQS+9oFChAIExgCOAFCCHRoaW5raW5n${'A'.repeat(124732)}`;
const secret = `ghp_${'A'.repeat(36)}`;
const thinking = { type: 'thinking', thinking: `key is ${secret}`, signature: blob };
const redactedThinking = { type: 'redacted_thinking', data: blob };
const messages = (...content) => ({ messages: [{ role: 'assistant', content }] });

for (const mode of ['default', 'paranoic']) {
  test(`${mode}: preserves thinking signatures and redacted_thinking data, redacts thinking text`, () => {
    const result = redactSecrets(JSON.stringify(messages(thinking, redactedThinking)), undefined, mode);
    const parsed = JSON.parse(result.body);
    assert.equal(parsed.messages[0].content[0].signature, blob);
    assert.equal(parsed.messages[0].content[0].thinking, 'key is [REDACTED_API_KEY]');
    assert.equal(parsed.messages[0].content[1].data, blob);
    assert.equal(result.count, 1);
  });
}

test('thinking-blob-shaped data on other shapes still hits the size guard', () => {
  for (const value of [
    JSON.stringify(thinking),
    JSON.stringify({ input: [{ content: [thinking] }] }),
    JSON.stringify(messages({ ...thinking, type: 'text' })),
    JSON.stringify(messages({ ...redactedThinking, type: 'thinking' })),
    JSON.stringify(messages({ type: 'thinking', thinking: blob, signature: 'x' })),
    JSON.stringify(messages({ type: 'tool_result', tool_use_id: 'toolu_1', content: [thinking] })),
    JSON.stringify(messages({ ...thinking, signature: `${blob} ${secret}` })),
  ]) {
    assert.throws(() => redactSecrets(value), /configured limit/);
  }
});
