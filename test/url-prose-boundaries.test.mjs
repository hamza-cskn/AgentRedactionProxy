import assert from 'node:assert/strict';
import test from 'node:test';
import { redactSecrets } from '../src/secret-redaction.mjs';

const proseUrls = [
  'http://localhost:8080 (contact dev@example.com)',
  'http://example.com:3000 — contact dev@example.com',
  '[http://localhost:8080](http://example.com)',
  'http://localhost:8080—then continue',
  'http://host ; Next action: contact me@example.com',
  'http://alice:8080 (contact dev@example.com)',
  'http://localhost:8080 Next action: contact me@example.com',
  'http://alice:8080 more@host/api',
];

for (const mode of ['default', 'paranoic']) {
  for (const input of proseUrls) {
    test(`${mode}: valid URL ends before surrounding prose: ${input}`, () => {
      assert.deepEqual(redactSecrets(input, undefined, mode), { body: input, count: 0 });
    });
  }
  for (const password of ['secret', 'secret%20words', '8080', '8080%20words', '8080—secret', '8080–secret']) {
    test(`${mode}: URL boundary preserves credential masking: ${password}`, () => {
      const input = `http://alice:${password}@host`;
      assert.equal(redactSecrets(input, undefined, mode).body, 'http://alice:REDACTED_PASSWORD@host');
    });
  }
  for (const input of ['http://alice:8080 @host', 'http://alice:8080\t @host']) {
    test(`${mode}: whitespace before an immediate @ still masks the password: ${input}`, () => {
      assert.equal(redactSecrets(input, undefined, mode).body, input.replace('8080', 'REDACTED_PASSWORD'));
    });
  }
}
