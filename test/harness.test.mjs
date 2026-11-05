import assert from 'node:assert/strict';
import test from 'node:test';
import { redactSecrets } from '../src/secret-redaction.mjs';
import { MODES, entropy, findLeak, json, proxyHarness, secret } from './helpers/harness.mjs';

// Leak tests are only as good as their secrets: every generator must produce a
// value the proxy detects. [generator, value, expected body]
const GENERATED = [
  ['github', secret.github(1), '[REDACTED_API_KEY]'],
  ['jwt', secret.jwt(1), '[REDACTED_JWT]'],
  ['privateKey', secret.privateKey(1), '[REDACTED_PRIVATE_KEY]'],
  ['urlPassword', secret.urlPassword(1), 'postgres://app:REDACTED_PASSWORD@db.example.com/main'],
];

for (const mode of MODES) {
  for (const [generator, value, expected] of GENERATED) {
    test(`harness secret.${generator} (${mode}): redactSecrets replaces it`, () => {
      const result = redactSecrets(value, undefined, mode);

      assert.deepEqual(result, { body: expected, count: 1 });
    });
  }
}

test('harness entropy: the same seed gives the same text', () => {
  assert.equal(entropy(32, 5), entropy(32, 5));
});

test('harness entropy: different seeds give different text', () => {
  assert.notEqual(entropy(32, 5), entropy(32, 6));
});

test('harness findLeak: returns the first shared 8-char fragment', () => {
  assert.equal(findLeak('xx abcdefgh xx', '12abcdefgh34'), 'abcdefgh');
});

test('harness findLeak: returns null when only 7 characters are shared', () => {
  assert.equal(findLeak('xx abcdefg xx', '12abcdefgh34'), null);
});

test('harness proxyHarness: records the forwarded request', async (t) => {
  const h = await proxyHarness(t);

  await h.send({ input: 'hello' });

  assert.equal(h.upstream.length, 1);
  assert.equal(h.upstream[0].url, 'https://upstream.test/v1/responses');
  assert.equal(h.upstream[0].body, '{"input":"hello"}');
});

test('harness proxyHarness: returns the upstream response to the client', async (t) => {
  const h = await proxyHarness(t, { upstream: json({ ok: true }) });

  const response = await h.send({ input: 'hello' });

  assert.equal(response.status, 200);
  assert.equal(response.body, '{"ok":true}');
});
