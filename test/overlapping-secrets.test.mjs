import assert from 'node:assert/strict';
import test from 'node:test';
import { MODES, assertNoLeak, entropy, proxyHarness } from './helpers/harness.mjs';

const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
const signature = entropy(43, 3);
// The payload segment alone is shaped like an AWS access key.
const jwtWithKeyPayload = `${header}.AKIA${entropy(16, 4).toUpperCase()}.${signature}`;

for (const mode of MODES) {
  test(`proxy (${mode}, JWT with key-shaped payload): no JWT segment reaches upstream`, async (t) => {
    const h = await proxyHarness(t, { mode });

    await h.send({ input: `token ${jwtWithKeyPayload}` });

    assertNoLeak(h.upstream[0].body, signature, 'upstream body');
  });
}

for (const mode of MODES) {
  test(`proxy (${mode}, user-defined text ending inside an IPv4): no octet of the address reaches upstream`, async (t) => {
    const h = await proxyHarness(t, { mode, sensitiveTexts: ['db at 10.20'] });

    await h.send({ input: 'db at 10.20.30.40 is down' });

    assert.doesNotMatch(h.upstream[0].body, /30\.40/);
  });
}
