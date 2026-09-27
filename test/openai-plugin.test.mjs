import assert from 'node:assert/strict';
import test from 'node:test';

import { OpenAIIPv4Proxy } from '../.opencode/plugins/openai-ipv4-proxy.js';

function token(payload) {
  return `header.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.signature`;
}

test('OpenCode OAuth hook routes Responses through the local proxy with login headers', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response('{}', { status: 200 });
  };
  try {
    const auth = {
      type: 'oauth',
      access: token({ chatgpt_compute_residency: 'us' }),
      accountId: 'account-test',
      expires: Date.now() + 60_000,
    };
    const plugin = await OpenAIIPv4Proxy({ client: { auth: { set: async () => {} } } });
    const provider = await plugin.auth.loader(async () => auth);
    await provider.fetch('https://api.openai.com/v1/responses?test=1', {
      method: 'POST',
      headers: { authorization: 'Bearer sdk-dummy' },
      body: '{"input":"10.1.2.3"}',
    });

    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'http://127.0.0.1:8787/v1/responses?test=1');
    assert.equal(new Headers(calls[0].init.headers).get('authorization'), `Bearer ${auth.access}`);
    assert.equal(new Headers(calls[0].init.headers).get('chatgpt-account-id'), 'account-test');
    assert.equal(new Headers(calls[0].init.headers).get('x-openai-internal-codex-residency'), 'us');
    assert.equal(calls[0].init.body, '{"input":"10.1.2.3"}');
    await assert.rejects(provider.fetch('https://api.openai.com/v1/chat/completions'),
      /Unsupported OpenAI OAuth endpoint/);
    assert.equal(calls.length, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('OpenCode OAuth hook refreshes expired login before forwarding', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  const saved = [];
  const freshAccess = token({ chatgpt_account_id: 'account-refreshed' });
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    if (String(url).includes('/oauth/token')) {
      return Response.json({ refresh_token: 'new-refresh', access_token: freshAccess, expires_in: 3600 });
    }
    return new Response('{}', { status: 200 });
  };
  try {
    let auth = { type: 'oauth', refresh: 'old-refresh', access: '', expires: 0 };
    const plugin = await OpenAIIPv4Proxy({ client: { auth: { set: async ({ body }) => {
      saved.push(body);
      auth = body;
    } } } });
    const provider = await plugin.auth.loader(async () => auth);
    await provider.fetch('https://api.openai.com/v1/responses', { method: 'POST' });

    assert.equal(calls.length, 2);
    assert.equal(calls[0].url, 'https://auth.openai.com/oauth/token');
    assert.equal(saved[0].refresh, 'new-refresh');
    assert.equal(saved[0].accountId, 'account-refreshed');
    assert.equal(new Headers(calls[1].init.headers).get('authorization'), `Bearer ${freshAccess}`);
    assert.equal(new Headers(calls[1].init.headers).get('chatgpt-account-id'), 'account-refreshed');
  } finally {
    globalThis.fetch = originalFetch;
  }
});
