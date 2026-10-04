import assert from 'node:assert/strict';
import test from 'node:test';

import { OpenAIIPv4Proxy } from '../.opencode/plugins/openai-ipv4-proxy.js';

function token(payload) {
  return `header.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.signature`;
}

test.beforeEach((context) => {
  const original = process.env.ARP_BYPASS;
  delete process.env.ARP_BYPASS;
  context.after(() => {
    if (original === undefined) delete process.env.ARP_BYPASS;
    else process.env.ARP_BYPASS = original;
  });
});

for (const value of [undefined, '', '0', 'true', 'yes', '1']) {
  test(`OpenCode bypass requires exactly ARP_BYPASS=1: ${String(value)}`, async (context) => {
    if (value !== undefined) process.env.ARP_BYPASS = value;
    const originalFetch = globalThis.fetch;
    const originalWarn = console.warn;
    const calls = [];
    const warnings = [];
    context.after(() => { globalThis.fetch = originalFetch; console.warn = originalWarn; });
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      return new Response('{}');
    };
    console.warn = (message) => warnings.push(message);
    const auth = { type: 'oauth', access: token({ chatgpt_compute_residency: 'us' }),
      accountId: 'account-test', expires: Date.now() + 60_000 };
    const plugin = await OpenAIIPv4Proxy({ client: { auth: { set: async () => {} } } });
    // Routing is fixed at startup, not changed by later environment mutations.
    process.env.ARP_BYPASS = value === '1' ? '0' : '1';
    const provider = await plugin.auth.loader(async () => auth);
    const controller = new AbortController();
    const body = '{"input":"10.1.2.3 [REDACTED_TEXT_example]"}';
    for (let i = 0; i < 2; i++) {
      await provider.fetch('http://127.0.0.1:8787/v1/responses?test=1', {
        method: 'POST', headers: { originator: 'opencode' }, body, signal: controller.signal,
      });
    }
    assert.equal(calls.length, 2);
    for (const call of calls) {
      assert.equal(call.url, value === '1' ? 'https://chatgpt.com/backend-api/codex/responses?test=1'
        : 'http://127.0.0.1:8787/v1/responses?test=1');
      assert.equal(call.init.body, body);
      assert.equal(call.init.signal, controller.signal);
      const headers = new Headers(call.init.headers);
      assert.equal(headers.get('authorization'), `Bearer ${auth.access}`);
      assert.equal(headers.get('chatgpt-account-id'), 'account-test');
      assert.equal(headers.get('x-openai-internal-codex-residency'), 'us');
      assert.equal(headers.get('originator'), 'opencode');
    }
    assert.equal(warnings.length, value === '1' ? 1 : 0);
    if (value === '1') assert.match(warnings[0], /BYPASS.*without redaction or marker restoration/);
    await assert.rejects(provider.fetch('https://api.openai.com/v1/chat/completions'), /Unsupported/);
    assert.equal(calls.length, 2);
  });
}

test('proxy connection failures never enable direct routing', async (context) => {
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; });
  const calls = [];
  globalThis.fetch = async (url) => { calls.push(String(url)); throw new Error('proxy unavailable'); };
  const plugin = await OpenAIIPv4Proxy({ client: { auth: { set: async () => {} } } });
  const provider = await plugin.auth.loader(async () => ({ type: 'oauth', access: 'test', expires: Date.now() + 60_000 }));
  await assert.rejects(provider.fetch('https://api.openai.com/v1/responses'), /proxy unavailable/);
  assert.deepEqual(calls, ['http://127.0.0.1:8787/v1/responses']);
});

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

for (const bypass of [false, true]) {
test(`OpenCode OAuth hook refreshes expired login before forwarding (bypass=${bypass})`, async () => {
  if (bypass) process.env.ARP_BYPASS = '1';
  const originalFetch = globalThis.fetch;
  const originalWarn = console.warn;
  console.warn = () => {};
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
    assert.equal(calls[1].url, bypass ? 'https://chatgpt.com/backend-api/codex/responses'
      : 'http://127.0.0.1:8787/v1/responses');
    assert.equal(saved[0].refresh, 'new-refresh');
    assert.equal(saved[0].accountId, 'account-refreshed');
    assert.equal(new Headers(calls[1].init.headers).get('authorization'), `Bearer ${freshAccess}`);
    assert.equal(new Headers(calls[1].init.headers).get('chatgpt-account-id'), 'account-refreshed');
  } finally {
    globalThis.fetch = originalFetch;
    console.warn = originalWarn;
  }
});
}
