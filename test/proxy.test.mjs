import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { gzipSync } from 'node:zlib';

import { MappingStore } from '../src/mapping-store.mjs';
import { createProxy } from '../src/proxy.mjs';

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

async function close(server) {
  await new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

async function readRequest(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

async function createStore() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'opencode-ipv4-proxy-'));
  return MappingStore.open(path.join(directory, 'mappings.json'));
}

test('redacts inference requests and deobfuscates buffered SSE responses', async (context) => {
  let capturedBody = '';
  let capturedAuthorization = '';
  const upstream = http.createServer(async (request, response) => {
    capturedBody = await readRequest(request);
    capturedAuthorization = request.headers.authorization;
    response.writeHead(200, { 'content-type': 'text/event-stream', 'content-encoding': 'gzip' });
    response.end(gzipSync([
      'data: {"type":"response.output_text.delta","item_id":"item_1","output_index":0,"content_index":0,"delta":"target 192"}\n\n',
      'data: {"type":"response.output_text.delta","item_id":"item_1","output_index":0,"content_index":0,"delta":".0.2"}\n\n',
      'data: {"type":"response.output_text.delta","item_id":"item_1","output_index":0,"content_index":0,"delta":".1"}\n\n',
      'data: [DONE]\n\n',
    ].join('')));
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const logs = [];
  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    logger: (line) => logs.push(line),
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/responses`, {
    method: 'POST',
    headers: {
      authorization: 'Bearer test-key',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ input: 'inspect 192.168.24.21' }),
  });
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.equal(capturedAuthorization, 'Bearer test-key');
  assert.equal(capturedBody.includes('192.168.24.21'), false);
  assert.equal(capturedBody.includes('192.0.2.1'), true);
  const outputText = body
    .split(/\r?\n\r?\n/)
    .filter((block) => block.startsWith('data: {'))
    .map((block) => JSON.parse(block.slice(5)).delta)
    .join('');
  assert.equal(outputText, 'target 192.168.24.21');
  assert.equal(response.headers.has('content-encoding'), false);
  assert.equal(logs.some((line) => line.includes('192.168.24.21')), false);
  assert.equal(logs.some((line) => line.includes('"outboundReplacements":1')), true);
  assert.equal(logs.some((line) => line.includes('"inboundReplacements":1')), true);
});

test('restores fragmented SSE when the upstream omits Content-Type', async (context) => {
  const upstream = http.createServer(async (request, response) => {
    await readRequest(request);
    response.end([
      'event: response.output_text.delta\ndata: {"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"192"}\n\n',
      'event: response.output_text.delta\ndata: {"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":".0.2.1"}\n\n',
    ].join(''));
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));
  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/backend-api/codex`,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));
  const response = await fetch(`${proxyOrigin}/v1/responses`, {
    method: 'POST',
    body: '{"input":"10.123.45.67"}',
  });
  const events = (await response.text()).split(/\r?\n\r?\n/).filter(Boolean)
    .map((block) => JSON.parse(block.split(/\r?\n/).find((line) => line.startsWith('data:')).slice(5)));
  assert.equal(events.map((event) => event.delta).join(''), '10.123.45.67');
});

test('Claude Code Messages route keeps OAuth headers and restores SSE text', async (context) => {
  let captured;
  const upstream = http.createServer(async (request, response) => {
    captured = {
      path: request.url,
      authorization: request.headers.authorization,
      body: await readRequest(request),
    };
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    response.end([
      'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"192.0"}}\n\n',
      'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":".2.1"}}\n\n',
    ].join(''));
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));
  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/v1`,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/messages`, {
    method: 'POST',
    headers: { authorization: 'Bearer claude-test', 'content-type': 'application/json' },
    body: '{"messages":[{"role":"user","content":"10.123.45.67"}]}',
  });
  const body = await response.text();
  assert.equal(response.status, 200);
  assert.equal(captured.path, '/v1/messages');
  assert.equal(captured.authorization, 'Bearer claude-test');
  assert.equal(captured.body.includes('10.123.45.67'), false);
  assert.equal(captured.body.includes('192.0.2.1'), true);
  const text = body.split(/\r?\n\r?\n/).filter(Boolean)
    .map((block) => JSON.parse(block.split(/\r?\n/).find((line) => line.startsWith('data:')).slice(5)).delta.text)
    .join('');
  assert.equal(text, '10.123.45.67');
});

test('Claude Code auxiliary POST bodies are redacted before forwarding', async (context) => {
  let captured;
  const upstream = http.createServer(async (request, response) => {
    captured = { path: request.url, body: await readRequest(request) };
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"input_tokens":5}');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));
  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/v1`,
    protectAllPostBodies: true,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/messages/count_tokens`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{"messages":[{"role":"user","content":"10.123.45.67"}]}',
  });
  assert.equal(response.status, 200);
  assert.equal(captured.path, '/v1/messages/count_tokens');
  assert.equal(captured.body.includes('10.123.45.67'), false);
  assert.equal(captured.body.includes('192.0.2.1'), true);
});

test('redacts API keys from outbound bodies without persisting or restoring them', async (context) => {
  const token = `sk-${'e'.repeat(24)}`;
  let captured;
  const upstream = http.createServer(async (request, response) => {
    captured = { authorization: request.headers.authorization, body: await readRequest(request) };
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ text: '[REDACTED_API_KEY] 192.0.2.1' }));
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));
  const store = await createStore();
  const logs = [];
  const proxy = createProxy({
    mode: 'never-see',
    store,
    upstreamBase: `${upstreamOrigin}/v1`,
    protectAllPostBodies: true,
    logger: (line) => logs.push(line),
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/messages`, {
    method: 'POST',
    headers: { authorization: 'Bearer client-login', 'content-type': 'application/json' },
    body: JSON.stringify({ input: `10.123.45.67 ${token}` }),
  });
  assert.equal(response.status, 200);
  assert.equal(captured.authorization, 'Bearer client-login');
  assert.equal(captured.body.includes(token), false);
  assert.equal(captured.body.includes('10.123.45.67'), false);
  assert.equal(captured.body.includes('[REDACTED_API_KEY]'), true);
  assert.equal((await response.text()).includes(token), false);
  assert.equal((await readFile(store.statePath, 'utf8')).includes(token), false);
  assert.equal(logs.some((line) => line.includes(token)), false);
  assert.equal(logs.some((line) => line.includes('"secretRedactions":1')), true);
});

test('non-paranoic IPv4 failure does not forward the original secret', async (context) => {
  const token = `ghp_${'f'.repeat(24)}`;
  let captured;
  const upstream = http.createServer(async (request, response) => {
    captured = await readRequest(request);
    response.end('{}');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));
  const proxy = createProxy({
    mode: 'non-paranoic',
    store: { obfuscate: async () => { throw new Error('test failure'); }, deobfuscate: async () => ({ body: '{}', count: 0 }) },
    upstreamBase: `${upstreamOrigin}/v1`,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));
  const response = await fetch(`${proxyOrigin}/v1/messages`, { method: 'POST', body: token });
  assert.equal(response.status, 200);
  assert.equal(captured, '[REDACTED_API_KEY]');
});

test('keeps MongoDB metadata and obfuscates every host IP while hiding the password', async (context) => {
  const captured = [];
  const upstream = http.createServer(async (request, response) => {
    captured.push(await readRequest(request));
    response.end('{}');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));
  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/v1`,
    protectAllPostBodies: true,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));
  const response = await fetch(`${proxyOrigin}/v1/messages`, {
    method: 'POST',
    body: 'mongodb://app_user:S3cr3t_99@10.20.30.40:27017,10.20.30.41:27017/analytics_db?replicaSet=rs0&ssl=true',
  });
  assert.equal(response.status, 200);
  assert.equal(captured[0], 'mongodb://app_user:REDACTED_PASSWORD@192.0.2.1:27017,192.0.2.2:27017/analytics_db?replicaSet=rs0&ssl=true');

  const spaced = await fetch(`${proxyOrigin}/v1/messages`, {
    method: 'POST',
    body: 'mongdb : / / app_user : hunter2 @ 10.20.30.41:27017,10.20.30.40:27017/analytics_db',
  });
  assert.equal(spaced.status, 200);
  assert.equal(captured[1], 'mongdb : / / app_user : REDACTED_PASSWORD @ 192.0.2.2:27017,192.0.2.1:27017/analytics_db');
});

test('never-see blocks malformed credential URLs that cannot be safely redacted', async (context) => {
  let upstreamCalls = 0;
  const upstream = http.createServer((_request, response) => {
    upstreamCalls += 1;
    response.end('{}');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));
  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/v1`,
    protectAllPostBodies: true,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));
  const response = await fetch(`${proxyOrigin}/v1/messages`, {
    method: 'POST',
    body: 'mongdb://user:pass word@host',
  });
  assert.equal(response.status, 502);
  assert.equal(upstreamCalls, 0);
});

test('unreadable outbound text fails closed even in non-paranoic mode', async (context) => {
  let upstreamCalls = 0;
  const upstream = http.createServer((_request, response) => {
    upstreamCalls += 1;
    response.end('{}');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));
  const proxy = createProxy({
    mode: 'non-paranoic',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/v1`,
    protectAllPostBodies: true,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));
  const response = await fetch(`${proxyOrigin}/v1/messages`, {
    method: 'POST',
    body: Buffer.from([0xff]),
  });
  assert.equal(response.status, 502);
  assert.equal(upstreamCalls, 0);
});

test('recognizes every OpenCode Zen inference endpoint', async (context) => {
  const captured = [];
  const upstream = http.createServer(async (request, response) => {
    captured.push({ url: request.url, body: await readRequest(request) });
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"text":"192.0.2.1"}');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const endpoints = [
    '/v1/responses',
    '/v1/messages',
    '/v1/chat/completions',
    '/v1/models/gemini-3-flash:streamGenerateContent?alt=sse',
    '/v1/models/gemini-3-flash:generateContent',
  ];
  for (const endpoint of endpoints) {
    const response = await fetch(`${proxyOrigin}${endpoint}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"text":"10.0.0.1"}',
    });
    assert.equal(await response.text(), '{"text":"10.0.0.1"}');
  }

  assert.equal(captured.length, endpoints.length);
  for (const request of captured) {
    assert.equal(request.body, '{"text":"192.0.2.1"}');
  }
  assert.equal(captured[3].url, '/zen/v1/models/gemini-3-flash:streamGenerateContent?alt=sse');
  assert.equal(captured[4].url, '/zen/v1/models/gemini-3-flash:generateContent');
});

test('does not transform non-inference endpoints', async (context) => {
  const upstream = http.createServer(async (_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"description":"192.0.2.1"}');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/models`);
  assert.equal(await response.text(), '{"description":"192.0.2.1"}');
});

test('never-see mode refuses to forward when outbound redaction fails', async (context) => {
  let upstreamCalls = 0;
  const upstream = http.createServer((_request, response) => {
    upstreamCalls += 1;
    response.end('unexpected');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const proxy = createProxy({
    mode: 'never-see',
    store: {
      obfuscate: async () => { throw new Error('state unavailable'); },
      deobfuscate: () => { throw new Error('not reached'); },
    },
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/responses`, {
    method: 'POST',
    body: '{"input":"10.0.0.1"}',
  });

  assert.equal(response.status, 502);
  assert.equal(upstreamCalls, 0);
});

test('capacity exhaustion never forwards, including non-paranoic mode', async (context) => {
  let upstreamCalls = 0;
  const upstream = http.createServer((_request, response) => {
    upstreamCalls += 1;
    response.end('unexpected');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const proxy = createProxy({
    mode: 'non-paranoic',
    store: {
      obfuscate: async () => {
        const error = new Error('capacity exhausted');
        error.code = 'MAPPING_CAPACITY_EXHAUSTED';
        throw error;
      },
      deobfuscate: async () => { throw new Error('not reached'); },
    },
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/responses`, {
    method: 'POST',
    body: '{"input":"10.0.0.1"}',
  });

  assert.equal(response.status, 507);
  assert.equal(upstreamCalls, 0);
  assert.deepEqual(await response.json(), {
    error: 'IPv4 mapping capacity exhausted; request was not forwarded',
  });
});

test('non-paranoic mode forwards raw body and returns a warning header', async (context) => {
  let capturedBody = '';
  const upstream = http.createServer(async (request, response) => {
    capturedBody = await readRequest(request);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"output":"ok"}');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const logs = [];
  const proxy = createProxy({
    mode: 'non-paranoic',
    store: {
      obfuscate: async () => { throw new Error('state unavailable'); },
      deobfuscate: async (text) => ({ body: text, count: 0 }),
    },
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    logger: (line) => logs.push(line),
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/responses`, {
    method: 'POST',
    body: '{"input":"10.0.0.1"}',
  });

  assert.equal(response.status, 200);
  assert.equal(capturedBody, '{"input":"10.0.0.1"}');
  assert.equal(
    response.headers.get('x-ipv4-proxy-warning'),
    'outbound-redaction-failed-raw-request-forwarded',
  );
  assert.equal(logs.some((line) => line.includes('10.0.0.1')), false);
});

test('returns the fake response when inbound deobfuscation fails', async (context) => {
  const upstream = http.createServer(async (request, response) => {
    await readRequest(request);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"output":"192.0.2.1"}');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const proxy = createProxy({
    mode: 'never-see',
    store: {
      obfuscate: async (text) => ({ body: text, count: 0 }),
      deobfuscate: async () => { throw new Error('decode failed'); },
    },
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/responses`, {
    method: 'POST',
    body: '{}',
  });

  assert.equal(await response.text(), '{"output":"192.0.2.1"}');
  assert.equal(
    response.headers.get('x-ipv4-proxy-warning'),
    'inbound-deobfuscation-failed-fake-response-returned',
  );
});

test('returns malformed SSE unchanged with a warning', async (context) => {
  const store = await createStore();
  await store.obfuscate('10.0.0.1');
  const upstream = http.createServer(async (request, response) => {
    await readRequest(request);
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    response.end('data: {not-json "192.0.2.1"}\n\n');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const proxy = createProxy({
    mode: 'never-see',
    store,
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/chat/completions`, {
    method: 'POST',
    body: '{}',
  });

  assert.equal(await response.text(), 'data: {not-json "192.0.2.1"}\n\n');
  assert.equal(
    response.headers.get('x-ipv4-proxy-warning'),
    'inbound-deobfuscation-failed-fake-response-returned',
  );
});

test('enforces the configured request body limit', async (context) => {
  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    maxBodyBytes: 8,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/responses`, {
    method: 'POST',
    body: '123456789',
  });
  assert.equal(response.status, 413);
});

test('treats inference paths without the /v1 prefix as inference too', async (context) => {
  const captured = [];
  const upstream = http.createServer(async (request, response) => {
    captured.push({ url: request.url, body: await readRequest(request) });
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"text":"192.0.2.1"}');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const endpoints = ['/responses', '/messages', '/chat/completions', '/models/gemini-3-flash:generateContent'];
  for (const endpoint of endpoints) {
    const response = await fetch(`${proxyOrigin}${endpoint}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"text":"10.0.0.1"}',
    });
    assert.equal(await response.text(), '{"text":"10.0.0.1"}');
  }

  assert.equal(captured.length, endpoints.length);
  for (const request of captured) {
    assert.equal(request.body, '{"text":"192.0.2.1"}');
  }
  assert.equal(captured[3].url, '/zen/v1/models/gemini-3-flash:generateContent');
});

test('blocks redirects from an inference endpoint instead of leaking the Location header', async (context) => {
  let upstreamCalls = 0;
  let redirectStatus = 307;
  const upstream = http.createServer((_request, response) => {
    upstreamCalls += 1;
    response.writeHead(redirectStatus, { location: 'https://attacker.example/steal' });
    response.end();
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  for (const status of [307, 308]) {
    redirectStatus = status;
    upstreamCalls = 0;
    const response = await fetch(`${proxyOrigin}/v1/responses`, {
      method: 'POST',
      body: '{"input":"10.0.0.1"}',
    });
    assert.equal(response.status, 502);
    assert.equal(response.headers.has('location'), false);
    assert.equal(upstreamCalls, 1);
  }
});

test('does not block redirects on non-inference endpoints', async (context) => {
  const upstream = http.createServer((_request, response) => {
    response.writeHead(302, { location: 'https://example.com/elsewhere' });
    response.end();
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/models`, { redirect: 'manual' });
  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), 'https://example.com/elsewhere');
});

test('redacts IPv4 addresses that appear in the logged endpoint path', async (context) => {
  const upstream = http.createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{}');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const logs = [];
  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    logger: (line) => logs.push(line),
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  await fetch(`${proxyOrigin}/v1/models/10.0.0.1:generateContent`);

  assert.equal(logs.some((line) => line.includes('10.0.0.1')), false);
  assert.equal(logs.some((line) => line.includes('[redacted-ipv4]')), true);
});

test('rejects a response that exceeds the limit after deobfuscation', async (context) => {
  const upstream = http.createServer(async (request, response) => {
    await readRequest(request);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('x');
  });
  const upstreamOrigin = await listen(upstream);
  context.after(() => close(upstream));

  const proxy = createProxy({
    mode: 'never-see',
    store: {
      obfuscate: async (text) => ({ body: text, count: 0 }),
      deobfuscate: async () => ({ body: '123456789', count: 1 }),
    },
    upstreamBase: `${upstreamOrigin}/zen/v1`,
    maxBodyBytes: 8,
    logger: () => {},
  });
  const proxyOrigin = await listen(proxy);
  context.after(() => close(proxy));

  const response = await fetch(`${proxyOrigin}/v1/responses`, {
    method: 'POST',
    body: '{}',
  });
  assert.equal(response.status, 502);
});

test('contains malformed URLs without calling upstream', async () => {
  let upstreamCalls = 0;
  const logs = [];
  const proxy = createProxy({
    mode: 'never-see',
    store: {},
    logger: (line) => logs.push(JSON.parse(line)),
    fetchImpl: async () => { upstreamCalls += 1; },
  });
  const request = Readable.from([]);
  Object.assign(request, { url: 'http://[', method: 'GET', headers: {} });
  const response = {
    writeHead(status) { this.status = status; },
    end(body) { this.body = body; },
  };
  await proxy.listeners('request')[0](request, response);
  assert.equal(response.status, 400);
  assert.equal(upstreamCalls, 0);
  assert.equal(logs[0].status, 400);
});

test('redacts escaped JSON before it reaches the upstream parser', async (context) => {
  let captured;
  const proxy = createProxy({
    mode: 'never-see',
    store: await createStore(),
    logger: () => {},
    fetchImpl: async (_url, { body }) => {
      captured = JSON.parse(body.toString());
      return new Response('{}');
    },
  });
  const origin = await listen(proxy);
  context.after(() => close(proxy));
  const response = await fetch(`${origin}/v1/responses`, {
    method: 'POST',
    body: String.raw`{"input":"10\u002e0\u002e0\u002e1"}`,
  });
  await response.text();
  assert.equal(response.status, 200);
  assert.equal(captured.input, '192.0.2.1');
});

for (const phase of ['headers', 'body']) {
  test(`expires an upstream stalled during ${phase}`, { timeout: 3000 }, async (context) => {
    let upstreamSignal;
    const proxy = createProxy({
      mode: 'never-see', store: {}, logger: () => {}, upstreamTimeoutMs: 50,
      fetchImpl: async (_url, { signal }) => {
        upstreamSignal = signal;
        if (phase === 'headers') {
          return new Promise((_resolve, reject) => {
            signal.addEventListener('abort', () => reject(signal.reason), { once: true });
          });
        }
        return new Response(new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('partial'));
            signal.addEventListener('abort', () => controller.error(signal.reason), { once: true });
          },
        }));
      },
    });
    const origin = await listen(proxy);
    context.after(() => close(proxy));
    const response = await fetch(`${origin}/v1/models`);
    await response.text();
    assert.equal(response.status, 504);
    assert.equal(upstreamSignal.aborted, true);
  });
}

test('aborts upstream when the client disconnects', { timeout: 3000 }, async (context) => {
  let upstreamSignal;
  let started;
  const upstreamStarted = new Promise((resolve) => { started = resolve; });
  let aborted;
  const upstreamAborted = new Promise((resolve) => { aborted = resolve; });
  const proxy = createProxy({
    mode: 'never-see', store: {}, logger: () => {},
    fetchImpl: async (_url, { signal }) => {
      upstreamSignal = signal;
      started();
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => { aborted(); reject(signal.reason); }, { once: true });
      });
    },
  });
  const origin = await listen(proxy);
  context.after(() => close(proxy));
  const request = http.get(`${origin}/v1/models`);
  request.on('error', () => {});
  context.after(() => request.destroy());
  await upstreamStarted;
  request.destroy();
  assert.ok(upstreamSignal, 'upstream must receive a cancellation signal');
  await upstreamAborted;
  assert.equal(upstreamSignal.aborted, true);
});

test('rejects a ninth concurrent request and releases slots after completion', { timeout: 3000 }, async (context) => {
  const pending = [];
  let started;
  const full = new Promise((resolve) => { started = resolve; });
  let hold = true;
  const proxy = createProxy({
    mode: 'never-see', store: {}, logger: () => {},
    fetchImpl: async () => {
      if (!hold) return new Response('{}');
      return new Promise((resolve) => {
        pending.push(resolve);
        if (pending.length === 8) started();
      });
    },
  });
  const origin = await listen(proxy);
  context.after(() => close(proxy));
  const requests = Array.from({ length: 8 }, () => fetch(`${origin}/v1/models`));
  await full;
  try {
    const rejected = await fetch(`${origin}/v1/models`, { signal: AbortSignal.timeout(500) });
    await rejected.text();
    assert.equal(rejected.status, 503);
    assert.equal(pending.length, 8);
  } finally {
    hold = false;
    for (const resolve of pending) resolve(new Response('{}'));
    await Promise.all(requests.map(async (result) => (await result).text()));
  }
  const response = await fetch(`${origin}/v1/models`);
  await response.text();
  assert.equal(response.status, 200);
});

test('restores fragmented SSE for every protocol with either route prefix', async (context) => {
  const cases = [
    ['/responses', (delta) => ({ type: 'response.function_call_arguments.delta', item_id: 'call_1', output_index: 0, delta }), (event) => event.delta],
    ['/messages', (text) => ({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } }), (event) => event.delta.text],
    ['/chat/completions', (content) => ({ choices: [{ index: 0, delta: { content } }] }), (event) => event.choices[0].delta.content],
    ['/models/gemini:streamGenerateContent', (text) => ({ candidates: [{ index: 0, content: { parts: [{ text }] } }] }), (event) => event.candidates[0].content.parts[0].text],
  ];
  let current;
  const proxy = createProxy({
    mode: 'never-see', store: await createStore(), logger: () => {},
    fetchImpl: async (_url, { body }) => {
      assert.equal(JSON.parse(body.toString()).input, '192.0.2.1');
      return new Response(['192', '.0.2', '.1'].map((chunk) => (
        `data: ${JSON.stringify(current(chunk))}\n\n`
      )).join(''), { headers: { 'content-type': 'text/event-stream' } });
    },
  });
  const origin = await listen(proxy);
  context.after(() => close(proxy));
  for (const [route, encode, decode] of cases) {
    current = encode;
    for (const prefix of ['', '/v1']) {
      const response = await fetch(`${origin}${prefix}${route}`, {
        method: 'POST', body: '{"input":"10.123.45.67"}',
      });
      const text = (await response.text()).split('\n\n').filter(Boolean)
        .map((block) => decode(JSON.parse(block.slice(6)))).join('');
      assert.equal(response.status, 200);
      assert.equal(response.headers.has('x-ipv4-proxy-warning'), false);
      assert.equal(text, '10.123.45.67', `${prefix}${route}`);
    }
  }
});
