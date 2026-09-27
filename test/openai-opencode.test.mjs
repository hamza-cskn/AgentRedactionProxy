import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import { MappingStore } from '../src/mapping-store.mjs';
import { createProxy } from '../src/proxy.mjs';

test('OpenCode OAuth plugin routes a redacted Responses request through the proxy', {
  skip: process.env.IPV4_PROXY_OPENCODE_TEST !== '1',
  timeout: 150_000,
}, async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ipv4-openai-oauth-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const captured = [];
  const upstream = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    captured.push({
      path: request.url,
      headers: request.headers,
      body: Buffer.concat(chunks).toString('utf8'),
    });
    response.writeHead(400, { 'content-type': 'application/json' });
    response.end('{"error":{"message":"mock finished"}}');
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  context.after(() => new Promise((resolve) => upstream.close(resolve)));
  const proxy = createProxy({
    mode: 'paranoic',
    store: await MappingStore.open(path.join(directory, 'mappings.json')),
    upstreamBase: `http://127.0.0.1:${upstream.address().port}/backend-api/codex`,
    protectAllPostBodies: true,
    logger: () => {},
  });
  // The plugin targets 8787, matching the production OpenAI listener.
  await new Promise((resolve) => proxy.listen(8787, '127.0.0.1', resolve));
  context.after(() => new Promise((resolve) => proxy.close(resolve)));

  const authDirectory = path.join(directory, 'data', 'opencode');
  await mkdir(authDirectory, { recursive: true });
  await writeFile(path.join(authDirectory, 'auth.json'), JSON.stringify({
    openai: {
      type: 'oauth',
      refresh: 'local-test-refresh',
      access: 'local-test-access',
      expires: Date.now() + 60_000,
      accountId: 'local-test-account',
    },
  }), { mode: 0o600 });
  const config = {
    enabled_providers: ['openai'],
    model: 'openai/gpt-5.4',
    small_model: 'openai/gpt-5.4',
    plugin: [new URL('../.opencode/plugins/openai-ipv4-proxy.js', import.meta.url).href],
    provider: { openai: { options: { baseURL: 'http://127.0.0.1:8787/v1' } } },
    autoupdate: false,
    share: 'disabled',
    snapshot: false,
    lsp: false,
    permission: { '*': 'deny' },
  };
  const run = promisify(execFile)('opencode', [
    'run', '--print-logs', '--log-level', 'DEBUG', '--format', 'json', '--title', 'OAuth proxy integration',
    'Repeat the address 10.123.45.67.',
  ], {
    cwd: directory,
    timeout: 120_000,
    maxBuffer: 4 * 1024 * 1024,
    env: {
      PATH: process.env.PATH,
      XDG_CONFIG_HOME: path.join(directory, 'config'),
      XDG_DATA_HOME: path.join(directory, 'data'),
      XDG_CACHE_HOME: path.join(directory, 'cache'),
      XDG_STATE_HOME: path.join(directory, 'state'),
      OPENCODE_TEST_HOME: directory,
      OPENCODE_TEST_MANAGED_CONFIG_DIR: path.join(directory, 'managed'),
      OPENCODE_CONFIG_CONTENT: JSON.stringify(config),
      OPENCODE_DISABLE_MODELS_FETCH: 'true',
      OPENCODE_DISABLE_AUTOUPDATE: 'true',
      OPENCODE_DISABLE_DEFAULT_PLUGINS: 'true',
      OPENCODE_DISABLE_SHARE: 'true',
      OPENCODE_DISABLE_CLAUDE_CODE: 'true',
      OPENCODE_DISABLE_EXTERNAL_SKILLS: 'true',
      OPENCODE_DISABLE_LSP_DOWNLOAD: 'true',
      OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER: 'true',
    },
  });
  run.child.stdin.end();
  const result = await run.then(() => null, (error) => error);

  const diagnostics = result?.stderr?.split('\n').filter((line) =>
    /plugin|auth|provider|config|failed/i.test(line)).join('\n');
  assert.equal(captured.length, 1, `${result?.stdout ?? ''}\n${diagnostics ?? ''}`);
  assert.equal(captured[0].path, '/backend-api/codex/responses');
  assert.equal(captured[0].headers.authorization, 'Bearer local-test-access');
  assert.equal(captured[0].headers['chatgpt-account-id'], 'local-test-account');
  assert.equal(captured[0].body.includes('10.123.45.67'), false);
  assert.equal(captured[0].body.includes('192.0.2.1'), true);
});
