import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import { legacyStore } from './helpers/mapping-fixtures.mjs';
import { createProxy } from '../src/proxy.mjs';

test('OpenCode restores tool arguments and redacts the subsequent tool result', {
  skip: process.env.IPV4_PROXY_OPENCODE_TEST !== '1',
  timeout: 45_000,
}, async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ipv4-opencode-integration-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const toolStream = await readFile(new URL('./fixtures/chat-tool.sse', import.meta.url), 'utf8');
  const finalStream = await readFile(new URL('./fixtures/chat-final.sse', import.meta.url), 'utf8');
  const captured = [];
  const upstream = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    captured.push({ path: request.url, body: JSON.parse(Buffer.concat(chunks).toString()) });
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    response.end(captured.length === 1 ? toolStream : finalStream);
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  context.after(() => new Promise((resolve) => upstream.close(resolve)));
  const proxy = createProxy({
    mode: 'paranoic',
    store: await legacyStore(path.join(directory, 'mappings.json'), ['10.123.45.67']),
    upstreamBase: `http://127.0.0.1:${upstream.address().port}/v1`,
    logger: () => {},
  });
  await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve));
  context.after(() => new Promise((resolve) => proxy.close(resolve)));

  const config = {
    enabled_providers: ['opencode'],
    model: 'opencode/ipv4-test',
    small_model: 'opencode/ipv4-test',
    provider: {
      opencode: {
        npm: '@ai-sdk/openai-compatible',
        options: { baseURL: `http://127.0.0.1:${proxy.address().port}/v1`, apiKey: 'local-test' },
        models: { 'ipv4-test': { name: 'IPv4 Test', tool_call: true, limit: { context: 32768, output: 1024 } } },
      },
    },
    autoupdate: false,
    share: 'disabled',
    snapshot: false,
    lsp: false,
    permission: { '*': 'deny', bash: { '*': 'deny', 'printf *': 'allow' } },
  };
  const run = promisify(execFile)('opencode', [
    'run', '--pure', '--format', 'json', '--title', 'IPv4 proxy integration',
    'Print the address 10.123.45.67 using printf, then report it.',
  ], {
    cwd: directory,
    timeout: 35_000,
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
  const { stdout } = await run;

  assert.equal(captured.length, 2, stdout);
  for (const request of captured) {
    assert.equal(request.path, '/v1/chat/completions');
    assert.equal(JSON.stringify(request.body).includes('10.123.45.67'), false);
    assert.match(JSON.stringify(request.body), /\[REDACTED_IP_[a-f0-9]{32}\]/);
  }
  const toolResult = captured[1].body.messages.find((message) => message.role === 'tool');
  assert.match(JSON.stringify(toolResult), /\[REDACTED_IP_[a-f0-9]{32}\]/);
  const events = stdout.trim().split('\n').map((line) => JSON.parse(line));
  const toolEvent = events.find((event) => event.type === 'tool_use');
  assert.equal(toolEvent.part.state.status, 'completed');
  assert.ok(toolEvent.part.state.input.command.includes('10.123.45.67'));
  assert.ok(toolEvent.part.state.output.includes('10.123.45.67'));
  assert.ok(events.some((event) => event.type === 'text' && event.part.text.includes('10.123.45.67')));
});
