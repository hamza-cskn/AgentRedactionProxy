#!/usr/bin/env node

import { fileURLToPath } from 'node:url';

import { loadConfig } from './config.mjs';
import { MappingStore } from './mapping-store.mjs';
import { createProxy } from './proxy.mjs';

const HOST = '127.0.0.1';
const ROUTES = [
  { client: 'opencode-openai-oauth', port: 8787, upstream: 'https://chatgpt.com/backend-api/codex' },
  { client: 'claude-code', port: 8788, upstream: 'https://api.anthropic.com/v1' },
];
const configUrl = new URL('../config.json', import.meta.url);

async function main() {
  if (process.argv[2] === 'status') {
    process.stdout.write(`${JSON.stringify(await MappingStore.status())}\n`);
    return;
  }
  const config = await loadConfig(configUrl);
  const store = await MappingStore.open();
  for (const route of ROUTES) {
    const server = createProxy({
      mode: config.mode,
      store,
      upstreamBase: route.upstream,
      protectAllPostBodies: true,
    });
    server.listen(route.port, HOST, () => {
      process.stderr.write(JSON.stringify({
        timestamp: new Date().toISOString(),
        event: 'proxy-started',
        client: route.client,
        mode: config.mode,
        listen: `http://${HOST}:${route.port}/v1`,
        upstream: route.upstream,
      }) + '\n');
    });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`[opencode-ipv4-proxy] ${error.message}\n`);
    process.exitCode = 1;
  });
}
