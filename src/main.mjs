#!/usr/bin/env node

import { fileURLToPath } from 'node:url';

import { loadConfig } from './config.mjs';
import { MappingStore } from './mapping-store.mjs';
import { createProxy } from './proxy.mjs';

const HOST = '127.0.0.1';
const PORT = 8787;
const configUrl = new URL('../config.json', import.meta.url);

async function main() {
  if (process.argv[2] === 'status') {
    process.stdout.write(`${JSON.stringify(await MappingStore.status())}\n`);
    return;
  }
  const config = await loadConfig(configUrl);
  const store = await MappingStore.open();
  const server = createProxy({ mode: config.mode, store });

  server.listen(PORT, HOST, () => {
    process.stderr.write(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'proxy-started',
      mode: config.mode,
      listen: `http://${HOST}:${PORT}/v1`,
      upstream: 'https://opencode.ai/zen/v1',
    }) + '\n');
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`[opencode-ipv4-proxy] ${error.message}\n`);
    process.exitCode = 1;
  });
}
