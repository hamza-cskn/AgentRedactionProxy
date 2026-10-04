#!/usr/bin/env node

import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { loadConfig } from './config.mjs';
import { MappingStore, defaultStatePath } from './mapping-store.mjs';
import { createProxy } from './proxy.mjs';
import { exists, loadStorage, storagePaths } from './encrypted-storage.mjs';

const HOST = process.env.ARP_LISTEN_HOST || '127.0.0.1';
const ROUTES = [
  { client: 'opencode-openai-oauth', port: 8787, upstream: 'https://chatgpt.com/backend-api/codex' },
  { client: 'claude-code', port: 8788, upstream: 'https://api.anthropic.com/v1' },
];
const configUrl = process.env.ARP_CONFIG_FILE || new URL('../config.json', import.meta.url);

async function main() {
  const directory = path.resolve(process.env.ARP_DATA_DIR || path.dirname(defaultStatePath()));
  const files = storagePaths(directory);
  const keyFile = process.env.ARP_MASTER_KEY_FILE || files.masterKey;
  const storage = await loadStorage(directory, keyFile);
  if (!await exists(storage.statePath) && await exists(path.join(directory, 'mappings.json'))) {
    throw new Error('Legacy mappings.json exists: stop the proxy and manually rename it to redaction_mapping.json before starting; no automatic file conversion');
  }
  if (process.argv[2] === 'status') {
    process.stdout.write(`${JSON.stringify(await MappingStore.status(storage.statePath, storage))}\n`);
    return;
  }
  const config = await loadConfig(configUrl, storage);
  for (const [index, value] of (config.sensitiveTexts ?? []).entries()) {
    const length = [...value].length;
    if (length < 5) process.stderr.write(JSON.stringify({
      timestamp: new Date().toISOString(),
      level: 'warning',
      event: 'short-user-defined-secret',
      entryIndex: index + 1,
      length,
      warning: 'Short literal entries can match ordinary text too broadly',
    }) + '\n');
  }
  const store = await MappingStore.open(storage.statePath, { ...storage, sensitiveTexts: config.sensitiveTexts,
    storageGuard: async () => {
      if (await exists(files.conversionLock) || await exists(keyFile) !== Boolean(storage.encryptionKey)) {
        throw new Error('Storage mode changed or conversion in progress; restart the proxy');
      }
    },
  });
  for (const route of ROUTES) {
    const server = createProxy({
      mode: config.mode,
      redactionLimits: config.redactionLimits,
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
        storage: storage.encryptionKey ? 'encrypted' : 'plaintext',
        listen: `http://${HOST}:${route.port}/v1`,
        upstream: route.upstream,
      }) + '\n');
    });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`[agent-redaction-proxy] ${error.message}\n`);
    process.exitCode = 1;
  });
}
