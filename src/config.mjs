import { readFile } from 'node:fs/promises';

const MODES = new Set(['paranoic', 'default']);

export async function loadConfig(configUrl) {
  const parsed = JSON.parse(await readFile(configUrl, 'utf8'));
  if (!parsed || typeof parsed !== 'object' || !MODES.has(parsed.mode)) {
    throw new Error('config.json mode must be "paranoic" or "default"');
  }
  return { mode: parsed.mode };
}
