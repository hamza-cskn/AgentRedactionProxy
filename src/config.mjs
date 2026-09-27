import { readFile } from 'node:fs/promises';

const MODES = new Set(['never-see', 'non-paranoic']);

export async function loadConfig(configUrl) {
  const parsed = JSON.parse(await readFile(configUrl, 'utf8'));
  if (!parsed || typeof parsed !== 'object' || !MODES.has(parsed.mode)) {
    throw new Error('config.json mode must be "never-see" or "non-paranoic"');
  }
  return { mode: parsed.mode };
}
