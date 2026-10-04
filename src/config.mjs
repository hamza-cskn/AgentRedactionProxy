import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveRedactionLimits } from './redaction-limits.mjs';
import { loadSensitiveTexts } from './sensitive-texts.mjs';

const MODES = new Set(['paranoic', 'default']);

export async function loadConfig(configUrl, { encryptionKey, sensitiveTextsFile } = {}) {
  const parsed = JSON.parse(await readFile(configUrl, 'utf8'));
  if (!parsed || typeof parsed !== 'object' || !MODES.has(parsed.mode)) {
    throw new Error('config.json mode must be "paranoic" or "default"');
  }
  const config = { mode: parsed.mode, redactionLimits: resolveRedactionLimits(parsed.redactionLimits) };
  if (parsed.sensitiveTextsFile !== undefined && parsed.sensitiveTextsFile !== null) {
    if (typeof parsed.sensitiveTextsFile !== 'string' || parsed.sensitiveTextsFile.trim() === '') throw new Error('sensitiveTextsFile must be a nonempty path or null');
    const configPath = configUrl instanceof URL ? fileURLToPath(configUrl) : path.resolve(configUrl);
    config.sensitiveTexts = await loadSensitiveTexts(path.resolve(path.dirname(configPath), parsed.sensitiveTextsFile), encryptionKey);
  } else if (sensitiveTextsFile) {
    config.sensitiveTexts = await loadSensitiveTexts(sensitiveTextsFile, encryptionKey);
  }
  return config;
}
