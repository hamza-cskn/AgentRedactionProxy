import { open } from 'node:fs/promises';
import { transformJsonText } from './json-text.mjs';
import { decryptText } from './encrypted-storage.mjs';

export const RESTORABLE_MARKER_SOURCE = '\\[REDACTED_(?:IP|TEXT|API_KEY|JWT|PRIVATE_KEY|PASSWORD)_[a-f0-9]{32}\\]';
const marker = new RegExp(`^${RESTORABLE_MARKER_SOURCE}$`);
const escape = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function validateSensitiveTexts(values) {
  if (!Array.isArray(values) || values.length > 1024 || values.some((value) => (
    typeof value !== 'string' || value.trim() === '' || Buffer.byteLength(value) > 4096
    || (value.length === 1 && value.charCodeAt(0) <= 127)
    || /\[REDACTED_/.test(value)
  ))) throw new Error('Sensitive texts must be nonempty literal strings, not single-character ASCII entries (maximum 1024 entries, 4096 bytes each; redaction markers are reserved)');
  return [...new Set(values)];
}

export async function loadSensitiveTexts(file, encryptionKey) {
  let handle;
  try {
    handle = await open(file, 'r');
    const fileLimit = encryptionKey ? 2 * 1024 * 1024 : 1024 * 1024;
    if ((await handle.stat()).size > fileLimit) throw new Error();
    const bytes = await handle.readFile();
    if (bytes.length > fileLimit) throw new Error();
    let text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (encryptionKey) text = decryptText(text, encryptionKey, 'user-defined-secrets');
    if (Buffer.byteLength(text) > 1024 * 1024) throw new Error();
    return validateSensitiveTexts(JSON.parse(text));
  } catch {
    throw new Error('Cannot load sensitive texts file: check encryption mode/key and require valid UTF-8 JSON with nonempty literal strings, excluding single-character ASCII entries, at most 1 MiB, 1024 entries and 4096 bytes per entry');
  } finally {
    await handle?.close();
  }
}

// Patterns are always escaped literals. Match complete existing markers before
// any substring entry so a short configured value cannot damage them.
export function replaceSensitiveTexts(text, patterns, replace) {
  if (patterns.length === 0) return { body: text, count: 0 };
  const spanning = patterns.filter((value) => /\[REDACTED_/.test(value));
  const literal = patterns.filter((value) => !/\[REDACTED_/.test(value));
  const regex = new RegExp([...spanning.map(escape), RESTORABLE_MARKER_SOURCE, ...literal.map(escape)].join('|'), 'g');
  return transformJsonText(text, (value) => {
    let count = 0;
    const body = value.replace(regex, (match) => {
      if (marker.test(match)) return match;
      count += 1;
      return replace(match);
    });
    return { body, count };
  });
}
