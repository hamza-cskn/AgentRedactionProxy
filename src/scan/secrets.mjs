import { privateKeySpans } from './private-key.mjs';
import { applySpans, resolveSpans } from './spans.mjs';
import { apiKeySpans, checkSize, checkTokenSizes, jwtSpans } from './tokens.mjs';
import { urlPasswordSpans } from './url-password.mjs';

// These are intentionally narrow. Generic long strings, UUIDs, and timestamps
// are useful agent context, not reliable evidence of a credential.
const ENCODED_URL = /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*%3a%2f[^\s"'<>]*/gi;
const BASE64_RUN = /[A-Za-z0-9+/_-]+={0,2}/g;

function checkEncodedUrls(body, limits, decodedUrl, mode) {
  for (const [encoded] of body.matchAll(ENCODED_URL)) {
    // Do not recursively unwrap arbitrary encoding layers. Uncertain encoded
    // credentials are rejected rather than rewritten into a different URL.
    if (decodedUrl) throw new Error('Unsafe encoded URL');
    let decoded;
    // Literal percent signs are legal surrounding text, not broken escapes.
    // Preserve them while decoding actual %HH sequences for the same checks.
    try {
      decoded = decodeURIComponent(encoded.replace(/%(?![0-9a-f]{2})/gi, '%25'));
    } catch {
      throw new Error('Unsafe encoded URL');
    }
    if (scanSecrets(decoded, limits, mode, true).length > 0) throw new Error('Unsafe encoded credential URL');
  }
}

// Built-in secret spans of one decoded string, resolved and non-overlapping.
// Throws when a candidate exceeds a size limit or an encoded URL is unsafe.
export function scanSecrets(value, limits, mode, decodedUrl = false) {
  // Never decode arbitrary base64 blobs; only bound their size.
  for (const [blob] of value.matchAll(BASE64_RUN)) checkSize(blob, blob.length, limits.maxBase64Chars, 'base64');
  checkTokenSizes(value, limits);
  const keys = privateKeySpans(value);
  // Encoded URLs inside a private key are redacted with it, not inspected.
  checkEncodedUrls(applySpans(value, keys, () => '[REDACTED_PRIVATE_KEY]'), limits, decodedUrl, mode);
  return resolveSpans([...keys, ...urlPasswordSpans(value), ...apiKeySpans(value, mode), ...jwtSpans(value, limits)]);
}
