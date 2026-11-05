import { redactUrlPasswords } from './url-credentials.mjs';
import { transformJsonText } from './scan/traverse.mjs';
import { privateKeySpans } from './scan/private-key.mjs';
import { applySpans } from './scan/spans.mjs';
import { RedactionCandidateSizeError, resolveRedactionLimits } from './redaction-limits.mjs';

// These are intentionally narrow. Generic long strings, UUIDs, and timestamps
// are useful agent context, not reliable evidence of a credential.
const ENCODED_URL = /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*%3a%2f[^\s"'<>]*/gi;
// Require a prefix boundary so words such as "task-queue" cannot match "sk-".
// Separators (including MY_ prefixes) and appended suffixes still permit masking.
// npm's documented core is 36 alphanumerics; PyPI's payload is at least 85
// base64url characters (api-docs.npmjs.com, docs.pypi.org/api/secrets/).
const API_KEY_FORMATS = [
  /github_pat_[A-Za-z0-9_-]{20,}/,                                  // GitHub fine-grained
  /gh[pousr]_[A-Za-z0-9_-]{20,}/,                                  // GitHub classic/OAuth
  /gl(?:pat|oas|dt|rt|rtr|cbt|ptt|ft|imt|agent|wt|soat|ffct)-[A-Za-z0-9_-]{8,}/,
  /xox[bp]-[A-Za-z0-9_-]{10,}/,                                   // Slack bot/user
  /xapp-[A-Za-z0-9_-]{10,}/,                                      // Slack app
  /(?:sk|rk)_(?:live|test)_[A-Za-z0-9_-]{8,}/,                      // Stripe
  /whsec_[A-Za-z0-9_-]{8,}/,                                      // Stripe webhook
  /sk-ant-[A-Za-z0-9_-]{10,}/,                                    // Anthropic
  /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/,                              // OpenAI
  /AIza[0-9A-Za-z_-]{20,}/,                                       // Google API key
  /ya29\.[A-Za-z0-9_-]{20,}/,                                     // Google OAuth
  /hf_[A-Za-z0-9_-]{20,}/,                                        // Hugging Face
  /(?:AKIA|ASIA)[A-Z0-9]{16,}/,                                   // AWS access key
  /npm_[A-Za-z0-9]{36}[A-Za-z0-9_-]*/,
  /pypi-[A-Za-z0-9_-]{85,}/,
  /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/,                   // SendGrid
  /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+/,
];
const API_KEY = new RegExp(`(?<![A-Za-z0-9])(?:${API_KEY_FORMATS.map((pattern) => pattern.source).join('|')})`, 'g');
const WEB_TOKEN = /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]+={0,2}(?:\.[A-Za-z0-9_-]*={0,2}){2,}/g;
const BASE64_RUN = /[A-Za-z0-9+/_-]+={0,2}/g;
const FILENAME_SUFFIX = /^\.(?:[a-z]{3}|yaml|jpeg|json|html|toml|conf|js|ts|py|go|rs|sh|c|h)(?=$|[\s"'`)\]},;])/i;

function checkSize(candidate, size, maximum, type, unit) {
  if (size > maximum) throw new RedactionCandidateSizeError(candidate, size, maximum, type, unit);
}

function checkJwtCandidate(token, limits) {
  const header = token.slice(0, token.indexOf('.')).replace(/=+$/, '');
  // JWT/JWE protected headers are JSON objects. A small, bounded sample can
  // rule out dotted identifiers without parsing or allocating the full header.
  const sampleChars = Math.min(64, Math.floor(limits.maxJwtHeaderBytes / 3) * 4);
  const sample = Buffer.from(header.slice(0, sampleChars), 'base64url');
  for (const byte of sample) {
    if ([32, 9, 10, 13].includes(byte)) continue;
    if (byte !== 123) return false;
    break;
  }
  // All-whitespace samples are uncertain, not an exemption for padded headers.
  checkSize(token, token.length, limits.maxJwtChars, 'jwt');
  checkSize(header, Math.floor(header.length * 3 / 4), limits.maxJwtHeaderBytes, 'jwt-header', 'bytes');
  return true;
}

function checkCandidateSizes(value, limits) {
  // Size guards are not credential classifiers. Check before any replacement
  // can hide an oversized candidate; never decode arbitrary base64 blobs.
  for (const [blob] of value.matchAll(BASE64_RUN)) checkSize(blob, blob.length, limits.maxBase64Chars, 'base64');
  for (const [token] of value.matchAll(API_KEY)) checkSize(token, token.length, limits.maxApiTokenChars, 'api-token');
  for (const [token] of value.matchAll(WEB_TOKEN)) checkJwtCandidate(token, limits);
}

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
    if (redactValue(decoded, limits, true, mode).count > 0) throw new Error('Unsafe encoded credential URL');
  }
}

function isFilenameToken(token, suffix, mode) {
  // Default mode deliberately preserves token-shaped filenames. Log
  // sanitization and paranoic mode do not use this exception.
  if (mode !== 'default' || !FILENAME_SUFFIX.test(suffix)) return false;
  if (token.startsWith('hf_')) return true;
  return token.startsWith('sk-') && !['sk-ant-', 'sk-proj-', 'sk-svcacct-'].some((prefix) => token.startsWith(prefix));
}

function isJwt(token, limits) {
  // Recognize the header only, including JWE; do not validate signatures.
  if (!checkJwtCandidate(token, limits)) return false;
  try {
    const header = JSON.parse(Buffer.from(token.slice(0, token.indexOf('.')), 'base64url').toString('utf8'));
    return typeof header?.alg === 'string';
  } catch {
    return false;
  }
}

function redactValue(value, limits, decodedUrl = false, mode = 'paranoic', replace = permanentMarker) {
  checkCandidateSizes(value, limits);
  let count = 0;
  const redact = (type, secret) => {
    count += 1;
    return replace(type, secret);
  };
  let body = applySpans(value, privateKeySpans(value), redact);
  checkEncodedUrls(body, limits, decodedUrl, mode);
  body = redactUrlPasswords(body, redact).body;
  body = body.replace(API_KEY, (token, offset, input) => {
    return isFilenameToken(token, input.slice(offset + token.length), mode) ? token : redact('API_KEY', token);
  });
  body = body.replace(WEB_TOKEN, (token) => isJwt(token, limits) ? redact('JWT', token) : token);
  return { body, count };
}

const permanentMarker = (type) => type === 'PASSWORD' ? 'REDACTED_PASSWORD' : `[REDACTED_${type}]`;

export function redactSecrets(text, redactionLimits, mode = 'paranoic', replace = permanentMarker) {
  const limits = resolveRedactionLimits(redactionLimits);
  return transformJsonText(text, (value) => redactValue(value, limits, false, mode, replace));
}
