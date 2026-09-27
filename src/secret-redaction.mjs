import { transformJsonText } from './json-text.mjs';
import { resolveRedactionLimits } from './redaction-limits.mjs';

// These are intentionally narrow. Generic long strings, UUIDs, and timestamps
// are useful agent context, not reliable evidence of a credential.
const URL_SCHEME = /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*[ \t]*:[ \t]*\/(?:[ \t]*\/)?/g;
const ENCODED_URL = /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*%3a%2f[^\s"'<>]*/gi;
const MAX_USERINFO_CHARS = 512;
const PORT_VALUE = /^(?:\d+|port|PORT|%s|\$[A-Za-z_][A-Za-z0-9_]*|\$?\{[A-Za-z_][A-Za-z0-9_.]*(?::-[A-Za-z0-9_]+)?\})[!.,;)\]}`]*$/;
const AUTHORITY_TERMINATORS = new Set(['@', '/', '?', '#', '\r', '\n', '"', "'", '<', '>']);
const PRIVATE_KEY_START = /-----BEGIN ((?:[A-Z0-9]+ )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/g;
const UNSAFE_PRIVATE_KEY = /-----(?:BEGIN|END) (?:(?:[A-Z0-9]+ )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|\bPuTTY-User-Key-File-\d+:/;
// Require a prefix boundary so words such as "task-queue" cannot match "sk-".
// Separators (including MY_ prefixes) and appended suffixes still permit masking.
// npm's documented core is 36 alphanumerics; PyPI's payload is at least 85
// base64url characters (api-docs.npmjs.com, docs.pypi.org/api/secrets/).
const API_KEY = /(?<![A-Za-z0-9])(?:github_pat_[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_-]{20,}|gl(?:pat|oas|dt|rt|rtr|cbt|ptt|ft|imt|agent|wt|soat|ffct)-[A-Za-z0-9_-]{8,}|xox[bp]-[A-Za-z0-9_-]{10,}|xapp-[A-Za-z0-9_-]{10,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9_-]{8,}|whsec_[A-Za-z0-9_-]{8,}|sk-ant-[A-Za-z0-9_-]{10,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{20,}|ya29\.[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9_-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16,}|npm_[A-Za-z0-9]{36}[A-Za-z0-9_-]*|pypi-[A-Za-z0-9_-]{85,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+)/g;
const WEB_TOKEN = /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]+={0,2}(?:\.[A-Za-z0-9_-]*={0,2}){2,}/g;
const BASE64_RUN = /[A-Za-z0-9+/_-]+={0,2}/g;

function checkSize(size, maximum) {
  if (size > maximum) throw new Error('Redaction candidate exceeds configured limit');
}

const horizontalSpace = (char) => char === ' ' || char === '\t';

function redactUrlPasswords(value) {
  let body = '';
  let cursor = 0;
  let count = 0;
  for (const match of value.matchAll(URL_SCHEME)) {
    const start = match.index + match[0].length;
    if (start < cursor) continue;
    let end = start;
    while (horizontalSpace(value[end])) end += 1;
    const userStart = end;
    const ipv6 = /^\[[0-9a-f:.%]+\]/i.exec(value.slice(end));
    if (ipv6) end += ipv6[0].length;
    while (end < value.length && value[end] !== ':' && !AUTHORITY_TERMINATORS.has(value[end])) {
      end += 1;
    }
    if (value[end] !== ':') continue;
    const user = value.slice(userStart, end).trim();
    if (/\s/.test(user)) {
      // Do not treat prose or the next URL's scheme as this URL's userinfo.
      // Whitespace in actual userinfo still fails closed.
      if (/^[^\r\n"'<>]*@/.test(value.slice(end))) throw new Error('Unsafe credential URL');
      continue;
    }
    end += 1;
    while (horizontalSpace(value[end])) end += 1;
    // A documented placeholder is not a password; arbitrary angle-bracketed
    // values are not exempted from the credential checks.
    if (/^<password>[ \t]*@/.test(value.slice(end))) continue;
    const passwordStart = end;
    while (end < value.length && !horizontalSpace(value[end])
      && !AUTHORITY_TERMINATORS.has(value[end])) {
      if (end - start >= MAX_USERINFO_CHARS) throw new Error('Unsafe credential URL');
      end += 1;
    }
    const passwordEnd = end;
    while (horizontalSpace(value[end])) end += 1;
    if (value[end] !== '@') {
      // Numeric ports and literal variable placeholders are ordinary code.
      // An @ before the path still signals possible userinfo and is not exempt.
      if (PORT_VALUE.test(value.slice(passwordStart, passwordEnd))
        && !/^[^/?#\r\n"'<>]*@/.test(value.slice(end))) continue;
      throw new Error('Unsafe credential URL');
    }
    if (passwordStart === passwordEnd || end - start > MAX_USERINFO_CHARS
      || !/\/[ \t]*\/$/.test(match[0])) {
      throw new Error('Unsafe credential URL');
    }
    let hostEnd = end + 1;
    while (horizontalSpace(value[hostEnd])) hostEnd += 1;
    const hostStart = hostEnd;
    while (hostEnd < value.length && !/\s/.test(value[hostEnd])
      && !AUTHORITY_TERMINATORS.has(value[hostEnd])) hostEnd += 1;
    if (hostEnd === hostStart || value[hostEnd] === '@') throw new Error('Unsafe credential URL');
    body += `${value.slice(cursor, passwordStart)}REDACTED_PASSWORD`;
    cursor = passwordEnd;
    count += 1;
  }
  return { body: body + value.slice(cursor), count };
}

function redactValue(value, limits, decodedUrl = false) {
  // Size guards are not credential classifiers. Check before any replacement
  // can hide an oversized candidate; never decode arbitrary base64 blobs.
  for (const [blob] of value.matchAll(BASE64_RUN)) checkSize(blob.length, limits.maxBase64Chars);
  for (const [token] of value.matchAll(API_KEY)) checkSize(token.length, limits.maxApiTokenChars);
  for (const [token] of value.matchAll(WEB_TOKEN)) {
    checkSize(token.length, limits.maxJwtChars);
    const header = token.slice(0, token.indexOf('.')).replace(/=+$/, '');
    checkSize(Math.floor(header.length * 3 / 4), limits.maxJwtHeaderBytes);
  }
  let count = 0;
  let cursor = 0;
  let body = '';
  for (const match of value.matchAll(PRIVATE_KEY_START)) {
    if (match.index < cursor) continue;
    const footer = `-----END ${match[1]}-----`;
    const end = value.indexOf(footer, match.index + match[0].length);
    if (end === -1) throw new Error('Unsafe private key');
    body += `${value.slice(cursor, match.index)}[REDACTED_PRIVATE_KEY]`;
    cursor = end + footer.length;
    count += 1;
  }
  body += value.slice(cursor);
  // Truncated/mismatched PEM and unsupported PuTTY blocks must not pass through.
  if (UNSAFE_PRIVATE_KEY.test(body)) throw new Error('Unsafe private key');

  for (const [encoded] of body.matchAll(ENCODED_URL)) {
    // Do not recursively unwrap arbitrary encoding layers. Uncertain encoded
    // credentials are rejected rather than rewritten into a different URL.
    if (decodedUrl) throw new Error('Unsafe encoded URL');
    let decoded;
    try { decoded = decodeURIComponent(encoded); } catch { throw new Error('Unsafe encoded URL'); }
    if (redactValue(decoded, limits, true).count > 0) throw new Error('Unsafe encoded credential URL');
  }

  const urls = redactUrlPasswords(body);
  count += urls.count;
  body = urls.body.replace(API_KEY, () => {
    count += 1;
    return '[REDACTED_API_KEY]';
  });
  body = body.replace(WEB_TOKEN, (token) => {
    // Validate only the recognizable header, not signatures or claim lengths.
    // This also covers JWE without leaving its encrypted segments behind.
    let header;
    try { header = JSON.parse(Buffer.from(token.slice(0, token.indexOf('.')), 'base64url').toString('utf8')); } catch { return token; }
    if (!header || typeof header.alg !== 'string') return token;
    count += 1;
    return '[REDACTED_JWT]';
  });

  return { body, count };
}

export function redactSecrets(text, redactionLimits) {
  const limits = resolveRedactionLimits(redactionLimits);
  return transformJsonText(text, (value) => redactValue(value, limits));
}
