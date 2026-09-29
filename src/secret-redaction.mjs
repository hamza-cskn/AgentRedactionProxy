import { isIP } from 'node:net';
import { transformJsonText } from './json-text.mjs';
import { resolveRedactionLimits } from './redaction-limits.mjs';

// These are intentionally narrow. Generic long strings, UUIDs, and timestamps
// are useful agent context, not reliable evidence of a credential.
const URL_SCHEME = /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*[ \t]*:[ \t]*\/(?:[ \t]*\/)?/g;
const ENCODED_URL = /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*%3a%2f[^\s"'<>]*/gi;
const MAX_USERINFO_CHARS = 512;
const PORT_VALUE = /^(?:\d+|port|PORT|\$[A-Za-z_][A-Za-z0-9_]*)[!.,;…)\]}`]*$/;
const HOST_LIST_PORTS = /^\d+(?:,(?:[A-Za-z0-9_.-]+|\[[0-9a-f:.%]+\])(?::\d+)?)+$/i;
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
const FILENAME_SUFFIX = /^\.(?:[a-z]{3}|yaml|jpeg|json|html|toml|conf|js|ts|py|go|rs|sh|c|h)(?=$|[\s"'`)\]},;])/i;

function checkSize(size, maximum) {
  if (size > maximum) throw new Error('Redaction candidate exceeds configured limit');
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
  checkSize(token.length, limits.maxJwtChars);
  checkSize(Math.floor(header.length * 3 / 4), limits.maxJwtHeaderBytes);
  return true;
}

const horizontalSpace = (char) => char === ' ' || char === '\t';

function portTemplate(value) {
  const printf = /^%[0-9]*[ds]/.exec(value);
  if (printf) return printf[0];
  const prefix = /^(?:[$#]\{|[$\\]\(|%\(|\{)/.exec(value);
  if (!prefix) return null;
  const stack = [];
  let quote = null;
  for (let index = prefix[0].length - 1; index < value.length; index += 1) {
    const char = value[index];
    if (char === '@' || char === '\r' || char === '\n') return null;
    if (quote) {
      if (char === '\\') {
        if (/[@\r\n]/.test(value[index + 1] ?? '')) return null;
        index += 1;
      } else if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'" || char === '`') {
      quote = char;
    } else if ('{(['.includes(char)) {
      if (stack.length >= 64) return null;
      stack.push(char);
    } else if ('})]'.includes(char)) {
      const opening = char === '}' ? '{' : char === ')' ? '(' : '[';
      if (stack.pop() !== opening) return null;
      if (stack.length === 0) {
        if (prefix[0] === '%(') {
          if (!/[ds]/.test(value[index + 1] ?? '')) return null;
          index += 1;
        }
        return value.slice(0, index + 1);
      }
    }
  }
  return null;
}

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
    const ipv6 = /^\[([^\]\s@]+)\]/.exec(value.slice(end));
    if (ipv6 && isIP(ipv6[1]) === 6) end += ipv6[0].length;
    while (end < value.length && value[end] !== ':' && !AUTHORITY_TERMINATORS.has(value[end])) {
      // Punctuation separated from the hostname belongs to surrounding prose.
      if (horizontalSpace(value[end]) && /^[ \t]+[;!—–]/.test(value.slice(end))) break;
      // A second scheme after whitespace starts a separate URL. Do not scan
      // into its credentials while looking for this URL's port or userinfo.
      if (horizontalSpace(value[end])
        && /^[ \t]+[A-Za-z][A-Za-z0-9+.-]*[ \t]*:[ \t]*\//.test(value.slice(end))) break;
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
    // Recognize a complete host:numeric-port before prose, not an arbitrary
    // password prefix. Immediate @ (including spacing before it) still wins.
    const numeric = /^\d+/.exec(value.slice(end));
    const hostLike = /^[A-Za-z0-9_.-]+$/.test(user) || (ipv6 && user === ipv6[0]);
    if (/\/[ \t]*\/$/.test(match[0]) && hostLike && numeric && Number(numeric[0]) <= 65535) {
      const afterPort = value.slice(end + numeric[0].length);
      const proseBoundary = /^[ \t]+(?![ \t]*@)/.test(afterPort)
        || (/^[—–]/.test(afterPort) && !/^[^ \t/?#\r\n"'<>]*@/.test(afterPort))
        || (value[match.index - 1] === '[' && /^\]\([A-Za-z][A-Za-z0-9+.-]*:\/\//.test(afterPort));
      if (proseBoundary) continue;
    }
    // These are literal port spellings, not evaluated expressions or password
    // exemptions. If followed by @, the entire value is still userinfo.
    const template = portTemplate(value.slice(end));
    if (template) end += template.length;
    while (end < value.length && !horizontalSpace(value[end])
      && !AUTHORITY_TERMINATORS.has(value[end])) {
      if (end - start >= MAX_USERINFO_CHARS) throw new Error('Unsafe credential URL');
      end += 1;
    }
    const passwordEnd = end;
    while (horizontalSpace(value[end])) end += 1;
    if (value[end] !== '@') {
      const candidate = value.slice(passwordStart, passwordEnd);
      const templatePort = template && /^[!.,;…)\]}`]*$/.test(candidate.slice(template.length));
      // Single-slash forms are paths, not URL authorities (e.g. data:/data:ro
      // or C:/data). A possible @ boundary still triggers the malformed-URL
      // checks, so a missing slash cannot exempt actual userinfo.
      const pathOnly = !/\/[ \t]*\/$/.test(match[0]);
      if (pathOnly
        && !/^[^\r\n"'<>]*@/.test(value.slice(userStart))) continue;
      const numericPortWithOptions = /^\d+(?:;[A-Za-z_][A-Za-z0-9_]*=[^;\s]*)+;?$/.test(candidate);
      const emptyTerminalPort = candidate === '' && user !== ''
        && (end === value.length || /[\r\n"'<>]/.test(value[end])
          || (value[end] === '/' && !/^[^\r\n"'<>]*@/.test(value.slice(end))));
      // Numeric ports and literal variable placeholders are ordinary code.
      // An @ before the path still signals possible userinfo and is not exempt.
      if ((PORT_VALUE.test(candidate) || templatePort || HOST_LIST_PORTS.test(candidate)
        || numericPortWithOptions || emptyTerminalPort)
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

function redactValue(value, limits, decodedUrl = false, mode = 'paranoic') {
  // Size guards are not credential classifiers. Check before any replacement
  // can hide an oversized candidate; never decode arbitrary base64 blobs.
  for (const [blob] of value.matchAll(BASE64_RUN)) checkSize(blob.length, limits.maxBase64Chars);
  for (const [token] of value.matchAll(API_KEY)) checkSize(token.length, limits.maxApiTokenChars);
  for (const [token] of value.matchAll(WEB_TOKEN)) checkJwtCandidate(token, limits);
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
    // Literal percent signs are legal surrounding text, not broken escapes.
    // Preserve them while decoding actual %HH sequences for the same checks.
    try { decoded = decodeURIComponent(encoded.replace(/%(?![0-9a-f]{2})/gi, '%25')); } catch { throw new Error('Unsafe encoded URL'); }
    if (redactValue(decoded, limits, true, mode).count > 0) throw new Error('Unsafe encoded credential URL');
  }

  const urls = redactUrlPasswords(body);
  count += urls.count;
  body = urls.body.replace(API_KEY, (token, offset, input) => {
    // Default mode explicitly trades protection of token-shaped filenames for
    // stability. Never use this exception for logging or in paranoic mode.
    if (mode === 'default' && /^(?:sk-(?!(?:ant|proj|svcacct)-)|hf_)/.test(token)
      && FILENAME_SUFFIX.test(input.slice(offset + token.length))) return token;
    count += 1;
    return '[REDACTED_API_KEY]';
  });
  body = body.replace(WEB_TOKEN, (token) => {
    // Validate only the recognizable header, not signatures or claim lengths.
    // This also covers JWE without leaving its encrypted segments behind.
    if (!checkJwtCandidate(token, limits)) return token;
    let header;
    try { header = JSON.parse(Buffer.from(token.slice(0, token.indexOf('.')), 'base64url').toString('utf8')); } catch { return token; }
    if (!header || typeof header.alg !== 'string') return token;
    count += 1;
    return '[REDACTED_JWT]';
  });

  return { body, count };
}

export function redactSecrets(text, redactionLimits, mode = 'paranoic') {
  const limits = resolveRedactionLimits(redactionLimits);
  return transformJsonText(text, (value) => redactValue(value, limits, false, mode));
}
