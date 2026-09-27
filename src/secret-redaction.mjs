import { transformJsonText } from './json-text.mjs';

// These are intentionally narrow. Generic long strings, UUIDs, and timestamps
// are useful agent context, not reliable evidence of a credential.
const URL_SCHEME = /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*[ \t]*:[ \t]*\/(?:[ \t]*\/)?/g;
const ENCODED_URL = /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*%3a%2f[^\s"'<>]*/gi;
const PASSWORD_ASSIGNMENT = /(^|[?;& \t])([A-Za-z0-9_%+-]+)[ \t]*=[ \t]*/gm;
const PASSWORD_NAMES = new Set([
  'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'api-key', 'apikey',
  'access_token', 'refresh_token', 'id_token', 'auth_token', 'client_secret', 'private_token', 'sig',
]);
const AWS_SECRET_NAMES = new Set(['aws_secret_access_key', 'aws_session_token']);
const DSN_FIELD = /(?:^|[; \t])(?:host|hostaddr|dbname|server|driver|user(?:[ \t]+id)?|uid)[ \t]*=/i;
const QUERY_VALUE_END = /[&#;"'<>]|(?<![ \t])[ \t]+(?=[A-Za-z][A-Za-z0-9+.-]*[ \t]*:[ \t]*\/)/;
const DSN_VALUE_END = /[&#;"'<>]|(?<![ \t])[ \t]+(?=[A-Za-z_][A-Za-z0-9_]*[ \t]*=|[A-Za-z][A-Za-z0-9+.-]*[ \t]*:[ \t]*\/)/;
const MAX_USERINFO_CHARS = 512;
const AUTHORITY_TERMINATORS = new Set(['@', '/', '?', '#', '\r', '\n', '"', "'", '<', '>']);
const PRIVATE_KEY_START = /-----BEGIN ((?:[A-Z0-9]+ )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/g;
const UNSAFE_PRIVATE_KEY = /-----(?:BEGIN|END) (?:(?:[A-Z0-9]+ )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|\bPuTTY-User-Key-File-\d+:/;
// A recognizable token remains sensitive when glued to an identifier or suffix.
const API_KEY = /github_pat_[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_-]{20,}|gl(?:pat|oas|dt|rt|rtr|cbt|ptt|ft|imt|agent|wt|soat|ffct)-[A-Za-z0-9_-]{8,}|xox[bp]-[A-Za-z0-9_-]{10,}|xapp-[A-Za-z0-9_-]{10,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9_-]{8,}|whsec_[A-Za-z0-9_-]{8,}|sk-ant-[A-Za-z0-9_-]{10,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{20,}|ya29\.[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9_-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16,}|npm_[A-Za-z0-9_-]{20,}|pypi-[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+/g;
const WEB_TOKEN = /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]+={0,2}(?:\.[A-Za-z0-9_-]*={0,2}){2,}/g;

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
    if (/^\[[0-9a-f:.%]+\](?::\d+)?(?:[/?#\s]|$)/i.test(value.slice(end))) continue;
    const userStart = end;
    while (end < value.length && value[end] !== ':' && !AUTHORITY_TERMINATORS.has(value[end])) {
      end += 1;
    }
    if (value[end] !== ':') continue;
    const user = value.slice(userStart, end).trim();
    if (/\s/.test(user)) throw new Error('Unsafe credential URL');
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
      // Host:port is benign, including @ in a subsequent path. A nonnumeric
      // value after ':' could be a password with a broken or missing boundary.
      if (/^\d+$/.test(value.slice(passwordStart, passwordEnd))
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

function redactPasswordParameters(value) {
  let count = 0;
  const body = value.replace(/[^\r\n]+/g, (line) => {
    const dsn = DSN_FIELD.test(line);
    let cursor = 0;
    let output = '';
    for (const match of line.matchAll(PASSWORD_ASSIGNMENT)) {
      if (match.index < cursor) continue;
      let name;
      try { name = decodeURIComponent(match[2]).toLowerCase(); } catch { continue; }
      const query = /[?;&]/.test(match[1]);
      if (!AWS_SECRET_NAMES.has(name) && !(PASSWORD_NAMES.has(name) && (query || dsn))) continue;
      let start = match.index + match[0].length;
      let end = start;
      const quote = line[start];
      if (quote === '"' || quote === "'") {
        start += 1;
        end = start;
        while (end < line.length && line[end] !== quote) {
          if (line[end] === '\\') end += 1;
          end += 1;
        }
        if (end >= line.length) throw new Error('Unsafe password parameter');
      } else {
        const boundary = (query ? QUERY_VALUE_END : DSN_VALUE_END).exec(line.slice(start));
        end = boundary ? start + boundary.index : line.length;
        while (end > start && horizontalSpace(line[end - 1])) end -= 1;
      }
      if (start === end) continue;
      output += `${line.slice(cursor, start)}REDACTED_PASSWORD`;
      cursor = end;
      count += 1;
    }
    return output + line.slice(cursor);
  });
  return { body, count };
}

function redactValue(value, decodedUrl = false) {
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
    if (redactValue(decoded, true).count > 0) throw new Error('Unsafe encoded credential URL');
  }

  const urls = redactUrlPasswords(body);
  const parameters = redactPasswordParameters(urls.body);
  count += urls.count + parameters.count;
  body = parameters.body.replace(API_KEY, () => {
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

export function redactSecrets(text) {
  return transformJsonText(text, redactValue);
}
