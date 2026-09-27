import { transformJsonText } from './json-text.mjs';

// These are intentionally narrow. Generic long strings, UUIDs, and timestamps
// are useful agent context, not reliable evidence of a credential.
const URL_SCHEME = /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*[ \t]*:[ \t]*\/[ \t]*\//g;
const PASSWORD_PARAMETER = /([?;&]\s*(?:password|passwd|pwd|secret|token|api[_-]?key)\s*=\s*)([^&#;\s"'<>]+)/gi;
const MAX_USERINFO_CHARS = 512;
const AUTHORITY_TERMINATORS = new Set(['@', '/', '?', '#', '\r', '\n', '"', "'", '<', '>']);
const PRIVATE_KEY = /-----BEGIN ((?:[A-Z0-9]+ )?PRIVATE KEY)-----[\s\S]*?-----END \1-----/g;
const API_KEY = /(?<![A-Za-z0-9_-])(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|gl(?:pat|oas|dt|rt|rtr|cbt|ptt|ft|imt|agent|wt|soat|ffct)-[A-Za-z0-9_-]{8,}|xox[bp]-[A-Za-z0-9-]{10,}|xapp-[A-Za-z0-9-]{10,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}|whsec_[A-Za-z0-9]{8,}|sk-ant-[A-Za-z0-9_-]{10,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{20,}|npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_-])/g;
const JWT = /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])/g;

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
    while (end < value.length && !horizontalSpace(value[end])
      && value[end] !== ':' && !AUTHORITY_TERMINATORS.has(value[end])) {
      if (end - start >= MAX_USERINFO_CHARS) throw new Error('Unsafe credential URL');
      end += 1;
    }
    while (horizontalSpace(value[end])) end += 1;
    if (value[end] !== ':') continue;
    end += 1;
    while (horizontalSpace(value[end])) end += 1;
    const passwordStart = end;
    while (end < value.length && !horizontalSpace(value[end])
      && !AUTHORITY_TERMINATORS.has(value[end])) {
      if (end - start >= MAX_USERINFO_CHARS) throw new Error('Unsafe credential URL');
      end += 1;
    }
    const passwordEnd = end;
    while (horizontalSpace(value[end])) end += 1;
    if (value[end] !== '@') {
      // A second word immediately followed by @ suggests a malformed password.
      while (end < value.length && !horizontalSpace(value[end])
        && !AUTHORITY_TERMINATORS.has(value[end])) end += 1;
      if (value[end] === '@') throw new Error('Unsafe credential URL');
      continue;
    }
    if (passwordStart === passwordEnd) throw new Error('Unsafe credential URL');
    body += `${value.slice(cursor, passwordStart)}REDACTED_PASSWORD`;
    cursor = passwordEnd;
    count += 1;
  }
  return { body: body + value.slice(cursor), count };
}

function redactValue(value) {
  const urls = redactUrlPasswords(value);
  let body = urls.body;
  let count = urls.count;
  body = body.replace(PASSWORD_PARAMETER, (_match, prefix) => {
    count += 1;
    return `${prefix}REDACTED_PASSWORD`;
  });

  for (const [pattern, marker] of [
    [PRIVATE_KEY, '[REDACTED_PRIVATE_KEY]'],
    [API_KEY, '[REDACTED_API_KEY]'],
    [JWT, '[REDACTED_JWT]'],
  ]) {
    body = body.replace(pattern, () => {
      count += 1;
      return marker;
    });
  }

  return { body, count };
}

export function redactSecrets(text) {
  return transformJsonText(text, redactValue);
}
