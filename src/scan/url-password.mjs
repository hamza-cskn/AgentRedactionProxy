import { isIP } from 'node:net';

// Scan literal URL syntax, including spaced delimiters and unknown schemes.
// We do not evaluate templates or infer computed credentials.
// Unknown schemes and spaced separators use the same credential checks.
const URL_SCHEME = /(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*)([ \t]*(?::+[ \t]*)?\/(?:[ \t]*\/)*)/g;
const AUTHORITY_END = new Set(['@', '/', '?', '#', '\r', '\n', '"', "'", '<', '>']);
const TEXT_END = '\r\n"\'<>';
const MAX_USERINFO_CHARS = 512;

const horizontalSpace = (char) => char === ' ' || char === '\t';

function skipSpace(text, index) {
  while (horizontalSpace(text[index])) index += 1;
  return index;
}

function hasAtBefore(text, index, delimiters) {
  for (; index < text.length; index += 1) {
    if (text[index] === '@') return true;
    if (delimiters.includes(text[index])) return false;
  }
  return false;
}

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

function readAuthorityPrefix(text, match) {
  const start = match.index + match[0].length;
  const fieldStart = skipSpace(text, start);
  let end = fieldStart;
  const ipv6 = /^\[([^\]\s@]+)\]/.exec(text.slice(end));
  if (ipv6 && isIP(ipv6[1]) === 6) end += ipv6[0].length;
  while (end < text.length && text[end] !== ':' && !AUTHORITY_END.has(text[end])) {
    if (horizontalSpace(text[end])) {
      const rest = text.slice(end);
      if (/^[ \t]+[;!—–]/.test(rest)) break;
      if (/^[ \t]+[A-Za-z][A-Za-z0-9+.-]*[ \t]*:[ \t]*\//.test(rest)) break;
    }
    end += 1;
  }
  if (text[end] !== ':') return null;
  return {
    start,
    field: text.slice(fieldStart, end).trim(),
    colon: end,
    ipv6: ipv6?.[0],
    doubleSlash: match[2].replace(/[ \t]/g, '') === '://',
  };
}

function endsAfterNumericPort(text, match, prefix, valueStart) {
  if (!prefix.doubleSlash) return false;
  const hostLike = /^[A-Za-z0-9_.-]+$/.test(prefix.field) || prefix.field === prefix.ipv6;
  const numeric = /^\d+/.exec(text.slice(valueStart));
  if (!hostLike || !numeric || Number(numeric[0]) > 65535) return false;
  const afterPort = valueStart + numeric[0].length;
  if (horizontalSpace(text[afterPort])) {
    return text[skipSpace(text, afterPort)] !== '@';
  }
  if (text[afterPort] === '—' || text[afterPort] === '–') {
    return !hasAtBefore(text, afterPort, ' \t/?#' + TEXT_END);
  }
  return text[match.index - 1] === '['
    && /^\]\([A-Za-z][A-Za-z0-9+.-]*:\/\//.test(text.slice(afterPort));
}

function readPortOrPassword(text, start, authorityStart) {
  const template = portTemplate(text.slice(start));
  let end = start + (template?.length ?? 0);
  while (end < text.length && !horizontalSpace(text[end]) && !AUTHORITY_END.has(text[end])) {
    if (end - authorityStart >= MAX_USERINFO_CHARS) return null;
    end += 1;
  }
  return { end, next: skipSpace(text, end) };
}

// Unparseable URL-like text is skipped; only identified passwords are redacted.
function passwordSpan(text, match) {
  const prefix = readAuthorityPrefix(text, match);
  if (!prefix) return null;
  if (/\s/.test(prefix.field)) return null;
  const start = skipSpace(text, prefix.colon + 1);
  if (/^<password>[ \t]*@/.test(text.slice(start))) return null;
  if (endsAfterNumericPort(text, match, prefix, start)) return null;
  const candidate = readPortOrPassword(text, start, prefix.start);
  if (!candidate || text[candidate.next] !== '@') return null;
  if (start === candidate.end || candidate.next - prefix.start > MAX_USERINFO_CHARS) return null;
  if (!prefix.doubleSlash) return null;
  const hostStart = skipSpace(text, candidate.next + 1);
  let hostEnd = hostStart;
  while (hostEnd < text.length && !/\s/.test(text[hostEnd]) && !AUTHORITY_END.has(text[hostEnd])) hostEnd += 1;
  if (hostEnd === hostStart || text[hostEnd] === '@') {
    return null;
  }
  return { start, end: candidate.end };
}

export function urlPasswordSpans(text) {
  const spans = [];
  let cursor = 0;
  for (const match of text.matchAll(URL_SCHEME)) {
    // Ordinary relative paths are not scheme-less credential URLs.
    if (match[2].replace(/[ \t]/g, '') === '/') continue;
    if (match.index + match[0].length < cursor) continue;
    const span = passwordSpan(text, match);
    if (!span) continue;
    spans.push({ ...span, type: 'PASSWORD' });
    cursor = span.end;
  }
  return spans;
}
