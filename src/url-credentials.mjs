import { isIP } from 'node:net';

// Scan literal URL syntax, including spaced delimiters and unknown schemes.
// We do not evaluate templates or infer computed credentials.
// Capture the scheme separately. Malformed separators still need a credential
// check: a missing colon or an extra slash must not hide a literal password.
const URL_SCHEME = /(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*)([ \t]*(?::+[ \t]*)?\/(?:[ \t]*\/)*)/g;
const AUTHORITY_END = new Set(['@', '/', '?', '#', '\r', '\n', '"', "'", '<', '>']);
const TEXT_END = '\r\n"\'<>';
const MAX_USERINFO_CHARS = 512;
const PORT_PUNCTUATION = /^[!.,;…)\]}`]*$/;
const WEB_SCHEMES = new Set(['http', 'https', 'ws', 'wss']);
const MULTI_HOST_SCHEMES = new Set(['mongodb', 'postgres', 'postgresql']);

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
    scheme: match[1].toLowerCase(),
    start,
    fieldStart,
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
    if (end - authorityStart >= MAX_USERINFO_CHARS) throw new Error('Unsafe credential URL');
    end += 1;
  }
  return { start, end, next: skipSpace(text, end), template, value: text.slice(start, end) };
}

function isConfiguredPort(value) {
  return /^\d+$/.test(value) || /^\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})$/.test(value);
}

function isHostListPort(value, allowVariables = false) {
  const [port, ...hosts] = value.split(',');
  const validPort = (part) => allowVariables ? isConfiguredPort(part) : /^\d+$/.test(part);
  if (!validPort(port) || hosts.length === 0) return false;
  return hosts.every((host) => {
    const match = /^([A-Za-z0-9_.-]+|\[[0-9a-f:.%]+\])(?::(.+))?$/i.exec(host);
    return match !== null && (match[2] === undefined || validPort(match[2]));
  });
}

function isWebReplacementPort(value) {
  const numeric = /^\d+/.exec(value);
  if (!numeric || Number(numeric[0]) > 65535) return false;
  // Keep closing braces belonging to references; strip only surrounding prose.
  const references = value.slice(numeric[0].length);
  const match = /^(?:\$(?:[A-Za-z0-9_]+|\{[A-Za-z0-9_]+\}))+/.exec(references);
  return match !== null && PORT_PUNCTUATION.test(references.slice(match[0].length));
}

function isSqlServerPort(value) {
  const [port, ...options] = value.split(';');
  if (!isConfiguredPort(port) || options.length === 0) return false;
  if (options.at(-1) === '') options.pop();
  return options.length > 0 && options.every((option) => /^[A-Za-z_][A-Za-z0-9_]*=[^;\s]*$/.test(option));
}

function isSchemePort(scheme, value) {
  if (WEB_SCHEMES.has(scheme)) return isWebReplacementPort(value);
  if (MULTI_HOST_SCHEMES.has(scheme)) return isHostListPort(value, true);
  if (scheme === 'sqlserver') return isSqlServerPort(value);
  return false;
}

function isRecognizedPort(text, prefix, candidate) {
  const { value, template, next } = candidate;
  if (hasAtBefore(text, next, '/?#' + TEXT_END)) return false;
  const plain = value.replace(/[!.,;…)\]}`]*$/, '');
  if (/^\d+$/.test(plain) || plain === 'port' || plain === 'PORT') return true;
  if (/^\$[A-Za-z_][A-Za-z0-9_]*$/.test(plain)) return true;
  if (template && PORT_PUNCTUATION.test(value.slice(template.length))) return true;
  if (isHostListPort(value)) return true;
  if (/^\d+(?:;[A-Za-z_][A-Za-z0-9_]*=[^;\s]*)+;?$/.test(value)) return true;
  // New syntax exceptions are deliberately stricter about a later @, even
  // after /?#: it may belong to a mistyped credential rather than a path.
  if (!hasAtBefore(text, candidate.start, TEXT_END) && isSchemePort(prefix.scheme, value)) return true;
  if (value !== '' || prefix.field === '') return false;
  if (next === text.length || TEXT_END.includes(text[next])) return true;
  return text[next] === '/' && !hasAtBefore(text, next, TEXT_END);
}

// Return a password span only after classifying the authority. Unrecognized
// port expressions retain the existing fail-closed policy, even without @.
function passwordSpan(text, match) {
  const prefix = readAuthorityPrefix(text, match);
  if (!prefix) return null;
  if (/\s/.test(prefix.field)) {
    if (hasAtBefore(text, prefix.colon, TEXT_END)) throw new Error('Unsafe credential URL');
    return null;
  }
  const start = skipSpace(text, prefix.colon + 1);
  if (/^<password>[ \t]*@/.test(text.slice(start))) return null;
  if (endsAfterNumericPort(text, match, prefix, start)) return null;
  const candidate = readPortOrPassword(text, start, prefix.start);
  if (text[candidate.next] !== '@') {
    if (!prefix.doubleSlash && !hasAtBefore(text, prefix.fieldStart, TEXT_END)) return null;
    if (isRecognizedPort(text, prefix, candidate)) return null;
    throw new Error('Unsafe credential URL');
  }
  if (start === candidate.end || candidate.next - prefix.start > MAX_USERINFO_CHARS || !prefix.doubleSlash) {
    throw new Error('Unsafe credential URL');
  }
  const hostStart = skipSpace(text, candidate.next + 1);
  let hostEnd = hostStart;
  while (hostEnd < text.length && !/\s/.test(text[hostEnd]) && !AUTHORITY_END.has(text[hostEnd])) hostEnd += 1;
  if (hostEnd === hostStart || text[hostEnd] === '@') {
    throw new Error('Unsafe credential URL');
  }
  return { start, end: candidate.end };
}

export function redactUrlPasswords(text, replace) {
  let body = '';
  let cursor = 0;
  let count = 0;
  for (const match of text.matchAll(URL_SCHEME)) {
    // Ordinary relative paths are not scheme-less credential URLs.
    if (match[2].replace(/[ \t]/g, '') === '/') continue;
    if (match.index + match[0].length < cursor) continue;
    const span = passwordSpan(text, match);
    if (!span) continue;
    body += text.slice(cursor, span.start) + replace('PASSWORD', text.slice(span.start, span.end));
    cursor = span.end;
    count += 1;
  }
  return { body: body + text.slice(cursor), count };
}
