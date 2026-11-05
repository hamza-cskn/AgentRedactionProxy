const DOCUMENTATION_PREFIXES = new Set([
  '192.0.2',
  '198.51.100',
  '203.0.113',
]);
const OCTET = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
const IPV4_PATTERN = new RegExp(`(^|[^0-9.]|(?<![0-9])\\.)(${OCTET}(?:\\.${OCTET}){3})(?!\\.?[0-9])`, 'g');
const AWS_IPV4_PATTERN = new RegExp(`\\b(ip-)(${OCTET}(?:-${OCTET}){3})(?![0-9])`, 'gi');

export function isDocumentationAddress(ip) {
  return DOCUMENTATION_PREFIXES.has(ip.slice(0, ip.lastIndexOf('.')));
}

export function collectExactIpv4(value) {
  IPV4_PATTERN.lastIndex = 0;
  const match = IPV4_PATTERN.exec(value);
  return match && match[0] === value ? match[2] : null;
}

// Each span covers the address only, not the ip- prefix of an AWS hostname.
// Documentation addresses are never sensitive and produce no span.
export function ipSpans(value) {
  const spans = [];
  for (const [pattern, hyphenated] of [[IPV4_PATTERN, false], [AWS_IPV4_PATTERN, true]]) {
    pattern.lastIndex = 0; // matchAll starts at lastIndex; collectExactIpv4 moves it.
    for (const match of value.matchAll(pattern)) {
      const [, prefix, address] = match;
      if (isDocumentationAddress(hyphenated ? address.replaceAll('-', '.') : address)) continue;
      const start = match.index + prefix.length;
      spans.push({ start, end: start + address.length, type: 'IP' });
    }
  }
  return spans;
}

export function replaceAddresses(text, lookup, fallback = null) {
  let count = 0;
  let body = text;
  for (const [pattern, hyphenated] of [[IPV4_PATTERN, false], [AWS_IPV4_PATTERN, true]]) {
    pattern.lastIndex = 0;
    body = body.replace(pattern, (match, prefix, address) => {
      const ip = hyphenated ? address.replaceAll('-', '.') : address;
      const replacement = lookup(ip);
      if (replacement === ip) return match;
      if (replacement === null || replacement === undefined) {
        return fallback === null ? match : `${prefix}${fallback}`;
      }
      count += 1;
      return `${prefix}${hyphenated ? replacement.replaceAll('.', '-') : replacement}`;
    });
  }
  return { body, count };
}

