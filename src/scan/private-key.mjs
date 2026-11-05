const PRIVATE_KEY_MARKER = /-----(BEGIN|END) ((?:[A-Z0-9]+ )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|\bPuTTY-User-Key-File-\d+:/g;

// Truncated PEM and PuTTY blocks run through the end of the string; an orphan
// END runs back to the previous span. Never reject: a rejected marker stays
// in the history and would fail every later request.
export function privateKeySpans(value) {
  const spans = [];
  let cursor = 0;
  for (const match of value.matchAll(PRIVATE_KEY_MARKER)) {
    if (match.index < cursor) continue;
    let start = match.index;
    let end = value.length;
    if (match[1] === 'BEGIN') {
      const footer = `-----END ${match[2]}-----`;
      const footerIndex = value.indexOf(footer, match.index + match[0].length);
      if (footerIndex !== -1) end = footerIndex + footer.length;
    } else if (match[1] === 'END') {
      start = cursor;
      end = match.index + match[0].length;
    }
    spans.push({ start, end, type: 'PRIVATE_KEY' });
    cursor = end;
  }
  return spans;
}
