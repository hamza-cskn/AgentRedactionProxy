import { RESTORABLE_MARKER_SOURCE } from '../sensitive-texts.mjs';

const escape = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const MARKER = new RegExp(`^${RESTORABLE_MARKER_SOURCE}$`);

// Entries are escaped literals, longest first so a shorter entry never splits a
// longer one at the same position. Existing markers are matched first and
// skipped, so a short entry cannot damage a marker it occurs in.
export function customTextMatcher(texts) {
  if (texts.length === 0) return () => [];
  const sorted = [...texts].sort((a, b) => b.length - a.length);
  const regex = new RegExp([RESTORABLE_MARKER_SOURCE, ...sorted.map(escape)].join('|'), 'g');
  return (value) => [...value.matchAll(regex)]
    .filter((match) => !MARKER.test(match[0]))
    .map((match) => ({ start: match.index, end: match.index + match[0].length, type: 'TEXT' }));
}
