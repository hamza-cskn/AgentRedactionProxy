// Priority for partial overlaps: a merged span takes the higher-ranked type.
const PRIORITY = ['PRIVATE_KEY', 'PASSWORD', 'API_KEY', 'JWT'];
const rank = (type) => PRIORITY.indexOf(type);

// Overlapping detections never leave a fragment of either secret visible: a
// contained span is absorbed by its container, and partially overlapping
// spans merge into one span typed after the higher-priority detector.
export function resolveSpans(spans) {
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end || rank(a.type) - rank(b.type));
  const resolved = [];
  for (const span of sorted) {
    const last = resolved.at(-1);
    if (!last || span.start >= last.end) {
      resolved.push({ ...span });
    } else if (span.end > last.end) {
      last.end = span.end;
      if (rank(span.type) < rank(last.type)) last.type = span.type;
    }
  }
  return resolved;
}

// Spans must be resolved: sorted and non-overlapping.
export function applySpans(text, spans, replace) {
  let body = '';
  let cursor = 0;
  for (const { start, end, type } of spans) {
    body += text.slice(cursor, start) + replace(type, text.slice(start, end));
    cursor = end;
  }
  return body + text.slice(cursor);
}
