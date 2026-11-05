import { ipSpans } from './ip.mjs';
import { secretSpans } from './secrets.mjs';
import { resolveSpans } from './spans.mjs';

// Every sensitive span of one decoded string, resolved and non-overlapping.
// Without secrets, only IPv4 addresses are detected.
export function scanString(value, { limits, mode, secrets = true, customText = () => [] }) {
  const spans = ipSpans(value);
  if (secrets) spans.push(...secretSpans(value, limits, mode), ...customText(value));
  return resolveSpans(spans);
}
