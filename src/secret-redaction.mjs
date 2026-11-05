import { resolveRedactionLimits } from './redaction-limits.mjs';
import { secretSpans } from './scan/secrets.mjs';
import { applySpans, resolveSpans } from './scan/spans.mjs';
import { transformJsonText } from './scan/traverse.mjs';

const permanentMarker = (type) => type === 'PASSWORD' ? 'REDACTED_PASSWORD' : `[REDACTED_${type}]`;

export function redactSecrets(text, redactionLimits, mode = 'paranoic', replace = permanentMarker) {
  const limits = resolveRedactionLimits(redactionLimits);
  return transformJsonText(text, (value) => {
    const spans = resolveSpans(secretSpans(value, limits, mode));
    return { body: applySpans(value, spans, replace), count: spans.length };
  });
}
