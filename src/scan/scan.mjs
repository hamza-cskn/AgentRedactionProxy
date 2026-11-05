import { RedactionCandidateSizeError } from '../redaction-limits.mjs';
import { ipSpans } from './ip.mjs';
import { UnsafeEncodedUrlError, secretSpans } from './secrets.mjs';
import { resolveSpans } from './spans.mjs';
import { transformJsonText } from './traverse.mjs';

// Every sensitive span of one decoded string, resolved and non-overlapping.
// Without secrets, only IPv4 addresses are detected.
export function scanString(value, { limits, mode, secrets = true, customText = () => [] }) {
  const spans = ipSpans(value);
  if (secrets) spans.push(...secretSpans(value, limits, mode), ...customText(value));
  return resolveSpans(spans);
}

// Content the scan refuses to rewrite; the request must be rejected, not retried.
export function isScanRejection(error) {
  return error instanceof RedactionCandidateSizeError || error instanceof UnsafeEncodedUrlError;
}

// Whether a JSON or plain-text body has anything to redact, without state.
export function containsSensitive(text, options) {
  return transformJsonText(text, (value) => ({ body: value, count: scanString(value, options).length })).count > 0;
}
