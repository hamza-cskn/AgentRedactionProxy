import { getSystemErrorMap } from 'node:util';
import { RedactionCandidateSizeError } from './redaction-limits.mjs';

export function logMetadata(logger, metadata) {
  logger(JSON.stringify({ timestamp: new Date().toISOString(), ...metadata }));
}

const SAFE_ERROR_NAMES = new Set([
  'Error', 'TypeError', 'RangeError', 'SyntaxError', 'AggregateError',
  'AbortError', 'TimeoutError',
]);
const SAFE_ERROR_CODES = new Set([
  ...Array.from(getSystemErrorMap().values(), ([name]) => name),
  'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT',
  'UND_ERR_SOCKET', 'UND_ERR_ABORTED', 'UND_ERR_DESTROYED', 'UND_ERR_CLOSED',
  'UND_ERR_INVALID_ARG', 'UND_ERR_INVALID_RETURN_VALUE', 'UND_ERR_NOT_SUPPORTED',
  'UND_ERR_REQ_CONTENT_LENGTH_MISMATCH', 'UND_ERR_RES_CONTENT_LENGTH_MISMATCH',
  'UND_ERR_HEADERS_OVERFLOW', 'UND_ERR_RES_EXCEEDED_MAX_SIZE',
  'ERR_INVALID_CHAR', 'ERR_INVALID_HTTP_TOKEN', 'ERR_INVALID_URL', 'ERR_ENCODING_INVALID_ENCODED_DATA',
  'ERR_STREAM_PREMATURE_CLOSE', 'ERR_HTTP_HEADERS_SENT',
  'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
]);

const SAFE_REDACTION_REASONS = new Map([
  ['Redaction candidate exceeds configured limit', 'redaction-candidate-too-large'],
  ['Unsafe private key', 'unsafe-private-key'],
  ['Unsafe encoded URL', 'unsafe-encoded-url'],
  ['Unsafe encoded credential URL', 'unsafe-encoded-credential-url'],
]);

// Never log arbitrary exception strings: messages, stacks and even custom
// names/codes can contain request data. Bound causes, including aggregate errors.
// Candidate size failures deliberately include a bounded request-text preview.
export function errorDiagnostics(error, depth = 0) {
  const result = {
    name: SAFE_ERROR_NAMES.has(error?.name) ? error.name : 'UnknownError',
  };
  if (error?.code !== undefined) {
    result.code = SAFE_ERROR_CODES.has(error.code) ? error.code : 'UNKNOWN_ERROR_CODE';
  }
  if (SAFE_REDACTION_REASONS.has(error?.message)) {
    result.reason = SAFE_REDACTION_REASONS.get(error.message);
  }
  if (error instanceof RedactionCandidateSizeError) {
    result.candidateLength = error.candidateLength;
    result.candidateLimit = error.candidateLimit;
    result.candidateType = error.candidateType;
    result.candidateUnit = error.candidateUnit;
    result.candidatePreview = error.candidatePreview;
  }
  if (depth < 3) {
    if (error?.cause) result.cause = errorDiagnostics(error.cause, depth + 1);
    if (error instanceof AggregateError) {
      result.errors = error.errors.slice(0, 4).map((item) => errorDiagnostics(item, depth + 1));
    }
  }
  return result;
}
