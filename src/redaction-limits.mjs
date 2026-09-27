export const DEFAULT_REDACTION_LIMITS = Object.freeze({
  maxApiTokenChars: 4096,
  maxJwtChars: 16384,
  maxJwtHeaderBytes: 4096,
  maxBase64Chars: 65536,
});

export function resolveRedactionLimits(overrides = {}) {
  if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) {
    throw new Error('redactionLimits must be an object');
  }
  for (const [name, value] of Object.entries(overrides)) {
    if (!Object.hasOwn(DEFAULT_REDACTION_LIMITS, name)) {
      throw new Error('Unknown redaction limit');
    }
    if (!Number.isSafeInteger(value) || value < 1 || value > 64 * 1024 * 1024) {
      throw new Error('Redaction limits must be integers between 1 and 67108864');
    }
  }
  return { ...DEFAULT_REDACTION_LIMITS, ...overrides };
}
