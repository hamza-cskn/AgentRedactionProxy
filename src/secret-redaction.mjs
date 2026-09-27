import { transformJsonText } from './json-text.mjs';

// These are intentionally narrow. Generic long strings, UUIDs, and timestamps
// are useful agent context, not reliable evidence of a credential.
const DATABASE_URL = /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis(?:s)?|amqp(?:s)?|mssql|sqlserver):\/\/[^\s"'<>]+/gi;
const JDBC_URL = /\bjdbc:(?:postgresql|mysql|mariadb|sqlserver|oracle|mongodb):[^\s"'<>]+/gi;
const PRIVATE_KEY = /-----BEGIN ((?:[A-Z0-9]+ )?PRIVATE KEY)-----[\s\S]*?-----END \1-----/g;
const API_KEY = /(?<![A-Za-z0-9_-])(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|gl(?:pat|oas|dt|rt|rtr|cbt|ptt|ft|imt|agent|wt|soat|ffct)-[A-Za-z0-9_-]{8,}|xox[bp]-[A-Za-z0-9-]{10,}|xapp-[A-Za-z0-9-]{10,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}|whsec_[A-Za-z0-9]{8,}|sk-ant-[A-Za-z0-9_-]{10,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{20,}|npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_-])/g;
const JWT = /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])/g;

function redactValue(value) {
  let body = value;
  let count = 0;

  for (const pattern of [DATABASE_URL, JDBC_URL]) {
    body = body.replace(pattern, (match) => {
      const candidate = match.replace(/[.,;!?)}\]]+$/, '');
      const suffix = match.slice(candidate.length);
      const authority = candidate.split('://')[1]?.split(/[/?#]/, 1)[0] ?? '';
      const hasUserPassword = /^[^:@/]*:[^@/]+@/.test(authority);
      const hasPasswordParameter = /[?;&](?:password|passwd|pwd)=[^&#;]+/i.test(candidate);
      if (!hasUserPassword && !hasPasswordParameter) return match;
      count += 1;
      return `[REDACTED_DATABASE_URL]${suffix}`;
    });
  }

  for (const [pattern, marker] of [
    [PRIVATE_KEY, '[REDACTED_PRIVATE_KEY]'],
    [API_KEY, '[REDACTED_API_KEY]'],
    [JWT, '[REDACTED_JWT]'],
  ]) {
    body = body.replace(pattern, () => {
      count += 1;
      return marker;
    });
  }

  return { body, count };
}

export function redactSecrets(text) {
  return transformJsonText(text, redactValue);
}
