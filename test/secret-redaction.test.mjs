import assert from 'node:assert/strict';
import test from 'node:test';

import { redactSecrets } from '../src/secret-redaction.mjs';

test('redacts provider tokens, PEM private keys, JWTs, and credential-bearing database URLs', () => {
  const token = `sk-${'a'.repeat(24)}`;
  const github = `ghp_${'b'.repeat(24)}`;
  const jwt = [
    Buffer.from('{"alg":"HS256"}').toString('base64url'),
    Buffer.from('{"sub":"example"}').toString('base64url'),
    'c'.repeat(24),
  ].join('.');
  const pem = '-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----';
  const database = 'postgres://alice:secret@db.example/app';
  const input = `${token} ${github} ${jwt} ${pem} ${database}`;
  const result = redactSecrets(input);

  for (const secret of [token, github, jwt, pem, database]) {
    assert.equal(result.body.includes(secret), false);
  }
  assert.equal(result.count, 5);
  assert.match(result.body, /\[REDACTED_API_KEY\]/);
  assert.match(result.body, /\[REDACTED_PRIVATE_KEY\]/);
  assert.match(result.body, /\[REDACTED_JWT\]/);
  assert.match(result.body, /\[REDACTED_DATABASE_URL\]/);
});

test('redacts secrets inside nested JSON strings without touching non-secret identifiers', () => {
  const token = `sk-ant-${'d'.repeat(24)}`;
  const input = JSON.stringify({
    arguments: JSON.stringify({ token, id: '123e4567-e89b-12d3-a456-426614174000' }),
    timestamp: '2026-09-27T14:41:51Z',
    database: 'postgres://db.example/app',
    longValue: 'x'.repeat(48),
  });
  const result = redactSecrets(input);
  assert.equal(result.count, 1);
  assert.equal(result.body.includes(token), false);
  const decoded = JSON.parse(JSON.parse(result.body).arguments);
  assert.equal(decoded.token, '[REDACTED_API_KEY]');
  assert.equal(decoded.id, '123e4567-e89b-12d3-a456-426614174000');
  assert.equal(JSON.parse(result.body).database, 'postgres://db.example/app');
  assert.equal(JSON.parse(result.body).longValue, 'x'.repeat(48));
});

test('redacts Redis passwords and JDBC password parameters but leaves passwordless URLs', () => {
  const input = [
    'rediss://:hunter2@cache.example/0',
    'jdbc:postgresql://db.example/app?user=alice&password=hunter2',
    'postgres://db.example/app',
  ].join(' ');
  const result = redactSecrets(input);
  assert.equal(result.count, 2);
  assert.equal(result.body.includes('hunter2'), false);
  assert.equal(result.body.includes('postgres://db.example/app'), true);
});
