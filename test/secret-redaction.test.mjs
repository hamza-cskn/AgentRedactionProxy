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
  assert.match(result.body, /postgres:\/\/alice:REDACTED_PASSWORD@db\.example\/app/);
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

test('redacts URL passwords across schemes while preserving connection structure', () => {
  const input = [
    'rediss://:hunter2@cache.example/0',
    'jdbc:postgresql://db.example/app?user=alice&password=hunter2',
    'mongdb : / / app_user : hunter2 @ 10.20.30.40:27017/analytics_db?replicaSet=rs0',
    'postgres://db.example/app',
  ].join(' ');
  const result = redactSecrets(input);
  assert.equal(result.count, 3);
  assert.equal(result.body.includes('hunter2'), false);
  assert.equal(result.body.includes('rediss://:REDACTED_PASSWORD@cache.example/0'), true);
  assert.equal(result.body.includes('jdbc:postgresql://db.example/app?user=alice&password=REDACTED_PASSWORD'), true);
  assert.equal(result.body.includes('mongdb : / / app_user : REDACTED_PASSWORD @ 10.20.30.40:27017/analytics_db?replicaSet=rs0'), true);
  assert.equal(result.body.includes('postgres://db.example/app'), true);
});

test('rejects ambiguous credential-shaped URLs rather than forwarding a possible password', () => {
  assert.throws(() => redactSecrets('mongdb://user:pass word@host'), /Unsafe credential URL/);
  assert.throws(() => redactSecrets(`mongdb://user:${'x'.repeat(600)}@host`), /Unsafe credential URL/);
  assert.equal(redactSecrets('https://example.com:8443/path').body, 'https://example.com:8443/path');
  const prose = `See https://example.com ${'word '.repeat(200)}`;
  assert.equal(redactSecrets(prose).body, prose);
});
