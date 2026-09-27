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

// Synthetic text only: these are expectations, not snapshots of the current
// regexes. Compare the complete output so a surviving secret suffix fails too.
const key = 'Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78';
const apiMarker = '[REDACTED_API_KEY]';
const pemMarker = '[REDACTED_PRIVATE_KEY]';
const jwtMarker = '[REDACTED_JWT]';
const passwordMarker = 'REDACTED_PASSWORD';
const github = `ghp_${key}`;
const jwtHeader = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url');
const jwtPayload = Buffer.from('{"sub":"synthetic-user"}').toString('base64url');
const jwt = `${jwtHeader}.${jwtPayload}.${key}`;
const privateKey = '-----BEGIN PRIVATE KEY-----\nQUJDREVGRw==\n-----END PRIVATE KEY-----';

const providerTokens = [
  ['OpenAI legacy', `sk-${key}`],
  ['OpenAI project', `sk-proj-${key}_synthetic-tail`],
  ['OpenAI service account', `sk-svcacct-${key}_synthetic-tail`],
  ['Anthropic', `sk-ant-api03-${key}_synthetic-tail`],
  ['GitHub classic', github],
  ['GitHub fine-grained', `github_pat_${key}_synthetic_tail`],
  ['GitHub OAuth', `gho_${key}`],
  ['GitHub user', `ghu_${key}`],
  ['GitHub server', `ghs_${key}`],
  ['GitHub refresh', `ghr_${key}`],
  ['GitLab personal', `glpat-${key}_synthetic-tail`],
  ['GitLab OAuth', `gloas-${key}`],
  ['GitLab deploy', `gldt-${key}`],
  ['GitLab runner', `glrt-${key}`],
  ['GitLab runner registration', `glrtr-${key}`],
  ['GitLab CI', `glcbt-${key}`],
  ['GitLab pipeline trigger', `glptt-${key}`],
  ['GitLab feed', `glft-${key}`],
  ['GitLab incoming mail', `glimt-${key}`],
  ['GitLab agent', `glagent-${key}`],
  ['GitLab workspace', `glwt-${key}`],
  ['GitLab SCIM', `glsoat-${key}`],
  ['GitLab feature flag', `glffct-${key}`],
  ['Slack bot', `xoxb-1234567890-9876543210-${key}`],
  ['Slack user', `xoxp-1234567890-9876543210-${key}`],
  ['Slack app', `xapp-1-${key}-1234567890`],
  ['Stripe live', `sk_live_${key}`],
  ['Stripe test', `sk_test_${key}`],
  ['Stripe restricted live', `rk_live_${key}`],
  ['Stripe restricted test', `rk_test_${key}`],
  ['Stripe webhook', `whsec_${key}`],
  ['Google', `AIza${key}_synthetic-tail`],
  ['npm', `npm_${key}`],
  ['PyPI', `pypi-${key}_synthetic-tail`],
  ['SendGrid', `SG.${key}.${key}_synthetic-tail`],
];

for (const [name, token] of providerTokens) {
  test(`secret text: redacts the entire ${name} token`, () => {
    assert.deepEqual(redactSecrets(token), { body: apiMarker, count: 1 });
  });
  test(`secret text: redacts ${name} tokens in pasted configuration`, () => {
    assert.deepEqual(redactSecrets(`API_TOKEN="${token}" # synthetic fixture`), {
      body: `API_TOKEN="${apiMarker}" # synthetic fixture`, count: 1,
    });
  });
}

const redactedTexts = [
  ['token in prose', `Use ${github} for this test.`, `Use ${apiMarker} for this test.`],
  ['pasted bearer header text', `Authorization: Bearer ${github}`, `Authorization: Bearer ${apiMarker}`],
  ['Markdown fence', `\x60\x60\x60env\nTOKEN=${github}\n\x60\x60\x60`, `\x60\x60\x60env\nTOKEN=${apiMarker}\n\x60\x60\x60`],
  ['punctuation', `(${github}),[${github}];${github}!`, `(${apiMarker}),[${apiMarker}];${apiMarker}!`, 3],
  ['Unicode context', `anahtar「${github}」gizli`, `anahtar「${apiMarker}」gizli`],
  ['repeated token across CRLF', `${github}\r\n${github}`, `${apiMarker}\r\n${apiMarker}`, 2],
  ['JWT', jwt, jwtMarker],
  ['JWT with short claims', `${jwtHeader}.e30.${key}`, jwtMarker],
  ['JWT with padded claims', `${jwtHeader}.e30=.${key}`, jwtMarker],
  ['unsigned JWT', `${Buffer.from('{"alg":"none"}').toString('base64url')}.${jwtPayload}.`, jwtMarker],
  ['JWT with whitespace in its decoded header', `${Buffer.from('{\n "alg": "HS256"\n}').toString('base64url')}.${jwtPayload}.${key}`, jwtMarker],
  ['two JWTs', `${jwt},${jwt}`, `${jwtMarker},${jwtMarker}`, 2],
  ['PEM', privateKey, pemMarker],
  ['PEM with CRLF', privateKey.replaceAll('\n', '\r\n'), pemMarker],
  ['PEM in prose', `before\n${privateKey}\nafter`, `before\n${pemMarker}\nafter`],
  ['adjacent PEM blocks', `${privateKey}${privateKey}`, `${pemMarker}${pemMarker}`, 2],
  ['token inside PEM is covered by the block', privateKey.replace('QUJDREVGRw==', github), pemMarker],
  ['MongoDB multi-host URL', 'mongodb://app_user:S3cr3t_99@10.20.30.40:27017,10.20.30.41:27017/analytics_db?replicaSet=rs0&authSource=admin&ssl=true', 'mongodb://app_user:REDACTED_PASSWORD@10.20.30.40:27017,10.20.30.41:27017/analytics_db?replicaSet=rs0&authSource=admin&ssl=true'],
  ['MongoDB SRV', 'mongodb+srv://alice:secret@cluster.example/app', 'mongodb+srv://alice:REDACTED_PASSWORD@cluster.example/app'],
  ['misspelled scheme', 'mongdb://alice:secret@db.example/app', 'mongdb://alice:REDACTED_PASSWORD@db.example/app'],
  ['unknown scheme', 'custom+db.v2://alice:secret@db.example/app', 'custom+db.v2://alice:REDACTED_PASSWORD@db.example/app'],
  ['uppercase scheme', 'POSTGRES://alice:secret@db.example/app', 'POSTGRES://alice:REDACTED_PASSWORD@db.example/app'],
  ['HTTP userinfo', 'https://alice:secret@service.example/path', 'https://alice:REDACTED_PASSWORD@service.example/path'],
  ['Redis without username', 'rediss://:secret@cache.example/0', 'rediss://:REDACTED_PASSWORD@cache.example/0'],
  ['encoded URL password', 'postgres://alice:p%40ss%3Aword%20two@db.example/app', 'postgres://alice:REDACTED_PASSWORD@db.example/app'],
  ['colon in URL password', 'postgres://alice:one:two:three@db.example/app', 'postgres://alice:REDACTED_PASSWORD@db.example/app'],
  ['Unicode password', 'mysql://alice:şifre密碼@db.example/app', 'mysql://alice:REDACTED_PASSWORD@db.example/app'],
  ['shell punctuation in password', 'mysql://alice:p$!&=word@db.example/app', 'mysql://alice:REDACTED_PASSWORD@db.example/app'],
  ['spaces around delimiters', 'mongdb : / / alice : secret @ db.example/app', 'mongdb : / / alice : REDACTED_PASSWORD @ db.example/app'],
  ['tabs around delimiters', 'mongo\t:\t/\t/\talice\t:\tsecret\t@\tdb.example/app', 'mongo\t:\t/\t/\talice\t:\tREDACTED_PASSWORD\t@\tdb.example/app'],
  ['JDBC userinfo', 'jdbc:postgresql://alice:secret@db.example/app', 'jdbc:postgresql://alice:REDACTED_PASSWORD@db.example/app'],
  ['JDBC query password', 'jdbc:postgresql://db.example/app?user=alice&password=secret', 'jdbc:postgresql://db.example/app?user=alice&password=REDACTED_PASSWORD'],
  ['JDBC semicolon password', 'jdbc:sqlserver://db.example;user=alice;password=secret;encrypt=true', 'jdbc:sqlserver://db.example;user=alice;password=REDACTED_PASSWORD;encrypt=true'],
  ['mixed-case query name and surrounding spaces', 'https://db.example/?PaSsWoRd = secret &mode=read', 'https://db.example/?PaSsWoRd = REDACTED_PASSWORD &mode=read'],
  ['query password containing spaces', 'https://db.example/?password=two secret words&mode=read', 'https://db.example/?password=REDACTED_PASSWORD&mode=read'],
  ['double-quoted query password', 'https://db.example/?password="two secret words"&mode=read', 'https://db.example/?password="REDACTED_PASSWORD"&mode=read'],
  ['single-quoted query password', "https://db.example/?password='two secret words'&mode=read", "https://db.example/?password='REDACTED_PASSWORD'&mode=read"],
  ['encoded query parameter name', 'https://db.example/?pass%77ord=secret&mode=read', 'https://db.example/?pass%77ord=REDACTED_PASSWORD&mode=read'],
  ['repeated password query parameters', 'https://db.example/?password=first&password=second', 'https://db.example/?password=REDACTED_PASSWORD&password=REDACTED_PASSWORD', 2],
  ['userinfo and query password', 'postgres://alice:first@db.example/app?password=second', 'postgres://alice:REDACTED_PASSWORD@db.example/app?password=REDACTED_PASSWORD', 2],
  ['API token as userinfo password', `postgres://alice:${github}@db.example/app`, 'postgres://alice:REDACTED_PASSWORD@db.example/app'],
  ['API token as query password', `https://db.example/?token=${github}`, 'https://db.example/?token=REDACTED_PASSWORD'],
  ['different URLs on separate lines', 'postgres://alice:first@one.example/app\nredis://:second@two.example/0', 'postgres://alice:REDACTED_PASSWORD@one.example/app\nredis://:REDACTED_PASSWORD@two.example/0', 2],
  ['all categories together', `${github}\n${jwt}\n${privateKey}\npostgres://alice:secret@db.example/app`, `${apiMarker}\n${jwtMarker}\n${pemMarker}\npostgres://alice:REDACTED_PASSWORD@db.example/app`, 4],
  ['malformed JSON still contains a literal token', `{"token":"${github}",`, `{"token":"${apiMarker}",`],
];

for (const kind of ['RSA', 'EC', 'DSA', 'OPENSSH', 'ENCRYPTED']) {
  redactedTexts.push([
    `${kind} PEM block`,
    `-----BEGIN ${kind} PRIVATE KEY-----\nQUJDREVGRw==\n-----END ${kind} PRIVATE KEY-----`,
    pemMarker,
  ]);
}
for (const name of ['passwd', 'pwd', 'secret', 'token', 'api_key', 'api-key', 'apikey']) {
  redactedTexts.push([
    `${name} query parameter`,
    `https://db.example/?${name}=secret&mode=read`,
    `https://db.example/?${name}=REDACTED_PASSWORD&mode=read`,
  ]);
}

for (const [name, input, expected, count = 1] of redactedTexts) {
  test(`secret text: ${name}`, () => {
    assert.deepEqual(redactSecrets(input), { body: expected, count });
    assert.equal(redactSecrets(expected).body, expected, 'redacting twice must not change the output');
  });
}

const unchangedTexts = [
  ['empty text', ''],
  ['ordinary prose', 'Explain how to configure the database.'],
  ['obvious short placeholders', 'sk-example ghp_example glpat-example npm_example'],
  ['UUID', '123e4567-e89b-12d3-a456-426614174000'],
  ['timestamp', '2026-09-27T14:41:51.055Z'],
  ['hex digest', 'ab12cd34'.repeat(8)],
  ['random identifier', key.repeat(3)],
  ['generic dotted identifier', 'abcdefghijk.lmnopqrstuv.wxyz0123456'],
  ['version', 'v1.2.3'],
  ['public key', '-----BEGIN PUBLIC KEY-----\nQUJDREVGRw==\n-----END PUBLIC KEY-----'],
  ['certificate', '-----BEGIN CERTIFICATE-----\nQUJDREVGRw==\n-----END CERTIFICATE-----'],
  ['passwordless database URL', 'mongodb://10.20.30.40:27017/app?replicaSet=rs0&authSource=admin&ssl=true'],
  ['username without password', 'ssh://alice@host.example'],
  ['HTTPS host and port', 'https://example.com:8443/path'],
  ['email in a URL path', 'https://example.com/contact/alice@example.com'],
  ['URL followed by long prose', `See https://example.com ${'word '.repeat(200)}`],
  ['IPv6 is outside the IPv4 contract', 'http://[2001:db8::1]:8080/path'],
  ['non-secret query values', 'https://db.example/?authSource=admin&replicaSet=rs0&ssl=true'],
  ['similar but different query keys', 'https://db.example/?passwordPolicy=strict&tokenCount=42&apikeyName=primary'],
  ['query names without assignment', 'https://db.example/?password&token'],
  ['already redacted markers', `${apiMarker} ${pemMarker} ${jwtMarker} ${passwordMarker}`],
  ['arbitrary passwords are not a supported pattern', 'PASSWORD=ordinary-example'],
  ['email and phone are outside the contract', 'alice@example.com +1-202-555-0100'],
  ['base64 content is explicitly outside the contract', Buffer.from(github).toString('base64')],
];

for (const [name, input] of unchangedTexts) {
  test(`non-secret or out-of-scope text: ${name}`, () => {
    assert.deepEqual(redactSecrets(input), { body: input, count: 0 });
  });
}

// A rejected request is preferable to guessing a credential boundary and
// forwarding a suffix. These tests must stay failing until that is enforced.
const unsafeTexts = [
  ['space inside password', 'mongo://alice:secret word@host.example'],
  ['several words inside password', 'mongo://alice:several secret words here@host.example'],
  ['space inside username', 'mongo://alice smith:secret@host.example'],
  ['raw slash inside password', 'mongo://alice:secret/word@host.example'],
  ['raw question mark inside password', 'mongo://alice:secret?word@host.example'],
  ['raw hash inside password', 'mongo://alice:secret#word@host.example'],
  ['raw at-sign inside password', 'mongo://alice:secret@word@host.example'],
  ['empty password', 'mongo://alice:@host.example'],
  ['overlong password', `mongo://alice:${'x'.repeat(600)}@host.example`],
  ['missing at-sign', 'mongo://alice:secret'],
  ['missing scheme slash', 'mongdb:/alice:secret@host.example'],
  ['unterminated PEM', '-----BEGIN PRIVATE KEY-----\nQUJDREVGRw=='],
  ['mismatched PEM footer', '-----BEGIN RSA PRIVATE KEY-----\nQUJDREVGRw==\n-----END EC PRIVATE KEY-----'],
  ['unterminated quoted query password', 'https://db.example/?password="secret words&mode=read'],
];

for (const [name, input] of unsafeTexts) {
  test(`unsafe secret text must fail closed: ${name}`, () => {
    assert.throws(() => redactSecrets(input), (error) => {
      assert.ok(error instanceof Error);
      for (const fragment of ['QUJDREVGRw==', 'several secret words here', input]) {
        assert.equal(error.message.includes(fragment), false, 'errors must not echo credential text');
      }
      return true;
    });
  });
}

for (const [name, input, expected] of [
  ['API key', github, apiMarker],
  ['PEM', privateKey, pemMarker],
  ['JWT', jwt, jwtMarker],
  ['URL password', 'mongo://alice:secret@host.example', 'mongo://alice:REDACTED_PASSWORD@host.example'],
]) {
  for (const depth of [1, 2, 4]) {
    test(`JSON text: ${name} nested ${depth} levels`, () => {
      let body = input;
      let redacted = expected;
      for (let level = 0; level < depth; level += 1) {
        body = JSON.stringify({ content: body, unchanged: 'ordinary text', count: 7 });
        redacted = JSON.stringify({ content: redacted, unchanged: 'ordinary text', count: 7 });
      }
      assert.deepEqual(redactSecrets(body), { body: redacted, count: 1 });
    });
  }
}

test('JSON text: Unicode-escaped token prefix without changing unrelated bytes', () => {
  const input = ` { "token": "\\u0067hp_${key}", "n": 9007199254740993, "escape": "\\u0041" } `;
  const expected = ` { "token": "${apiMarker}", "n": 9007199254740993, "escape": "\\u0041" } `;
  assert.deepEqual(redactSecrets(input), { body: expected, count: 1 });
});

test('JSON text: property names, arrays, nulls and booleans', () => {
  const input = JSON.stringify({ [github]: [github, null, true, 42, 'ordinary text'] });
  const expected = JSON.stringify({ [apiMarker]: [apiMarker, null, true, 42, 'ordinary text'] });
  assert.deepEqual(redactSecrets(input), { body: expected, count: 2 });
});

test('JSON text: escaped URL delimiters', () => {
  const input = String.raw`{"input":"mongo:\/\/alice\u003asecret\u0040host.example"}`;
  assert.deepEqual(redactSecrets(input), {
    body: '{"input":"mongo://alice:REDACTED_PASSWORD@host.example"}', count: 1,
  });
});

test('JSON text: nested malformed credentials must not bypass rejection', () => {
  const input = JSON.stringify({ arguments: JSON.stringify({ url: 'mongo://alice:secret word@host.example' }) });
  assert.throws(() => redactSecrets(input), /Unsafe credential URL/);
});

test('secret text: a rejection does not contaminate subsequent calls', () => {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    assert.throws(() => redactSecrets('mongo://alice:secret word@host.example'), /Unsafe credential URL/);
    assert.deepEqual(redactSecrets(github), { body: apiMarker, count: 1 });
    assert.deepEqual(redactSecrets('ordinary text'), { body: 'ordinary text', count: 0 });
  }
});

test('long non-secret text and one-dot identifiers remain unchanged', () => {
  for (const input of ['A'.repeat(32_768), `A.${'b'.repeat(32_768)}`]) {
    assert.deepEqual(redactSecrets(input), { body: input, count: 0 });
  }
});
