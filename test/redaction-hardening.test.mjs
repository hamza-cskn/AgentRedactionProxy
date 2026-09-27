import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { MappingStore } from '../src/mapping-store.mjs';
import { createProxy } from '../src/proxy.mjs';
import { redactSecrets } from '../src/secret-redaction.mjs';

// Synthetic text only. Credentials and IPv4 addresses are critical in both
// modes: paranoic must block anything it cannot redact with certainty, while
// default may forward ambiguous text only after the secret is removed.
const key = 'Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78';
const opaque = 'opaqueValue123';
const pemBody = 'QUJDREVGRw==';

// Each case must either be redacted or rejected; its fragments must never
// reach the model.
const leakTexts = [
  ['token followed by a hyphen suffix', `ghp_${key}-old`, [key]],
  ['token preceded by an underscore prefix', `MY_ghp_${key}`, [key]],
  ['Stripe key followed by an underscore suffix', `sk_live_${key}_old`, [key]],
  ['Anthropic key followed by a dot suffix', `sk-ant-api03-${key}.bak`, [key]],
  ['five-part JWE', `eyJhbGciOiJSU0EtT0FFUCJ9.${key}.${key}x.${key}y.${key}z`, [key]],
  ['PGP private key block', `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${pemBody}\n-----END PGP PRIVATE KEY BLOCK-----`, [pemBody]],
  ['PuTTY private key', `PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPublic-Lines: 1\nAAAA\nPrivate-Lines: 1\n${pemBody}\nPrivate-MAC: ${key}`, [pemBody, key]],
  ['indented PEM in YAML', `tls:\n  key: |\n    -----BEGIN PRIVATE KEY-----\n    ${pemBody}\n    -----END PRIVATE KEY-----`, [pemBody]],
  ['AWS access key ID', 'aws_access_key_id = AKIAZ7Q3EXAMPLE4KEY2', ['AKIAZ7Q3EXAMPLE4KEY2']],
  ['AWS secret access key', `aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/${key}`, [key]],
  ['Google OAuth access token', `ya29.${key}_synthetic-tail`, [key]],
  ['Hugging Face token', `hf_${key}`, [key]],
  ['Slack incoming webhook', `https://hooks.slack.com/services/T01ABCDEF/B01ABCDEF/${key}`, [key]],
  ['libpq keyword DSN password', 'host=db.example user=alice password=hunter2 dbname=app', ['hunter2']],
  ['ADO.NET password', 'Server=db.example;User Id=alice;Password=hunter2;Encrypt=true', ['hunter2']],
  ['ODBC Pwd', 'Driver={PostgreSQL};Server=db.example;Uid=alice;Pwd=hunter2;', ['hunter2']],
  ['percent-encoded credential URL', 'next=postgres%3A%2F%2Falice%3Ahunter2%40db.example%2Fapp', ['hunter2']],
  ['password followed by two words and an email', 'mongo://alice:hunter2 see me@example.com', ['hunter2']],
  ['git token as userinfo password', `https://x-access-token:ghs_${key}@github.com/org/repo.git`, [key]],
  ['git token as bare userinfo', `https://ghp_${key}@github.com/org/repo.git`, [key]],
];
for (const name of ['access_token', 'refresh_token', 'id_token', 'auth_token', 'client_secret', 'private_token', 'sig']) {
  leakTexts.push([`${name} query parameter`, `https://api.example/cb?state=abc&${name}=${opaque}&mode=read`, [opaque]]);
}

// Text that must pass through untouched so ordinary agent work keeps working.
const benignTexts = [
  ['scp-style git remote', 'git@github.com:org/repo.git'],
  ['SSH URL with user and port', 'ssh://git@github.com:22/org/repo'],
  ['Windows file URL', 'file:///C:/Users/alice/project'],
  ['at-sign in URL path after port', 'http://localhost:3000/users/@alice'],
  ['username and port without password', 'https://alice@host.example:8443/path'],
  ['angle-bracket password placeholder', 'postgres://alice:<password>@db.example/app'],
  ['SSH public key', `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${key} alice@laptop`],
  ['container digest', `sha256:${'ab12cd34'.repeat(8)}`],
  ['pagination query', 'https://api.example/items?page=2&sort=asc&limit=50'],
  ['clock time', 'Deploy at 12:30:45 UTC.'],
  ['Windows path', String.raw`C:\Users\alice\project`],
  ['mailto and URN', 'mailto:alice@example.com urn:ietf:rfc:3986'],
  ['token-like prose words', 'The token count and password policy are documented.'],
];

const assertSafeRejection = (error, fragments) => {
  assert.ok(error instanceof Error);
  for (const fragment of fragments) {
    assert.equal(error.message.includes(fragment), false, 'errors must not echo credential text');
  }
  return true;
};

for (const [name, input, fragments] of leakTexts) {
  for (const [shape, wrap] of [
    ['plain', (text) => text],
    ['nested tool arguments', (text) => JSON.stringify({ arguments: JSON.stringify({ content: text }) })],
  ]) {
    test(`hardening leak (${shape}): ${name}`, () => {
      let result;
      try {
        result = redactSecrets(wrap(input));
      } catch (error) {
        assertSafeRejection(error, fragments);
        return;
      }
      for (const fragment of fragments) {
        assert.equal(result.body.includes(fragment), false, `fragment survived: ${fragment}`);
      }
      assert.ok(result.count >= 1);
    });
  }
}

for (const [name, input] of benignTexts) {
  test(`hardening benign text is unchanged: ${name}`, () => {
    assert.deepEqual(redactSecrets(input), { body: input, count: 0 });
  });
}

// IPv4 is critical information in every mode.
async function createStore() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'redaction-hardening-'));
  return MappingStore.open(path.join(directory, 'mappings.json'));
}

for (const [name, input, fragments] of [
  ['IPv4-mapped IPv6', '::ffff:10.20.30.40', ['10.20.30.40']],
  ['nip.io hostname', 'http://10.20.30.40.nip.io:8080/', ['10.20.30.40']],
  ['reverse DNS name', '40.30.20.10.in-addr.arpa', ['40.30.20.10']],
  ['version-prefixed address', 'v10.20.30.40', ['10.20.30.40']],
  ['AWS private DNS hostname', 'ssh ec2-user@ip-10-20-30-40.ec2.internal', ['10-20-30-40']],
]) {
  test(`hardening IPv4 text never survives: ${name}`, async () => {
    const store = await createStore();
    const result = await store.obfuscate(input);
    for (const fragment of fragments) {
      assert.equal(result.body.includes(fragment), false, `real address survived: ${fragment}`);
    }
    assert.ok(result.count >= 1);
  });
}

// The same texts through each mode's request path.
async function send(mode, body) {
  const forwarded = [];
  const proxy = createProxy({
    mode,
    store: await createStore(),
    protectAllPostBodies: true,
    logger: () => {},
    fetchImpl: async (_url, init) => {
      forwarded.push(init.body.toString('utf8'));
      return new Response('{}');
    },
  });
  await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${proxy.address().port}/v1/messages`, { method: 'POST', body });
    return { status: response.status, text: await response.text(), forwarded };
  } finally {
    await new Promise((resolve) => proxy.close(resolve));
  }
}

const ipInSecretContext = [
  ['URL password and host IP', 'mongo://alice:hunter2@10.20.30.40:27017/app', ['hunter2', '10.20.30.40']],
  ['libpq DSN with host IP', 'host=10.20.30.40 user=alice password=hunter2', ['hunter2', '10.20.30.40']],
  ['token beside IP', `10.20.30.40 ghp_${key}-old`, [key, '10.20.30.40']],
];

for (const mode of ['paranoic', 'default']) {
  for (const [name, input, fragments] of [...leakTexts, ...ipInSecretContext]) {
    test(`${mode} hardening request never forwards: ${name}`, async () => {
      const { text, forwarded } = await send(mode, input);
      for (const body of [...forwarded, text]) {
        for (const fragment of fragments) {
          assert.equal(body.includes(fragment), false, `fragment reached upstream or client: ${fragment}`);
        }
      }
    });
  }
  for (const [name, input] of benignTexts) {
    test(`${mode} hardening request forwards benign text unchanged: ${name}`, async () => {
      const { status, forwarded } = await send(mode, input);
      assert.equal(status, 200);
      assert.deepEqual(forwarded, [input]);
    });
  }
}

// Ambiguous credential boundaries: paranoic must not guess.
for (const [name, input] of [
  ['password followed by two words and an email', 'mongo://alice:hunter2 see me@example.com'],
  ['space inside password with host IP', 'mongo://alice:hunter 2@10.20.30.40/app'],
]) {
  test(`paranoic hardening blocks ambiguous text: ${name}`, async () => {
    const { status, forwarded } = await send('paranoic', input);
    assert.deepEqual(forwarded, [], 'ambiguous credential text must not be forwarded');
    assert.equal(status, 502);
  });
}
