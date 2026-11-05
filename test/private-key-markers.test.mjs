import assert from 'node:assert/strict';
import test from 'node:test';
import { redactSecrets } from '../src/secret-redaction.mjs';
import { KEY_MARKER, MODES, assertNoLeak, entropy, pem, prng, proxyHarness, puttyHeader } from './helpers/harness.mjs';

const KEY = '[REDACTED_PRIVATE_KEY]';
const TYPES = ['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'OPENSSH PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'PGP PRIVATE KEY BLOCK'];
// No TYPES entry is DSA, so this footer never closes the opening marker.
const MISMATCHED = 'DSA PRIVATE KEY';

// [scenario, input for a key type, expected body]; each redacts exactly once.
const SHAPES = [
  ['unterminated BEGIN redacts to the end of the string', (type) => `${pem.begin(type)}\nBODY`, KEY],
  ['text before an unterminated BEGIN is kept', (type) => `keep\n${pem.begin(type)}\nBODY`, `keep\n${KEY}`],
  ['mismatched END is treated as unterminated', (type) => `${pem.begin(type)}\nBODY\n${pem.end(MISMATCHED)}\nTAIL`, KEY],
  ['orphan END redacts back to the string start', (type) => `BODY\n${pem.end(type)}\nkeep`, `${KEY}\nkeep`],
  ['complete block keeps the text after it', (type) => `${pem.block('BODY', type)}\nkeep`, `${KEY}\nkeep`],
  ['CRLF block keeps the text after it', (type) => `${pem.begin(type)}\r\nBODY\r\n${pem.end(type)}\r\nkeep`, `${KEY}\r\nkeep`],
  ['extra dashes stay outside the redaction', (type) => `-${pem.begin(type)}-BODY-${pem.end(type)}-keep`, `-${KEY}-keep`],
];

for (const mode of MODES) {
  for (const type of TYPES) {
    for (const [scenario, build, expected] of SHAPES) {
      test(`redactSecrets (${mode}, ${type}): ${scenario}`, () => {
        const input = build(type);

        const result = redactSecrets(input, undefined, mode);

        assert.deepEqual(result, { body: expected, count: 1 });
      });
    }
  }
}

for (const mode of MODES) {
  for (const version of [1, 2, 3, 10]) {
    test(`redactSecrets (${mode}): PuTTY v${version} header redacts to the end of the string`, () => {
      const input = `keep ${puttyHeader(version)} ssh-ed25519\nPrivate-Lines: 1\nBODY`;

      const result = redactSecrets(input, undefined, mode);

      assert.deepEqual(result, { body: `keep ${KEY}`, count: 1 });
    });
  }
}

// [scenario, input, expected body, expected count]
const SEQUENCES = [
  ['two complete blocks keep the text between them',
    `a ${pem.block('S1')} b ${pem.block('S2', 'EC PRIVATE KEY')} c`, `a ${KEY} b ${KEY} c`, 2],
  ['orphan END before a block redacts only up to itself',
    `S0 ${pem.end()} b ${pem.begin()} S1 ${pem.end()} c`, `${KEY} b ${KEY} c`, 2],
  ['second END after a block redacts the text between them',
    `a ${pem.begin()} S1 ${pem.end()} S2 ${pem.end()} c`, `a ${KEY}${KEY} c`, 2],
  ['inner BEGIN of another type stays inside the outer block',
    `a ${pem.begin()} S1 ${pem.begin('RSA PRIVATE KEY')} S2 ${pem.end()} c`, `a ${KEY} c`, 1],
  ['unterminated outer BEGIN swallows a later complete block',
    `a ${pem.begin()} S1 ${pem.begin('RSA PRIVATE KEY')} S2 ${pem.end('RSA PRIVATE KEY')} c`, `a ${KEY}`, 1],
  ['PuTTY header swallows a later END',
    `a ${puttyHeader()} S1 ${pem.end()} c`, `a ${KEY}`, 1],
  ['PuTTY header after a block keeps the text between them',
    `a ${pem.begin()} S1 ${pem.end()} b ${puttyHeader()} S2`, `a ${KEY} b ${KEY}`, 2],
];

for (const mode of MODES) {
  for (const [scenario, input, body, count] of SEQUENCES) {
    test(`redactSecrets (${mode}): ${scenario}`, () => {
      const result = redactSecrets(input, undefined, mode);

      assert.deepEqual(result, { body, count });
    });
  }
}

// [scenario, request value, expected value after redaction]
const JSON_SCOPES = [
  ['unterminated BEGIN stops at the end of its JSON string',
    { a: `keep1 ${pem.begin()}\nS1`, b: 'keep2' }, { a: `keep1 ${KEY}`, b: 'keep2' }],
  ['orphan END stops at the start of its JSON string',
    { a: 'keep1', b: `S1\n${pem.end()} keep2` }, { a: 'keep1', b: `${KEY} keep2` }],
  ['key split across two JSON strings is redacted in both',
    { a: `keep1 ${pem.begin()}\nS1`, b: `S2\n${pem.end()} keep2`, c: 'keep3' }, { a: `keep1 ${KEY}`, b: `${KEY} keep2`, c: 'keep3' }],
  ['marker in a property name is redacted',
    { [`${pem.begin()} S1`]: 'keep' }, { [KEY]: 'keep' }],
  ['Messages text block is redacted and its sibling kept',
    { messages: [{ role: 'user', content: [{ type: 'text', text: `${pem.begin()}\nS1` }, { type: 'text', text: 'keep' }] }] },
    { messages: [{ role: 'user', content: [{ type: 'text', text: KEY }, { type: 'text', text: 'keep' }] }] }],
  ['JSON nested in tool arguments is redacted',
    { arguments: JSON.stringify({ k: `${pem.begin()} S1`, o: 'keep' }) }, { arguments: JSON.stringify({ k: KEY, o: 'keep' }) }],
];

for (const mode of MODES) {
  for (const [scenario, value, expected] of JSON_SCOPES) {
    test(`redactSecrets (${mode}): ${scenario}`, () => {
      const input = JSON.stringify(value);

      const result = redactSecrets(input, undefined, mode);

      assert.deepEqual(JSON.parse(result.body), expected);
    });
  }
}

// [look-alike, text]; none of these is a private key.
const LOOK_ALIKES = [
  ['certificate block', `${pem.begin('CERTIFICATE')}\nQUJD\n${pem.end('CERTIFICATE')}`],
  ['public key block', `${pem.begin('PUBLIC KEY')}\nQUJD\n${pem.end('PUBLIC KEY')}`],
  ['RSA public key block', `${pem.begin('RSA PUBLIC KEY')}\nQUJD\n${pem.end('RSA PUBLIC KEY')}`],
  ['unterminated certificate request', `${pem.begin('CERTIFICATE REQUEST')}\nQUJD`],
  ['orphan CRL footer', `${pem.end('X509 CRL')} trailing`],
  ['marker words without dashes', 'BEGIN PRIVATE KEY and END PRIVATE KEY without dashes'],
  ['lowercase marker', `${pem.begin('private key')} lowercase`],
  ['four-dash marker', `${'-'.repeat(4)}BEGIN PRIVATE KEY${'-'.repeat(4)} four dashes`],
  ['double-space marker', `${pem.begin(' PRIVATE KEY')} double space`],
  ['marker without closing dashes', `${pem.begin().slice(0, -5)} no closing dashes`],
  ['plural marker', `${pem.begin('PRIVATE KEYS')} plural`],
  ['lowercase key type', `${pem.begin('rsa PRIVATE KEY')} lowercase type`],
  ['markdown horizontal rules', `${'-'.repeat(5)}\nmarkdown rule\n${'-'.repeat(5)}`],
  ['prose about key files', 'the private key lives in ~/.ssh/id_ed25519, the public key in id_ed25519.pub'],
  ['PuTTY header without a colon', 'PuTTY-User-Key-File-3 has no colon'],
  ['PuTTY header inside a word', 'MyPuTTY-User-Key-File-3: is not at a word boundary'],
  ['PuTTY header without a version', 'PuTTY-User-Key-File-: has no version'],
  ['PuTTY header with a non-numeric version', 'PuTTY-User-Key-File-x: has no numeric version'],
  ['SSH public key line', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host'],
];
const WRAPS = [['plain text', (text) => text], ['JSON string', (text) => JSON.stringify({ text })]];

for (const mode of MODES) {
  for (const [wrapName, wrap] of WRAPS) {
    for (const [lookAlike, text] of LOOK_ALIKES) {
      test(`redactSecrets (${mode}, ${wrapName}): ${lookAlike} is left untouched`, () => {
        const input = wrap(text);

        const result = redactSecrets(input, undefined, mode);

        assert.deepEqual(result, { body: input, count: 0 });
      });
    }
  }
}

// Fuzz is the one place with generator logic (docs/testing.md). Key material
// always directly follows an opening marker or directly precedes a closing one,
// so it sits inside a redacted span. A PuTTY header needs a word boundary before it.
function fuzzCase(seed) {
  const random = prng(seed);
  const pick = (items) => items[Math.floor(random() * items.length)];
  const separators = [' ', '\n', '\r\n', '', '\t'];
  const prefix = Array.from({ length: Math.floor(random() * 3) }, (_, index) => `word${seed}x${index}Z`).join(' ');
  const secrets = [];
  let text = prefix;
  let first = null;
  for (let index = 0, segments = 1 + Math.floor(random() * 6); index < segments; index += 1) {
    const roll = random();
    const separator = pick(separators);
    if (roll < 0.45) {
      const secret = entropy(16, seed * 64 + index);
      secrets.push(secret);
      const opening = random() < 0.5;
      first ??= opening ? 'open' : 'end';
      text += opening
        ? (random() < 0.5 ? `${separator}${pem.begin(pick(TYPES))}` : `${separator || ' '}${puttyHeader(1 + Math.floor(random() * 3))}`) + `${separator}${secret}`
        : `${separator}${secret}${separator}${pem.end(pick(TYPES))}`;
    } else if (roll < 0.7) {
      first ??= 'end';
      text += `${separator}${pem.end(pick(TYPES))}`;
    } else {
      text += `${separator}plain${seed}x${index}P`;
    }
  }
  // Output must start with: the whole text when there is no marker, the
  // redaction when an orphan END comes first, otherwise the prefix.
  const start = first === null ? text : first === 'end' ? KEY : prefix;
  return { text, secrets, start };
}

const FUZZ_WRAPS = [
  ['plain text', (text) => text, (body) => body],
  ['JSON string', (text) => JSON.stringify({ text }), (body) => JSON.parse(body).text],
  ['JSON in tool arguments', (text) => JSON.stringify({ arguments: JSON.stringify({ text }) }),
    (body) => JSON.parse(JSON.parse(body).arguments).text],
];
const SEEDS = 3000;

for (const mode of MODES) {
  for (const [wrapName, wrap, unwrap] of FUZZ_WRAPS) {
    test(`redactSecrets fuzz (${mode}, ${wrapName}): no marker or key material survives over ${SEEDS} seeds`, () => {
      for (let seed = 1; seed <= SEEDS; seed += 1) {
        const { text, secrets, start } = fuzzCase(seed);
        const where = `seed ${seed}: ${JSON.stringify(text)}`;

        const result = redactSecrets(wrap(text), undefined, mode);
        const output = unwrap(result.body);

        assert.equal(KEY_MARKER.test(output), false, `marker survived, ${where}`);
        assertNoLeak(output, secrets, `output of ${where}`);
        assert.ok(output.startsWith(start), `wrong start, ${where}`);
        // Every redacted span holds a marker at least as long as KEY.
        assert.ok(output.length <= text.length, `output grew, ${where}`);
        assert.equal(result.count, output.split(KEY).length - 1, `count mismatch, ${where}`);
        assert.deepEqual(redactSecrets(result.body, undefined, mode), { body: result.body, count: 0 }, `not idempotent, ${where}`);
      }
    });
  }
}

// One history with every broken shape; key bodies are distinctive for leak checks.
const KEY_BODIES = [entropy(24, 101), entropy(24, 102), entropy(24, 103), entropy(24, 104)];
const BROKEN_KEYS = [
  { role: 'user', content: `please look at ${pem.begin()}\n${KEY_BODIES[0]}` },
  { role: 'assistant', content: `${KEY_BODIES[1]}\n${pem.end('RSA PRIVATE KEY')}\nok` },
  { role: 'user', content: `${puttyHeader()} ssh-rsa\n${KEY_BODIES[2]}` },
  { role: 'assistant', content: `${pem.begin('EC PRIVATE KEY')}\n${KEY_BODIES[3]}\n${pem.end('RSA PRIVATE KEY')}` },
];
const conversation = (...turns) => ({ model: 'm', messages: [...BROKEN_KEYS, ...turns.map((content) => ({ role: 'user', content }))] });
const MESSAGES = { path: '/v1/messages' };

for (const mode of MODES) {
  test(`proxy (${mode}): broken keys in history do not block the next turns`, async (t) => {
    const h = await proxyHarness(t, { mode });

    const first = await h.send(conversation('turn 1'), MESSAGES);
    const second = await h.send(conversation('turn 1', 'turn 2'), MESSAGES);
    const third = await h.send(conversation('turn 1', 'turn 2', 'turn 3'), MESSAGES);

    assert.deepEqual([first.status, second.status, third.status], [200, 200, 200]);
    assert.equal(h.upstream.length, 3);
  });

  test(`proxy (${mode}): upstream receives no key marker or key material`, async (t) => {
    const h = await proxyHarness(t, { mode });

    await h.send(conversation('turn 1'), MESSAGES);

    assert.equal(KEY_MARKER.test(h.upstream[0].body), false);
    assertNoLeak(h.upstream[0].body, KEY_BODIES, 'upstream body');
  });

  test(`proxy (${mode}): client gets its original text back`, async (t) => {
    const h = await proxyHarness(t, { mode });
    const body = JSON.stringify(conversation('turn 1'));

    const response = await h.send(body, MESSAGES);

    assert.equal(response.body, body);
  });

  test(`proxy (${mode}): logs contain no key marker or key material`, async (t) => {
    const h = await proxyHarness(t, { mode });

    await h.send(conversation('turn 1'), MESSAGES);

    assert.equal(KEY_MARKER.test(h.logs.join('\n')), false);
    assertNoLeak(h.logs.join('\n'), KEY_BODIES, 'logs');
  });
}

test('proxy (paranoic): a percent-encoded key marker in the request path is redacted in logs',
  { todo: 'logPathname redacts the still percent-encoded path, so %20 inside a marker defeats the match' }, async (t) => {
    const h = await proxyHarness(t, { mode: 'paranoic', store: {} });
    const keyBody = entropy(24, 105);

    await h.send('', { method: 'GET', path: `/v1/${encodeURIComponent(`${pem.begin()}${keyBody}`)}` });

    assertNoLeak(h.logs.join('\n'), keyBody, 'logs');
  });
