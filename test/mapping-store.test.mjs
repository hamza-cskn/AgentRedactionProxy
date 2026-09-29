import assert from 'node:assert/strict';
import { mappedText, legacyStore } from './helpers/mapping-fixtures.mjs';
import { execFile } from 'node:child_process';
import fs, { chmod, mkdtemp, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import {
  MappingStore,
  containsSensitiveIpv4,
} from '../src/mapping-store.mjs';

async function statePath() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'opencode-ipv4-store-'));
  return path.join(directory, 'mappings.json');
}

test('obfuscates consistently and reverses mapped addresses', async () => {
  const store = await MappingStore.open(await statePath());
  const first = await store.obfuscate('127.0.0.1 then 10.0.0.1 then 127.0.0.1');
  const second = await store.obfuscate('10.0.0.1 and 8.8.8.8');

  assert.equal(first.body, mappedText(store, '192.0.2.1 then 192.0.2.2 then 192.0.2.1'));
  assert.equal(first.count, 3);
  assert.equal(second.body, mappedText(store, '192.0.2.2 and 192.0.2.3'));
  assert.equal((await store.deobfuscate(second.body)).body, '10.0.0.1 and 8.8.8.8');
});

test('preserves mappings across store restarts', async () => {
  const filePath = await statePath();
  const firstStore = await MappingStore.open(filePath);
  await firstStore.obfuscate('192.168.24.21');

  const secondStore = await MappingStore.open(filePath);
  const transformed = await secondStore.obfuscate('192.168.24.21 and 172.16.0.1');

  assert.equal(transformed.body, mappedText(secondStore, '192.0.2.1 and 192.0.2.2'));
  const persisted = JSON.parse(await readFile(filePath, 'utf8'));
  assert.equal(persisted.mappings.length, 2);
});

test('AWS hostnames share persistent dotted-IP mappings and restore their original shape', async (context) => {
  const filePath = await statePath();
  context.after(() => fs.rm(path.dirname(filePath), { recursive: true, force: true }));
  const store = await MappingStore.open(filePath);
  const input = '10.20.30.40 ip-10-20-30-40.ec2.internal ip-10-20-30-40.eu-west-1.compute.internal';
  await store.obfuscate(input);
  const expected = mappedText(store, '192.0.2.1 ip-192-0-2-1.ec2.internal ip-192-0-2-1.eu-west-1.compute.internal');
  assert.deepEqual(await store.obfuscate(input), { body: expected, count: 3 });
  assert.deepEqual(await store.obfuscate(expected), { body: expected, count: 0 });
  const reopened = await MappingStore.open(filePath);
  assert.deepEqual(await reopened.obfuscate(input), { body: expected, count: 3 });
  assert.deepEqual(await reopened.deobfuscate(expected), { body: input, count: 3 });
  assert.equal(JSON.parse(await readFile(filePath, 'utf8')).mappings.length, 1);
});

for (const [input, expected] of [
  ['10.20.30.40', true],
  ['ip-10-20-30-40.ec2.internal', true],
  [String.raw`{"input":"10\u002e20\u002e30\u002e40"}`, true],
  [JSON.stringify({ arguments: JSON.stringify({ host: 'ip-10-20-30-40.ec2.internal' }) }), true],
  ['192.0.2.1 ip-192-0-2-1.ec2.internal', false],
  ['ordinary text', false],
  ['999.20.30.40 ip-999-20-30-40.ec2.internal', false],
]) {
  test(`stateless IPv4 safety check: ${input}`, () => {
    assert.equal(containsSensitiveIpv4(input), expected);
  });
}

test('passes RFC 5737 and invalid addresses unchanged', async () => {
  const store = await MappingStore.open(await statePath());
  const transformed = await store.obfuscate(
    '192.0.2.44 198.51.100.72 203.0.113.19 999.10.20.30',
  );

  assert.equal(
    transformed.body,
    '192.0.2.44 198.51.100.72 203.0.113.19 999.10.20.30',
  );
  assert.equal(transformed.count, 0);
});

test('fails closed after 762 persistent mappings', async () => {
  const store = await MappingStore.open(await statePath());
  const addresses = [];
  for (let index = 0; index < 762; index += 1) {
    addresses.push(`10.20.${Math.floor(index / 254)}.${(index % 254) + 1}`);
  }

  const transformed = await store.obfuscate(addresses.join(' '));
  const output = transformed.body.split(' ');
  assert.equal(new Set(output).size, 762);
  assert.equal(output[0], mappedText(store, '192.0.2.1'));
  assert.equal(output[761], mappedText(store, '203.0.113.254'));
  await assert.rejects(
    store.obfuscate('172.16.0.1'),
    { code: 'MAPPING_CAPACITY_EXHAUSTED' },
  );
});

test('rolls back new mappings when one request exceeds remaining capacity', async () => {
  const store = await MappingStore.open(await statePath());
  const addresses = [];
  for (let index = 0; index < 761; index += 1) {
    addresses.push(`10.30.${Math.floor(index / 254)}.${(index % 254) + 1}`);
  }
  await store.obfuscate(addresses.join(' '));

  await assert.rejects(
    store.obfuscate('172.16.0.1 172.16.0.2'),
    { code: 'MAPPING_CAPACITY_EXHAUSTED' },
  );
  assert.equal((await store.obfuscate('172.16.0.3')).body, mappedText(store, '203.0.113.254'));
});

test('refuses to open a corrupt mapping file', async () => {
  const filePath = await statePath();
  await writeFile(filePath, '{"version":1,"nextIndex":1,"mappings":[]}');

  await assert.rejects(MappingStore.open(filePath), /Invalid mapping state/);
});

test('serializes concurrent allocations', async () => {
  const store = await MappingStore.open(await statePath());
  const [first, second] = await Promise.all([
    store.obfuscate('10.0.0.1'),
    store.obfuscate('10.0.0.2'),
  ]);

  assert.equal(first.body, mappedText(store, '192.0.2.1'));
  assert.equal(second.body, mappedText(store, '192.0.2.2'));
});

test('coordinates allocations across store instances', async () => {
  const filePath = await statePath();
  const firstStore = await MappingStore.open(filePath);
  const secondStore = await MappingStore.open(filePath);
  const [first, second] = await Promise.all([
    firstStore.obfuscate('10.0.0.1'),
    secondStore.obfuscate('10.0.0.2'),
  ]);

  await firstStore.deobfuscate('');
  assert.deepEqual(new Set([first.body, second.body]), new Set(firstStore.state.mappings.map((m) => m.fake)));
  const state = JSON.parse(await readFile(filePath, 'utf8'));
  assert.equal(state.mappings.length, 2);
});

test('rolls back mappings when transformed output exceeds the limit', async () => {
  const filePath = await statePath();
  const store = await MappingStore.open(filePath);

  await assert.rejects(
    store.obfuscate('10.0.0.1', { maxBytes: 1 }),
    { code: 'TRANSFORMED_BODY_TOO_LARGE' },
  );
  const transformed = await store.obfuscate('10.0.0.2');
  assert.equal(transformed.body, mappedText(store, '192.0.2.1'));
});

test('writes mapping state with private POSIX permissions', async () => {
  const filePath = await statePath();
  const store = await MappingStore.open(filePath);
  await store.obfuscate('10.0.0.1');

  assert.equal((await stat(filePath)).mode & 0o777, 0o600);
  assert.equal((await stat(path.dirname(filePath))).mode & 0o777, 0o700);
});

test('redacts an IPv4 address that touches punctuation with no surrounding space', async () => {
  const store = await MappingStore.open(await statePath());

  assert.equal((await store.obfuscate('Connect to 10.0.0.1.')).body, mappedText(store, 'Connect to 192.0.2.1.'));
  assert.equal((await store.obfuscate('ip=10.0.0.2,port=80')).body, mappedText(store, 'ip=192.0.2.2,port=80'));
  assert.equal((await store.obfuscate('(10.0.0.3)')).body, mappedText(store, '(192.0.2.3)'));
  assert.equal((await store.obfuscate('"10.0.0.4"')).body, mappedText(store, '"192.0.2.4"'));
  assert.equal((await store.obfuscate('10.0.0.5;10.0.0.6')).body, mappedText(store, '192.0.2.5;192.0.2.6'));
});

test('still refuses to match digit sequences that are not a real IPv4 address', async () => {
  const store = await MappingStore.open(await statePath());

  // Five dotted groups: no 4-octet window here is bounded on both sides by
  // non-digit/non-dot characters, so nothing should be treated as an IP.
  assert.equal((await store.obfuscate('1.2.3.4.5')).count, 0);
  // A candidate whose last octet is directly glued to more digits is not a
  // real IP (e.g. "10.0.0.1999" is not "10.0.0.1" followed by "999").
  assert.equal((await store.obfuscate('10.0.0.1999')).body, '10.0.0.1999');
  assert.equal((await store.obfuscate('10.0.0.1999')).count, 0);
});

// Fresh state makes every text expectation deterministic; no real mappings or
// provider credentials are used by this corpus.
for (const [name, input, expected, count] of [
  ['private address', '10.20.30.40', '192.0.2.1', 1],
  ['loopback', '127.0.0.1', '192.0.2.1', 1],
  ['public address', '8.8.8.8', '192.0.2.1', 1],
  ['zero octets', '0.0.0.0', '192.0.2.1', 1],
  ['maximum octets', '255.255.255.255', '192.0.2.1', 1],
  ['octet digit boundaries', '9.10.99.100 199.200.249.250', '192.0.2.1 192.0.2.2', 2],
  ['CIDR', '10.20.30.40/24', '192.0.2.1/24', 1],
  ['host and port', '10.20.30.40:27017', '192.0.2.1:27017', 1],
  ['punctuation', '(10.20.30.40),[10.20.30.40];10.20.30.40!', '(192.0.2.1),[192.0.2.1];192.0.2.1!', 3],
  ['sentence ending', 'Connect to 10.20.30.40.', 'Connect to 192.0.2.1.', 1],
  ['ellipsis', '...10.20.30.40...', '...192.0.2.1...', 1],
  ['letter boundaries', 'host10.20.30.40internal', 'host192.0.2.1internal', 1],
  ['Unicode context', 'host「10.20.30.40」adres', 'host「192.0.2.1」adres', 1],
  ['newlines and tabs', '10.20.30.40\r\n\t10.20.30.40', '192.0.2.1\r\n\t192.0.2.1', 2],
  ['multi-host URL', 'mongodb://alice:REDACTED_PASSWORD@10.20.30.40:27017,10.20.30.41:27017/app?ssl=true', 'mongodb://alice:REDACTED_PASSWORD@192.0.2.1:27017,192.0.2.2:27017/app?ssl=true', 2],
  ['URL path and query', 'https://host.example/10.20.30.40?target=10.20.30.41', 'https://host.example/192.0.2.1?target=192.0.2.2', 2],
  ['same address reused', '10.20.30.40 10.20.30.41 10.20.30.40', '192.0.2.1 192.0.2.2 192.0.2.1', 3],
  ['JSON property and value', '{"10.20.30.40":"10.20.30.40","n":9007199254740993}', '{"192.0.2.1":"192.0.2.1","n":9007199254740993}', 2],
  ['JSON array', '["10.20.30.40",null,true,42,"ordinary"]', '["192.0.2.1",null,true,42,"ordinary"]', 1],
  ['JSON escaped digits and dots', String.raw`{"ip":"\u0031\u0030\u002e20\u002e30\u002e40"}`, '{"ip":"192.0.2.1"}', 1],
  ['nested JSON', JSON.stringify({ arguments: JSON.stringify({ host: '10.20.30.40' }) }), JSON.stringify({ arguments: JSON.stringify({ host: '192.0.2.1' }) }), 1],
  ['malformed JSON containing literal IP', '{"host":"10.20.30.40",', '{"host":"192.0.2.1",', 1],
  ['mixed invalid and valid IPs', '999.20.30.40 10.20.30.40 10.20.30.999', '999.20.30.40 192.0.2.1 10.20.30.999', 1],
  ['empty', '', '', 0],
  ['ordinary prose', 'connect to db.example', 'connect to db.example', 0],
  ['all reserved documentation ranges', '192.0.2.1 198.51.100.254 203.0.113.255', '192.0.2.1 198.51.100.254 203.0.113.255', 0],
  ['first octet too large', '256.20.30.40', '256.20.30.40', 0],
  ['second octet too large', '10.256.30.40', '10.256.30.40', 0],
  ['third octet too large', '10.20.256.40', '10.20.256.40', 0],
  ['fourth octet too large', '10.20.30.256', '10.20.30.256', 0],
  ['too few octets', '10.20.30', '10.20.30', 0],
  ['too many octets', '1.10.20.30.40', '1.10.20.30.40', 0],
  ['digits attached on the left', '99910.20.30.40', '99910.20.30.40', 0],
  ['digits attached on the right', '10.20.30.40999', '10.20.30.40999', 0],
  ['timestamp', '2026-09-27T14:41:51.055Z', '2026-09-27T14:41:51.055Z', 0],
]) {
  test(`IPv4 text: ${name}`, async (context) => {
    const filePath = await statePath();
    context.after(() => fs.rm(path.dirname(filePath), { recursive: true, force: true }));
    const store = await MappingStore.open(filePath);
    const first = await store.obfuscate(input);
    const wanted = count ? mappedText(store, expected) : expected;
    assert.deepEqual(first, { body: wanted, count });
    assert.deepEqual(await store.obfuscate(input), { body: wanted, count }, 'repeat input must reuse mappings');
    assert.deepEqual(await store.obfuscate(wanted), { body: wanted, count: 0 }, 'output must not be remapped');
  });
}

test('leaves no temporary file behind when a save fails before rename', {
  skip: process.getuid?.() === 0 ? 'cannot restrict a root-owned directory' : false,
}, async () => {
  const filePath = await statePath();
  const store = await MappingStore.open(filePath);
  const directory = path.dirname(filePath);

  await chmod(directory, 0o500);
  try {
    await assert.rejects(store.obfuscate('10.0.0.9'));
  } finally {
    await chmod(directory, 0o700);
  }

  const entries = await readdir(directory);
  assert.deepEqual(entries.filter((name) => name.endsWith('.tmp')), []);

  // Nothing should have been persisted, so a fresh store starts allocation over.
  const reopened = await MappingStore.open(filePath);
  assert.equal((await reopened.obfuscate('10.0.0.9')).body, mappedText(reopened, '192.0.2.1'));
});

test('leaves no temporary file behind after a normal successful save', async () => {
  const filePath = await statePath();
  const store = await MappingStore.open(filePath);
  await store.obfuscate('10.0.0.1');

  const entries = await readdir(path.dirname(filePath));
  assert.deepEqual(entries.filter((name) => name.endsWith('.tmp')), []);
});

test('redacts addresses after ellipses without matching invalid dotted numbers', async () => {
  const store = await MappingStore.open(await statePath());
  const result = await store.obfuscate('...10.0.0.1 .10.0.0.1 1.2.3.4.5 999.10.0.0.1');
  assert.equal(result.body, mappedText(store, '...192.0.2.1 .192.0.2.1 1.2.3.4.5 999.10.0.0.1'));
  assert.equal(result.count, 2);
});

test('redacts JSON escapes and nested tool arguments without rounding numbers', async () => {
  const store = await MappingStore.open(await statePath());
  const input = String.raw`{ "input":"10\u002e0\u002e0\u002e1", "arguments":"{\"host\":\"10\\u002e0\\u002e0\\u002e1\"}", "id":9007199254740993 }`;
  const result = await store.obfuscate(input);
  const parsed = JSON.parse(result.body);
  assert.equal(parsed.input, mappedText(store, '192.0.2.1'));
  assert.equal(JSON.parse(parsed.arguments).host, mappedText(store, '192.0.2.1'));
  assert.equal(result.count, 2);
  assert.ok(result.body.includes('9007199254740993'));
  const restored = JSON.parse((await store.deobfuscate(result.body)).body);
  assert.equal(restored.input, '10.0.0.1');
  assert.equal(JSON.parse(restored.arguments).host, '10.0.0.1');
});

test('restores escaped JSON addresses', async () => {
  const store = await legacyStore(await statePath(), ['10.0.0.1']);
  const result = await store.deobfuscate(String.raw`{"host":"192\u002e0\u002e2\u002e1"}`);
  assert.equal(JSON.parse(result.body).host, '10.0.0.1');
});

function failFileOperation(context, matches, method) {
  const originalOpen = fs.open;
  let failing = true;
  context.mock.method(fs, 'open', async (...args) => {
    const handle = await originalOpen(...args);
    if (failing && matches(args[0])) {
      context.mock.method(handle, method, async () => {
        throw Object.assign(new Error('injected filesystem failure'), { code: 'EIO' });
      });
    }
    return handle;
  });
  syncBuiltinESMExports();
  context.after(() => {
    context.mock.restoreAll();
    syncBuiltinESMExports();
  });
  return () => { failing = false; };
}

for (const method of ['writeFile', 'sync']) {
  test(`cleans its lock after lock ${method} fails`, async (context) => {
    const filePath = await statePath();
    const store = await MappingStore.open(filePath);
    const recover = failFileOperation(context, (name) => name === `${filePath}.lock`, method);
    await assert.rejects(store.obfuscate('10.0.0.1'), { code: 'EIO' });
    assert.equal((await readdir(path.dirname(filePath))).includes('mappings.json.lock'), false);
    recover();
    assert.equal((await store.obfuscate('10.0.0.2')).body, mappedText(store, '192.0.2.1'));
  });

  test(`rolls back and cleans temporary files after state ${method} fails`, async (context) => {
    const filePath = await statePath();
    const store = await MappingStore.open(filePath);
    const recover = failFileOperation(context, (name) => name.endsWith('.tmp'), method);
    await assert.rejects(store.obfuscate('10.0.0.1'), { code: 'EIO' });
    assert.deepEqual(await readdir(path.dirname(filePath)), []);
    recover();
    assert.equal((await store.obfuscate('10.0.0.2')).body, mappedText(store, '192.0.2.1'));
  });
}

test('blocks on directory sync failure without rolling back a committed mapping', async (context) => {
  const filePath = await statePath();
  const store = await MappingStore.open(filePath);
  const recover = failFileOperation(context, (name) => name === path.dirname(filePath), 'sync');
  await assert.rejects(store.obfuscate('10.0.0.1'), { code: 'MAPPING_DURABILITY_FAILED' });
  assert.equal(store.realToFake.get('10.0.0.1'), mappedText(store, '192.0.2.1'));
  assert.equal(JSON.parse(await readFile(filePath, 'utf8')).mappings.length, 1);
  // A retry must not skip the failed durability check just because the mapping exists.
  await assert.rejects(store.obfuscate('10.0.0.1'), { code: 'MAPPING_DURABILITY_FAILED' });
  recover();
  assert.equal((await store.obfuscate('10.0.0.1')).body, mappedText(store, '192.0.2.1'));
  assert.equal((await store.obfuscate('10.0.0.2')).body, mappedText(store, '192.0.2.2'));
});

test('rolls back after rename failure without leaving temporary state', async (context) => {
  const filePath = await statePath();
  const store = await MappingStore.open(filePath);
  context.mock.method(fs, 'rename', async () => {
    throw Object.assign(new Error('injected rename failure'), { code: 'EIO' });
  });
  syncBuiltinESMExports();
  context.after(() => { context.mock.restoreAll(); syncBuiltinESMExports(); });
  await assert.rejects(store.obfuscate('10.0.0.1'), { code: 'EIO' });
  assert.deepEqual(await readdir(path.dirname(filePath)), []);
  context.mock.restoreAll();
  syncBuiltinESMExports();
  assert.equal((await store.obfuscate('10.0.0.2')).body, mappedText(store, '192.0.2.1'));
});

test('coordinates allocations across separate processes', async () => {
  const filePath = await statePath();
  const moduleUrl = new URL('../src/mapping-store.mjs', import.meta.url).href;
  const script = `import { MappingStore } from ${JSON.stringify(moduleUrl)};
    const store = await MappingStore.open(process.argv[1]);
    process.stdout.write((await store.obfuscate(process.argv[2])).body);`;
  const results = await Promise.all(['10.0.0.1', '10.0.0.2'].map((ip) => (
    promisify(execFile)(process.execPath, ['--input-type=module', '-e', script, filePath, ip])
  )));
  assert.equal(new Set(results.map((result) => result.stdout)).size, 2);
  for (const result of results) assert.match(result.stdout, /^\[REDACTED_IP_[a-f0-9]{32}\]$/);
  assert.equal(JSON.parse(await readFile(filePath, 'utf8')).mappings.length, 2);
});

test('status reports only capacity without creating or changing state', async () => {
  const filePath = await statePath();
  assert.deepEqual(await MappingStore.status(filePath), { used: 0, capacity: 762, remaining: 762 });
  assert.deepEqual(await readdir(path.dirname(filePath)), []);
  const store = await MappingStore.open(filePath);
  await store.obfuscate('10.0.0.1');
  const before = await readFile(filePath, 'utf8');
  await chmod(filePath, 0o400);
  assert.deepEqual(await MappingStore.status(filePath), { used: 1, capacity: 762, remaining: 761 });
  assert.equal(await readFile(filePath, 'utf8'), before);
  assert.equal((await stat(filePath)).mode & 0o777, 0o400);
});

test('status errors do not include corrupt mapping contents', async () => {
  const filePath = await statePath();
  await writeFile(filePath, '10.123.45.67 invalid JSON');
  await assert.rejects(MappingStore.status(filePath), { message: 'Invalid mapping state' });
});

test('JSON transformation preserves unrelated escapes and rolls back oversized output', async () => {
  const filePath = await statePath();
  const store = await MappingStore.open(filePath);
  const unrelated = String.raw`{"message":"\\u002e", "emoji":"\ud83d\ude00"}`;
  assert.equal((await store.obfuscate(unrelated)).body, unrelated);
  const input = String.raw`{"host":"1.1.1.1"}`;
  await assert.rejects(store.obfuscate(input, { maxBytes: Buffer.byteLength(input) }), {
    code: 'TRANSFORMED_BODY_TOO_LARGE',
  });
  assert.deepEqual(await MappingStore.status(filePath), { used: 0, capacity: 762, remaining: 762 });
});
