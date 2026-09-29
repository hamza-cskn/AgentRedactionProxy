import assert from 'node:assert/strict';
import test from 'node:test';
import { redactSecrets } from '../src/secret-redaction.mjs';

const names = ['hf_model_configuration_defaults', 'sk-test-production-deployment'];

for (const name of names) {
  for (const extension of ['txt', 'yaml', 'jpeg', 'json', 'toml', 'py', 'TS', 'abc']) {
    const filename = `${name}.${extension}`;
    for (const input of [filename, `Edit ./deploy/${filename}`, JSON.stringify({ arguments: JSON.stringify({ path: filename }) })]) {
      test(`filename exception only in default: ${input}`, () => {
        assert.deepEqual(redactSecrets(input, undefined, 'default'), { body: input, count: 0 });
        assert.equal(redactSecrets(input, undefined, 'paranoic').body.includes(name), false);
        assert.equal(redactSecrets(input).body.includes(name), false);
      });
    }
  }
  for (const suffix of ['', '.unknown', '.jsonx', '.yaml.fake', '.yaml@host', '.yaml/path']) {
    test(`unrecognized filename suffix stays protected: ${name}${suffix}`, () => {
      assert.equal(redactSecrets(`${name}${suffix}`, undefined, 'default').body.includes(name), false);
    });
  }
}

test('filename exceptions do not exempt other token families, URL passwords or size limits', () => {
  const github = `ghp_${'Ab12'.repeat(9)}`;
  assert.equal(redactSecrets(`${github}.yaml`, undefined, 'default').body, '[REDACTED_API_KEY].yaml');
  for (const prefix of ['sk-ant-api03-', 'sk-proj-', 'sk-svcacct-']) {
    assert.equal(redactSecrets(`${prefix}${'Ab12'.repeat(9)}.bak`, undefined, 'default').body, '[REDACTED_API_KEY].bak');
  }
  assert.equal(redactSecrets(`http://alice:${names[0]}.yaml@host`, undefined, 'default').body, 'http://alice:REDACTED_PASSWORD@host');
  assert.throws(() => redactSecrets(`${names[0]}.yaml`, { maxApiTokenChars: 8 }, 'default'), /configured limit/);
});
