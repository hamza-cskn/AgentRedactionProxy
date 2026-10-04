import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { loadConfig } from '../src/config.mjs';
import { DEFAULT_REDACTION_LIMITS } from '../src/redaction-limits.mjs';

test('shipped config uses default mode', async () => {
  const config = await loadConfig(new URL('../config.json', import.meta.url));
  assert.equal(config.mode, 'default');
});

for (const [mode, accepted] of [
  ['default', true],
  ['paranoic', true],
  ['non-paranoic', false],
  ['never-see', false],
]) {
  test(`config ${accepted ? 'accepts' : 'rejects legacy'} mode: ${mode}`, async (context) => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'agent-redaction-config-'));
    context.after(() => rm(directory, { recursive: true, force: true }));
    const configPath = path.join(directory, 'config.json');
    await writeFile(configPath, JSON.stringify({ mode }));
    if (accepted) {
      assert.deepEqual(await loadConfig(configPath), { mode, redactionLimits: DEFAULT_REDACTION_LIMITS });
    } else {
      await assert.rejects(loadConfig(configPath), {
        message: 'config.json mode must be "paranoic" or "default"',
      });
    }
  });
}
