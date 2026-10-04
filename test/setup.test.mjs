import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const setup = path.resolve('scripts/setup.sh');
const pluginSource = path.resolve('.opencode/plugins/openai-ipv4-proxy.js');
const configSource = path.resolve('examples/opencode.jsonc');

// All Docker/OpenCode/download operations are isolated shims, never live host
// containers, credentials, projects or network requests.
const shim = `#!/usr/bin/env node
const fs=require('node:fs');
const path=require('node:path');
const name=path.basename(process.argv[1]);
const args=process.argv.slice(2);
const file=process.env.ARP_TEST_STATE;
const state=JSON.parse(fs.readFileSync(file,'utf8'));
const done=(output='',code=0)=>{fs.writeFileSync(file,JSON.stringify(state));process.stdout.write(output);process.exit(code);};
if(name==='curl') {
  const output=args[args.indexOf('-o')+1];
  if(process.env.ARP_TEST_DOWNLOAD_FAIL) done('',1);
  fs.copyFileSync(args.some(arg=>arg.includes('/plugins/'))?process.env.ARP_TEST_PLUGIN:process.env.ARP_TEST_CONFIG,output);
  if(process.env.ARP_TEST_BAD_CHECKSUM) fs.appendFileSync(output,'modified');
  done();
}
if(name==='opencode') {
  if(args[0]==='auth') done(process.env.ARP_TEST_NO_AUTH?'OpenAI api':'OpenAI oauth');
  done(process.env.ARP_TEST_NO_MODELS?'':'openai/test-model\\n');
}
if(name==='docker') {
  state.commands.push(args);
  if(args[0]==='info') done('',process.env.ARP_TEST_NO_DOCKER?1:0);
  if(args[0]==='pull') done('',process.env.ARP_TEST_PULL_FAIL?1:0);
  if(args[0]==='inspect') {
    if(!state.container) done('',1);
    const format=args[args.indexOf('--format')+1];
    if(format.includes('install-id')) done(state.container.id||'');
    if(format.includes('managed')) done(state.container.managed?'1':'');
    if(format.includes('.Config.Image')) done(state.container.image||'366366/agent-redaction-proxy:latest');
    if(format.includes('.Mounts')) done(state.container.volume||'agent-redaction-proxy-data');
    if(format.includes('.State.Running')) done(state.container.running?'true':'false');
    done('{}');
  }
  if(args[0]==='port') done('127.0.0.1:'+args[2].split('/')[0]);
  if(args[0]==='run') {
    if(process.env.ARP_TEST_RUN_CONFLICT) {state.container={managed:false,running:true,id:'another-process'};done('',1);}
    state.container={managed:true,running:true,id:args.find(arg=>arg.startsWith('io.agent-redaction-proxy.install-id=')).split('=')[1]};
    done('test-container');
  }
  if(args[0]==='start') {state.container.running=true;done();}
  if(args[0]==='stop') {state.container.running=false;done();}
  if(args[0]==='rm') {state.container=null;done();}
  if(args[0]==='exec') done();
  done('',1);
}
done('',1);
`;

async function fixture(t, overrides = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'arp-setup-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const project = path.join(directory, 'project with spaces');
  const bin = path.join(directory, 'bin');
  await mkdir(project);
  await mkdir(bin);
  for (const command of ['curl', 'docker', 'opencode']) {
    const file = path.join(bin, command);
    await writeFile(file, shim);
    await chmod(file, 0o755);
  }
  const stateFile = path.join(directory, 'state.json');
  await writeFile(stateFile, JSON.stringify({ container: null, commands: [] }));
  const env = { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    ARP_TEST_STATE: stateFile, ARP_TEST_PLUGIN: pluginSource, ARP_TEST_CONFIG: configSource,
    ...overrides };
  const run = (action = 'install') => exec('bash', [setup, action], { cwd: project, env, timeout: 20_000 });
  const state = async () => JSON.parse(await readFile(stateFile, 'utf8'));
  const setContainer = async (container) => writeFile(stateFile, JSON.stringify({ container, commands: [] }));
  return { project, directory, run, state, setContainer, env,
    plugin: path.join(project, '.opencode/plugins/openai-ipv4-proxy.js'),
    config: path.join(project, 'opencode.jsonc'),
    receipt: path.join(project, '.opencode/.agent-redaction-proxy-install') };
}

test('setup installs and uninstalls project files while preserving shared container and volume', async (t) => {
  const f = await fixture(t);
  assert.match((await f.run()).stdout, /Ready/);
  assert.equal(await readFile(f.plugin, 'utf8'), await readFile(pluginSource, 'utf8'));
  assert.equal(await readFile(f.config, 'utf8'), await readFile(configSource, 'utf8'));
  assert.equal((await stat(f.receipt)).mode & 0o777, 0o700);
  const state = await f.state();
  assert.equal(state.container.running, true);
  const run = state.commands.find((args) => args[0] === 'run');
  assert.equal(run.includes('127.0.0.1:8787:8787'), true);
  assert.equal(run.includes('agent-redaction-proxy-data:/data'), true);
  assert.match((await f.run('uninstall')).stdout, /mapping data were preserved/);
  await assert.rejects(readFile(f.plugin), { code: 'ENOENT' });
  await assert.rejects(readFile(f.config), { code: 'ENOENT' });
  assert.equal((await f.state()).container.running, true);
  assert.equal((await f.state()).commands.some((args) => args.includes('volume') || args[0] === 'rm'), false);
  assert.match((await f.run('uninstall')).stdout, /Nothing changed/);
});

test('repeat setup reuses the shared proxy and preserves existing JSONC byte-for-byte', async (t) => {
  const f = await fixture(t);
  const original = '{ // keep comments\n "provider": {},\n}\n';
  await writeFile(f.config, original);
  await f.run();
  await f.run();
  assert.equal((await f.state()).commands.filter((args) => args[0] === 'run').length, 1);
  assert.equal(await readFile(f.config, 'utf8'), original);
  await f.run('uninstall');
  assert.equal(await readFile(f.config, 'utf8'), original);
});

test('existing JSON config is preserved and no competing JSONC file is created', async (t) => {
  const f = await fixture(t);
  const config = path.join(f.project, 'opencode.json');
  await writeFile(config, '{"model":"openai/example"}');
  await f.run();
  await assert.rejects(readFile(f.config), { code: 'ENOENT' });
  await f.run('uninstall');
  assert.equal(await readFile(config, 'utf8'), '{"model":"openai/example"}');
});

test('uninstall refuses modified plugin/config instead of deleting user edits', async (t) => {
  for (const target of ['plugin', 'config']) {
    const f = await fixture(t);
    await f.run();
    const plugin = await readFile(f.plugin, 'utf8');
    const config = await readFile(f.config, 'utf8');
    await writeFile(f[target], target === 'plugin' ? `${plugin}\n// user edit` : `${config}\n// user edit`);
    await assert.rejects(f.run('uninstall'), (error) => /was modified/.test(error.stderr));
    assert.equal(await readFile(f[target], 'utf8'), `${target === 'plugin' ? plugin : config}\n// user edit`);
    assert.equal(await readFile(f[target === 'plugin' ? 'config' : 'plugin'], 'utf8'), target === 'plugin' ? config : plugin);
    await stat(f.receipt);
  }
});

test('pre-existing unmanaged plugin is never overwritten or removed', async (t) => {
  const f = await fixture(t);
  await mkdir(path.dirname(f.plugin), { recursive: true });
  await writeFile(f.plugin, 'user plugin');
  await assert.rejects(f.run(), (error) => /will not be overwritten/.test(error.stderr));
  await f.run('uninstall');
  assert.equal(await readFile(f.plugin, 'utf8'), 'user plugin');
});

for (const failure of ['ARP_TEST_PULL_FAIL', 'ARP_TEST_DOWNLOAD_FAIL', 'ARP_TEST_BAD_CHECKSUM', 'ARP_TEST_NO_AUTH', 'ARP_TEST_NO_MODELS', 'ARP_TEST_NO_DOCKER']) {
  test(`setup failure ${failure} rolls back project files and newly created container`, async (t) => {
    const f = await fixture(t, { [failure]: '1' });
    await assert.rejects(f.run(), (error) => {
      assert.equal(error.code, 1);
      assert.doesNotMatch(error.stderr, /unbound variable/);
      return true;
    });
    assert.equal((await f.state()).container, null);
    assert.deepEqual(await readdir(f.project), []);
  });
}

test('unmanaged Docker container and same-name race remain untouched', async (t) => {
  for (const race of [false, true]) {
    const f = await fixture(t, race ? { ARP_TEST_RUN_CONFLICT: '1' } : {});
    if (!race) await f.setContainer({ managed: false, running: true, id: 'another-process' });
    await assert.rejects(f.run());
    assert.equal((await f.state()).container.id, 'another-process');
    assert.equal((await f.state()).commands.some((args) => ['rm', 'stop'].includes(args[0])), false);
    assert.deepEqual(await readdir(f.project), []);
  }
});

test('failed setup restores a previously stopped managed container', async (t) => {
  const f = await fixture(t, { ARP_TEST_NO_MODELS: '1' });
  await f.setContainer({ managed: true, running: false, id: 'existing' });
  await assert.rejects(f.run());
  assert.deepEqual((await f.state()).container, { managed: true, running: false, id: 'existing' });
  assert.deepEqual(await readdir(f.project), []);
});

test('setup rejects symlinked project integration paths and leaves targets untouched', async (t) => {
  const f = await fixture(t);
  const outside = path.join(f.directory, 'outside');
  await mkdir(outside);
  await writeFile(path.join(outside, 'keep'), 'user data');
  await symlink(outside, path.join(f.project, '.opencode'));
  await assert.rejects(f.run(), (error) => /symbolic links/.test(error.stderr));
  assert.equal(await readFile(path.join(outside, 'keep'), 'utf8'), 'user data');
});

test('setup lock owned by another process is preserved', async (t) => {
  const f = await fixture(t);
  const lock = path.join(f.project, '.opencode/.agent-redaction-proxy-setup.lock');
  await mkdir(lock, { recursive: true });
  await assert.rejects(f.run(), (error) => /setup lock/.test(error.stderr));
  await stat(lock);
});
