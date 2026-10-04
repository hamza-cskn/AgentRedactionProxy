import assert from 'node:assert/strict';
import { redactedText } from './helpers/mapping-fixtures.mjs';
import { EventEmitter } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';

import { MappingStore } from '../src/mapping-store.mjs';
import { createProxy } from '../src/proxy.mjs';
import { redactSecrets } from '../src/secret-redaction.mjs';

const benign = [
  'http://localhost:8080 (contact dev@example.com)',
  'http://example.com:3000 — contact dev@example.com',
  '[http://localhost:8080](http://example.com)',
  'http://localhost:8080—then continue',
  'http://host ; Next action: contact me@example.com',
  'git clone git@github.com:owner/repository.git',
  'rsync -av user@host:/srv/app ./app',
  'docker run --mount type=bind,src=/data,dst=/data,readonly nginx',
  'FROM node:24-alpine\nCOPY --from=build /app/dist /app',
  'postgresql:///app?host=/var/run/postgresql',
  'unix:///var/run/docker.sock',
  'http+unix://%2Fvar%2Frun%2Fdocker.sock/containers/json',
  'file:///etc/hosts',
  'sqlite:///./database.db',
  'sqlite:///:memory:',
  'git+ssh://git@github.com/owner/repository.git',
  'ssh://git@host.example:2222/repository.git',
  'https://user@example.com/repository',
  String.raw`const pattern = /https?:\/\/[^/]+/g;`,
  'export PATH=/usr/local/bin:/usr/bin:/bin',
  'SSH_AUTH_SOCK=/tmp/ssh-agent.sock',
  'const style = { color: "#fff", display: "block" };',
  '<a href="http://localhost:3000">local</a>',
  'GET http://localhost:3000/health HTTP/1.1',
  'http://[::ffff:192.0.2.1]:8080/health',
  'http://localhost:8080/#/login',
  'https://例え.テスト:443/路径',
  String.raw`printf "%s\n" "http://localhost:8080/api"`,
  'const v = package.dependencies["my-package"];',
  'com.example.app.module.ClassName',
  'archive.tar.gz package-lock.json docker-compose.yaml',
  'ghp_example xoxb_example sk_short hf_tiny',
  'docker run -v /data:/data:ro nginx',
  `docker run -v /data:/${'nested/'.repeat(90)}:ro nginx`,
  'docker run -v data:/data:ro nginx',
  'docker run --volume=data:/data:ro nginx',
  'podman run -v cache:/cache:rw image',
  'data:/data:ro',
  'docker run -v C:/data:/data:ro nginx',
  'file://C:/Users/alice/project',
  'C:/data:/data:ro',
  'http://[fe80::1%eth0]:8080/api',
  'http://[fe80::1%25eth0]:8080/api',
  'http://[fe80::1%en0]/api',
  'url: http://localhost:{{ .Values.port }}/health',
  'curl http://localhost:$(PORT)/health',
  '"http://localhost:#{port}/api"',
  String.raw`"http://localhost:\(port)/api"`,
  '"http://localhost:%(port)d"',
  'http://localhost:${PORT-3000}/api',
  'http://localhost:${PORT:?required}/api',
  'http://localhost:${config.port ?? 3000}/api',
  'http://localhost:%d/api',
  'http://localhost:%04d/api',
  'http://localhost:{}/api',
  'http://localhost:{0}/api',
  'http://localhost:{port:d}/api',
  'url: http://localhost:{{ .Values.port | default 80 }}/health',
  'http://host:${portFor({tls:true})}/api',
  'http://host:$(call port, $(SERVICE))/api',
  String.raw`http://host:\(port(for: env))/api`,
  'http://host:{{ ports["http"] }}/api',
  'http://host:${portFor("}")}/api',
  'mongodb://db1:27017,db2/app',
  'mongodb://db1:27017,db2,db3:27019/app',
  'http://localhost:8080…',
  'mongodb://db1.example:27017,db2.example:27017/app',
  'mongodb://[::1]:27017,[::2]:27018/app',
  'jdbc:sqlserver://db.example:1433;databaseName=app;encrypt=true',
  'http://example.com:',
  'http://host.example:/path',
  'http://[::1]:/path',
  'https%3A%2F%2Fexample.com%2F?q=100%',
  'https%3A%2F%2Fexample.com%2F?q=100%GG',
  'http://${HOST}:${PORT}/api',
  'f"http://{host}:{port}"',
  'http://localhost:$PORT',
  'task-queue-worker-production-deployment.yaml',
  'Edit ./deploy/task-queue-worker-production-deployment.yaml',
  'const endpoints = [http://localhost:3000];',
  'http://example.com\nNext step: run tests.',
  'const url = "http://localhost:3000";',
  'https://example.com:8080 https://alice:REDACTED_PASSWORD@other.example/path',
  'const url = "https://example.com/?token=count"; render(url);',
  'Please use host=example.com and token=the next lexical token, then continue parsing.',
  'GET /search?token=hello world and explain how the parser works',
  '[local](http://localhost:3000)',
  'Visit http://localhost:3000.',
  'Visit http://localhost:3000!',
  '[local](http://localhost:3000!)',
  'https://example.com:8080, then run tests.',
  'const url = `http://${host}:${port}`;',
  'http://localhost:${PORT:-3000}/api',
  'http://localhost:%s/api',
  'http://host:port/path',
  'http://localhost:PORT',
  'http://[::1]:$PORT/api',
  'http://example.com is the endpoint: use GET.',
  'http://example.com https://other.example:8080',
  'let token;token=lexer.next();return token;',
  'const host = config.host; const token = lexer.next(); return token;',
  'Edit pypi-package-release-automation.yaml',
  'Edit npm_package_configuration_defaults.json',
  'auto &token=lexer.current();',
  'ready?token=next():token=null;',
  'host=config.host; token=lexer.next();',
  'Read https://host/?token=secret and then explain the output.',
  'host=db.example password="secret words',
  "Server=db;Pwd='secret",
];
const npmToken = `npm_${'aB12'.repeat(9)}`;
const pypiToken = `pypi-${'aB12_-'.repeat(15)}`;
const protectedTexts = [
  ['http://alice:$(fn({port])@host/api', 'http://alice:REDACTED_PASSWORD@host/api'],
  ['http://alice:secret@[fe80::1%25eth0]:8080/api', 'http://alice:REDACTED_PASSWORD@[fe80::1%25eth0]:8080/api'],
  ['http://[example:secret]@host/api', 'http://[example:REDACTED_PASSWORD@host/api'],
  ['http://alice:{{ .Values.port }}@host/api', 'http://alice:REDACTED_PASSWORD@host/api'],
  ['http://alice:$(PORT)@host/api', 'http://alice:REDACTED_PASSWORD@host/api'],
  ['http://alice:#{port}@host/api', 'http://alice:REDACTED_PASSWORD@host/api'],
  [String.raw`http://alice:\(port)@host/api`, 'http://alice:REDACTED_PASSWORD@host/api'],
  ['http://alice:%(port)d@host/api', 'http://alice:REDACTED_PASSWORD@host/api'],
  ['http://alice:${portFor({tls:true})}@host/api', 'http://alice:REDACTED_PASSWORD@host/api'],
  ['http://alice:${portFor("}")}@host/api', 'http://alice:REDACTED_PASSWORD@host/api'],
  ['http://alice:$(call port, $(SERVICE))@host/api', 'http://alice:REDACTED_PASSWORD@host/api'],
  ['/prefix/http://alice:secret@host/api', '/prefix/http://alice:REDACTED_PASSWORD@host/api'],
  ['https://example.com https://alice:secret@other.example/path', 'https://example.com https://alice:REDACTED_PASSWORD@other.example/path'],
  ['https://example.com\thttps : / / alice:secret@other.example/path', 'https://example.com\thttps : / / alice:REDACTED_PASSWORD@other.example/path'],
  ['mongodb://alice:27017,db2.example:27017@host/app', 'mongodb://alice:REDACTED_PASSWORD@host/app'],
  ['jdbc:sqlserver://alice:1433;databaseName=secret@host/app', 'jdbc:sqlserver://alice:REDACTED_PASSWORD@host/app'],
  ['http://alice:port@host/path', 'http://alice:REDACTED_PASSWORD@host/path'],
  ['http://alice:PORT@host/path', 'http://alice:REDACTED_PASSWORD@host/path'],
  ['http://alice:${PORT:-3000}@host/path', 'http://alice:REDACTED_PASSWORD@host/path'],
  ['[link](http://alice:3000.)@host/path)', '[link](http://alice:REDACTED_PASSWORD@host/path)'],
  ['http://alice:3000`@host/path', 'http://alice:REDACTED_PASSWORD@host/path'],
  ['http://alice:3000!@host/path', 'http://alice:REDACTED_PASSWORD@host/path'],
  ['http://alice:3000! @host/path', 'http://alice:REDACTED_PASSWORD @host/path'],
  ['http://alice:3000!)@host/path', 'http://alice:REDACTED_PASSWORD@host/path'],
  ['host=db.example password=secret', 'host=db.example password=secret'],
  ['host=db.example password="two secret words"', 'host=db.example password="two secret words"'],
  ['host=db.example password=two secret words', 'host=db.example password=two secret words'],
  ['password=secret host=db.example', 'password=secret host=db.example'],
  ['const dsn = "host=db.example password=secret";', 'const dsn = "host=db.example password=secret";'],
  ['Server=db.example;Pwd=secret;', 'Server=db.example;Pwd=secret;'],
  ['jdbc:sqlserver://db.example;password=secret;', 'jdbc:sqlserver://db.example;password=secret;'],
  ['jdbc:sqlserver : / / db.example;password=secret;', 'jdbc:sqlserver : / / db.example;password=secret;'],
  ['https://host/?token=secret&mode=read', 'https://host/?token=secret&mode=read'],
  ['aws_secret_access_key=secret', 'aws_secret_access_key=secret'],
  [`./${npmToken}.txt`, './[REDACTED_API_KEY].txt'],
  [`./${pypiToken}.txt`, './[REDACTED_API_KEY].txt'],
  [`${npmToken}_old`, '[REDACTED_API_KEY]'],
  [`MY_${npmToken}`, 'MY_[REDACTED_API_KEY]'],
  [`pypi-${'a'.repeat(85)}`, '[REDACTED_API_KEY]'],
];

test('URI stability matrix: schemes, hosts, port notation, paths and prose wrappers', () => {
  const schemes = ['http', 'https', 'ws', 'mongodb', 'custom+db.v2', 'jdbc:postgresql'];
  const hosts = ['localhost', 'example.com', 'service_name', '10.20.30.40', '[::1]', '[fe80::1%25eth0]'];
  const ports = ['8080', '0', '65535', '$PORT', '${PORT}', '{{ .Values.port }}', '$(PORT)', '#{port}', String.raw`\(port)`, '%(port)d', '{port:d}'];
  const paths = ['', '/api', '/users/@alice', '?q=word', '#fragment'];
  const wrappers = [(text) => text, (text) => `See ${text}.`, (text) => `[local](${text})`, (text) => `\`${text}\``];
  let checked = 0;
  for (const scheme of schemes) for (const host of hosts) for (const port of ports) {
    for (const suffix of paths) for (const wrap of wrappers) {
      const input = wrap(`${scheme}://${host}:${port}${suffix}`);
      assert.deepEqual(redactSecrets(input), { body: input, count: 0 }, input);
      checked += 1;
    }
  }
  assert.equal(checked, 7920);
});

test('port notation is never a userinfo-password exemption', () => {
  const passwords = ['8080', '$PORT', '${PORT}', '${PORT:?required}', '{{ .Values.port }}', '{{ .Values.port | default 80 }}', '$(PORT)', '#{port}', String.raw`\(port)`, '%(port)d', '{port:d}', '{}'];
  for (const scheme of ['http', 'mongodb', 'custom+db.v2']) {
    for (const password of passwords) {
      const input = `${scheme}://alice:${password}@host/api`;
      const expected = `${scheme}://alice:REDACTED_PASSWORD@host/api`;
      assert.equal(redactSecrets(input).body, expected, input);
      for (const malformed of [
        `${scheme}:/alice:${password}@host/api`,
        ...(password === '8080' ? [] : [`${scheme}://alice:${password} more@host/api`]),
      ]) {
        assert.throws(() => redactSecrets(malformed), /Unsafe credential URL/, malformed);
      }
    }
  }
});

for (const input of [
  'https%3A%2F%2Falice%3Asecret%40host%2F?q=100%',
  'https%3A%2F%2Falice%3Asecret%%40host%2F',
  'https%3A%2F%2Fhost%2F?key=ghp%5FAb12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78%',
  'https%3A%2F%2Fhost%2F?q=%E0',
]) {
  test(`encoded percent handling must still reject unsafe input: ${input}`, () => {
    assert.throws(() => redactSecrets(input), /Unsafe encoded/);
    assert.throws(() => redactSecrets(JSON.stringify({ arguments: JSON.stringify({ content: input }) })), /Unsafe encoded/);
  });
}

// Field names never determine sensitivity. A recognizable value is protected
// under any name; an opaque value is not classified by its surrounding label.
for (const name of ['password', 'token', 'secret', 'api_key', 'access_token', 'aws_secret_access_key', 'aws_session_token', 'ordinary']) {
  const token = `ghp_${'Ab12'.repeat(9)}`;
  for (const wrap of [
    (value) => `https://host/?${name}=${value}&mode=read`,
    (value) => `host=db.example;${name}=${value};`,
    (value) => `${name}=${value}`,
    (value) => `${name}: ${value}`,
    (value) => JSON.stringify({ [name]: value }),
  ]) {
    benign.push(wrap('opaqueValue123'));
    protectedTexts.push([wrap(token), wrap('[REDACTED_API_KEY]')]);
  }
}

for (const input of [
  'http://alice:3000.) word@host/path',
  'http://alice:3000! word@host/path',
  'http://alice:PORT word@host/path',
  'http://alice:secret/word@host/path',
  'http://alice smith:secret@host/path',
  'http://alice smith:secret/word@host/path',
  'http://alice smith:secret?word@host/path',
  'http://alice:secret',
  'mongo:/alice:secret@host/api',
  'data:/alice:secret word@host/api',
  'docker run -v data:/alice:secret@host nginx',
  `docker run -v data:/alice:${'secret'.repeat(90)}@host nginx`,
  '/prefix/mongo:/alice:secret@host/api',
  '/prefix/mongo:/alice:secret word@host/api',
  '/prefix/mongo:/alice:secret/word@host/api',
  'C:/alice:secret@host/api',
  'file://C:/alice:secret@host/api',
  'http://alice:{{ .Values.port }} word@host/api',
  'http://alice:#{port} word@host/api',
  'http://alice:${fn("me@domain")}/api',
  'http://host:${unclosed/api',
  `http://host:${'{'.repeat(65)}port${'}'.repeat(65)}/api`,
  'http://alice:@host',
  'http://alice:/secret@host',
  'http://alice:secret https://other.example/path',
  'mongodb://alice:27017,db2.example:27017 word@host/app',
]) {
  test(`false-positive fixes still reject malformed credentials: ${input}`, () => {
    assert.throws(() => redactSecrets(input), /Unsafe credential URL/);
  });
}

for (const [input, expected] of [...benign.map((text) => [text, text]), ...protectedTexts]) {
  test(`literal false-positive boundary: ${input}`, () => {
    assert.equal(redactSecrets(input).body, expected);
    const nested = JSON.stringify({ arguments: JSON.stringify({ content: input }) });
    assert.equal(JSON.parse(JSON.parse(redactSecrets(nested).body).arguments).content, expected);
  });
}

for (const mode of ['default', 'paranoic']) {
  test(`${mode}: false-positive fixes preserve initial and history requests without exposing credentials or IPs`, async (context) => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'redaction-false-positives-'));
    context.after(() => rm(directory, { recursive: true, force: true }));
    const store = await MappingStore.open(path.join(directory, 'mappings.json'));
    let forwarded;
    const proxy = createProxy({ mode, store, logger: () => {}, fetchImpl: async (_url, init) => {
      forwarded = JSON.parse(init.body.toString());
      return new Response('{}');
    } });
    for (const [input, expected] of [...benign.map((text) => [text, text]), ...protectedTexts]) {
      for (const history of [false, true]) {
        const messages = [{ role: 'user', content: `${input}\n10.20.30.40` }];
        if (history) messages.push({ role: 'assistant', content: 'OK' }, { role: 'user', content: 'Continue' });
        const request = Object.assign(Readable.from([Buffer.from(JSON.stringify({ messages }))]), {
          method: 'POST', url: '/v1/responses', headers: {},
        });
        const response = Object.assign(new EventEmitter(), {
          writableFinished: false,
          setHeader() {},
          writeHead(status) { this.statusCode = status; },
          end() { this.writableFinished = true; },
        });
        forwarded = undefined;
        await proxy.listeners('request')[0](request, response);
        assert.equal(response.statusCode, 200, `${input}, history=${history}`);
        assert.equal(redactedText(store, forwarded.messages[0].content), `${expected}\n${store.realToFake.get('10.20.30.40')}`, input);
      }
    }
  });
}
