// Test harness: the real redaction pipeline with a fake upstream, captured logs
// and a throwaway mapping store. No sockets, no live APIs. See docs/testing.md.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { MappingStore } from '../../src/mapping-store.mjs';
import { createProxy } from '../../src/proxy.mjs';

export const MODES = ['default', 'paranoic'];

// Markers and tokens are assembled at runtime. Literal ones in source are
// redacted (or rejected by older proxies) when an agent reads this repo through
// the proxy, and real-looking tokens trip secret scanners on push.
const DASHES = '-'.repeat(5);
export const pem = {
  begin: (type = 'PRIVATE KEY') => `${DASHES}BEGIN ${type}${DASHES}`,
  end: (type = 'PRIVATE KEY') => `${DASHES}END ${type}${DASHES}`,
  block: (body, type = 'PRIVATE KEY') => `${pem.begin(type)}\n${body}\n${pem.end(type)}`,
};
export const puttyHeader = (version = 3) => `PuTTY-User-Key-File-${version}:`;
// Independent of src/: detects any private key marker left in an output.
export const KEY_MARKER = new RegExp(`${DASHES}(?:BEGIN|END) (?:(?:[A-Z0-9]+ )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)${DASHES}|\\bPuTTY-User-Key-File-\\d+:`);

// Deterministic PRNG (mulberry32): a failing seed reproduces exactly.
export function prng(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Distinctive alphanumeric text. Unlike 'A'.repeat(n), every 8-char window is
// effectively unique, so a fragment leak check means something.
const ALPHANUMERIC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export function entropy(length, seed = 1) {
  const random = prng(seed);
  return Array.from({ length }, () => ALPHANUMERIC[Math.floor(random() * ALPHANUMERIC.length)]).join('');
}

const base64url = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
export const secret = {
  github: (seed = 1) => `ghp_${entropy(36, seed)}`,
  jwt: (seed = 1) => `${base64url({ alg: 'HS256', typ: 'JWT' })}.${base64url({ sub: entropy(16, seed) })}.${entropy(43, seed + 1)}`,
  urlPassword: (seed = 1) => `postgres://app:${entropy(20, seed)}@db.example.com/main`,
  privateKey: (seed = 1, type = 'PRIVATE KEY') => pem.block(entropy(64, seed), type),
};

// First window-sized fragment of value found in text, or null.
export function findLeak(text, value, window = 8) {
  for (let index = 0; index + window <= value.length; index += 1) {
    const fragment = value.slice(index, index + window);
    if (text.includes(fragment)) return fragment;
  }
  return null;
}

export function assertNoLeak(text, values, where) {
  for (const value of [values].flat()) {
    assert.equal(findLeak(text, value), null, `${where} contains a fragment of ${JSON.stringify(value.slice(0, 12))}...`);
  }
}

// Mapping store in a temp dir, removed when the test ends.
export async function tempStore(t, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'arp-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return MappingStore.open(path.join(directory, 'redaction_mapping.json'), options);
}

// Upstream responders: each receives the recorded call and returns a Response.
export const echo = (call) => new Response(call.body, { headers: { 'content-type': 'application/json' } });
export const json = (value, status = 200) => () => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
export const sse = (text) => () => new Response(text, { headers: { 'content-type': 'text/event-stream' } });
export const fail = (error = new Error('upstream unreachable')) => () => { throw error; };

// Stands in for fetch. Records what would have left the machine.
export function fakeUpstream(respond = echo) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const call = {
      url: String(url),
      method: init.method,
      headers: Object.fromEntries(init.headers),
      body: init.body === undefined ? '' : Buffer.from(init.body).toString('utf8'),
    };
    calls.push(call);
    return respond(call);
  };
  return { calls, fetchImpl };
}

// Calls the proxy's request handler directly: no sockets, exact chunk boundaries.
export async function invoke(proxy, { method = 'POST', path: url = '/v1/responses', headers = {}, body = '', chunks = [body] } = {}) {
  const request = Object.assign(Readable.from(chunks.map((chunk) => Buffer.from(chunk))), { method, url, headers });
  const response = Object.assign(new EventEmitter(), {
    statusCode: 200, headers: {}, body: '', headersSent: false, writableFinished: false, destroyed: false,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    writeHead(status, values = {}) {
      this.statusCode = status;
      for (const [name, value] of Object.entries(values)) this.setHeader(name, value);
      this.headersSent = true;
    },
    end(chunk = '') {
      this.body = Buffer.from(chunk).toString('utf8');
      this.headersSent = true;
      this.writableFinished = true;
    },
    destroy() { this.destroyed = true; },
  });
  await proxy.listeners('request')[0](request, response);
  return { status: response.statusCode, headers: response.headers, body: response.body };
}

// Real proxy and mapping store, fake upstream, captured logs. Pass store: {} (or a
// stub) when the test never reaches the store, to skip the temp dir.
export async function proxyHarness(t, { upstream = echo, store, sensitiveTexts, ...options } = {}) {
  const fake = fakeUpstream(upstream);
  const logs = [];
  const mappingStore = store ?? await tempStore(t, { sensitiveTexts });
  const proxy = createProxy({
    mode: 'default', upstreamBase: 'https://upstream.test/v1', protectAllPostBodies: true,
    store: mappingStore, logger: (line) => logs.push(line), fetchImpl: fake.fetchImpl, ...options,
  });
  return {
    proxy, store: mappingStore, logs, upstream: fake.calls,
    send: (body, request = {}) => invoke(proxy, { body: typeof body === 'string' ? body : JSON.stringify(body), ...request }),
  };
}
