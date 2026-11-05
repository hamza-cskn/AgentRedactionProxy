import http from 'node:http';

import { containsSensitiveIpv4 } from './mapping-store.mjs';
import { errorDiagnostics, logMetadata } from './proxy-logging.mjs';
import { redactSecrets } from './secret-redaction.mjs';
import { resolveRedactionLimits } from './redaction-limits.mjs';
import { deobfuscateSse, protocolForPath, stripV1Prefix } from './sse-transform.mjs';

const DEFAULT_MAX_BODY_BYTES = 64 * 1024 * 1024;
const UPSTREAM_BASE = 'https://opencode.ai/zen/v1';
const HOP_BY_HOP_HEADERS = new Set([
  'connection', 'content-length', 'host', 'keep-alive', 'proxy-authenticate',
  'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade',
]);
const LOG_IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/g;

export class BodyLimitError extends Error {}

// Only deliberate rejections carry a client-visible message. Unexpected
// exceptions always use the generic 502/504 response and safe diagnostics.
class RequestRejection extends Error {
  constructor(status, message, warning, diagnostic) {
    super(message);
    this.status = status;
    this.warning = warning;
    this.diagnostic = diagnostic;
  }
}

async function readBody(stream, maxBytes) {
  if (!stream) return Buffer.alloc(0);
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > maxBytes) throw new BodyLimitError(`Body exceeds ${maxBytes} bytes`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function requestHeaders(nodeHeaders) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(nodeHeaders)) {
    if (value === undefined || HOP_BY_HOP_HEADERS.has(name.toLowerCase())) continue;
    for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item);
  }
  return headers;
}

function upstreamUrl(requestUrl, upstreamBase) {
  const local = new URL(requestUrl, 'http://127.0.0.1');
  const upstream = new URL(upstreamBase);
  upstream.pathname = `${upstream.pathname.replace(/\/$/, '')}${stripV1Prefix(local.pathname)}`;
  upstream.search = local.search;
  return { local, upstream };
}

function logPathname(pathname, store, limits) {
  try {
    if (!store.containsSensitiveTexts?.(decodeURIComponent(pathname))) {
      return redactSecrets(pathname.replace(LOG_IPV4_PATTERN, '[redacted-ipv4]'), limits).body;
    }
  } catch {
    // A logging failure must neither echo sensitive text nor abort the request.
  }
  return '[redacted-endpoint]';
}

function sendJsonError(response, status, message, headers = {}) {
  response.writeHead(status, { 'content-type': 'application/json', ...headers });
  response.end(JSON.stringify({ error: message }));
}

function mappingFailure(error, original, redacted, secretCount, { mode, store }) {
  switch (error.code) {
    case 'MAPPING_CAPACITY_EXHAUSTED':
    case 'SECRET_MAPPING_CAPACITY_EXHAUSTED':
      throw new RequestRejection(507, 'Redaction mapping capacity exhausted; request was not forwarded', 'mapping-capacity-exhausted');
    case 'TRANSFORMED_BODY_TOO_LARGE':
      throw new RequestRejection(413, 'Transformed request body exceeds 64 MiB limit', 'transformed-request-too-large');
  }
  const mustProtect = mode === 'paranoic' || secretCount > 0
    || containsSensitiveIpv4(redacted) || store.containsSensitiveTexts?.(original);
  if (mustProtect) {
    throw new RequestRejection(502, 'Outbound IPv4 redaction failed; request was not forwarded', 'outbound-redaction-failed');
  }
  return 'outbound-ipv4-state-unavailable-no-ipv4-request-forwarded';
}

async function redactRequest(body, options) {
  const { mode, store, limits, maxBodyBytes } = options;
  let redacted;
  let original;
  try {
    original = new TextDecoder('utf-8', { fatal: true }).decode(body);
    redacted = redactSecrets(original, limits, mode);
  } catch (error) {
    throw new RequestRejection(502, 'Outbound secret redaction failed; request was not forwarded',
      'outbound-secret-redaction-failed', errorDiagnostics(error, { preview: options.debug }));
  }
  if (Buffer.byteLength(redacted.body, 'utf8') > maxBodyBytes) {
    throw new RequestRejection(413, 'Transformed request body exceeds 64 MiB limit', 'transformed-request-too-large');
  }
  try {
    if (redacted.count > 0 && !store.obfuscateRequest) throw new Error('Restorable secret mappings are unavailable');
    const transformed = store.obfuscateRequest
      ? await store.obfuscateRequest(body.toString('utf8'), { maxBytes: maxBodyBytes, mode, redactionLimits: limits })
      : await store.obfuscate(redacted.body, { maxBytes: maxBodyBytes });
    return {
      body: Buffer.from(transformed.body, 'utf8'),
      count: transformed.count,
      secretCount: transformed.secretCount ?? redacted.count,
    };
  } catch (error) {
    const warning = mappingFailure(error, body.toString('utf8'), redacted.body, redacted.count, options);
    return { body: Buffer.from(redacted.body, 'utf8'), count: 0, secretCount: redacted.count, warning };
  }
}

async function fetchUpstream(request, body, upstream, inference, controller, state, options) {
  controller.signal.throwIfAborted();
  const timeout = setTimeout(() => {
    state.timedOut = true;
    controller.abort();
  }, options.upstreamTimeoutMs);
  timeout.unref();
  try {
    state.failureStage = 'upstream-fetch';
    const response = await options.fetchImpl(upstream, {
      method: request.method,
      headers: requestHeaders(request.headers),
      body: body.length > 0 ? body : undefined,
      redirect: 'manual',
      signal: controller.signal,
    });
    if (inference && response.status >= 300 && response.status < 400) {
      await response.body?.cancel?.().catch(() => {});
      throw new RequestRejection(502, 'Redirect from inference endpoint blocked to preserve IPv4 redaction guarantee', 'inference-redirect-blocked');
    }
    state.failureStage = 'upstream-body';
    return { response, body: await readBody(response.body, options.maxBodyBytes) };
  } catch (error) {
    if (error instanceof BodyLimitError) {
      throw new RequestRejection(502, 'Upstream response exceeds 64 MiB limit', 'upstream-response-too-large');
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function restoreResponse(body, contentType, protocol, { store, maxBodyBytes }) {
  let transformed;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(body);
    const isSse = contentType?.toLowerCase().includes('text/event-stream') || /(?:^|\n)(?:event|data):/.test(text);
    transformed = isSse ? await deobfuscateSse(text, protocol, store) : await store.deobfuscate(text);
    if (Buffer.byteLength(transformed.body, 'utf8') <= maxBodyBytes) {
      return { body: Buffer.from(transformed.body, 'utf8'), count: transformed.count };
    }
  } catch {
    return { body, count: 0, warning: 'inbound-deobfuscation-failed-fake-response-returned' };
  }
  throw new RequestRejection(502, 'Transformed upstream response exceeds 64 MiB limit', 'transformed-response-too-large');
}

function sendUpstreamResponse(response, upstream, body, warning) {
  const headers = new Headers();
  for (const [name, value] of upstream.headers.entries()) {
    if (HOP_BY_HOP_HEADERS.has(name.toLowerCase()) || name.toLowerCase() === 'content-encoding') continue;
    headers.append(name, value);
  }
  if (warning) headers.set('x-ipv4-proxy-warning', warning);
  response.statusCode = upstream.status;
  response.statusMessage = upstream.statusText;
  for (const [name, value] of headers) response.setHeader(name, value);
  response.setHeader('content-length', body.length);
  response.end(body);
}

function logWarning(logger, endpoint, warning) {
  logMetadata(logger, { level: 'warning', warning, endpoint });
}

async function forwardRequest(request, response, upstream, controller, state, options) {
  const { protocol, inference } = state;
  let body;
  try {
    body = await readBody(request, options.maxBodyBytes);
  } catch (error) {
    if (error instanceof BodyLimitError) throw new RequestRejection(413, 'Request body exceeds 64 MiB limit');
    throw error;
  }
  if (inference && body.length > 0) {
    const redacted = await redactRequest(body, options);
    body = redacted.body;
    state.outboundReplacements = redacted.count;
    state.secretRedactions = redacted.secretCount;
    state.warning = redacted.warning;
    if (state.warning) logWarning(options.logger, state.endpoint, state.warning);
  }
  const result = await fetchUpstream(request, body, upstream, inference, controller, state, options);
  body = result.body;
  if (inference && body.length > 0) {
    const restored = await restoreResponse(body, result.response.headers.get('content-type'), protocol, options);
    body = restored.body;
    state.inboundReplacements = restored.count;
    if (restored.warning) {
      state.warning ??= restored.warning;
      logWarning(options.logger, state.endpoint, state.warning);
    }
  }
  state.failureStage = 'response-write';
  sendUpstreamResponse(response, result.response, body, state.warning);
  return result.response.status;
}

function sendFailure(response, error, state, debug) {
  const rejection = error instanceof RequestRejection;
  const status = rejection ? error.status : state.timedOut ? 504 : 502;
  const message = rejection ? error.message : state.timedOut ? 'Upstream request timed out' : 'Proxy request failed';
  if (!response.destroyed && !response.headersSent) sendJsonError(response, status, message);
  else if (!response.destroyed) response.destroy();
  if (rejection) return { status, warning: error.warning, error: error.diagnostic };
  return {
    status,
    warning: state.timedOut ? 'upstream-timeout' : 'proxy-request-failed',
    failureStage: state.failureStage,
    error: errorDiagnostics(error, { preview: debug }),
  };
}

async function waitForResponse(response) {
  if (response.writableFinished || response.destroyed) return;
  await new Promise((resolve) => {
    const done = () => {
      response.removeListener('finish', done);
      response.removeListener('close', done);
      resolve();
    };
    response.once('finish', done);
    response.once('close', done);
  });
}

async function handleRequest(request, response, local, upstream, options) {
  const startedAt = Date.now();
  const protocol = protocolForPath(local.pathname);
  const state = {
    endpoint: logPathname(local.pathname, options.store, options.limits),
    protocol,
    inference: request.method === 'POST' && (protocol !== null || options.protectAllPostBodies),
    outboundReplacements: 0, inboundReplacements: 0, secretRedactions: 0,
    failureStage: 'request-preparation', timedOut: false,
  };
  const controller = new AbortController();
  const abort = () => controller.abort();
  const onClose = () => { if (!response.writableFinished) abort(); };
  request.once('aborted', abort);
  response.once('close', onClose);
  try {
    let outcome;
    try {
      const status = await forwardRequest(request, response, upstream, controller, state, options);
      outcome = { status, secretRedactions: state.secretRedactions, warning: state.warning };
    } catch (error) {
      outcome = sendFailure(response, error, state, options.debug);
    }
    logMetadata(options.logger, {
      mode: options.mode, endpoint: state.endpoint,
      outboundReplacements: state.outboundReplacements,
      inboundReplacements: state.inboundReplacements,
      ...outcome,
      durationMs: Date.now() - startedAt,
    });
  } finally {
    request.removeListener('aborted', abort);
    // Keep the concurrency slot until the buffered reply has flushed or closed.
    await waitForResponse(response);
    response.removeListener('close', onClose);
  }
}

export function createProxy({
  mode, store, upstreamBase = UPSTREAM_BASE, protectAllPostBodies = false,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES, upstreamTimeoutMs = 10 * 60 * 1000,
  maxConcurrentRequests = 8, redactionLimits, debug = false,
  logger = (line) => process.stderr.write(`${line}\n`), fetchImpl = fetch,
}) {
  const options = { mode, store, protectAllPostBodies, maxBodyBytes, upstreamTimeoutMs, logger, fetchImpl, debug,
    limits: resolveRedactionLimits(redactionLimits) };
  let activeRequests = 0;
  return http.createServer(async (request, response) => {
    if (activeRequests >= maxConcurrentRequests) {
      sendJsonError(response, 503, 'Proxy concurrent request limit reached', { connection: 'close' });
      request.resume();
      logMetadata(logger, { mode, status: 503, warning: 'concurrent-request-limit' });
      return;
    }
    let urls;
    try {
      urls = upstreamUrl(request.url, upstreamBase);
    } catch {
      sendJsonError(response, 400, 'Invalid request URL');
      logMetadata(logger, { mode, status: 400, warning: 'invalid-request-url' });
      return;
    }
    activeRequests += 1;
    try {
      await handleRequest(request, response, urls.local, urls.upstream, options);
    } finally {
      activeRequests -= 1;
    }
  });
}
