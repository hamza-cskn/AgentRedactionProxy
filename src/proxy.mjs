import http from 'node:http';

import { containsSensitiveIpv4 } from './mapping-store.mjs';
import { redactSecrets } from './secret-redaction.mjs';
import { resolveRedactionLimits } from './redaction-limits.mjs';
import { deobfuscateSse, protocolForPath, stripV1Prefix } from './sse-transform.mjs';

const DEFAULT_MAX_BODY_BYTES = 64 * 1024 * 1024;
const UPSTREAM_BASE = 'https://opencode.ai/zen/v1';
const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'content-length',
  'host',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

export class BodyLimitError extends Error {}

const LOG_IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/g;

// Log output must never carry real IPv4 addresses, even ones that end up in
// the URL path rather than the body, so this masks them one-way before any
// endpoint value reaches the logger.
function redactIpv4ForLogging(value) {
  return value.replace(LOG_IPV4_PATTERN, '[redacted-ipv4]');
}

async function readBody(stream, maxBytes) {
  if (!stream) return Buffer.alloc(0);
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > maxBytes) {
      throw new BodyLimitError(`Body exceeds ${maxBytes} bytes`);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function copyHeaders(source, { response = false } = {}) {
  const headers = new Headers();
  for (const [name, value] of source.entries()) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower)) continue;
    if (response && lower === 'content-encoding') continue;
    headers.append(name, value);
  }
  return headers;
}

function requestHeaders(nodeHeaders) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(nodeHeaders)) {
    if (value === undefined || HOP_BY_HOP_HEADERS.has(name.toLowerCase())) continue;
    if (Array.isArray(value)) {
      for (const item of value) headers.append(name, item);
    } else {
      headers.set(name, value);
    }
  }
  return headers;
}

function upstreamUrl(requestUrl, upstreamBase) {
  const local = new URL(requestUrl, 'http://127.0.0.1');
  const base = new URL(upstreamBase);
  base.pathname = `${base.pathname.replace(/\/$/, '')}${stripV1Prefix(local.pathname)}`;
  base.search = local.search;
  return { local, upstream: base };
}

function writeHeaders(response, headers) {
  for (const [name, value] of headers.entries()) {
    response.setHeader(name, value);
  }
}

function logMetadata(logger, metadata) {
  logger(JSON.stringify({ timestamp: new Date().toISOString(), ...metadata }));
}

export function createProxy({
  mode,
  store,
  upstreamBase = UPSTREAM_BASE,
  protectAllPostBodies = false,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  upstreamTimeoutMs = 10 * 60 * 1000,
  maxConcurrentRequests = 8,
  redactionLimits,
  logger = (line) => process.stderr.write(`${line}\n`),
  fetchImpl = fetch,
}) {
  const limits = resolveRedactionLimits(redactionLimits);
  let activeRequests = 0;
  return http.createServer(async (request, response) => {
    const startedAt = Date.now();
    if (activeRequests >= maxConcurrentRequests) {
      response.writeHead(503, { 'content-type': 'application/json', connection: 'close' });
      response.end(JSON.stringify({ error: 'Proxy concurrent request limit reached' }));
      request.resume();
      logMetadata(logger, { mode, status: 503, warning: 'concurrent-request-limit' });
      return;
    }
    let local;
    let upstream;
    try {
      ({ local, upstream } = upstreamUrl(request.url, upstreamBase));
    } catch {
      response.writeHead(400, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: 'Invalid request URL' }));
      logMetadata(logger, { mode, status: 400, warning: 'invalid-request-url' });
      return;
    }
    const protocol = protocolForPath(local.pathname);
    const inference = request.method === 'POST' && (protocol !== null || protectAllPostBodies);
    let logPathname = '[redacted-endpoint]';
    try {
      logPathname = redactSecrets(redactIpv4ForLogging(local.pathname), limits).body;
    } catch {
      // Strict credential checks may reject a path; never echo it or let a
      // logging-only transformation escape the request handler.
    }
    let outboundCount = 0;
    let inboundCount = 0;
    let secretCount = 0;
    let warning = null;
    let timeout;
    let timedOut = false;
    const controller = new AbortController();
    const abort = () => controller.abort();
    const onClose = () => {
      if (!response.writableFinished) abort();
    };
    request.once('aborted', abort);
    response.once('close', onClose);
    activeRequests += 1;

    try {
      let requestBody;
      try {
        requestBody = await readBody(request, maxBodyBytes);
      } catch (error) {
        if (error instanceof BodyLimitError) {
          response.writeHead(413, { 'content-type': 'application/json' });
          response.end(JSON.stringify({ error: 'Request body exceeds 64 MiB limit' }));
          logMetadata(logger, {
            mode,
            endpoint: logPathname,
            status: 413,
            outboundReplacements: 0,
            inboundReplacements: 0,
            durationMs: Date.now() - startedAt,
          });
          return;
        }
        throw error;
      }

      if (inference && requestBody.length > 0) {
        try {
          const text = new TextDecoder('utf-8', { fatal: true }).decode(requestBody);
          const redacted = redactSecrets(text, limits, mode);
          requestBody = Buffer.from(redacted.body, 'utf8');
          secretCount = redacted.count;
        } catch {
          response.writeHead(502, { 'content-type': 'application/json' });
          response.end(JSON.stringify({ error: 'Outbound secret redaction failed; request was not forwarded' }));
          logMetadata(logger, {
            mode,
            endpoint: logPathname,
            status: 502,
            warning: 'outbound-secret-redaction-failed',
            durationMs: Date.now() - startedAt,
          });
          return;
        }
        if (requestBody.length > maxBodyBytes) {
          response.writeHead(413, { 'content-type': 'application/json' });
          response.end(JSON.stringify({ error: 'Transformed request body exceeds 64 MiB limit' }));
          logMetadata(logger, {
            mode,
            endpoint: logPathname,
            status: 413,
            warning: 'transformed-request-too-large',
            durationMs: Date.now() - startedAt,
          });
          return;
        }
        try {
          const transformed = await store.obfuscate(requestBody.toString('utf8'), { maxBytes: maxBodyBytes });
          requestBody = Buffer.from(transformed.body, 'utf8');
          outboundCount = transformed.count;
        } catch (error) {
          if (error.code === 'MAPPING_CAPACITY_EXHAUSTED') {
            response.writeHead(507, { 'content-type': 'application/json' });
            response.end(JSON.stringify({
              error: 'IPv4 mapping capacity exhausted; request was not forwarded',
            }));
            logMetadata(logger, {
              mode,
              endpoint: logPathname,
              status: 507,
              outboundReplacements: 0,
              inboundReplacements: 0,
              warning: 'mapping-capacity-exhausted',
              durationMs: Date.now() - startedAt,
            });
            return;
          }
          if (error.code === 'TRANSFORMED_BODY_TOO_LARGE') {
            response.writeHead(413, { 'content-type': 'application/json' });
            response.end(JSON.stringify({ error: 'Transformed request body exceeds 64 MiB limit' }));
            logMetadata(logger, {
              mode,
              endpoint: logPathname,
              status: 413,
              outboundReplacements: 0,
              inboundReplacements: 0,
              warning: 'transformed-request-too-large',
              durationMs: Date.now() - startedAt,
            });
            return;
          }
          if (mode === 'paranoic' || containsSensitiveIpv4(requestBody.toString('utf8'))) {
            response.writeHead(502, { 'content-type': 'application/json' });
            response.end(JSON.stringify({ error: 'Outbound IPv4 redaction failed; request was not forwarded' }));
            logMetadata(logger, {
              mode,
              endpoint: logPathname,
              status: 502,
              outboundReplacements: 0,
              inboundReplacements: 0,
              warning: 'outbound-redaction-failed',
              durationMs: Date.now() - startedAt,
            });
            return;
          }
          warning = 'outbound-ipv4-state-unavailable-no-ipv4-request-forwarded';
          logger(JSON.stringify({
            timestamp: new Date().toISOString(),
            level: 'warning',
            warning,
            endpoint: logPathname,
          }));
        }
      }

      controller.signal.throwIfAborted();
      timeout = setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, upstreamTimeoutMs);
      timeout.unref();
      const upstreamResponse = await fetchImpl(upstream, {
        method: request.method,
        headers: requestHeaders(request.headers),
        body: requestBody.length > 0 ? requestBody : undefined,
        redirect: 'manual',
        signal: controller.signal,
      });

      if (inference && upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
        await upstreamResponse.body?.cancel?.().catch(() => {});
        response.writeHead(502, { 'content-type': 'application/json' });
        response.end(JSON.stringify({
          error: 'Redirect from inference endpoint blocked to preserve IPv4 redaction guarantee',
        }));
        logMetadata(logger, {
          mode,
          endpoint: logPathname,
          status: 502,
          outboundReplacements: outboundCount,
          inboundReplacements: 0,
          warning: 'inference-redirect-blocked',
          durationMs: Date.now() - startedAt,
        });
        return;
      }

      let responseBody;
      try {
        responseBody = await readBody(upstreamResponse.body, maxBodyBytes);
        clearTimeout(timeout);
      } catch (error) {
        if (error instanceof BodyLimitError) {
          response.writeHead(502, { 'content-type': 'application/json' });
          response.end(JSON.stringify({ error: 'Upstream response exceeds 64 MiB limit' }));
          logMetadata(logger, {
            mode,
            endpoint: logPathname,
            status: 502,
            outboundReplacements: outboundCount,
            inboundReplacements: 0,
            warning: 'upstream-response-too-large',
            durationMs: Date.now() - startedAt,
          });
          return;
        }
        throw error;
      }

      if (inference && responseBody.length > 0) {
        try {
          const text = new TextDecoder('utf-8', { fatal: true }).decode(responseBody);
          const isSse = upstreamResponse.headers.get('content-type')
            ?.toLowerCase()
            .includes('text/event-stream') || /(?:^|\n)(?:event|data):/.test(text);
          const transformed = isSse
            ? await deobfuscateSse(text, protocol, store)
            : await store.deobfuscate(text);
          if (Buffer.byteLength(transformed.body, 'utf8') > maxBodyBytes) {
            response.writeHead(502, { 'content-type': 'application/json' });
            response.end(JSON.stringify({ error: 'Transformed upstream response exceeds 64 MiB limit' }));
            logMetadata(logger, {
              mode,
              endpoint: logPathname,
              status: 502,
              outboundReplacements: outboundCount,
              inboundReplacements: 0,
              warning: 'transformed-response-too-large',
              durationMs: Date.now() - startedAt,
            });
            return;
          }
          responseBody = Buffer.from(transformed.body, 'utf8');
          inboundCount = transformed.count;
        } catch {
          warning ??= 'inbound-deobfuscation-failed-fake-response-returned';
          logger(JSON.stringify({
            timestamp: new Date().toISOString(),
            level: 'warning',
            warning,
            endpoint: logPathname,
          }));
        }
      }

      const headers = copyHeaders(upstreamResponse.headers, { response: true });
      if (warning) headers.set('x-ipv4-proxy-warning', warning);
      response.statusCode = upstreamResponse.status;
      response.statusMessage = upstreamResponse.statusText;
      writeHeaders(response, headers);
      response.setHeader('content-length', responseBody.length);
      response.end(responseBody);

      logMetadata(logger, {
        mode,
        endpoint: logPathname,
        status: upstreamResponse.status,
        outboundReplacements: outboundCount,
        secretRedactions: secretCount,
        inboundReplacements: inboundCount,
        ...(warning ? { warning } : {}),
        durationMs: Date.now() - startedAt,
      });
    } catch (error) {
      const status = timedOut ? 504 : 502;
      if (!response.destroyed && !response.headersSent) {
        response.writeHead(status, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ error: timedOut ? 'Upstream request timed out' : 'Proxy request failed' }));
      } else if (!response.destroyed) {
        response.destroy();
      }
      logMetadata(logger, {
        mode,
        endpoint: logPathname,
        status,
        outboundReplacements: outboundCount,
        inboundReplacements: inboundCount,
        warning: timedOut ? 'upstream-timeout' : 'proxy-request-failed',
        durationMs: Date.now() - startedAt,
      });
    } finally {
      clearTimeout(timeout);
      request.removeListener('aborted', abort);
      // Keep the slot until a buffered response has flushed or the client has left.
      if (!response.writableFinished && !response.destroyed) {
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
      response.removeListener('close', onClose);
      activeRequests -= 1;
    }
  });
}
