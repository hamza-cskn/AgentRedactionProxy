# OpenCode IPv4 Proxy

A local reverse proxy that consistently replaces IPv4 addresses in plain text
before OpenCode Zen model requests leave the machine, then restores those
addresses in buffered model responses before OpenCode receives them.

## Start

Requires Node.js 24 or newer on macOS or Linux. There are no npm dependencies.

Merge [examples/opencode.jsonc](examples/opencode.jsonc) into the `opencode.jsonc`
in the project where you run OpenCode. It routes the `opencode` provider to
`http://127.0.0.1:8787/v1` and restricts enabled providers to `opencode`.
Preserve your other project settings. See the
[OpenCode configuration documentation](https://opencode.ai/docs/config/)
for configuration precedence.

Start the proxy first:

```bash
# Run from this proxy's directory.
npm start
```

Then quit and restart OpenCode from the configured project directory.

## Modes

Set `mode` in `config.json`, then restart the proxy.

### `never-see`

- The proxy persists new mappings before forwarding a model request.
- If outbound IPv4 processing fails, the proxy returns `502` and does not call
  OpenCode Zen.
- If inbound deobfuscation fails, the already-safe response is returned with
  fake IPv4 addresses and an `x-ipv4-proxy-warning` header.
- If the proxy is unavailable, OpenCode's request fails. There is no direct
  provider fallback in the project config.

### `non-paranoic`

- Requests and responses are normally transformed in the same way.
- If outbound processing fails, the raw request is forwarded to OpenCode Zen.
- Fail-open requests produce a body-free warning on stderr and add an
  `x-ipv4-proxy-warning` response header.

## Mapping

- Mappings persist at
  `~/.local/share/opencode-ipv4-proxy/mappings.json`.
- The state directory and file use POSIX `0700` and `0600` permissions.
- State updates use a cross-process lock with a five-second wait. Locks are
  never removed as stale automatically because doing so could remove a live
  lock. Atomic updates fsync both the file and containing directory before a
  newly mapped request is forwarded. If directory sync fails after the rename,
  the mapping stays committed and `never-see` blocks forwarding. Subsequent
  requests retry the durability check, including requests using existing mappings.
- Fake addresses are allocated sequentially from `192.0.2.1` through
  `192.0.2.254`, then `198.51.100.1` through `198.51.100.254`, and finally
  `203.0.113.1` through `203.0.113.254`.
- Existing RFC 5737 addresses pass through unchanged.
- After all 762 mappings are allocated, a request containing any new IPv4 is
  rejected with HTTP `507`. The request is never forwarded in either mode, and
  mappings tentatively created by that request are rolled back.
- The proxy refuses to start if the mapping file is malformed.
- If a process crashes while holding the lock, stop every proxy process and
  manually remove `~/.local/share/opencode-ipv4-proxy/mappings.json.lock`.

### Status and manual recovery

Run `npm run status` to print `used`, `capacity`, and `remaining` counts. This
command does not create, modify, or print mappings, and does not start the proxy.
Counts are a snapshot and can change while requests are running.

For a leftover lock, stop every proxy process first, then remove only
`mappings.json.lock` from the state directory. Never remove a live process's lock.

For corrupt or exhausted mappings, stop every proxy process and move
`mappings.json` to a private backup before restarting. Keep the backup's `0600`
permissions. Resetting reuses fake addresses: existing conversation history can
then restore them to the wrong real addresses. Start new OpenCode sessions after
a reset. To recover old sessions, restore their original mapping file while all
proxy processes are stopped. There is no automatic reset or stale-lock removal.

## Protocol Support

The proxy forwards to `https://opencode.ai/zen/v1` and transforms request and
response bodies for all current Zen inference endpoint families:

- OpenAI Responses: `/v1/responses`
- Anthropic Messages: `/v1/messages`
- OpenAI-compatible Chat Completions: `/v1/chat/completions`
- Gemini generate/streamGenerateContent endpoints

The same routes without the `/v1` prefix are supported, including SSE responses.
JSON strings are decoded before IPv4 replacement, including JSON encoded inside
tool-argument strings. Unchanged strings, numeric literals, and JSON whitespace
are preserved. Plain text uses the same address matcher directly.

Responses are buffered completely before deobfuscation. SSE is parsed according
to its protocol family so text, reasoning, and tool-argument deltas can be
reassembled before replacement. Transformed text is distributed back across
approximately the same chunk lengths while preserving event count and order.
Each streamed field is transformed once as a complete string; individual chunks
are not scanned again. Other JSON string values are restored independently.
Malformed SSE that cannot be parsed follows the fake-response fallback.
Unrecognized event fields receive only whole-address replacement; fragmented
addresses in unrecognized fields may remain fake. Buffering removes live token
streaming.

Request and response bodies are limited to 64 MiB.
The limit is enforced both before and after transformation. A transformed
oversized outbound request is rejected without persisting its new mappings; an
oversized transformed inbound response returns `502`.

At most eight requests are processed concurrently. Excess requests receive
`503` before their bodies are buffered. Each upstream fetch has a ten-minute
deadline covering both response headers and the complete body; expiry returns
`504`. Client disconnects cancel upstream fetches. These limits do not impose a
fixed process-memory ceiling: parsing and SSE transformation create extra copies.

## Security Boundary

The `never-see` guarantee covers dotted-decimal IPv4 addresses in plain-text
content of inference HTTP bodies sent to the OpenCode Zen model provider.
This includes decoded JSON strings and JSON encoded inside tool-argument
strings. It does not inspect or decode base64 payloads, images, or binary
attachments; those contents are outside the guarantee and are not rejected
because they are attachments.

It does not cover:

- HTTP headers or query parameters
- Non-inference endpoints such as `/v1/models`
- Other network traffic from OpenCode or local tools
- Session sharing, telemetry, software updates, or external integrations
- OpenCode runs where the project provider restriction is not loaded
- Higher-precedence inline or managed OpenCode configuration that overrides the
  project provider restriction

Inbound deobfuscation intentionally gives local OpenCode and its tools the real
IPv4 values. If a model independently emits an RFC 5737 address that exactly
matches an existing fake mapping, the proxy also restores it; this ambiguity is
accepted by the current design.

Mapping state is plaintext and contains real IPv4 addresses. Normal request
logs contain only timestamp, mode, endpoint, status, replacement counts, and
duration. Request and response bodies and concrete IPv4 values are not logged.

## Test

Tests use only local mock upstream servers and do not call OpenCode Zen:

```bash
npm test
```

The suite includes filesystem-failure injection, separate-process mapping
allocation, escaped JSON, SSE routing, deadlines, and cancellation. GitHub
Actions is configured to run it on Node.js 24 and 26 on Linux and macOS, plus a
separate Linux job for the OpenCode CLI integration with version 1.18.31.

With OpenCode installed, run the additional CLI integration test:

```bash
npm run test:opencode
```

It uses temporary configuration and state, dummy credentials, and a local mock
model. The model requests a `printf` tool call, allowing the test to verify that
OpenCode receives the real address and sends the subsequent tool result through
redaction again. No live model calls are made. OpenCode may install its own
runtime dependencies on first use. This optional test is skipped by `npm test`.
The CLI round trip was verified with OpenCode 1.18.31; it exercises Chat
Completions. The other protocol families are covered by local proxy/SSE tests.
