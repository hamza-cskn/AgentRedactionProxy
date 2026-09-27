# IPv4 Proxy for OpenCode OAuth and Claude Code

A local reverse proxy that consistently replaces IPv4 addresses in plain text
before model requests leave the machine, then restores those addresses in
buffered model responses. It serves OpenCode's OpenAI login and Claude Code's
Claude login on separate local ports, with one shared mapping store.

## Start

Requires Node.js 24 or newer on macOS or Linux. There are no npm dependencies.

Start the proxy first from this directory:

```bash
npm start
```

It listens on `127.0.0.1:8787` for OpenCode OpenAI OAuth requests and
`127.0.0.1:8788` for Claude Code requests. Both listeners use the mappings in
`~/.local/share/opencode-ipv4-proxy/mappings.json`.

### OpenCode with an existing OpenAI login

Sign in to OpenAI through OpenCode before enabling the project plugin. Copy
[the OAuth routing plugin](.opencode/plugins/openai-ipv4-proxy.js) into the
`.opencode/plugins/` directory of each project where you use OpenCode; this
repository already contains it. Merge [the example config](examples/opencode.jsonc)
into that project's `opencode.jsonc`. It restricts enabled providers to
`openai` and points its Responses base URL at the local proxy. Preserve other
project settings and check [OpenCode config precedence](https://opencode.ai/docs/config/).

Run OpenCode from that project with:

```bash
OPENCODE_DISABLE_DEFAULT_PLUGINS=true opencode
```

This disables OpenCode's built-in OAuth transport, which otherwise bypasses
`baseURL`. The project plugin uses the existing OpenCode OAuth credential and
refreshes it when needed. The plugin intentionally provides no login command;
to sign in again, run OpenCode without this project plugin, then restore it.
Do not set `OPENAI_API_KEY` for this login-based setup.

### Claude Code with an existing Claude login

Sign in with `claude auth login`, then run from the desired project with:

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8788 claude
```

Do not set `ANTHROPIC_API_KEY`: Claude Code gives it precedence over your
subscription login. [Claude Code documents the base URL setting](https://code.claude.com/docs/en/env-vars).
Claude Code's subscription login has not been live-tested in this project yet.

## Modes

Set `mode` in `config.json`, then restart the proxy.

### `never-see`

- The proxy persists new mappings before forwarding a model request.
- If outbound IPv4 processing fails, the proxy returns `502` and does not call
  the upstream model service.
- If inbound deobfuscation fails, the already-safe response is returned with
  fake IPv4 addresses and an `x-ipv4-proxy-warning` header.
- If the proxy is unavailable, the configured request fails. The OpenCode
  project config and startup flag do not provide a direct provider fallback.

### `non-paranoic`

- Requests and responses are normally transformed in the same way.
- If outbound processing fails, the raw request is forwarded upstream.
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

Port `8787` forwards to `https://chatgpt.com/backend-api/codex` for OpenCode's
OpenAI OAuth Responses requests. Port `8788` forwards to
`https://api.anthropic.com/v1` for Claude Code's Anthropic Messages requests.
The OpenCode plugin accepts only Responses inference requests; the proxy
redacts every POST body on both ports, including Claude token-count requests.
The core transformer also understands Chat Completions and Gemini SSE for
local compatibility tests, but neither production listener is configured as
a general gateway for those providers.

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

At most eight requests per listener are processed concurrently. Excess requests receive
`503` before their bodies are buffered. Each upstream fetch has a ten-minute
deadline covering both response headers and the complete body; expiry returns
`504`. Client disconnects cancel upstream fetches. These limits do not impose a
fixed process-memory ceiling: parsing and SSE transformation create extra copies.

## Security Boundary

The `never-see` guarantee covers dotted-decimal IPv4 addresses in plain-text
content of POST bodies sent through either configured listener.
This includes decoded JSON strings and JSON encoded inside tool-argument
strings. It does not inspect or decode base64 payloads, images, or binary
attachments; those contents are outside the guarantee and are not rejected
because they are attachments.

It does not cover:

- HTTP headers or query parameters
- GET requests, non-POST request bodies, and traffic that does not pass through
  these listeners
- Other network traffic from OpenCode, Claude Code, or local tools
- Session sharing, telemetry, software updates, or external integrations
- OpenCode runs where the project plugin, provider restriction, or startup flag
  is not loaded
- Claude Code runs without `ANTHROPIC_BASE_URL` pointed at this proxy
- Higher-precedence inline or managed OpenCode configuration that overrides the
  project provider restriction

Inbound deobfuscation intentionally gives local clients and their tools the real
IPv4 values. If a model independently emits an RFC 5737 address that exactly
matches an existing fake mapping, the proxy also restores it; this ambiguity is
accepted by the current design.

Mapping state is plaintext and contains real IPv4 addresses. Normal request
logs contain only timestamp, mode, endpoint, status, replacement counts, and
duration. Request and response bodies and concrete IPv4 values are not logged.

## Test

Tests use only local mock upstream servers and do not call a live model service:

```bash
npm test
```

The suite includes filesystem-failure injection, separate-process mapping
allocation, escaped JSON, SSE routing, deadlines, and cancellation. GitHub
Actions is configured to run it on Node.js 24 and 26 on Linux and macOS, plus a
separate Linux job for the OpenCode CLI integration with version 1.18.31.

With OpenCode installed, run both CLI integration tests:

```bash
npm run test:opencode
```

They use temporary configuration, dummy credentials, and local mock models.
One checks a Chat Completions tool round trip; the other checks that OpenCode's
OpenAI OAuth provider sends a redacted Responses request through the project
plugin. No live model calls are made. OpenCode may install plugin runtime
dependencies on first use. These optional tests are skipped by `npm test`.
The CLI integrations were verified with OpenCode 1.18.31. Claude Code's
Messages path is covered by local proxy/SSE tests; a live Claude login is
required for subscription end-to-end verification.
