# Agent Redaction Proxy

> **TL;DR:** Keeps sensitive data local when using AI coding agents (OpenCode, Claude Code).

It replaces real IPv4 addresses, recognizable credentials and configured literal sensitive strings with persistent random markers before requests leave your machine, and restores known markers in LLM responses and tool arguments.

<img width="344" height="264" alt="Agent Redaction Proxy concept" src="https://github.com/user-attachments/assets/aed2009c-9fbe-44c4-8b26-954c3fa94544" />

*The model doesn't know the real IP. So answers wrongly as we want.*

---

## What & How

- **What:** A zero-dependency local reverse proxy that sits between your AI coding agents and upstream LLM providers.
- **How:** 
  1. **Outbound:** Masks IPv4 addresses, recognized credentials and configured literal strings with persistent random markers.
  2. **Upstream:** Forwards sanitized prompts to the provider.
  3. **Inbound:** Buffers LLM responses (including Server-Sent Events / SSE streams) and restores known markers before delivering local text and tool arguments.

```
[Local Agent / Tools]
       │  ▲
       │  │ (Inbound: restores known markers -> real IPs)
       ▼  │
[Agent Redaction Proxy]
  • Maps real IPv4 -> [REDACTED_IP_<random-id>]
  • Redacts credentials -> [REDACTED_*]
       │  ▲
       │  │ (Buffers response / SSE events)
       ▼  │
 [Upstream LLM API] (OpenAI Codex / Anthropic)
```

---

## Features

| Feature | Details |
| :--- | :--- |
| **IPv4 Masking & Restoration** | Persistent 1:1 mapping of real IPv4s to random markers. AWS private hostnames (e.g., `ip-10-20-30-40.ec2.internal`) are also recognized and restored with their original hyphenated shape. |
| **Credential Redaction** | Reversible masking of recognizable API-token formats (including AWS access key IDs), JWT/JWE tokens, PEM/PGP private keys, and positional URL passwords (`user:pass@host`). Field and parameter names do not classify values as secrets. |
| **Fail-Closed Security** | Rejects requests (HTTP 502) if secret redaction fails, credentials appear malformed, or mapping limits are reached. |
| **SSE Stream Support** | Reassembles streamed deltas (OpenAI Responses, Anthropic Messages), including Anthropic initial block text, before restoring IPs. Responses string deltas without an `item_id` leave the entire response unchanged with markers (or legacy fake addresses) and an `x-ipv4-proxy-warning` header; restoration never guesses their grouping. |
| **Zero Dependencies** | Built with native Node.js ESM. No external packages required. |

---

## Quick Start

### 1. Requirements
- Node.js >= 24 (macOS or Linux).
- No npm dependencies to install.
- Alternatively, Docker with Compose on macOS, Windows or Linux (Linux containers).

### 2. Start the Proxy
```bash
npm start
```

The proxy starts two listeners:
- `http://127.0.0.1:8787` &rarr; OpenCode (forwards to `https://chatgpt.com/backend-api/codex`)
- `http://127.0.0.1:8788` &rarr; Claude Code (forwards to `https://api.anthropic.com/v1`)

### 3. Check Mapping Status
```bash
npm run status
```
Outputs current capacity snapshot:
```json
{"used": 0, "capacity": 762, "remaining": 762}
```

---

## Docker

Published image destination: `366366/agent-redaction-proxy`. GitHub Actions builds and smoke-tests the container after the existing test jobs pass. Pushes to `main` (or a manual workflow run on `main`) publish `latest` and `sha-<full-commit-sha>` for `linux/amd64` and `linux/arm64`. Pull requests/other branches build and test only, without registry login or publishing. The repository secret `DOCKER_ACCESS_TOKEN` must be a Docker Hub token for `366366` with write access to this image. It is used only for registry login, never passed into the Docker build. Publication begins only after the workflow and Docker files are committed and pushed.

The provided Compose file still builds from local source. Once an image has been published, you can download it with `docker pull 366366/agent-redaction-proxy:latest`.

Create a `data` directory beside `compose.yaml`, then run:

```bash
docker compose up --build -d
docker compose logs -f proxy
```

On macOS/Linux, create the directory yourself (`mkdir -p data`) and set `ARP_UID` and `ARP_GID` to your user/group IDs (`export ARP_UID=$(id -u) ARP_GID=$(id -g)`) before using Compose. On Windows, create `data` in Explorer or PowerShell; the default container UID/GID is 1000. Docker Desktop must be running with Linux containers. These variables contain IDs, never encryption keys.

The proxy runs non-root with a read-only image, writable persistent `/data`, dropped capabilities and host-loopback-only published ports. It listens on `0.0.0.0` only inside the container. Agents on the host continue using `127.0.0.1:8787` and `127.0.0.1:8788`; their OAuth credentials stay in client headers, not container configuration. Do not expose the proxy publicly—it has no local client authentication.

Place optional literal strings in `data/user_defined_secrets.json`. Existing mappings must be copied/moved explicitly, while all proxies are stopped, to `data/redaction_mapping.json`. Do not start an empty store for existing conversations. Changes to image-baked `config.json` require rebuilding, or mount a config file read-only and set `ARP_CONFIG_FILE` to its container path.

### Encryption and one-way conversion

| Mode | Redaction-mapping | User-defined secrets |
|---|---|---|
| Plaintext | `redaction_mapping.json` | `user_defined_secrets.json` |
| Encrypted | `redaction_mapping.secret.json` | `user_defined_secrets.secret.json` |

Mode is selected only by whether `master_key_secret` exists (or the file pointed to by `ARP_MASTER_KEY_FILE`). An existing key file must contain a canonical base64-encoded random 32-byte key; it is **not a human password**. Both files use Node's built-in AES-256-GCM, fresh random 12-byte nonces and 16-byte authentication tags. Their type/version is authenticated. Wrong keys, tampering, plaintext in encrypted mode or encrypted-only files without a key fail startup; nothing is converted automatically. The optional user-defined secrets file can be absent. New stores are created in the selected mode.

To convert, stop every proxy using the directory, including native instances:

```bash
docker compose stop proxy
docker compose run --rm --no-deps proxy node scripts/encrypt-storage.mjs /data
```

Alternatively run `npm run encrypt-storage -- /absolute/path/to/data` natively. The script requires a terminal and prompts with input hidden. Generate the key using a cryptographic generator/password manager (for example `openssl rand -base64 32`) and keep it out of shell arguments, environment variables and logs. Store a protected backup: losing the key loses restoration.

The script validates input, writes and verifies encrypted output, publishes `master_key_secret` last, then deletes plaintext originals. Preparation failure preserves original plaintext files and removes its incomplete outputs. Existing encrypted outputs/key files are never overwritten. Missing inputs become an empty mapping/list. Marker UUIDs and legacy aliases remain unchanged. Cleanup failure after activation reports leftover plaintext files; encrypted mode remains active. This is rollback before activation, not a crash-proof multi-file transaction or secure disk erasure. Remove reported plaintext leftovers manually with all proxies stopped; protect existing backups/snapshots too. After an interrupted conversion, inspect outputs and `.encryption-conversion.lock` before manual recovery. There is no encrypted-to-plaintext script.

The generated master-key file is initially in `data`. For Docker secret injection, create a private `secrets` directory and **move** `data/master_key_secret` to `secrets/master_key_secret`, then run:

```bash
docker compose -f compose.yaml -f compose.encrypted.yaml up --build -d
```

This mounts the key read-only at `/run/secrets/master_key_secret`. Use the same two `-f` options for subsequent `run`, `up` and `status` commands. Do not restart with plaintext-only Compose after removing the key from `data`. Compose file-backed secrets do not encrypt the host key file: protect `secrets/master_key_secret` with host permissions/ACLs and disk encryption. Do not store the key alongside encrypted data in backups. Encryption does not protect process memory, a compromised running container, or someone with access to both ciphertext and the key.

Runtime paths: `ARP_DATA_DIR` selects the data directory, `ARP_MASTER_KEY_FILE` selects the optional key-file path, `ARP_CONFIG_FILE` selects configuration, and `ARP_LISTEN_HOST` controls the bind address. These settings are paths/addresses, not secret values. Without Docker, the default data directory remains `~/.local/share/opencode-ipv4-proxy`.

---

## Agent Setup

### OpenCode (OpenAI OAuth)
1. Sign in to OpenAI through OpenCode first (`opencode auth login`).
2. Copy [`.opencode/plugins/openai-ipv4-proxy.js`](.opencode/plugins/openai-ipv4-proxy.js) into your target project's `.opencode/plugins/` directory.
3. Add the proxy URL to your project's `opencode.jsonc` (see [`examples/opencode.jsonc`](examples/opencode.jsonc)):
   ```jsonc
   {
     "$schema": "https://opencode.ai/config.json",
     "enabled_providers": ["openai"],
     "provider": {
       "openai": {
         "options": {
           "baseURL": "http://127.0.0.1:8787/v1"
         }
       }
     }
   }
   ```
4. Run OpenCode with default plugins disabled:
   ```bash
   OPENCODE_DISABLE_DEFAULT_PLUGINS=true opencode
   ```
   *(Do not set `OPENAI_API_KEY` for this OAuth setup).*

### Claude Code (Anthropic)
1. Sign in with `claude auth login`.
2. Run Claude Code with `ANTHROPIC_BASE_URL` pointing to the proxy:
   ```bash
   ANTHROPIC_BASE_URL=http://127.0.0.1:8788 claude
   ```
   *(Do not set `ANTHROPIC_API_KEY` so Claude Code uses your subscription login).*

---

## Configuration (`config.json`)

Configure proxy behavior in `config.json`:

```json
{
  "mode": "paranoic",
  "sensitiveTextsFile": null,
  "redactionLimits": {
    "maxApiTokenChars": 4096,
    "maxJwtChars": 16384,
    "maxJwtHeaderBytes": 4096,
    "maxBase64Chars": 65536
  }
}
```

- `"paranoic"` (default): Strict fail-closed policy. Durably commits mappings before forwarding. Rejects outbound requests if redaction or storage fails.
- `"default"`: Same transformation logic, but requests containing no recognized sensitive values can bypass storage failures with a warning header. IPs, recognized credentials and configured literal matches still fail closed.

### Your own sensitive strings

Create a private JSON file containing literal strings:

```json
["private-service-name", "my-literal-password"]
```

With `sensitiveTextsFile` omitted or null, the proxy automatically loads `user_defined_secrets.json` from its data directory, or `user_defined_secrets.secret.json` in encrypted mode, if present. Restart after changes. An explicit `sensitiveTextsFile` path overrides this choice; it must already match the selected encryption mode. Relative paths resolve against the config file's directory; absolute paths also work. The conversion script only handles the standard filenames in the data directory, so move custom-path files there and remove the override before converting. Keep plaintext inputs private (`chmod 600 user_defined_secrets.json`). A synthetic example is in `examples/sensitive-texts.example.json`.

Matching is exact and case-sensitive, including decoded JSON strings and multiline values; overlapping entries prefer the longer match. Whitespace is preserved, not trimmed or collapsed. Entries are literals, not regular expressions. Matches use persistent `[REDACTED_TEXT_<random-id>]` markers and restore just like IPs. Removing an entry does not erase its existing restoration mapping. Limits: 1 MiB file, 1024 entries, 4096 UTF-8 bytes per entry. Empty/whitespace-only strings, single-character ASCII entries and the reserved `[REDACTED_` namespace are rejected. Accepted entries shorter than five Unicode code points generate startup warnings with entry index and length, never their contents. Invalid or missing configured files stop startup.

Built-in credentials use reversible `API_KEY`, `JWT`, `PRIVATE_KEY` and `PASSWORD` markers too. Originals are persisted in the private mapping file, encrypted when a master-key file is present, otherwise plaintext. Only exact known markers restore; the model must preserve them. Old one-way markers such as `[REDACTED_API_KEY]` cannot be recovered because their originals were never saved. HTTP headers remain outside scanning scope.

### Candidate size limits

The values above are configurable defaults. Omitted entries use their defaults; overrides must be integers from 1 through 67108864. Restart the proxy after editing the configuration.

- API-token and JWT/JWE limits count the full ASCII candidate, including prefixes and separators. A bounded header sample rules out dotted identifiers that cannot have a JSON-object header. Possible JWT headers are then size-checked before full decoding or parsing; leading whitespace does not bypass the limits.
- The arbitrary-blob limit counts each contiguous standard-base64/base64url-like run, including padding, in decoded JSON strings or plain text. This is a size guard, not a secret detector: it can also block long ordinary identifiers and base64 attachments/data URLs. Line-wrapped or separately stored fragments are not joined into one blob.
- Exceeding any limit rejects the outbound request with HTTP 502 in **both modes**, without forwarding it, truncating it, or including the candidate in logs/errors. Checks run before redaction can remove a candidate. Malformed JWT-like candidates are also bounded before header parsing.
- Arbitrary base64 is not decoded or recursively searched for hidden secrets. The existing 64 MiB body limit remains separate; these guards do not enable incremental streaming or limit inbound restoration.

### Literal matching boundaries

- In both modes, a hostname and numeric port (0–65535) can end before whitespace/prose, a dash, or a Markdown link target. For example, `http://localhost:8080 (contact dev@example.com)` no longer swallows the email into userinfo. An immediate `@`, including horizontal spacing before it, still triggers password redaction; contiguous passwords containing dashes remain protected. This intentionally treats `http://alice:8080 more@host` as a URL followed by text, not a password containing raw spaces. Malformed credential forms without a recognized URL/prose boundary still fail closed. Percent-encoded password spaces remain protected.
- Numeric ports and literal port notation (shell, Helm/Jinja, Makefile, Ruby, Swift and Python forms) are accepted inside ordinary prose and code. Balanced, single-line expressions are scanned as syntax only, with a nesting limit of 64; nothing is evaluated. A following `@host` still makes the value userinfo, not an exempt placeholder.
- Single-slash forms without a possible `@` boundary are treated as paths rather than guessed URL authorities, allowing Docker/Podman volumes and Windows paths. Malformed single-slash userinfo with an `@` boundary still fails closed. IPv6 zone identifiers and passwordless multi-host connection strings are supported without treating field names as secret classifiers.
- There is no field-name-based detection: `password=`, `token=`, and AWS secret assignment names do not trigger redaction in query strings, connection-string assignments, code, or configuration. Values are still scanned for recognizable secret formats and IPv4 addresses, regardless of their labels. Opaque passwords and AWS secret/session values without a recognized format are not protected by their names.
- npm and PyPI matching follows their documented token shapes ([npm](https://api-docs.npmjs.com/), [PyPI](https://docs.pypi.org/api/secrets/)). In `default` mode only, `sk-` and `hf_` candidates followed by a filename extension are preserved: exactly three ASCII letters, or `yaml`, `jpeg`, `json`, `html`, `toml`, `conf`, `js`, `ts`, `py`, `go`, `rs`, `sh`, `c`, `h` (case-insensitive, followed by end of text or a supported prose delimiter). This intentionally can expose a real token with the same spelling. `paranoic` and log sanitization retain conservative redaction. Other token families, URL passwords, IPv4 masking and candidate size limits are not exempted.
- The filename exception excludes explicit `sk-ant-`, `sk-proj-` and `sk-svcacct-` prefixes; these remain redacted even in `default` mode.
- HTTP header detection is out of scope. Generic `.env`/JSON/YAML password fields and `curl -u` are not covered as separate formats. Recognized token patterns inside text are still redacted. PEM-marker fail-closed behavior is unchanged.

---

## Known Gaps — Deliberate Scope Exclusions

These limitations are intentional and outside the project's scope:

- **Domain names:** Domain names are deliberately not obfuscated. They remain visible to the upstream model. Recognized IPv4 addresses embedded in hostnames (including supported AWS private hostname formats) are still obfuscated; this is IP masking, not domain-name protection.
- **Semantic or evaluated sensitive data:** The proxy matches literal text; it does not execute code or infer values produced by string concatenation, variable substitution, or other computations. For example, `"10.20." + "30.40"` is not detected as the resulting IPv4 address. Reassembling network chunks and protocol-defined SSE fragments is separate and remains supported.
- **Placeholder versus password distinction:** The proxy does not reliably distinguish a placeholder from a real password. Characters such as `$`, `{`, and `}` can occur in either. Do not rely on placeholder-looking text being preserved or classified correctly; general semantic classification is deliberately out of scope.

### Marker compatibility and limitations

- **Exact restoration:** Only complete, known `[REDACTED_<type>_<32 lowercase hexadecimal characters>]` markers are restored. Types are `IP`, `TEXT`, `API_KEY`, `JWT`, `PRIVATE_KEY` and `PASSWORD`. Unknown or edited markers remain unchanged. IDs are random and persisted, not hashes of the original. Randomness reduces accidental collisions; a copied known marker still restores regardless of its provenance.
- **Not valid IP syntax:** Markers are not IPv4 addresses or valid URL hosts. Strict IP/URL schema validation upstream may reject them. Local tool arguments are restored before delivery, provided the model preserves the marker exactly.
- **Legacy migration:** Version-1 and version-2 state is atomically migrated to version 3 on the next successful outbound transformation. Existing version-2 IP markers stay unchanged; version-1 fake-IP aliases are retained for existing conversations. Read-only `status` does not migrate files. Back up state with all proxy instances stopped before upgrading; older proxy versions cannot read version-3 state.
- **Legacy documentation-IP collisions:** Fresh stores no longer allocate documentation IPs. Migrated stores still restore their old aliases, so literal examples matching those aliases can still restore to real hosts. This compatibility risk is retained explicitly; migration does not establish provenance. Do not reset mappings while continuing old conversations.

---

## Storage & Maintenance

- **Mapping Location:** `~/.local/share/opencode-ipv4-proxy/redaction_mapping.json`, or `redaction_mapping.secret.json` in encrypted mode (POSIX `0600` permissions, directory `0700`). Docker uses `/data`. On Windows use equivalent host ACLs. Original IPs, credentials and custom strings are encrypted only when a master-key file is present.
- **Filename upgrade:** With every proxy stopped, manually rename existing `mappings.json` to `redaction_mapping.json`; the proxy refuses to silently abandon a legacy-named mapping file. This filename change and the explicit encryption conversion are separate from the existing JSON state-schema migration.
- **Capacity:** 762 persistent IP mappings and 10000 credential/custom-text mappings. Requests exceeding either capacity return HTTP 507. The read-only `status` command currently reports IP capacity only.
- **Stale Lock Recovery:** If the proxy process crashed during a write, stop all proxy instances and remove the lockfile:
  ```bash
  rm ~/.local/share/opencode-ipv4-proxy/redaction_mapping.json.lock
  ```
- In encrypted mode the lock is `redaction_mapping.secret.json.lock`. Never remove locks while another process is running.
- **Reset Mappings:** Stop all proxy instances and move the selected redaction-mapping to a protected backup. Preserve its master key separately when encrypted.
  > **Note:** Resetting loses restoration for previous markers and legacy aliases. Always start fresh agent chat sessions after a reset. Never restore an unrelated mapping backup for an existing conversation.

---

## Testing

`test/false-positives.test.mjs` covers fixed false positives, including both modes and conversation history. `test/known-false-positives.test.mjs` records deliberate conservative policies. Marker persistence, migration, documentation-address separation and stream splits are covered in `test/ip-markers.test.mjs`; the original fake-IP boundary regressions remain as legacy compatibility tests. URL/prose boundaries have explicit credential-protection companions in `test/url-prose-boundaries.test.mjs`.

```bash
# Run unit & mock tests (offline, no live LLM calls)
npm test

# Run OpenCode CLI integration tests (requires OpenCode CLI installed)
npm run test:opencode
```
