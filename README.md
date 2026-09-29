# Agent Redaction Proxy

> **TL;DR:** Keeps sensitive data local when using AI coding agents (OpenCode, Claude Code).

It replaces real IPv4 addresses with persistent `[REDACTED_IP_<random-id>]` markers before requests leave your machine and restores them in LLM responses. Recognizable credentials and API keys are permanently redacted.

<img width="344" height="264" alt="Agent Redaction Proxy concept" src="https://github.com/user-attachments/assets/aed2009c-9fbe-44c4-8b26-954c3fa94544" />

*The model doesn't know the real IP. So answers wrongly as we want.*

---

## What & How

- **What:** A zero-dependency local reverse proxy that sits between your AI coding agents and upstream LLM providers.
- **How:** 
  1. **Outbound:** Masks plain-text IPv4 addresses with consistent, randomly identified markers and strips recognized credentials/API keys.
  2. **Upstream:** Forwards sanitized prompts to the provider.
  3. **Inbound:** Buffers LLM responses (including Server-Sent Events / SSE streams) and transparently restores the original IPv4 addresses so local tools and terminals work normally.

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
| **Credential Redaction** | Permanent one-way redaction of recognizable API-token formats (including AWS access key IDs), JWT/JWE tokens, PEM/PGP private keys, and positional URL passwords (`user:pass@host`). Field and parameter names do not classify values as secrets. |
| **Fail-Closed Security** | Rejects requests (HTTP 502) if secret redaction fails, credentials appear malformed, or mapping limits are reached. |
| **SSE Stream Support** | Reassembles streamed deltas (OpenAI Responses, Anthropic Messages), including Anthropic initial block text, before restoring IPs. Responses string deltas without an `item_id` leave the entire response unchanged with markers (or legacy fake addresses) and an `x-ipv4-proxy-warning` header; restoration never guesses their grouping. |
| **Zero Dependencies** | Built with native Node.js ESM. No external packages required. |

---

## Quick Start

### 1. Requirements
- Node.js >= 24 (macOS or Linux).
- No npm dependencies to install.

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
  "redactionLimits": {
    "maxApiTokenChars": 4096,
    "maxJwtChars": 16384,
    "maxJwtHeaderBytes": 4096,
    "maxBase64Chars": 65536
  }
}
```

- `"paranoic"` (default): Strict fail-closed policy. Durably commits mappings before forwarding. Rejects outbound requests if redaction or storage fails.
- `"default"`: Same transformation logic, but requests containing no real IPv4 addresses can bypass storage failures with a warning header.

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

- **Exact restoration:** Only complete, known `[REDACTED_IP_<32 lowercase hexadecimal characters>]` markers are restored. Unknown or edited markers remain unchanged. IDs are random and persisted, not hashes of the IP. Randomness reduces accidental collisions; a copied known marker still restores regardless of its provenance.
- **Not valid IP syntax:** Markers are not IPv4 addresses or valid URL hosts. Strict IP/URL schema validation upstream may reject them. Local tool arguments are restored before delivery, provided the model preserves the marker exactly.
- **Legacy migration:** Version-1 state is atomically migrated to version 2 on the next successful outbound transformation. All real IPs then map to markers; old fake-IP aliases are retained for existing conversations. Read-only `status` does not migrate files. Back up state with all proxy instances stopped before upgrading; older proxy versions cannot read version-2 state.
- **Legacy documentation-IP collisions:** Fresh stores no longer allocate documentation IPs. Migrated stores still restore their old aliases, so literal examples matching those aliases can still restore to real hosts. This compatibility risk is retained explicitly; migration does not establish provenance. Do not reset mappings while continuing old conversations.

---

## Storage & Maintenance

- **Mapping Location:** `~/.local/share/opencode-ipv4-proxy/mappings.json` (POSIX `0600` permissions, directory `0700`).
- **Capacity:** The existing operational limit of 762 persistent IP mappings remains unchanged, though markers no longer depend on an IPv4 address pool. Requests exceeding capacity return HTTP 507.
- **Stale Lock Recovery:** If the proxy process crashed during a write, stop all proxy instances and remove the lockfile:
  ```bash
  rm ~/.local/share/opencode-ipv4-proxy/mappings.json.lock
  ```
- **Reset Mappings:** Stop all proxy instances and move `mappings.json` to a backup.
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
