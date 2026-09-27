# Agent Redaction Proxy

> **TL;DR:** Keeps sensitive data local when using AI coding agents (OpenCode, Claude Code).
> It replaces real IPv4 addresses with safe RFC 5737 documentation IPs before requests leave your machine and restores them in LLM responses. Recognizable credentials and API keys are permanently redacted.

<img width="344" height="264" alt="Agent Redaction Proxy concept" src="https://github.com/user-attachments/assets/aed2009c-9fbe-44c4-8b26-954c3fa94544" />

---

## What & How

- **What:** A zero-dependency local reverse proxy that sits between your AI coding agents and upstream LLM providers.
- **How:** 
  1. **Outbound:** Masks plain-text IPv4 addresses with RFC 5737 dummy addresses (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) and strips recognized credentials/API keys.
  2. **Upstream:** Forwards sanitized prompts to the provider.
  3. **Inbound:** Buffers LLM responses (including Server-Sent Events / SSE streams) and transparently restores the original IPv4 addresses so local tools and terminals work normally.

```
[Local Agent / Tools]
       │  ▲
       │  │ (Inbound: restores fake IPs -> real IPs)
       ▼  │
[Agent Redaction Proxy]
  • Maps real IPv4 -> RFC 5737 fake IP
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
| **IPv4 Masking & Restoration** | 1:1 mapping of real IPv4s to documentation IPs. AWS private hostnames (e.g., `ip-10-20-30-40.ec2.internal`) are also recognized and mapped. |
| **Credential Redaction** | Permanent one-way redaction of API keys (OpenAI, Anthropic, GitHub, GitLab, AWS, Slack, Stripe, Google, Hugging Face, PyPI, npm), JWT/JWE tokens, PEM/PGP private keys, and URL/DSN passwords (`user:pass@host`). |
| **Fail-Closed Security** | Rejects requests (HTTP 502) if secret redaction fails, credentials appear malformed, or mapping limits are reached. |
| **SSE Stream Support** | Reassembles streamed deltas (OpenAI Responses, Anthropic Messages) across chunk boundaries before restoring IPs. |
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
  "mode": "paranoic"
}
```

- `"paranoic"` (default): Strict fail-closed policy. Durably commits mappings before forwarding. Rejects outbound requests if redaction or storage fails.
- `"default"`: Same transformation logic, but requests containing no real IPv4 addresses can bypass storage failures with a warning header.

---

## Storage & Maintenance

- **Mapping Location:** `~/.local/share/opencode-ipv4-proxy/mappings.json` (POSIX `0600` permissions, directory `0700`).
- **Capacity:** Supports up to 762 concurrent IP mappings across RFC 5737 blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Requests exceeding capacity return HTTP 507.
- **Stale Lock Recovery:** If the proxy process crashed during a write, stop all proxy instances and remove the lockfile:
  ```bash
  rm ~/.local/share/opencode-ipv4-proxy/mappings.json.lock
  ```
- **Reset Mappings:** Stop all proxy instances and move `mappings.json` to a backup.
  > **Note:** Resetting reuses fake IP addresses. Always start fresh agent chat sessions after a reset so past conversation history is not deobfuscated with mismatched IPs.

---

## Testing

```bash
# Run unit & mock tests (offline, no live LLM calls)
npm test

# Run OpenCode CLI integration tests (requires OpenCode CLI installed)
npm run test:opencode
```
