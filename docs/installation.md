# Installation

The recommended macOS/Linux and Windows installers are in the [quick start](../README.md#quick-start). The alternatives below are for manual setup.

## Windows PowerShell

Use Windows PowerShell 5.1 or PowerShell 7, as a normal user. Docker Desktop must already be running with Linux containers, and OpenCode must already be signed in with OpenAI OAuth. The installer does not install prerequisites, request elevation, or change execution policy.

The quick-start `irm ... | iex` command downloads and executes the installer immediately: use only a source you trust. To inspect it first, download it instead:

```powershell
Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/hamza-cskn/AgentRedactionProxy/main/scripts/setup.ps1 -OutFile setup.ps1
Get-Content .\setup.ps1
.\setup.ps1
```

If execution policy blocks the downloaded file, inspect it and use `Unblock-File .\setup.ps1` where your policy permits. Do not disable organizational policy. Uninstall with `.\setup.ps1 uninstall` from the same project. Keep the downloaded file yourself; uninstall removes only managed integration files.

The PowerShell installer uses the same pinned plugin/config checksums, shared Docker container/volume, and receipt/lock names as the shell installer. It also rejects Windows junctions and applies a current-user-only ACL to new receipt directories. Install/uninstall tests run on Windows CI in both PowerShell versions; they mock Docker, downloads and OpenCode rather than accessing live accounts.

The hosted script is available only once these changes reach `main`; a push to `dev` does not update the quick-start URL.

## Quick Start with Node.js

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

### Docker only

Start the proxy:

```sh
docker run -d --name agent-redaction-proxy -p 127.0.0.1:8787:8787 -p 127.0.0.1:8788:8788 -v agent-redaction-proxy-data:/data 366366/agent-redaction-proxy:latest
docker logs agent-redaction-proxy
```

Connect your agent: [OpenCode](#opencode-openai-oauth) · [Claude Code](#claude-code-anthropic).

For Compose and encryption, see [operations](operations.md#docker).

### Project installer behavior

`scripts/setup.sh` supports macOS/Linux; `scripts/setup.ps1` supports Windows. Both check Docker/OpenCode and an existing OpenAI OAuth login, start or reuse an installer-managed local proxy, install `.opencode/plugins/openai-ipv4-proxy.js`, and verify OpenAI models are available. If login is missing, run `opencode auth login --provider openai --pure` first. Existing global configuration and credentials are never modified. Other clients, including Claude Code, still use the manual setup below.

The plugin and default config are downloaded from a pinned commit and checked against SHA-256 digests. A project config is created only if neither `opencode.json` nor `opencode.jsonc` exists; existing files remain byte-for-byte unchanged. Repeat setup reuses the same container and mappings. Existing unmanaged plugins/containers, conflicting bindings and symbolic-link installation paths are rejected rather than replaced. If setup fails, its project files and newly created container are rolled back; mapping volumes are never deleted.

Uninstall compares files against private installation receipts before removing them. Modified files are left untouched and require manual review. The proxy is shared across projects, so uninstall does not stop or remove it; use `docker stop agent-redaction-proxy` separately if no project needs it. Receipt files live in `.opencode/.agent-redaction-proxy-install`; a stale `.opencode/.agent-redaction-proxy-setup.lock` must be removed manually only after confirming no installer is running. The installer requires the published Docker image.

## Agent Setup

### OpenCode (OpenAI OAuth)

1. Sign in to OpenAI through OpenCode first (`opencode auth login`).
2. Copy [`.opencode/plugins/openai-ipv4-proxy.js`](../.opencode/plugins/openai-ipv4-proxy.js) into your target project's `.opencode/plugins/` directory.
3. Add the proxy URL to your project's `opencode.jsonc` (see [`examples/opencode.jsonc`](../examples/opencode.jsonc)):
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

### Temporary bypass (OpenCode)

Exit OpenCode, then launch it from your project with:

```sh
ARP_BYPASS=1 opencode
```

This launch sends OpenAI requests directly to the provider using your existing OAuth login. A startup warning confirms bypass. No redaction or marker restoration occurs; old conversation markers stay fake, so use a fresh conversation. The proxy and mappings are unchanged. Exit and run `opencode` normally to restore protection (unset `ARP_BYPASS` first if you exported it). Only the exact value `1` enables bypass; proxy failures never enable it automatically. This switch does not affect Claude Code or other projects' running sessions.

Requires the updated project plugin. For an older installer-managed installation, uninstall and reinstall using the [quick-start commands](../README.md#quick-start); repeating setup alone preserves the existing plugin.

In PowerShell, set the variable for the launch, then remove it before launching normally:

```powershell
$env:ARP_BYPASS = '1'
opencode
# After exiting OpenCode:
Remove-Item Env:ARP_BYPASS
```
