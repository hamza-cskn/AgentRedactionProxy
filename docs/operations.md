# Operations

## Docker

Published image destination: `366366/agent-redaction-proxy`. GitHub Actions builds and smoke-tests the container after the existing test jobs pass. Pushes to `main` (or a manual workflow run on `main`) publish `latest` and `sha-<full-commit-sha>` for `linux/amd64` and `linux/arm64`. Pull requests/other branches build and test only, without registry login or publishing. The repository secret `DOCKER_ACCESS_TOKEN` must be a Docker Hub token for `366366` with write access to this image. It is used only for registry login, never passed into the Docker build.

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

## Testing

`test/false-positives.test.mjs` covers fixed false positives, including both modes and conversation history. `test/known-false-positives.test.mjs` records deliberate conservative policies. Marker persistence, migration, documentation-address separation and stream splits are covered in `test/ip-markers.test.mjs`; the original fake-IP boundary regressions remain as legacy compatibility tests. URL/prose boundaries have explicit credential-protection companions in `test/url-prose-boundaries.test.mjs`.

```bash
# Run unit & mock tests (offline, no live LLM calls)
npm test

# Run OpenCode CLI integration tests (requires OpenCode CLI installed)
npm run test:opencode
```
