# Encrypt persistent storage

ARP stores original sensitive values locally so it can restore redacted responses. Storage is plaintext by default. Optional AES-256-GCM encryption protects the persistent redaction-mapping and user-defined secrets at rest; it does not change detection or proxy mode.

## Before converting

- Stop every proxy using the same storage, including native instances. Make a protected backup first.
- Convert the existing data directory or Docker volume. Do not create an empty store for existing conversations.
- The master key must be a base64-encoded random 32-byte key, not a human password. Generate it with a cryptographic password manager or `openssl rand -base64 32`; keep a protected backup separate from encrypted data.
- The conversion command prompts for the key with input hidden. Never supply it in command arguments, environment variables, or logs. Losing the key loses restoration.
- If `sensitiveTextsFile` points outside the data directory, move that file to `user_defined_secrets.json` in the data directory and remove the override before converting. The script handles only the standard filenames.

## Quick-start Docker container

These commands apply to the container created by `setup.sh`. Its mapping data lives in the named volume `agent-redaction-proxy-data`, not in your project folder.

Confirm the container's `/data` volume:

```sh
docker inspect agent-redaction-proxy --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}'
```

It must report `agent-redaction-proxy-data`. If it reports something else, use that existing storage instead; do not convert a new empty volume.

Stop the proxy, then convert interactively:

```sh
docker stop agent-redaction-proxy
docker run --rm -it --network none --read-only \
  --mount type=volume,source=agent-redaction-proxy-data,target=/data \
  366366/agent-redaction-proxy:latest \
  node scripts/encrypt-storage.mjs /data
```

Paste the master key at the hidden prompt. After successful conversion:

```sh
docker start agent-redaction-proxy
docker logs --tail 20 agent-redaction-proxy
```

New `proxy-started` entries should show `"storage":"encrypted"`. This setup keeps `master_key_secret` inside the data volume. Anyone who can read the entire volume can also read its key; for separate key injection, use the Compose setup below. Do not back up the key alongside encrypted data.

## Docker Compose

Run from the repository directory with the existing `data` bind mount and ownership configured as described in [operations](operations.md#docker):

```sh
docker compose stop proxy
docker compose run --rm --no-deps proxy node scripts/encrypt-storage.mjs /data
```

After successful conversion, move the generated key into a private host directory. Do not overwrite an existing `secrets/master_key_secret`; resolve that conflict first:

```sh
mkdir -p secrets
chmod 700 secrets
mv -i data/master_key_secret secrets/master_key_secret
chmod 600 secrets/master_key_secret
docker compose -f compose.yaml -f compose.encrypted.yaml up --build -d
```

On Windows, use equivalent host ACLs and file-management commands. Docker Desktop must use Linux containers.

The overlay mounts the key read-only at `/run/secrets/master_key_secret` and sets `ARP_MASTER_KEY_FILE`. Use both `-f` options for subsequent Compose operations. Do not restart using only `compose.yaml` after moving the key out of `data`.

## Native Node.js

With all proxy instances stopped, run from the repository:

```sh
npm run encrypt-storage -- /absolute/path/to/existing-data
```

The default native data directory is `~/.local/share/opencode-ipv4-proxy`. Restart with the same data directory after successful conversion. The key is read from `master_key_secret` there unless `ARP_MASTER_KEY_FILE` specifies another file. Protect the key and data with file permissions or equivalent Windows ACLs.

## File names and startup behavior

| File | Plaintext | Encrypted |
|---|---|---|
| Redaction-mapping | `redaction_mapping.json` | `redaction_mapping.secret.json` |
| User-defined secrets | `user_defined_secrets.json` | `user_defined_secrets.secret.json` |

Presence of the master-key file selects encrypted storage; absence selects plaintext. ARP does not automatically convert or fall back to plaintext. Wrong keys, corrupt encrypted files, or incompatible storage stop startup. The optional user-defined secrets file may be absent; new stores use the selected mode.

Conversion preserves marker UUIDs and legacy aliases. Missing inputs become an empty mapping/list. Legacy `mappings.json` must first be manually renamed to `redaction_mapping.json` while every proxy is stopped.

## Failure and recovery

The script validates inputs, writes and verifies encrypted files, publishes the master-key file last, then removes plaintext originals. Existing encrypted outputs and key files are never overwritten.

Failure before activation preserves plaintext originals and removes incomplete outputs where possible. Failure after activation reports cleanup problems; encrypted mode is active, but plaintext leftovers may remain. Stop all proxies and inspect reported files before restarting. After an interrupted conversion, also inspect `.encryption-conversion.lock` and partial outputs; do not blindly remove locks while a process is running.

This is rollback before activation, not a crash-proof multi-file transaction or secure disk erasure. Old backups and snapshots may still contain plaintext. There is no encrypted-to-plaintext conversion script.

Encryption does not protect process memory, a compromised running proxy, or anyone holding both the key and ciphertext. Docker Compose file-backed secrets mount a file; they do not encrypt the host key file. Protect it with host permissions and disk encryption.
