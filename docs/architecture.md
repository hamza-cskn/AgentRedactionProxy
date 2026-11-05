# Architecture

| Layer | Files | Responsibility |
|---|---|---|
| Proxy | `src/proxy.mjs`, `src/sse-transform.mjs`, `src/proxy-logging.mjs` | HTTP forwarding, limits, failure policy, SSE reassembly, logging. |
| Scan | `src/scan/` | Finds sensitive spans in decoded strings. Stateless. |
| Redactor | `src/redactor.mjs`, `src/secret-redaction.mjs` | Replaces spans with markers and restores them; owns the state schema. |
| Store | `src/store.mjs`, `src/encrypted-storage.mjs` | Persists mapping state: lock, encryption, durability. |

`src/mapping-store.mjs` (`MappingStore`) joins the store and the redactor: every operation runs a `Redactor` on a fresh state snapshot inside a `StateStore` transaction, so several proxy processes can share one state file.

## Scan

- `traverse.mjs` walks a JSON body, including JSON nested in tool arguments, and hands each decoded string to the detectors. It skips opaque payloads (image base64, thinking signatures) in the top-level body for every pass.
- Each detector returns `{ start, end, type }` spans on the original string: `private-key.mjs`, `url-password.mjs`, `tokens.mjs` (API keys, JWTs), `ip.mjs`, `custom-text.mjs` (user-defined texts).
- `secrets.mjs` also enforces the size limits and the encoded-URL checks, and throws when a request must be rejected.
- `spans.mjs` resolves overlaps: a contained span is absorbed by its container, and partially overlapping spans merge into one span typed after the higher-priority detector (`PRIVATE_KEY`, `PASSWORD`, `API_KEY`, `JWT`, `TEXT`, `IP`). No fragment of either secret stays visible.

## Request flow

1. The proxy calls `MappingStore.obfuscateRequest`. Under the lock, the redactor scans each string once and replaces the spans with persistent markers. New mappings are saved before the request is forwarded.
2. A scan rejection (oversized candidate, unsafe encoded URL) becomes a 502 and nothing is saved.
3. If the store fails, the proxy forwards the request unchanged only when a stateless scan finds nothing to protect and the mode is `default`.
4. Responses are restored by `MappingStore.deobfuscate`; SSE deltas are joined per channel first, so a marker split across events is restored whole.

`redactSecrets` applies the same scan with permanent, non-restorable markers. The proxy uses it to sanitize logged request paths.
