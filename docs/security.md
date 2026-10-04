# Security and limitations

Keep the proxy local: it has no local client authentication. Mapping files contain original sensitive values; protect them and their backups. Encryption at rest is optional. See [operations](operations.md#encryption-and-one-way-conversion).

## Known Gaps — Deliberate Scope Exclusions

These limitations are intentional and outside the project's scope:

- **Domain names:** Domain names are deliberately not obfuscated. They remain visible to the upstream model. Recognized IPv4 addresses embedded in hostnames (including supported AWS private hostname formats) are still obfuscated; this is IP masking, not domain-name protection.
- **Semantic or evaluated sensitive data:** The proxy matches literal text; it does not execute code or infer values produced by string concatenation, variable substitution, or other computations. For example, `"10.20." + "30.40"` is not detected as the resulting IPv4 address. Reassembling network chunks and protocol-defined SSE fragments is separate and remains supported.
- **Placeholder versus password distinction:** The proxy does not reliably distinguish a placeholder from a real password. Characters such as `$`, `{`, and `}` can occur in either. Do not rely on placeholder-looking text being preserved or classified correctly; general semantic classification is deliberately out of scope.

### Marker compatibility and limitations

- **Stream restoration:** Protocol-defined SSE fragments are reassembled before restoration, including Anthropic initial block text. Responses string deltas without an `item_id` leave the entire response unchanged with markers (or legacy fake addresses) and an `x-ipv4-proxy-warning` header; restoration never guesses their grouping.
- **Exact restoration:** Only complete, known `[REDACTED_<type>_<32 lowercase hexadecimal characters>]` markers are restored. Types are `IP`, `TEXT`, `API_KEY`, `JWT`, `PRIVATE_KEY` and `PASSWORD`. Unknown or edited markers remain unchanged. IDs are random and persisted, not hashes of the original. Randomness reduces accidental collisions; a copied known marker still restores regardless of its provenance.
- **Not valid IP syntax:** Markers are not IPv4 addresses or valid URL hosts. Strict IP/URL schema validation upstream may reject them. Local tool arguments are restored before delivery, provided the model preserves the marker exactly.
- **Legacy migration:** Version-1 and version-2 state is atomically migrated to version 3 on the next successful outbound transformation. Existing version-2 IP markers stay unchanged; version-1 fake-IP aliases are retained for existing conversations. Read-only `status` does not migrate files. Back up state with all proxy instances stopped before upgrading; older proxy versions cannot read version-3 state.
- **Legacy documentation-IP collisions:** Fresh stores no longer allocate documentation IPs. Migrated stores still restore their old aliases, so literal examples matching those aliases can still restore to real hosts. This compatibility risk is retained explicitly; migration does not establish provenance. Do not reset mappings while continuing old conversations.


For detection boundaries and mode-specific exceptions, see [configuration](configuration.md#literal-matching-boundaries).
