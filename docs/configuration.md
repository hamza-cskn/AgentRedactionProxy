# Configuration

## Configuration (`config.json`)

Configure proxy behavior in `config.json`:

```json
{
  "mode": "default",
  "sensitiveTextsFile": null,
  "redactionLimits": {
    "maxApiTokenChars": 4096,
    "maxJwtChars": 16384,
    "maxJwtHeaderBytes": 4096,
    "maxBase64Chars": 65536
  }
}
```

- `"default"` (shipped mode): Requests containing no recognized sensitive values can bypass storage failures with a warning header. IPs, recognized credentials and configured literal matches still fail closed. Filename exceptions described below apply only in this mode.
- `"paranoic"`: Strict fail-closed policy. Durably commits mappings before forwarding. Rejects outbound requests if redaction or storage fails.

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
