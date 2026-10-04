# Agent Redaction Proxy

A local proxy for OpenCode and Claude Code. It masks IPv4 addresses, recognizable credentials and user-defined sensitive strings before sending them to the model, then restores known markers in responses and tool arguments.

## Quick start

Requires macOS/Linux, Docker running, and OpenCode signed in with OpenAI OAuth. Run from your project:

```sh
cd "/path/to/your/project"
curl -fsSL https://raw.githubusercontent.com/hamza-cskn/AgentRedactionProxy/main/scripts/setup.sh | bash
```

Restart OpenCode and select an OpenAI model with `/models`.

To uninstall, run from the same project:

```sh
curl -fsSL https://raw.githubusercontent.com/hamza-cskn/AgentRedactionProxy/main/scripts/setup.sh | bash -s -- uninstall
```

Uninstall preserves the shared container and mapping data.

For Claude Code, Windows/Docker, or native Node.js setup, see [installation](docs/installation.md).

## Temporary bypass

Exit OpenCode and launch without protection:

```sh
ARP_BYPASS=1 opencode
```

A startup warning confirms bypass. Use a fresh conversation: bypass skips redaction and marker restoration. Exit and launch `opencode` normally to restore protection. Older installations need the [updated plugin](docs/installation.md#temporary-bypass-opencode).

## Boundaries

The shipped mode is `default`; strict `paranoic` mode is available. Both protect recognized IPs and credentials, but detection is not a guarantee against secret leakage.

Domain names, HTTP headers, opaque passwords and computed values (such as string concatenation) are outside detection scope. Placeholder/password ambiguity is deliberately unresolved. [Full limitations](docs/security.md).

Keep the proxy local and protect mapping files—they contain original sensitive values. Do not reset mappings while continuing old conversations.

## Documentation

- [Installation](docs/installation.md) — manual clients, installer behavior and bypass.
- [Configuration](docs/configuration.md) — modes, user-defined secrets and detection limits.
- [Operations](docs/operations.md) — Docker, encryption, mapping recovery and tests.
- [Security and limitations](docs/security.md) — deliberate gaps and marker compatibility.
