# Testing

`npm test` runs the whole suite offline, with no live LLM calls. `node --test test/<file>.test.mjs` runs one file. The two tests `npm test` skips are OpenCode CLI integration tests; `npm run test:opencode` runs them and needs the OpenCode CLI installed.

## What a test must catch

The proxy sits between coding agents and LLM APIs. Three outcomes are bugs:

- **Leak**: a secret (API key, JWT, private key, URL password, user-defined text, real IPv4) reaches upstream, the logs or a client error response.
- **Lockout**: a request is rejected for content that stays in the chat history, so every later turn fails too.
- **False positive**: ordinary text is redacted or changed.

A test that cannot catch one of these is not worth writing. Before writing tests, list which of these the change touches and which existing tests already cover them. When done, report which property each new test covers, which mutation it caught (rule 8) and any bug found.

## General principles

- Test behavior, not implementation. Assert what the code should do—its inputs and observable outputs—rather than private internals or incidental implementation details.
- Keep one concept per test. A test should validate a single feature or behavior; if you need multiple unrelated assertions, split it into separate tests.
- Use Arrange–Act–Assert (AAA). Set up the data, perform the action, then verify the result. This makes tests easy to scan and maintain.
- Name tests descriptively. A useful pattern is: method/scenario/expected result, such as calculateTotal_withEmptyCart_returnsZero.
- Keep tests independent. Each test should create the state it needs and not rely on execution order, shared mutable state, or another test having run first. Independence also enables safe parallel execution.
- Use the simplest input that proves the point. Avoid large fixtures and unnecessary data; minimal tests are easier to understand and diagnose.
- Avoid logic in tests. Do not add loops, conditionals, or complex string-building that can introduce bugs into the test itself; keep expected values explicit.
- Isolate external dependencies. For unit tests, avoid real databases, networks, file systems, or clocks where practical; use fakes, stubs, or mocks appropriately.
- Make failures informative. Assertions should clearly show the expected versus actual value, and test names should make the cause of failure obvious.
- Keep the suite fast. Slow tests reduce how often developers run them; reserve slower integration or end-to-end tests for behaviors that truly require them.
- Refactor tests with production code. Remove duplication with helpers or fixtures, but preserve clarity—tests are documentation of intended behavior.

### How they apply here

- **Names:** `<function or component> (<mode>, <shape>): <scenario and expected result>`, for example `redactSecrets (paranoic, RSA PRIVATE KEY): unterminated BEGIN redacts to the end of the string`.
- **Logic in tests:** parameterize with a module-level table and a loop that creates one named `test()` per case. Test bodies hold no loops, conditionals or computed expected values. Fuzz tests are the one exception: seeded `prng`, invariants only, the seed in every failure message.
- **External dependencies:** the upstream API is always faked, and `invoke` calls the request handler without sockets. `store: {}` behaves as an unavailable store: the proxy then forwards a request unchanged only if a stateless scan finds nothing to protect, so it suits tests of rejections and of that fallback. Leak tests use a real store in a temp dir, because the store runs the redaction under test.
- **Clocks:** log lines carry `timestamp` and `durationMs`. Assert on fields, never on whole log lines.

## Project rules

1. **Test leak properties end to end.** Use `proxyHarness`: the real proxy and mapping store with a fake upstream. Leaks hide between passes (built-in patterns, user-defined texts, IPv4 mapping), so a unit test of one pass is not enough. Assert what upstream received, what the client received and what was logged.
2. **Check fragments, not whole secrets.** Build secrets with `secret.*` or `entropy()`, never `'A'.repeat(n)`, and check them with `assertNoLeak`, which fails on any shared 8-character window. Check every outbound surface: upstream body, URL and headers, logs, client error responses.
3. **False positives:** look-alikes stay byte-for-byte identical, and redaction never spills into a neighbouring JSON string.
4. **Round trip:** the client gets its original text back exactly.
5. **Availability:** replay the same history for three turns; every turn is forwarded.
6. **Cover the shapes the proxy sees:** both modes (`MODES`); plain text, JSON-escaped, JSON nested in tool arguments, percent-encoded, CRLF, split across two JSON strings, split across body chunks (`send(body, { chunks })`), SSE responses. Test with and without `debug: true` whenever logging is involved.
7. **Exempt data** (image base64, thinking signatures) stays byte-identical after every pass, including when a user-defined sensitive text occurs inside it.
8. **Prove each test.** Break the code it guards (drop the check, flip the condition), run the test and watch it fail. Then revert the edit and confirm with `git diff` that only your intended changes remain. A test that still passes against broken code is wrong: fix it or delete it.
9. **Never weaken or delete a test to get green.** If behavior changes on purpose, say which test changed and why. Record a known gap as `test(name, { todo: '<reason>' }, fn)`, never as a silent skip.
10. **No literal secrets in source.** Build PEM markers, PuTTY headers, tokens and credential URLs at runtime with the harness. Agents read this repo through the proxy, which redacts literal ones (older versions reject the whole request), and real-looking tokens trip secret scanners on push.
11. **Mechanics:** `node:test` and `node:assert/strict`, no new dependencies. Never bind ports 8787/8788, because a running proxy owns them. Create temp dirs only through `tempStore`, which removes them after the test.

## Mock harness

`test/helpers/harness.mjs`. Its own tests are in `test/harness.test.mjs`.

| Export | Purpose |
|---|---|
| `proxyHarness(t, options)` | Real `createProxy` and mapping store, fake upstream, captured logs. Returns `{ send, upstream, logs, store, proxy }`. Options pass through to `createProxy` (`mode`, `debug`, `redactionLimits`, ...), plus `upstream` (a responder), `store` (an override) and `sensitiveTexts`. |
| `send(body, { method, path, headers, chunks })` | Sends a request; objects are JSON-encoded. Defaults to `POST /v1/responses`. Resolves to `{ status, headers, body }`. |
| `upstream` | Every call that would have left the machine, as `{ url, method, headers, body }`. |
| `logs` | Raw JSON log lines. |
| `echo`, `json(value, status)`, `sse(text)`, `fail(error)` | Upstream responders. `echo`, the default, returns the forwarded body, so the client response tests restoration. |
| `invoke(proxy, request)` | Drives any `createProxy` server without sockets, with exact chunk boundaries. |
| `fakeUpstream(responder)` | `{ fetchImpl, calls }` for a hand-built `createProxy`. |
| `tempStore(t, options)` | `MappingStore` in a temp dir, removed after the test. |
| `secret.github`, `secret.jwt`, `secret.urlPassword`, `secret.privateKey` | Deterministic secrets per seed, each pinned to be detected in both modes. |
| `entropy(length, seed)` | Distinctive text for key bodies and custom secrets. |
| `pem.begin`, `pem.end`, `pem.block`, `puttyHeader`, `KEY_MARKER` | Key markers built at runtime, and a detector for any left in an output. |
| `assertNoLeak(text, secrets, where)`, `findLeak(text, secret)` | Fail on, or find, any shared 8-character fragment. |
| `MODES`, `prng(seed)` | Both modes, and the seeded PRNG for fuzz tests. |

Example:

```js
import test from 'node:test';
import { MODES, assertNoLeak, proxyHarness, secret } from './helpers/harness.mjs';

for (const mode of MODES) {
  test(`proxy (${mode}, Messages text block): GitHub token never reaches upstream`, async (t) => {
    const h = await proxyHarness(t, { mode });
    const token = secret.github(1);

    await h.send({ messages: [{ role: 'user', content: [{ type: 'text', text: `use ${token}` }] }] }, { path: '/v1/messages' });

    assertNoLeak(h.upstream[0].body, token, 'upstream body');
  });
}
```

`test/private-key-markers.test.mjs` and `test/debug-diagnostics.test.mjs` follow these rules. Older test files predate them.
