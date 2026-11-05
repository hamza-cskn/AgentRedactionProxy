import assert from 'node:assert/strict';
import test from 'node:test';
import { errorDiagnostics } from '../src/proxy-logging.mjs';
import { RedactionCandidateSizeError } from '../src/redaction-limits.mjs';
import { MODES, assertNoLeak, entropy, proxyHarness } from './helpers/harness.mjs';

const TOKEN = `ghp_${entropy(60, 7)}`; // 64 chars: over LIMITS, longer than the 32-char preview
const LIMITS = { maxApiTokenChars: 40 };
const PREVIEW = TOKEN.slice(0, 32);
const SIZE_MESSAGE = 'Redaction candidate exceeds configured limit';
const sizeError = () => new RedactionCandidateSizeError(TOKEN, TOKEN.length, 40, 'api-token');

// [where the size error sits, error builder]
const ERROR_SHAPES = [
  ['size error', () => sizeError()],
  ['size error as cause', () => new Error('Proxy request failed', { cause: sizeError() })],
  ['size error two causes deep', () => new Error('outer', { cause: new Error('middle', { cause: sizeError() }) })],
  ['size error inside AggregateError', () => new AggregateError([new Error('x'), sizeError()], 'many')],
];
const WITHOUT_PREVIEW = [['no options', undefined], ['empty options', {}], ['preview: false', { preview: false }]];

for (const [shape, build] of ERROR_SHAPES) {
  for (const [label, options] of WITHOUT_PREVIEW) {
    test(`errorDiagnostics (${shape}, ${label}): contains no fragment of the token`, () => {
      const error = build();

      const diagnostic = errorDiagnostics(error, options);

      assertNoLeak(JSON.stringify(diagnostic), TOKEN, 'diagnostic');
    });
  }
}

test('errorDiagnostics (size error, no options): reports length, limit, type and unit only', () => {
  const diagnostic = errorDiagnostics(sizeError());

  assert.deepEqual(diagnostic, {
    name: 'Error', reason: 'redaction-candidate-too-large',
    candidateLength: 64, candidateLimit: 40, candidateType: 'api-token', candidateUnit: 'chars',
  });
});

// [where the size error sits, error builder, where its preview lands]
const PREVIEW_LOCATIONS = [
  ['size error', () => sizeError(), (diagnostic) => diagnostic.candidatePreview],
  ['size error as cause', () => new Error('a', { cause: sizeError() }), (diagnostic) => diagnostic.cause.candidatePreview],
  ['size error inside AggregateError', () => new AggregateError([sizeError()]), (diagnostic) => diagnostic.errors[0].candidatePreview],
];

for (const [shape, build, locate] of PREVIEW_LOCATIONS) {
  test(`errorDiagnostics (${shape}, preview: true): carries the first 32 characters`, () => {
    const error = build();

    const diagnostic = errorDiagnostics(error, { preview: true });

    assert.equal(locate(diagnostic), PREVIEW);
  });
}

test('errorDiagnostics (size error, preview: true): never carries the whole token', () => {
  const diagnostic = errorDiagnostics(sizeError(), { preview: true });

  assert.equal(JSON.stringify(diagnostic).includes(TOKEN), false);
});

// [scenario, error builder]; none of these is a real size error.
const SPOOFS = [
  ['plain Error with the size message and a preview field',
    () => Object.assign(new Error(SIZE_MESSAGE), { candidatePreview: TOKEN })],
  ['Error whose message, code, name and stack are the token',
    () => Object.assign(new Error(TOKEN), { code: TOKEN, name: TOKEN, stack: TOKEN })],
  ['spoofed size error as cause',
    () => new Error('x', { cause: Object.assign(new Error(SIZE_MESSAGE), { candidatePreview: TOKEN }) })],
];

for (const [scenario, build] of SPOOFS) {
  test(`errorDiagnostics (${scenario}, preview: true): contains no fragment of the token`, () => {
    const error = build();

    const diagnostic = errorDiagnostics(error, { preview: true });

    assertNoLeak(JSON.stringify(diagnostic), TOKEN, 'diagnostic');
  });
}

// [shape, request body holding the oversized token]
const BODY_SHAPES = [
  ['raw text', TOKEN],
  ['JSON string', JSON.stringify({ input: TOKEN })],
  ['Messages text block', JSON.stringify({ messages: [{ role: 'user', content: [{ type: 'text', text: `see ${TOKEN}` }] }] })],
  ['JSON in tool arguments', JSON.stringify({ arguments: JSON.stringify({ token: TOKEN }) })],
];

// The request is rejected before the store is used, so a stub store suffices.
for (const mode of MODES) {
  for (const [shape, body] of BODY_SHAPES) {
    test(`proxy (${mode}, ${shape}): oversized token is rejected before upstream`, async (t) => {
      const h = await proxyHarness(t, { mode, store: {}, redactionLimits: LIMITS });

      const response = await h.send(body);

      assert.equal(response.status, 502);
      assert.equal(h.upstream.length, 0);
    });

    test(`proxy (${mode}, ${shape}): without --debug the log has no fragment of the token`, async (t) => {
      const h = await proxyHarness(t, { mode, store: {}, redactionLimits: LIMITS });

      await h.send(body);

      assertNoLeak(h.logs.join('\n'), TOKEN, 'log');
    });

    test(`proxy (${mode}, ${shape}): with --debug the log carries the 32-char preview`, async (t) => {
      const h = await proxyHarness(t, { mode, store: {}, redactionLimits: LIMITS, debug: true });

      await h.send(body);

      assert.equal(JSON.parse(h.logs[0]).error.candidatePreview, PREVIEW);
    });

    test(`proxy (${mode}, ${shape}): with --debug the client error has no fragment of the token`, async (t) => {
      const h = await proxyHarness(t, { mode, store: {}, redactionLimits: LIMITS, debug: true });

      const response = await h.send(body);

      assertNoLeak(`${response.body}\n${JSON.stringify(response.headers)}`, TOKEN, 'client response');
    });
  }
}

for (const debug of [false, true]) {
  test(`proxy (paranoic, debug ${debug}): a clean request is forwarded unchanged`, async (t) => {
    const h = await proxyHarness(t, { mode: 'paranoic', debug });
    const body = JSON.stringify({ input: 'hello' });

    await h.send(body);

    assert.equal(h.upstream[0].body, body);
  });
}
