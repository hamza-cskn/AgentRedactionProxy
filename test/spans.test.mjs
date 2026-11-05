import assert from 'node:assert/strict';
import test from 'node:test';
import { applySpans, resolveSpans } from '../src/scan/spans.mjs';

const span = (start, end, type) => ({ start, end, type });

// [scenario, detected spans, resolved spans]
const CASES = [
  ['disjoint spans stay separate', [span(5, 8, 'JWT'), span(0, 3, 'API_KEY')], [span(0, 3, 'API_KEY'), span(5, 8, 'JWT')]],
  ['adjacent spans stay separate', [span(0, 3, 'JWT'), span(3, 6, 'API_KEY')], [span(0, 3, 'JWT'), span(3, 6, 'API_KEY')]],
  ['a contained span is absorbed by its container', [span(0, 10, 'JWT'), span(2, 5, 'PRIVATE_KEY')], [span(0, 10, 'JWT')]],
  ['equal spans keep the higher-priority type', [span(0, 4, 'API_KEY'), span(0, 4, 'PASSWORD')], [span(0, 4, 'PASSWORD')]],
  ['partial overlap merges into the higher-priority type', [span(0, 6, 'JWT'), span(4, 9, 'PASSWORD')], [span(0, 9, 'PASSWORD')]],
  ['a chain of partial overlaps merges into one span', [span(0, 4, 'JWT'), span(3, 7, 'API_KEY'), span(6, 9, 'JWT')], [span(0, 9, 'API_KEY')]],
];

for (const [scenario, detected, expected] of CASES) {
  test(`resolveSpans: ${scenario}`, () => {
    assert.deepEqual(resolveSpans(detected), expected);
  });
}

test('applySpans: replaces each span and keeps the text between them', () => {
  const body = applySpans('a KEY b PWD c', [span(2, 5, 'API_KEY'), span(8, 11, 'PASSWORD')], (type) => `<${type}>`);

  assert.equal(body, 'a <API_KEY> b <PASSWORD> c');
});
