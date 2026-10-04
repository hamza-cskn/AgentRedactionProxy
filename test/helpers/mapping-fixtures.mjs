import { writeFile } from 'node:fs/promises';
import { MappingStore } from '../../src/mapping-store.mjs';
import { transformJsonText } from '../../src/json-text.mjs';

// Existing golden text uses numbered documentation addresses as allocation
// references. Resolve EXPECTATIONS only to the actual random markers; never
// normalize the output being tested or use this for literal documentation IPs.
export function mappedText(store, text) {
  return text.replace(/(?:192[.-]0[.-]2|198[.-]51[.-]100|203[.-]0[.-]113)[.-](\d+)(?!\d)/g, (ip, last) => {
    const pool = ip.startsWith('192') ? 0 : ip.startsWith('198') ? 1 : 2;
    return store.state.mappings[pool * 254 + Number(last) - 1]?.fake ?? ip;
  });
}

// Existing category fixtures assert what is recognized, independently of the
// random ID. Only markers actually registered in this store are normalized.
// Exact persistence/restoration is asserted in reversible-texts.test.mjs.
export function redactedText(store, text) {
  return transformJsonText(text, (value) => {
    let count = 0;
    const body = value.replace(/\[REDACTED_(API_KEY|PRIVATE_KEY|JWT|PASSWORD)_[a-f0-9]{32}\]/g, (marker, type) => {
      if (!(store.state.secretMappings ?? []).some((mapping) => mapping.fake === marker && mapping.type === type)) return marker;
      count += 1;
      return type === 'PASSWORD' ? 'REDACTED_PASSWORD' : `[REDACTED_${type}]`;
    });
    return { body, count };
  }).body;
}

export async function legacyStore(file, addresses) {
  await writeFile(file, JSON.stringify({ version: 1, nextIndex: addresses.length,
    mappings: addresses.map((real, index) => ({ real, fake: `192.0.2.${index + 1}` })),
  }));
  return MappingStore.open(file);
}
