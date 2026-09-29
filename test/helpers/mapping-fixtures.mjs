import { writeFile } from 'node:fs/promises';
import { MappingStore } from '../../src/mapping-store.mjs';

// Existing golden text uses numbered documentation addresses as allocation
// references. Resolve EXPECTATIONS only to the actual random markers; never
// normalize the output being tested or use this for literal documentation IPs.
export function mappedText(store, text) {
  return text.replace(/(?:192[.-]0[.-]2|198[.-]51[.-]100|203[.-]0[.-]113)[.-](\d+)(?!\d)/g, (ip, last) => {
    const pool = ip.startsWith('192') ? 0 : ip.startsWith('198') ? 1 : 2;
    return store.state.mappings[pool * 254 + Number(last) - 1]?.fake ?? ip;
  });
}

export async function legacyStore(file, addresses) {
  await writeFile(file, JSON.stringify({ version: 1, nextIndex: addresses.length,
    mappings: addresses.map((real, index) => ({ real, fake: `192.0.2.${index + 1}` })),
  }));
  return MappingStore.open(file);
}
