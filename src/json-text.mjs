// Transform decoded JSON strings, including JSON nested in tool arguments.
// Preserve numeric literals, whitespace, and strings with no replacements.
export function transformJsonText(text, replace, preserveString) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return replace(text);
  }

  const preserved = new Set();
  if (preserveString) {
    const tokens = [...text.matchAll(/"(?:[^"\\]|\\.)*"|[{}\[\]:,]|[^\s{}\[\]:,]+/g)];
    let cursor = 0;
    const walk = (value, path, parent) => {
      const token = tokens[cursor++];
      if (token[0] === '{') {
        while (tokens[cursor][0] !== '}') {
          const property = JSON.parse(tokens[cursor++][0]);
          cursor += 1; // Colon.
          walk(value?.[property], [...path, property], value);
          if (tokens[cursor][0] === ',') cursor += 1;
        }
        cursor += 1;
      } else if (token[0] === '[') {
        let index = 0;
        while (tokens[cursor][0] !== ']') {
          walk(value?.[index], [...path, index], value);
          index += 1;
          if (tokens[cursor][0] === ',') cursor += 1;
        }
        cursor += 1;
      } else if (token[0].startsWith('"') && preserveString(JSON.parse(token[0]), path, parent, parsed)) {
        preserved.add(token.index);
      }
    };
    walk(parsed, [], null);
  }

  let count = 0;
  const body = text.replace(/"(?:[^"\\]|\\.)*"/g, (token, offset) => {
    if (preserved.has(offset)) return token;
    const transformed = transformJsonText(JSON.parse(token), replace);
    count += transformed.count;
    return transformed.count > 0 ? JSON.stringify(transformed.body) : token;
  });
  return { body, count };
}
