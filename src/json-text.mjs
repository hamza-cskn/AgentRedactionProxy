// Transform decoded JSON strings, including JSON nested in tool arguments.
// Preserve numeric literals, whitespace, and strings with no replacements.
export function transformJsonText(text, replace) {
  try {
    JSON.parse(text);
  } catch {
    return replace(text);
  }

  let count = 0;
  const body = text.replace(/"(?:[^"\\]|\\.)*"/g, (token) => {
    const transformed = transformJsonText(JSON.parse(token), replace);
    count += transformed.count;
    return transformed.count > 0 ? JSON.stringify(transformed.body) : token;
  });
  return { body, count };
}
