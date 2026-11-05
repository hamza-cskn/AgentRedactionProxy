// Transform decoded JSON strings, including JSON nested in tool arguments.
// Preserve numeric literals, whitespace, exempt strings and strings with no
// replacements. Only the request body itself has exempt paths: nested JSON
// is not decoded by the upstream API, so it is always scanned in full.
export function transformJsonText(text, replace, topLevel = true) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return replace(text);
  }

  const exempt = topLevel ? exemptOffsets(text, parsed) : new Set();
  let count = 0;
  const body = text.replace(/"(?:[^"\\]|\\.)*"/g, (token, offset) => {
    if (exempt.has(offset)) return token;
    const transformed = transformJsonText(JSON.parse(token), replace, false);
    count += transformed.count;
    return transformed.count > 0 ? JSON.stringify(transformed.body) : token;
  });
  return { body, count };
}

// Offsets of string tokens that every pass must leave byte-identical.
function exemptOffsets(text, parsed) {
  const exempt = new Set();
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
    } else if (token[0].startsWith('"') && isOpaquePayload(JSON.parse(token[0]), path, parent, parsed)) {
      exempt.add(token.index);
    }
  };
  walk(parsed, [], null);
  return exempt;
}

// Opaque base64 payloads the upstream API decodes or verifies; rewriting them breaks the request.
function isOpaquePayload(value, path, parent, root) {
  return isResponseImageData(value, path, parent)
    || isMessagesImageData(value, path, parent, root)
    || isMessagesThinkingBlob(value, path, parent, root);
}

function isResponseImageData(value, path, parent) {
  return path.length === 5 && path[0] === 'input' && Number.isInteger(path[1])
    && path[2] === 'content' && Number.isInteger(path[3]) && path[4] === 'image_url'
    && parent?.type === 'input_image'
    && /^data:image\/(?:png|jpeg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(value);
}

// Anthropic Messages image block, top-level or inside a tool_result:
// messages[i].content[j](.content[k]).source.data
function isMessagesImageData(value, path, parent, root) {
  if (path[0] !== 'messages' || !Number.isInteger(path[1]) || path[2] !== 'content' || !Number.isInteger(path[3])) return false;
  let block = root.messages[path[1]]?.content?.[path[3]];
  if (path.length === 8) {
    if (block?.type !== 'tool_result' || path[4] !== 'content' || !Number.isInteger(path[5])) return false;
    block = block.content?.[path[5]];
  } else if (path.length !== 6) {
    return false;
  }
  return path.at(-2) === 'source' && path.at(-1) === 'data'
    && block?.type === 'image' && block.source === parent
    && parent?.type === 'base64' && /^image\/(?:png|jpeg|gif|webp)$/.test(parent.media_type)
    && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

// Anthropic Messages opaque reasoning: messages[i].content[j].signature on a
// thinking block, or .data on a redacted_thinking block. Encrypted by the API
// and rejected if modified; the readable thinking text is still redacted.
function isMessagesThinkingBlob(value, path, parent, root) {
  if (path.length !== 5 || path[0] !== 'messages' || !Number.isInteger(path[1])
    || path[2] !== 'content' || !Number.isInteger(path[3])) return false;
  const block = root.messages[path[1]]?.content?.[path[3]];
  return block === parent
    && ((block?.type === 'thinking' && path[4] === 'signature')
      || (block?.type === 'redacted_thinking' && path[4] === 'data'))
    && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}
