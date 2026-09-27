function addChannel(channels, key, owner, property) {
  if (typeof owner?.[property] !== 'string') return;
  const records = channels.get(key) ?? [];
  records.push({ owner, property, length: [...owner[property]].length });
  channels.set(key, records);
}

function collectChatCompletionChannels(event, channels) {
  for (const [choicePosition, choice] of (event.choices ?? []).entries()) {
    const choiceIndex = choice.index ?? choicePosition;
    const delta = choice.delta;
    if (!delta || typeof delta !== 'object') continue;

    for (const field of ['content', 'reasoning', 'reasoning_content', 'refusal']) {
      addChannel(channels, `choice:${choiceIndex}:${field}`, delta, field);
    }
    for (const [toolPosition, toolCall] of (delta.tool_calls ?? []).entries()) {
      const toolIndex = toolCall.index ?? toolPosition;
      addChannel(
        channels,
        `choice:${choiceIndex}:tool:${toolIndex}:arguments`,
        toolCall.function,
        'arguments',
      );
    }
  }
}

function collectResponsesChannels(event, channels) {
  if (typeof event.type !== 'string' || !event.type.endsWith('.delta')) return;
  if (typeof event.delta !== 'string') return;
  // Neither joining unidentified chunks nor restoring each prefix is safe.
  // Let the proxy return the original fake response when identity is missing.
  if (typeof event.item_id !== 'string' || !event.item_id) {
    throw new Error('Cannot safely restore an unidentified SSE delta');
  }
  const keyParts = [
    event.type,
    event.item_id,
    event.output_index,
    event.content_index,
    event.summary_index,
  ];
  addChannel(channels, keyParts.join(':'), event, 'delta');
}

function collectAnthropicChannels(event, channels) {
  if (event.type === 'content_block_start') {
    const block = event.content_block;
    if (block?.type === 'text' || block?.type === 'thinking') {
      addChannel(channels, `block:${event.index}:${block.type}_delta`, block, block.type);
    }
    return;
  }
  if (event.type !== 'content_block_delta' || !event.delta) return;
  const fieldByType = {
    text_delta: 'text',
    input_json_delta: 'partial_json',
    thinking_delta: 'thinking',
  };
  const field = fieldByType[event.delta.type];
  if (field) {
    addChannel(channels, `block:${event.index}:${event.delta.type}`, event.delta, field);
  }
}

function collectGeminiChannels(event, channels) {
  for (const [candidatePosition, candidate] of (event.candidates ?? []).entries()) {
    const candidateIndex = candidate.index ?? candidatePosition;
    for (const [partIndex, part] of (candidate.content?.parts ?? []).entries()) {
      const textType = part.thought === true ? 'thought' : 'visible';
      addChannel(
        channels,
        `candidate:${candidateIndex}:part:${partIndex}:${textType}:text`,
        part,
        'text',
      );
    }
  }
}

function collectChannels(protocol, event, channels) {
  if (protocol === 'chat-completions') collectChatCompletionChannels(event, channels);
  if (protocol === 'responses') collectResponsesChannels(event, channels);
  if (protocol === 'anthropic') collectAnthropicChannels(event, channels);
  if (protocol === 'gemini') collectGeminiChannels(event, channels);
}

function collectOtherStrings(owner, property, channels, streamedFields) {
  if (streamedFields.get(owner)?.has(property)) return;
  const value = owner[property];
  if (typeof value === 'string') {
    addChannel(channels, `whole:${channels.size}`, owner, property);
  } else if (value && typeof value === 'object') {
    for (const key of Object.keys(value)) {
      collectOtherStrings(value, key, channels, streamedFields);
    }
  }
}

function parseEventBlock(block, partIndex) {
  const newline = block.includes('\r\n') ? '\r\n' : '\n';
  const lines = block.split(/\r?\n/);
  const dataIndices = [];
  const dataParts = [];

  for (let index = 0; index < lines.length; index += 1) {
    if (!lines[index].startsWith('data:')) continue;
    dataIndices.push(index);
    dataParts.push(lines[index].slice(5).replace(/^ /, ''));
  }
  if (dataIndices.length === 0) return null;

  const data = dataParts.join('\n');
  if (data.trim() === '[DONE]') return null;
  return {
    partIndex,
    lines,
    newline,
    dataIndices,
    value: JSON.parse(data),
  };
}

function rewriteEvent(event) {
  const [first, ...rest] = event.dataIndices;
  event.lines[first] = `data: ${JSON.stringify(event.value)}`;
  for (const index of rest) event.lines[index] = null;
  return event.lines.filter((line) => line !== null).join(event.newline);
}

function distribute(records, transformed) {
  const codePoints = [...transformed];
  let offset = 0;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    const end = index === records.length - 1 ? codePoints.length : offset + record.length;
    record.owner[record.property] = codePoints.slice(offset, end).join('');
    offset = end;
  }
}

export function stripV1Prefix(pathname) {
  return pathname === '/v1' || pathname.startsWith('/v1/') ? pathname.slice(3) : pathname;
}

export function protocolForPath(pathname) {
  const suffix = stripV1Prefix(pathname);
  if (suffix === '/responses') return 'responses';
  if (suffix === '/messages') return 'anthropic';
  if (suffix === '/chat/completions') return 'chat-completions';
  if (/^\/models\/[^/]+:(?:streamGenerateContent|generateContent)$/.test(suffix)) {
    return 'gemini';
  }
  return null;
}

export async function deobfuscateSse(text, protocol, store) {
  const parts = text.split(/(\r?\n\r?\n)/);
  const events = [];
  const channels = new Map();

  for (let index = 0; index < parts.length; index += 2) {
    if (!parts[index]) continue;
    const event = parseEventBlock(parts[index], index);
    if (!event) continue;
    events.push(event);
    collectChannels(protocol, event.value, channels);
  }

  // Streamed fields must only be restored after reassembly. Scanning their
  // serialized chunks again can mistake an address prefix for a complete IP.
  const streamedFields = new WeakMap();
  for (const records of channels.values()) {
    for (const { owner, property } of records) {
      const properties = streamedFields.get(owner) ?? new Set();
      properties.add(property);
      streamedFields.set(owner, properties);
    }
  }
  for (const event of events) collectOtherStrings(event, 'value', channels, streamedFields);

  let count = 0;
  const channelEntries = [...channels.entries()];
  if (channelEntries.length > 0) {
    const combined = channelEntries.map(([, records]) => (
      records.map((record) => record.owner[record.property]).join('')
    ));
    const transformed = await store.deobfuscateMany(combined);
    for (let index = 0; index < channelEntries.length; index += 1) {
      distribute(channelEntries[index][1], transformed[index].body);
      count += transformed[index].count;
    }
  }

  for (const event of events) parts[event.partIndex] = rewriteEvent(event);
  return { body: parts.join(''), count };
}
