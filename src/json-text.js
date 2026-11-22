// Shorten losslessly representable Unicode escapes before combining HTTP chunks.
const shortEscapes = new Map([
  [8, '\\b'],
  [9, '\\t'],
  [10, '\\n'],
  [12, '\\f'],
  [13, '\\r'],
  [34, '\\"'],
  [92, '\\\\'],
]);

// JSON.parse still validates the document and handles the remaining escapes.
export function createJsonTextCompactor() {
  let insideString = false;
  let pending = '';
  let preserveRemainder = false;
  const quoteOrEscape = /["\\]/g;
  const printableEscape = /^[\da-fA-F]{4}$/;

  function append(decoded) {
    const input = pending + decoded;
    pending = '';
    if (preserveRemainder) return input;
    const parts = [];
    let start = 0;
    quoteOrEscape.lastIndex = 0;

    for (let token = quoteOrEscape.exec(input); token; token = quoteOrEscape.exec(input)) {
      const index = token.index;
      if (token[0] === '"') {
        insideString = !insideString;
        continue;
      }
      if (!insideString) continue;
      const escape = input[index + 1];
      if (!escape || (escape === 'u' && index + 6 > input.length)) {
        pending = input.slice(index);
        parts.push(input.slice(start, index));
        return parts.join('');
      }

      if (escape === 'u') {
        const hex = input.slice(index + 2, index + 6);
        if (!printableEscape.test(hex)) {
          // Avoid changing an invalid escape when a later escape is folded.
          preserveRemainder = true;
          break;
        }
        const code = Number.parseInt(hex, 16);
        const shorter = shortEscapes.get(code) ?? (code >= 0x20 ? String.fromCharCode(code) : undefined);
        if (shorter !== undefined) {
          if (start < index) parts.push(input.slice(start, index));
          parts.push(shorter);
          start = index + 6;
        }
        quoteOrEscape.lastIndex = index + 6;
        continue;
      } else if (!'"\\/bfnrt'.includes(escape)) {
        preserveRemainder = true;
        break;
      }
      quoteOrEscape.lastIndex = index + 2;
    }
    if (!parts.length) return input;
    parts.push(input.slice(start));
    return parts.join('');
  }

  function finish() {
    const remaining = pending;
    pending = '';
    return remaining;
  }

  return { append, finish };
}
