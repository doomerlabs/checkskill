export function markdownBlocks(source) {
  const blocks = [];
  let group = [];
  let section = '';
  let sectionPath = [];
  let fence = null;
  let frontmatter = false;
  let buffer = [];

  function flush() {
    if (!buffer.length) return;
    // No rule or context pattern matches a block shorter than "local".
    if (buffer.length === 1 && buffer[0].text.length < 5) {
      buffer = [];
      return;
    }
    let length = 0;
    for (const entry of buffer) {
      entry.normalized = length;
      length += entry.text.length + 1;
    }
    const block = {
      section, sectionPath: sectionPath.filter(Boolean), group, index: group.length, line: buffer[0].line,
      text: buffer.map(entry => entry.text).join(' '), entries: buffer,
    };
    group.push(block);
    blocks.push(block);
    buffer = [];
  }

  let line = 0;
  for (const row of source.matchAll(/([^\r\n]*)(?:\r\n|\r|\n|$)/g)) {
    line++;
    const raw = row[1];
    const text = raw.trim();
    if (text === '---' && (line === 1 || frontmatter)) {
      frontmatter = !frontmatter;
      continue;
    }
    if (frontmatter) continue;

    const marker = /^\s*(`{3,}|~{3,})(.*)$/.exec(raw);
    if (marker && (!fence || (marker[1].startsWith(fence) && !marker[2].trim()))) {
      flush();
      fence = fence ? null : marker[1];
      continue;
    }
    const heading = !fence && /^\s*(#{1,6})\s+(.+)$/.exec(raw);
    const code = Boolean(fence) || (!buffer.length && /^(?: {4}|\t)/.test(raw));
    if (heading || !text || code || (!fence && /^(?:[-*+]|\d+[.)])\s/.test(text))) flush();
    if (heading) {
      section = heading[2];
      sectionPath = sectionPath.slice(0, heading[1].length - 1);
      sectionPath[heading[1].length - 1] = section;
      group = [];
      continue;
    }
    if (text) buffer.push({ line, text, code, rowStart: row.index, start: row.index + raw.indexOf(text) });
    if (code || /(?: {2,}|\\)$/.test(raw)) flush();
  }
  flush();
  return blocks;
}

export function evidence(source, block, index, length) {
  const finish = index + length - 1;
  const first = block.entries.findLast(entry => entry.normalized <= index);
  const last = block.entries.findLast(entry => entry.normalized <= finish);
  const start = first.start + Math.min(index - first.normalized, first.text.length);
  const end = last.start + Math.min(finish - last.normalized + 1, last.text.length);
  return { start, end, line: first.line, endLine: last.line, column: start - first.rowStart + 1,
    section: block.section, text: source.slice(start, end) };
}


// The analysis view joins only lines in the same Markdown paragraph. Map its
// UTF-16 offsets back to the unchanged input before creating evidence.
export function proseView(source, blocks) {
  const parts = [];
  const shifts = [];
  let cursor = 0;
  let removed = 0;
  for (const { entries } of blocks) {
    for (let i = 1; i < entries.length; i++) {
      const start = entries[i - 1].start + entries[i - 1].text.length;
      const end = entries[i].start;
      parts.push(source.slice(cursor, start), ' ');
      removed += end - start - 1;
      shifts.push([end - removed, removed]);
      cursor = end;
    }
  }
  if (!shifts.length) return { text: source, original: offset => offset };
  parts.push(source.slice(cursor));
  return {
    text: parts.join(''),
    original(offset) {
      let low = 0;
      let high = shifts.length;
      while (low < high) {
        const middle = (low + high) >>> 1;
        if (shifts[middle][0] <= offset) low = middle + 1;
        else high = middle;
      }
      return offset + (low ? shifts[low - 1][1] : 0);
    },
  };
}
