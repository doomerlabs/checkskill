import * as P from './patterns.js';

const inputPattern = /\b(?:display_markdown|(?:notice|advisory) (?:content|text|data)|(?:show|display|append) (?:blocking |non-blocking |the )?(?:notices?|advisories)|(?:internal |pending )?hypothesis requests?|review (?:reports?|findings?|areas?)|remote findings|tool (?:results?|outputs?)|(?:api|server|service|webhook) (?:responses?|reports?|outputs?|payloads?)|retrieved (?:pages?|documents?)|untrusted (?:web content|content|source)|copied comments?|(?:external|third[- ]party) (?:content|documents?))\b/gi;
const actionPattern = /\b(?:read|review|investigate|assess|inspect|propose|summarize|follow|act on|perform|generate|submit|use|analy[sz]e|treat|show|display|append|process|parse|render|extract|execute|run|apply|send)\b/gi;
const inputPresent = new RegExp(inputPattern.source, 'i');
const actionVerb = new RegExp('^(?:' + actionPattern.source + ')$', 'i');
const dataBoundary = new RegExp(P.DATA_BOUNDARY + '|\\b(?:solely|only) for (?:user-visible )?display\\b', 'gi');
const targetedOperation = /\b(upload|deploy|register|registration|install|backup|import|export|preview|publish|delete|migrate|fetch|acknowledge|receipt|scan|sync|connect|restart|setup|test|review|watcher)(?:s|ing|ed|ment|ation)?\b/gi;
const commandName = /\b[a-z][a-z0-9_]*_command\b/gi;
const disclosureVerb = /\b(?:announce|deliver|disclose|explain|include|inform|notify|report|show|summarize|surface|tell)\b/gi;
const disclosureSubject = /\b(?:activity|advisories|approval|changes|concerns|coverage|errors?|failures?|findings?|handoff|material|outcome|permissions?|results?|review status|unresolved|uploads?)\b/i;
const userAudience = /\b(?:to (?:the )?(?:user|operator|reader)|(?:in|as part of) (?:the |your )?(?:final (?:reply|response|answer)|user-facing (?:reply|response|answer))|(?:tell|inform|notify|show) (?:the )?(?:user|operator|reader))\b/i;
const internalAudience = /\b(?:to|via|in|into|through) (?:the )?(?:(?:review|analysis|internal|local) )?(?:tools?|services?|logs?|telemetry|tool output)\b/i;
const deliverAdvisories = /\bdeliver (?:required )?(?:service )?advisories and\s*$/i;
const cloneLine = /^[ \t]*git clone\s+[^\r\n]{1,260}\r?$/gim;
const ignoresCloneFailure = /\|\|\s*(?:true\b|:(?=\s|$))/i;
const sharedCheckout = /\s+['"]?((?:\/(?:private\/)?tmp\/|\$\{?TMPDIR\}?\/)[\w./-]{2,145})['"]?(?=\s|$)/i;
const checkedArtifact = /\b(?:sha256sum\s+-c\b|verify\b[^\r\n;]{0,65}\b(?:checksum|signature|commit|revision)\b)/i;

export function* uncheckedCheckoutFallbacks(source) {
  for (const match of source.matchAll(cloneLine)) {
    const command = match[0];
    if (!/https?:\/\/\S+/i.test(command) || !ignoresCloneFailure.test(command)) continue;
    const path = sharedCheckout.exec(command)?.[1].replace(/\/+$/, '');
    if (!path) continue;
    const escaped = path.replace(/[.*+?^$${}()|[\]\\]/g, '\\$&');
    const invocation = new RegExp(
      `^[ \t]*(?:(?:bash|sh|pwsh|python3?|node)[ \t]+)?["']?${escaped}/[\\w./-]+(?=[\\s"']|$)`, 'im');
    const position = match.index + command.length;
    const next = source.slice(position, position + 530);
    const executed = invocation.exec(next);
    if (!executed || checkedArtifact.test(next.slice(0, executed.index))) continue;
    const end = position + executed.index + executed[0].length;
    yield { start: match.index, length: end - match.index };
  }
}

export function clausesFor(block) {
  return block.clauses ??= [...block.text.matchAll(/\S[\s\S]*?(?:[.!?;](?=\s|$)|$)/g)];
}

function span(block, text, index) {
  return [block, { 0: text, index }];
}

function negatedAt(text, index) {
  const prefix = text.slice(Math.max(0, index - 65), index).split(/[,;:]|\b(?:but|whereas|instead)\b/i).at(-1);
  return /\b(?:never|must not|should not|do not|don't|avoid|without|no)\b[^.!?]{0,55}$/i.test(prefix);
}

function inputType(text) {
  if (/display_markdown|notice|advisory|advisories/i.test(text)) return 'advisory';
  if (/hypothesis requests?/i.test(text)) return 'hypothesis';
  if (/review |remote findings/i.test(text)) return 'review';
  return text.toLowerCase().replace(/s$/, '');
}

function identity(source) {
  return ['advisory', 'hypothesis'].includes(source.type) ? source.type :
    source.text.toLowerCase().replace(/s$/, '');
}

function inputs(block, clause) {
  return [...clause[0].matchAll(inputPattern)].map(found => {
    const action = /^(?:show|display|append) /i.exec(found[0]);
    const text = action ? found[0].slice(action[0].length) : found[0];
    return { text, type: inputType(text), offset: found.index + (action?.[0].length ?? 0),
      evidence: span(block, text, clause.index + found.index + (action?.[0].length ?? 0)) };
  });
}

const actionGroup = {
  show: 'display', append: 'display', render: 'display',
  analyze: 'assess', analyse: 'assess', investigate: 'assess', review: 'assess',
};

function actionFor(block, clause, source, previous, next, previousAction, guarded) {
  const text = clause[0];
  const last = source.offset + source.text.length;
  const lower = previous ? previous.offset + previous.text.length : 0;
  const higher = next?.offset ?? text.length;
  const before = text.slice(lower, source.offset);
  const after = text.slice(last, higher);
  const direct = [...before.matchAll(actionPattern)].at(-1);
  const comma = after.indexOf(',');
  const conditional = /^\s*(?:when|if|once|after)\b/i.test(text) && comma !== -1;
  let start;
  let end;
  if (conditional) {
    const tail = after.slice(comma + 1);
    const verb = /^\s*(?:then\s+)?(\w+)/i.exec(tail);
    if (!verb || !actionVerb.test(verb[1])) return;
    start = last + comma + 1 + verb[0].lastIndexOf(verb[1]);
    end = higher;
  } else if (direct && !/[,;:]/.test(before.slice(direct.index + direct[0].length))) {
    start = lower + direct.index;
    end = higher;
  } else if (guarded) {
    return { key: 'boundary', evidence: span(block, guarded[0], clause.index + guarded.index) };
  } else if (previous && /^\s*(?:,\s*|(?:and|or)\s+(?:the\s+)?)$/i.test(before)) {
    return previousAction;
  } else {
    return;
  }
  const prefix = text.slice(0, start);
  if (/\b(?:never|must not|do not|don't)\s*$/i.test(prefix) ||
      /\b(?:merely|just|only) because\b/i.test(prefix)) return;
  const action = text.slice(start, end).split(/[,;]|\s+using\s+|\s+and\s+then\s+/i, 1)[0]
    .trimEnd().replace(/[.!?]+$/, '').replace(/^\s+/, '');
  const verb = action.match(/^\w+/)?.[0].toLowerCase();
  const key = guarded && verb === 'treat' ? 'boundary' :
    source.type === 'advisory' && (verb === 'display' || verb === 'use' || actionGroup[verb] === 'display') ? 'display' :
      (actionGroup[verb] ?? verb) + ':' + action.slice(verb.length).toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
  return { key, evidence: span(block, action, clause.index + start) };
}

export function externalFlows(blocks) {
  const bySection = new Map();
  for (const block of blocks) {
    if (!inputPresent.test(block.text)) continue;
    const records = bySection.get(block.group) ?? [];
    bySection.set(block.group, records);
    const clauses = clausesFor(block);
    for (const [clauseIndex, clause] of clauses.entries()) {
      const sources = inputs(block, clause);
      if (!sources.length) {
        const previous = records.at(-1);
        const previousClause = previous?.block === block &&
          clauses[clauseIndex - 1] === previous.clause;
        if (previousClause && previous.action) {
          const guard = [...clause[0].matchAll(dataBoundary)].find(found => !negatedAt(clause[0], found.index));
          if (guard) records.push({ block, clause, source: previous.source, guard, appliesTo: previous });
        }
        continue;
      }
      const guards = new Map();
      let nextSource = 0;
      for (const guard of clause[0].matchAll(dataBoundary)) {
        if (negatedAt(clause[0], guard.index)) continue;
        while (nextSource < sources.length && sources[nextSource].offset < guard.index) nextSource++;
        const inside = sources[nextSource]?.offset < guard.index + guard[0].length;
        const named = sources[inside ? nextSource : nextSource - 1];
        if (named) guards.set(named, guard);
      }
      let previousAction;
      for (const [index, source] of sources.entries()) {
        const guard = guards.get(source);
        const action = actionFor(block, clause, source, sources[index - 1], sources[index + 1], previousAction, guard);
        previousAction = action;
        if (action || guard) records.push({ block, clause, source, action, guard });
      }
    }
  }
  const flows = [];
  for (const records of bySection.values()) {
    const distinct = new Map();
    for (const [index, record] of records.entries()) {
      const { block, clause, source, action } = record;
      if (!action) continue;
      const key = identity(source) + ':' + action.key;
      const prior = distinct.get(key);
      if (prior && !/display_markdown/i.test(source.text)) continue;
      let governing = record.guard && record;
      // A named boundary may appear in an adjacent clause. An intervening
      // workflow with a different input ends that scope.
      for (const direction of [-1, 1]) {
        if (governing) break;
        for (let i = index + direction; i >= 0 && i < records.length; i += direction) {
          const other = records[i];
          if (Math.abs(block.index - other.block.index) > 1 || identity(source) !== identity(other.source)) break;
          if (other.action && other.action.key !== 'boundary' && other.action.key !== action.key) break;
          if (other.guard) {
            if (!other.appliesTo || other.appliesTo === record) governing = other;
            break;
          }
        }
      }
      if (action.key === 'boundary') {
        const adjacent = [records[index - 1], records[index + 1]];
        if (adjacent.some(other => other?.action && other.action.key !== 'boundary' &&
            identity(other.source) === identity(source) && Math.abs(block.index - other.block.index) <= 1)) continue;
      }
      // "Treat … as data" is itself a documented use of the input.
      const boundary = governing && span(governing.block, governing.guard[0], governing.clause.index + governing.guard.index);
      distinct.set(key, { source: source.evidence, action: action.evidence, boundary });
    }
    flows.push(...distinct.values());
  }
  return flows;
}

function operations(text) {
  return new Set([
    ...[...text.matchAll(targetedOperation)].map(found => /acknowledge|receipt/i.test(found[1]) ?
      'receipt' : found[1].toLowerCase().replace(/^registration$/, 'register')),
    ...[...text.matchAll(commandName)].flatMap(found => {
      const name = found[0].toLowerCase();
      return [name, name.slice(0, -'_command'.length).replaceAll('_', ' ')];
    }),
  ]);
}

export function scopedContext(block, clause, pattern, anchor, type) {
  const names = operations(clause[0]);
  const find = typeof pattern === 'function' ? pattern : text => pattern.exec(text);
  const before = block.group[block.index - 1];
  const after = block.group[block.index + 1];
  const clauses = clausesFor(block);
  const position = clauses.indexOf(clause);
  const window = [
    ...(before ? clausesFor(before).slice(-5).map(part => ({ block: before, part })) : []),
    ...clauses.slice(Math.max(0, position - 5), position + 6).map(part => ({ block, part })),
    ...(after ? clausesFor(after).slice(0, 5).map(part => ({ block: after, part })) : []),
  ];
  const index = window.findIndex(item => item.part === clause);
  let nearest;
  for (const [position, { block: other, part }] of window.entries()) {
    const found = find(part[0]);
    if (!found || type !== 'reporting' && negatedAt(part[0], found.index)) continue;
    if (position === index && type === 'approval') {
      const action = anchor.exec(part[0]);
      if (action && action.index < found.index) {
        const contrast = /\b(?:but|whereas|while)\b/i.exec(part[0].slice(action.index + action[0].length, found.index));
        const suffix = /^\s+for\s+[^,;.!?]*/i.exec(part[0].slice(found.index + found[0].length));
        const actionNames = operations(part[0].slice(action.index, found.index));
        const guardNames = operations(suffix?.[0] ?? '');
        if (guardNames.size && actionNames.size && ![...guardNames].some(name => actionNames.has(name))) continue;
        if (contrast) {
          const start = action.index + action[0].length + contrast.index;
          const own = operations(part[0].slice(action.index, start));
          const qualified = operations(part[0].slice(start, found.index) + ' ' + (suffix?.[0] ?? ''));
          if (qualified.size && own.size && ![...qualified].some(name => own.has(name))) continue;
        }
      }
    }
    if (position !== index) {
      const qualifier = type === 'approval' ?
        part[0].slice(0, found.index + found[0].length) +
          (/^\s+(?:for|to)\s+[^,;.!?]*/i.exec(part[0].slice(found.index + found[0].length))?.[0] ?? '') :
        part[0];
      const candidateNames = operations(qualifier);
      const matchingName = [...candidateNames].some(name => names.has(name));
      if (type === 'reporting' && other !== block && !matchingName) continue;
      const genericReceipt = type === 'command' && names.size === 0 &&
        candidateNames.size === 1 && candidateNames.has('receipt');
      if (candidateNames.size && !matchingName && !genericReceipt) continue;
      const between = window.slice(Math.min(position, index) + 1, Math.max(position, index));
      if (anchor.test(part[0]) || between.some(item => anchor.test(item.part[0]))) continue;
      // An unqualified safeguard after another operation belongs to that
      // operation. Named safeguards and introductory safeguards can lead.
      if (position < index && !matchingName && window.slice(0, position).some(item => anchor.test(item.part[0]))) continue;
      if (position > index && !matchingName && other !== block) {
        const first = window.findIndex(item => item.block === other);
        if (window.slice(first, position).some(item => operations(item.part[0]).size)) continue;
      }
    }
    const distance = Math.abs(position - index);
    if (!nearest || distance < nearest.distance) {
      nearest = { evidence: span(other, found[0], part.index + found.index), distance };
    }
  }
  return nearest?.evidence;
}

function userDisclosure(text) {
  if (!userAudience.test(text) && !/\bdeliver\b/i.test(text)) return;
  for (const action of text.matchAll(disclosureVerb)) {
    if (negatedAt(text, action.index)) continue;
    const end = action.index + 180;
    const tail = text.slice(action.index, end);
    const boundary = /[,;]|[.!?]$|\s+(?:and|but|then)\s+(?=(?:submit|record|log|upload|send|report|tell|include|show|notify)\b)/i.exec(tail);
    // Avoid using an incomplete statement to infer a disclosure destination.
    if (!boundary && end < text.length) continue;
    const statement = tail.slice(0, boundary?.index).trimEnd();
    if (disclosureSubject.test(statement) && userAudience.test(statement) && !internalAudience.test(statement)) {
      return { 0: statement, index: action.index };
    }
    // Error reporting inherits the audience when it accompanies delivery of
    // service advisories in the same instruction.
    if (/^report errors?$/i.test(statement) && deliverAdvisories.test(text.slice(Math.max(0, action.index - 85), action.index))) {
      return { 0: statement, index: action.index };
    }
  }
}

export function reportingContext(block, clause) {
  return scopedContext(block, clause, userDisclosure, new RegExp(P.QUIET, 'i'), 'reporting');
}
