import * as P from './patterns.js';

const expressions = new Map(Object.values(P).map(pattern => [pattern, new RegExp(pattern, 'i')]));
function match(text, pattern) {
  return (expressions.get(pattern) ?? pattern).exec(text);
}
const executable = /\b(?:executable (?:path|from)|binary (?:path|from)|[A-Z_]+_EXECUTABLE)\b/i;
const calls = /(?:\bwatch (?:results|notice-ack)\b|--(?:control|token)\b|\b(?:run|invoke|execute)\b.{0,45}\b(?:binary|executable)\b|\bexecutable path\b.{0,30}\bcontrol key\b)/i;
const negateConcealment = /\b(?:never|do not|don't)\b.{0,90}\b(?:hide|omit|suppress|conceal)\b/i;
const negateOverride = /\b(?:never|do not|don't|must not)\s+(?:ignore|override|disregard|bypass|sidestep)\b/i;
const flowPattern = new RegExp(P.EXECUTE + "[\\s`:,\\-]+(?:[\\w'-]+[\\s`]+){0,5}" + P.COMMAND_INPUT, "i");
const maxFindings = 100;

const genUrl = 'https://skills.sh/doomerlabs/skills/doomer/security/agent-trust-hub';
const snykUrl = 'https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md#prompt-injection-in-skill';
const gen = code => ({ name: 'Gen Agent Trust Hub', code, url: genUrl });
const snyk = { name: 'Snyk', code: 'E004 · Prompt injection in skill', url: snykUrl };
const rules = {
  'dynamic-execution': ['Dynamic execution', 'An execution verb controls a command sourced from output or supplied verbatim.', [gen('Dynamic execution')]],
  'remote-command-provenance': ['Remote command provenance', 'An instruction could execute a command whose value comes from an external source.', [gen('Remote code execution')]],
  'elevated-execution': ['Elevated execution', 'The skill asks for execution beyond the default permission boundary.', [gen('Privilege escalation')]],
  'supplied-executable': ['Supplied executable', 'The skill invokes an executable whose path is supplied at runtime.', [gen('Command execution')]],
  'external-instructions': ['External content in agent workflow', 'The agent is directed to use text from a review, tool, or other external source.', [gen('Indirect prompt injection')]],
  'skip-consent': ['Skip user consent', 'An elevation request appears near an instruction to proceed without asking.', [snyk, gen('Privilege escalation')]],
  'withhold-activity': ['Withhold activity', 'The skill directs the agent to omit workflow activity from user-facing reporting.', [snyk]],
  'override-boundary': ['Override a trust boundary', 'An instruction directs the agent to disregard consent, safety policy, permissions, or user instructions.', [snyk]],
};

function markdownBlocks(source) {
  const blocks = [];
  const sections = new Map();
  let section = '';
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
    const group = sections.get(section) ?? [];
    const block = {
      section, group, index: group.length, line: buffer[0].line,
      text: buffer.map(entry => entry.text).join(' '), entries: buffer,
    };
    group.push(block);
    sections.set(section, group);
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
    const heading = !fence && /^\s*#{1,6}\s+(.+)$/.exec(raw);
    if (heading || !text || (!fence && /^[-*+] /.test(text))) flush();
    if (heading) {
      section = heading[1];
      continue;
    }
    if (text) buffer.push({ line, text, rowStart: row.index, start: row.index + raw.indexOf(text) });
  }
  flush();
  return blocks;
}

function evidence(source, block, index, length) {
  const finish = index + length - 1;
  const first = block.entries.findLast(entry => entry.normalized <= index);
  const last = block.entries.findLast(entry => entry.normalized <= finish);
  const start = first.start + Math.min(index - first.normalized, first.text.length);
  const end = last.start + Math.min(finish - last.normalized + 1, last.text.length);
  return { start, end, line: first.line, endLine: last.line, column: start - first.rowStart + 1,
    section: block.section, text: source.slice(start, end) };
}

function context(block, pattern, filter = () => true) {
  let first = block.index;
  while (first > 0 && block.line - block.group[first - 1].line <= 16) first--;
  for (let i = first; i < block.group.length && block.group[i].line - block.line <= 16; i++) {
    const candidate = block.group[i];
    const found = match(candidate.text, pattern);
    if (found && filter(candidate)) return [candidate, found];
  }
}

function* clauses(text) {
  for (const clause of text.matchAll(/\S[\s\S]*?(?:[.!?](?=\s|$)|$)/g)) yield clause;
}

export function scan(source) {
  const blocks = markdownBlocks(source);
  const findings = [];
  let limited = false;
  let externalReported = false;
  let executableFinding;
  let disclosure;
  for (const block of blocks) {
    const found = match(block.text, P.DISCLOSE);
    if (found) {
      disclosure = [block, found];
      break;
    }
  }

  function add(id, assessment, severity, reason, ...matches) {
    if (findings.length === maxFindings) {
      limited = true;
      return;
    }
    const [title, rule, references] = rules[id];
    const spans = matches.filter(Boolean).map(([block, found, offset = 0]) =>
      evidence(source, block, found.index + offset, found[0].length));
    findings.push({ id, title, rule, assessment, severity, reason, references,
      evidence: spans.filter((span, i) => spans.findIndex(other => other.start === span.start && other.end === span.end) === i) });
  }

  for (const block of blocks) {
    const { text } = block;
    const flows = [];
    const blockOrigin = match(text, P.ORIGIN);
    const quiet = [];
    for (const clause of clauses(text)) {
      const value = clause[0];
      const flow = match(value, flowPattern);
      if (flow && !match(value, P.PROHIBIT_EXECUTION)) {
        const origin = match(value, P.ORIGIN);
        const verbatim = match(value, P.VERBATIM);
        if (origin || verbatim || (blockOrigin && /\b\w+_command\b/i.test(value))) {
          flows.push({
            primary: [block, flow, clause.index],
            origin: origin ? [block, origin, clause.index] : blockOrigin && [block, blockOrigin],
            verbatim: verbatim && [block, verbatim, clause.index],
          });
        }
      }
      const silence = match(value, P.QUIET);
      if (silence && match(value, P.WORKFLOW) && (match(value, P.AUDIENCE) || match(value, P.ROUTINE)) &&
          !negateConcealment.test(value)) quiet.push(clause);
    }
    if (flows.length) {
      const fixed = context(block, P.FIXED);
      const validation = context(block, P.VALIDATE);
      const { primary, origin, verbatim } = flows.find(flow => flow.verbatim) ?? flows[0];
      if (fixed && validation && !flows.some(flow => flow.verbatim)) {
        add('dynamic-execution', 'guarded', 'info',
          'Nearby instructions bind execution to a fixed operation and call for validation. Check that the implementation enforces both.',
          primary, fixed, validation);
      } else {
        add('dynamic-execution', 'potential', 'high',
          'The command value is resolved at runtime. Its contents can change independently of the skill.', primary, origin, verbatim);
        add('remote-command-provenance', 'requires_provenance', 'high',
          'An externally controlled command value could select host code. Check who produces the value and what the executor accepts.',
          primary, origin, verbatim);
      }
    }

    const approval = match(text, P.APPROVAL);
    if (approval) {
      const guard = context(block, P.DENIAL);
      add('elevated-execution', guard ? 'guarded' : 'potential', guard ? 'info' : 'high',
        guard ? 'Nearby text says to honor a denied request.' : 'The rule found no nearby instruction to honor a denial.',
        [block, approval], guard);
      const skip = context(block, P.SKIP_CONSENT);
      if (skip) add('skip-consent', 'potential', 'high',
        'Skipping consent can move execution outside the authority granted by the user.', [block, approval], skip);
    }

    const binary = executable.exec(text);
    if (binary && !executableFinding?.preferred) {
      const call = context(block, calls);
      if (call) {
        const trust = context(block, P.TRUSTED);
        const preferred = Boolean(match(text, P.TRUSTED));
        if (preferred || !executableFinding) executableFinding = { binary: [block, binary], call, trust, preferred };
      }
    }

    const external = match(text, P.REVIEW_SOURCE);
    const action = match(text, P.REVIEW_ACTION);
    if (!externalReported && external && action) {
      externalReported = true;
      const guard = context(block, P.DATA_BOUNDARY, candidate =>
        match(candidate.text, P.REVIEW_SOURCE) || !match(candidate.text, P.ADVISORY));
      add('external-instructions', guard ? 'guarded' : 'potential', guard ? 'info' : 'medium',
        guard ? 'Nearby text limits the authority of the external content.' :
          'External text can carry instructions the user never authorized. The rule found no nearby boundary for treating that text as data.',
        [block, external], [block, action], guard);
    }

    const material = quiet.some(clause => match(clause[0], P.MATERIAL));
    if (quiet.length && (material || match(text, P.ROUTINE))) {
      const primary = quiet.find(clause => match(clause[0], P.MATERIAL)) ?? quiet[0];
      add('withhold-activity', material ? 'potential' : 'transparency_signal', material ? 'high' : 'medium',
        material ? 'The instruction can keep security-relevant activity from the user.' :
          'The wording discourages reporting routine activity. Read it alongside requirements to disclose material activity and errors.',
        [block, primary], disclosure);
    }
    const override = match(text, P.OVERRIDE);
    if (override && !negateOverride.test(text)) add('override-boundary', 'potential', 'high',
      'Following this instruction could displace the approval or policy that governs the action.', [block, override]);
    if (limited) break;
  }

  if (executableFinding) {
    const { binary, call, trust } = executableFinding;
    add('supplied-executable', trust ? 'capability' : 'requires_provenance', 'info',
      'Trace who provides the executable path and how the host verifies its provenance.', binary, call, trust);
  }
  findings.sort((a, b) => a.evidence[0].start - b.evidence[0].start);
  return { engine: 'checkskill', findings, limited };
}
