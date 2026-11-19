import { externalFlows, reportingContext, scopedContext, clausesFor } from './workflows.js';
import { evidence, markdownBlocks, proseView } from './markdown.js';
import { maskEvidence, missingManifest, scanSnykSignals, snykReference } from './snyk-rules.js';
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
const acknowledge = /\bwatch notice-ack\b/i;
const receiptRule = /\b(?:manual receipt|manual acknowledgement)\b/i;
const validatedReceipt = /\bvalidated ID and revision\b/i;
const sourceUpload = /\b(?:uploads?|sends?|transmits?)\b.{0,90}\b(?:source (?:code|snapshots?)|repository diffs?)\b(?:\s+and the diff)?/i;
const uploadFallback = /^otherwise ask the user\b/i;
const uploadApproval = /\b(?:reuse|require|obtain|ask for)\b.{0,130}\b(?:saved|explicit|user|service) approval\b/i;

const genUrl = 'https://skills.sh/doomerlabs/skills/doomer/security/agent-trust-hub';
const gen = code => ({ name: 'Gen Agent Trust Hub', code, url: genUrl });
const snyk = snykReference('prompt_injection_skill_instructions', 'E004');
const rules = {
  'dynamic-execution': ['Dynamic execution', 'An execution verb controls a command sourced from output or supplied verbatim.', [gen('Dynamic execution')]],
  'remote-command-provenance': ['Remote command provenance', 'An instruction could execute a command whose value comes from an external source.', [gen('Remote code execution')]],
  'elevated-execution': ['Elevated execution', 'The skill asks for execution beyond the default permission boundary.', [gen('Privilege escalation')]],
  'supplied-executable': ['Supplied executable', 'The skill invokes an executable whose path is supplied at runtime.', [gen('Command execution')]],
  'external-instructions': ['External content in agent workflow', 'The agent is directed to use text from a review, tool, or other external source.', [gen('Indirect prompt injection')]],
  'source-upload': ['Consent-gated source upload', 'The workflow can send repository source or diffs and describes the authorization required.', []],
  'skip-consent': ['Skip user consent', 'An elevation request appears near an instruction to proceed without asking.', [snyk, gen('Privilege escalation')]],
  'withhold-activity': ['Withhold activity', 'The skill directs the agent to omit workflow activity from user-facing reporting.', [snyk]],
  'override-boundary': ['Override a trust boundary', 'An instruction directs the agent to disregard consent, safety policy, permissions, or user instructions.', [snyk]],
};

function context(block, pattern, filter = () => true) {
  let first = block.index;
  while (first > 0 && block.line - block.group[first - 1].line <= 16) first--;
  for (let i = first; i < block.group.length && block.group[i].line - block.line <= 16; i++) {
    const candidate = block.group[i];
    const found = match(candidate.text, pattern);
    if (found && filter(candidate)) return [candidate, found];
  }
}

export function scan(source, limit = maxFindings) {
  const blocks = markdownBlocks(source);
  const findings = [];
  let limited = false;
  let executableFinding;
  let fixedReceipt;

  function add(id, assessment, severity, reason, ...matches) {
    if (findings.length === limit) {
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
    const blockOrigin = match(text, P.ORIGIN);
    for (const clause of clausesFor(block)) {
      const value = clause[0];
      const flow = match(value, flowPattern);
      if (flow && !match(value, P.PROHIBIT_EXECUTION)) {
        const origin = match(value, P.ORIGIN);
        const verbatim = match(value, P.VERBATIM);
        if (origin || verbatim || (blockOrigin && /\b\w+_command\b/i.test(value))) {
          const flowEnd = flow.index + flow[0].length;
          if (value[flowEnd] === String.fromCharCode(96) && flow[0].includes(String.fromCharCode(96))) {
            flow[0] += value[flowEnd];
          }
          const primary = [block, flow, clause.index];
          const originEvidence = origin ? [block, origin, clause.index] :
            blockOrigin && blockOrigin.index < clause.index + flow.index && [block, blockOrigin];
          const verbatimEvidence = verbatim && [block, verbatim, clause.index];
          const fixed = !verbatim && scopedContext(block, clause, expressions.get(P.FIXED), flowPattern, 'command');
          const validation = fixed && scopedContext(block, clause, expressions.get(P.VALIDATE), flowPattern, 'command');
          if (fixed && validation) {
            add('dynamic-execution', 'guarded', 'info',
              'The command is tied to a fixed operation and validated arguments. Check that the implementation enforces both.',
              primary, fixed, validation);
          } else {
            add('dynamic-execution', 'potential', 'high',
              'The command value is resolved at runtime. Its contents can change independently of the skill.',
              primary, originEvidence, verbatimEvidence);
            add('remote-command-provenance', 'requires_provenance', 'high',
              'An externally controlled command value could select host code. Check who produces the value and what the executor accepts.',
              primary, originEvidence, verbatimEvidence);
          }
        }
      }

      const approval = match(value, P.APPROVAL);
      if (approval) {
        const anchor = expressions.get(P.APPROVAL);
        const guard = scopedContext(block, clause, expressions.get(P.DENIAL), anchor, 'approval');
        add('elevated-execution', guard ? 'guarded' : 'potential', guard ? 'info' : 'high',
          guard ? 'The approval instructions for this operation say to honor a denied request.' :
            'The rule found no denial instruction tied to this request.',
          [block, approval, clause.index], guard);
        const skip = scopedContext(block, clause, expressions.get(P.SKIP_CONSENT), anchor, 'approval');
        if (skip) add('skip-consent', 'potential', 'high',
          'Skipping consent can move execution outside the authority granted by the user.', [block, approval, clause.index], skip);
      }

      const upload = sourceUpload.exec(value);
      if (upload && !/\b(?:do not|never|must not|without)\s*$/i.test(value.slice(0, upload.index))) {
        const approval = scopedContext(block, clause, uploadApproval, sourceUpload, 'upload');
        if (approval) {
          const fallback = scopedContext(block, clause, uploadFallback, sourceUpload, 'upload');
          add('source-upload', 'capability', 'info',
            'This workflow can send repository data after checking saved or explicit approval.',
            [block, upload, clause.index], approval, fallback);
        }
      }

      const silence = match(value, P.QUIET);
      const material = match(value, P.MATERIAL);
      if (silence && match(value, P.WORKFLOW) && (match(value, P.AUDIENCE) || match(value, P.ROUTINE)) &&
          (material || match(text, P.ROUTINE)) && !negateConcealment.test(value)) {
        const disclosure = reportingContext(block, clause);
        const reason = material ? 'The instruction can keep security-relevant activity from the user.' :
          'The wording discourages reporting routine activity.';
        add('withhold-activity', material ? 'potential' : 'transparency_signal', material ? 'high' : 'medium',
          reason + (disclosure ? ' The cited disclosure shows what the workflow directs the agent to share.' :
            ' No relevant user-facing disclosure was found nearby, so this finding cannot establish what the user is told.'),
          [block, clause], disclosure);
      }
      if (limited) break;
    }

    const receipt = acknowledge.exec(text);
    const previous = block.group[block.index - 1];
    if (receipt && previous && receiptRule.test(previous.text)) {
      const fixed = match(previous.text, P.FIXED);
      const validated = validatedReceipt.exec(previous.text);
      if (fixed && validated) fixedReceipt = { command: [block, receipt], fixed: [previous, fixed], validated: [previous, validated] };
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

    const override = match(text, P.OVERRIDE);
    if (override && !negateOverride.test(text)) add('override-boundary', 'potential', 'high',
      'Following this instruction could displace the approval or policy that governs the action.', [block, override]);
    if (limited) break;
  }

  if (!limited) for (const flow of externalFlows(blocks)) {
    add('external-instructions', flow.boundary ? 'guarded' : 'potential', flow.boundary ? 'info' : 'medium',
      flow.boundary ? 'The workflow limits how this external input may be used.' :
        'External text can carry instructions the user never authorized. The rule found no data boundary tied to this input.',
      flow.source, flow.action, flow.boundary);
    if (limited) break;
  }

  if (fixedReceipt) {
    add('supplied-executable', 'capability', 'info',
      'A fixed local acknowledgement records receipt using the validated notice ID and revision.',
      fixedReceipt.command, fixedReceipt.fixed, fixedReceipt.validated);
  }
  if (executableFinding && (!fixedReceipt || executableFinding.call[0] !== fixedReceipt.command[0])) {
    const { binary, call, trust } = executableFinding;
    add('supplied-executable', trust ? 'capability' : 'requires_provenance', 'info',
      'Trace who provides the executable path and how the host verifies its provenance.', binary, call, trust);
  }
  const additional = scanSnykSignals(source, limit - findings.length, proseView(source, blocks));
  findings.push(...additional.findings);
  maskEvidence(findings, additional.secrets, source);
  findings.sort((a, b) => a.evidence[0].start - b.evidence[0].start);
  return { engine: 'checkskill', findings, limited: limited || additional.limited };
}

export function scanPackage(files) {
  const manifest = files.find(file => file.path === 'SKILL.md');
  const findings = manifest ? [] : [missingManifest()];
  let limited = false;
  const ordered = manifest ? [manifest, ...files.filter(file => file !== manifest)] : files;
  for (const { path, content } of ordered) {
    const result = scan(content, maxFindings - findings.length);
    for (const finding of result.findings) findings.push({ ...finding, path });
    if (result.limited) {
      limited = true;
      break;
    }
  }
  return { engine: 'checkskill', findings, limited };
}
