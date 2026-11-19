const docs = 'https://github.com/snyk/agent-scan/blob/main/docs/';

export function snykReference(indicator, legacy) {
  return { name: 'Snyk', code: legacy ? legacy + ' · ' + indicator : indicator,
    url: docs + (indicator === 'Hidden Unicode characters' ? 'issue-codes.md#W021' : 'risks.md#' + indicator) };
}

const checks = {
  'agent-role-override': ['Agent role override', 'Skill text attempts to replace the agent’s governing instructions or impersonate a privileged role.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'suspicious-download': ['Suspicious download source', 'The skill requests a download or installation from an obscured or unverified artifact source.',
    'suspicious_download_url', 'E005', 'high'],
  'dangerous-code-pattern': ['Dangerous code pattern', 'Code or instructions connect sensitive data to an external destination, enable persistent access, or execute code obtained at runtime.',
    'malicious_code', 'E006', 'high'],
  'credential-handling': ['Insecure credential handling', 'A directive moves a credential into output, generated commands, or plaintext storage.',
    'insecure_credential_handling', 'W007', 'high'],
  'embedded-secret': ['Potential embedded secret', 'A value resembles a credential or private key in the skill source.',
    'secret_detection', 'W008', 'high'],
  'financial-execution': ['Direct financial authority', 'The skill gives the agent a path to submit or authorize a financial transaction.',
    'direct_money_access', 'W009', 'medium'],
  'third-party-content': ['Third-party content exposure', 'The skill asks the agent to process content controlled by an external party.',
    'third_party_content_exposure', 'W011', 'medium'],
  'runtime-dependency': ['Unverifiable runtime dependency', 'External content can supply instructions or executable code at runtime.',
    'unverifiable_dependencies', 'W012', 'high'],
  'system-modification': ['Host configuration change', 'The skill asks the agent to modify system services, accounts, security settings, or host-level files.',
    'modifying_system_services', 'W013', 'medium'],
  'missing-skill-manifest': ['Missing SKILL.md', 'A skill folder is expected to include a root SKILL.md manifest.',
    'missing_skill_md', 'W014', 'medium'],
  'hidden-unicode': ['Invisible Unicode', 'An invisible control or format character can make the rendered source differ from what the agent receives.',
    'Hidden Unicode characters', 'W021', 'medium'],
};

function finding(id, reason, evidence, assessment) {
  const [title, rule, indicator, legacy, severity] = checks[id];
  return { id, title, rule, assessment, severity, reason, references: [snykReference(indicator, legacy)], evidence };
}

export function missingManifest() {
  return finding('missing-skill-manifest', 'The submitted folder has no SKILL.md at its root.', [], 'potential');
}

const roleOverride = /\b(?:ignore|disregard|forget|override|replace)\s+(?:(?:all|any|the|your|earlier|previous|prior|above|system|developer|original|existing)\s+){1,6}(?:instructions?|prompts?|rules?|directives?|constraints?)\b|(?:^|\n)[ \t]*(?:<\|(?:system|developer)\|>|\[(?:SYSTEM|DEVELOPER)\]|(?:SYSTEM|DEVELOPER) (?:MESSAGE|INSTRUCTIONS)\s*:)/gi;
const credentials = /\b(?:api[ _-]?(?:key|token)s?|access[ _-]?tokens?|auth(?:entication)?[ _-]?tokens?|refresh[ _-]?tokens?|bearer tokens?|private keys?|passwords?|credentials?|session cookies?|signing secrets?)\b/i;
const unsafeHandling = /\b(?:print|echo|log|display|reveal|paste|include|embed|put|write|store|save|return|send|copy|share|expose|output)\b[^.!?;\r\n]{0,100}\b(?:api[ _-]?(?:key|token)s?|access[ _-]?tokens?|auth(?:entication)?[ _-]?tokens?|refresh[ _-]?tokens?|bearer tokens?|private keys?|passwords?|credentials?|session cookies?|signing secrets?)\b[^.!?;\r\n]{0,95}/gi;
const unsafeDestination = /\b(?:verbatim|plain(?:[ -]?text)?|logs?|console|stdout|chat|messages?|repl(?:y|ies)|responses?|output|shell history|command(?:[- ]line)?|argument|prompt|world.readable|unprotected|external|public)\b/i;
const safeCredential = /\b(?:masked|redacted|placeholder|dummy|sample|name of|reference to)\b/i;
const knownToken = /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{35,}|(?:AKIA|ASIA)[A-Z0-9]{16}|sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{15,}|AIza[A-Za-z0-9_-]{35}|npm_[A-Za-z0-9]{30,}|sk_(?:live|test)_[A-Za-z0-9]{16,})\b/g;
const assignment = /(?<![\w-])([\w-]+)["']?[ \t]*[:=][ \t]*(?:"([^"\r\n]{4,256})"|'([^'\r\n]{4,256})'|([A-Za-z0-9_+/=!@.%-]{6,256}))/g;
const secretName = /(?:^|[_-])(?:api[_-]?key|(?:access|auth|refresh)[_-]?token|client[_-]?secret|session[_-]?cookie|password|passwd|secret|token)$/i;
const privateKey = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g;
const placeholder = /^(?:\$\{|\$[A-Z_]|<|\{\{|%[A-Z_])|\b(?:placeholder|redacted|changeme|change-me|replace-me|your[-_ ]|dummy|sample|example|insert|process\.env|getenv)\b|^(?:x+|\*+|null|undefined|true|false|password|secret|none)$/i;

const payment = /\b(?:submit|initiate|authorize|execute|make|send|transfer|withdraw|place|sign|broadcast|charge|refund|pay)\b[^.!?;\r\n]{0,62}\b(?:payments?|funds|money|cash|bank transfers?|transactions?|market orders?|trades?|invoices?|credit cards?|customers?|cryptocurrency|crypto assets?|wallet transfers?)\b/gi;
const publicData = /\b(?:browse|read|fetch|retrieve|load|search|analy[sz]e|summarize|process|follow|use|consume|ingest|inspect)\b[^.!?;\r\n]{0,85}\b(?:(?:arbitrary|user[- ]supplied) (?:urls?|websites?)|public (?:web(?:sites?| pages?)?|posts?|issues?|comments?|forums?|pages?|feeds?|social media)|social[- ]media(?: posts?| comments?)?|forum (?:posts?|comments?)|user[- ](?:submitted|generated|controlled) (?:content|data|posts?|comments?|input)|third[- ]party (?:content|api responses?|websites?|pages?|documents?)|external (?:content|api responses?|websites?|pages?|documents?)|issue tracker (?:comments?|posts?))\b/gi;
const systemChange = /\b(?:systemctl\s+(?:start|stop|enable|disable|restart|mask|unmask|edit|daemon-reload)|launchctl\s+(?:load|unload|bootstrap|bootout|enable|disable)|(?:Enable|Disable|Start|Stop|Restart|Configure|Modify|Change|Edit|Update|Install|Create|Remove|Add|Delete|Grant|Revoke)\b[^.!?;\r\n]{0,70}\b(?:system(?:d)? services?|system service configuration|service on (?:boot|startup)|firewall|security (?:settings|configuration|polic(?:y|ies))|antivirus|host (?:users?|accounts?|permissions?)|system (?:users?|accounts?|permissions?|files)|startup (?:services?|items?|agents?|tasks?)|scheduled (?:system|startup) task)|(?:useradd|userdel|usermod)\b|(?:Set-Service|New-Service|sc\.exe)\s+[\w-]+)/gi;
const urlPattern = /\bhttps?:\/\/[^\s<>"'\x60|)]+/gi;
const downloadAction = /\b(?:download|install|execute|launch|run|fetch|retrieve|load|pull|clone|curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b/i;
const runtimeUse = /\b(?:as (?:the |its )?(?:runbook|instructions?|prompts?|configuration)|(?:follow|obey|apply|execute|run|eval|source|load|install|import)\b[^.!?;\r\n]{0,55}\b(?:downloaded|fetched|returned|retrieved|remote|helper|script|binary|instructions?|runbook|contents?|package)|at runtime|on every (?:run|invocation)|latest release)\b/i;
const artifact = /\.(?:sh|ps1|bat|cmd|exe|msi|pkg|dmg|zip|tar|tgz|gz|apk|deb|rpm|bin)(?:$|[?#])/i;
const shortener = /(?:^|\.)(?:bit\.ly|goo\.gl|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|ow\.ly|lnkd\.in|rebrand\.ly|shorturl\.at)$/i;
const downloadHost = /(?:^|\.)(?:drive\.google\.com|dropbox\.com|mega\.nz|mediafire\.com|pastebin\.com|anonfiles\.com|discordapp\.com)$/i;

const unsafeExecution = /\b(?:curl|wget)\b[^|\r\n]{0,180}\|[ \t]*(?:(?:sudo|env)\s+)?(?:bash|sh|zsh|ksh|dash|powershell|pwsh)\b|\b(?:Invoke-Expression|iex)\b[^\r\n]{0,100}\b(?:Invoke-WebRequest|Invoke-RestMethod|curl)\b/gi;
const sensitiveTransfer = /\b(?:upload|send|post|transmit|forward|export|exfiltrate)\b[^.!?;\r\n]{0,90}\b(?:credentials?|api keys?|access tokens?|private keys?|passwords?|session cookies?|environment variables?|private files?|secrets?)\b[^.!?;\r\n]{0,75}\b(?:external|public|webhook|remote|third[- ]party|https?:)/gi;
const persistence = /\b(?:install|create|enable|configure|add)\b[^.!?;\r\n]{0,70}\b(?:backdoors?|covert persistence|unauthorized remote access|hidden startup (?:agent|task)|persistence mechanism)\b/gi;
const hiddenCharacter = /(?:(?![\t\r\n])[\p{Cf}\p{Cc}])+/gu;
const encodedText = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}/g;
const encodedExecution = /\b(?:base64|FromBase64String|atob|b64decode)\b[^.!?;\r\n]{0,80}\b(?:execute|eval|invoke|pipe|run|interpret)\b/gi;
const secretsToOutput = /\b(?:echo|printf|print|console\.log)\b[^;\r\n]{0,60}\$\{?[A-Z_]*(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD|PRIVATE_KEY|CLIENT_SECRET|SESSION_COOKIE)\b\}?/g;

function negated(source, start) {
  const prior = source.slice(Math.max(0, start - 64), start).split(/[.!?;\r\n]/).at(-1);
  return /\b(?:do not|don't|never|must not|should not|avoid|prohibit|forbid|blocked example|negative example|if you see)\s*(?:\w+\s+){0,4}['"\x60]*$/i.test(prior);
}

function sourceLocation(source) {
  const starts = [0];
  for (const match of source.matchAll(/\r\n|\r|\n/g)) starts.push(match.index + match[0].length);

  function lineAt(position) {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      if (starts[mid] <= position) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  }

  return (start, length, masked = false) => {
    const line = lineAt(start);
    const end = start + length;
    return { start, end, line: line + 1, endLine: lineAt(end - 1) + 1, column: start - starts[line] + 1,
      section: '', text: masked ? '[credential redacted]' : source.slice(start, end) };
  };
}

export function scanSnykSignals(source, limit) {
  const results = [];
  let locate;
  let limited = false;

  function add(id, start, length, reason, assessment = 'potential', masked = false) {
    if (results.length >= limit) {
      limited = true;
      return;
    }
    locate ??= sourceLocation(source);
    results.push(finding(id, reason, [locate(start, length, masked)], assessment));
  }

  function scanMatches(id, pattern, reason, assessment, accepts = () => true) {
    for (const match of source.matchAll(pattern)) {
      if (!negated(source, match.index) && accepts(match)) {
        add(id, match.index, match[0].length, reason, assessment);
        if (limited) break;
      }
    }
  }

  // Collect sensitive spans first so evidence from any overlapping rule can be masked.
  const secrets = new Map();
  for (const match of source.matchAll(knownToken)) secrets.set(match.index, match[0].length);
  for (const match of source.matchAll(privateKey)) secrets.set(match.index, match[0].length);
  for (const match of source.matchAll(assignment)) {
    if (!secretName.test(match[1])) continue;
    const value = match.slice(2).find(Boolean);
    if (!value || placeholder.test(value)) continue;
    const start = match.index + match[0].lastIndexOf(value);
    if (!secrets.has(start)) secrets.set(start, value.length);
  }
  for (const [start, length] of secrets) {
    add('embedded-secret', start, length, 'The source contains a credential-like literal. The response masks its value.', 'potential', true);
    if (limited) break;
  }

  if (!limited) scanMatches('credential-handling', unsafeHandling,
    'The directive can place secret values in model-visible output, commands, or insecure storage.', 'potential',
    match => credentials.test(match[0]) && unsafeDestination.test(match[0]) && !safeCredential.test(match[0]));
  if (!limited) scanMatches('credential-handling', secretsToOutput,
    'The command sends a secret-bearing environment variable to output.');
  if (!limited) scanMatches('agent-role-override', roleOverride,
    'The matched text can steer the agent away from the instructions that govern it.');
  if (!limited) scanMatches('agent-role-override', encodedText,
    'Encoded text contains a directive that can replace the agent’s governing instructions.', 'potential', match => {
      // Decode only bounded candidates and check the text without rendering it.
      const length = match[0].length;
      if (length < 24 || length > 2048 || length % 4 !== 0) return false;
      try {
        return [...atob(match[0]).matchAll(roleOverride)].length > 0;
      } catch {
        return false;
      }
    });
  if (!limited) scanMatches('dangerous-code-pattern', encodedExecution,
    'The instruction connects an encoded value to execution. Review the decoded content as text.');
  if (!limited) scanMatches('dangerous-code-pattern', unsafeExecution,
    'The matched code passes freshly downloaded text into an interpreter.');
  if (!limited) scanMatches('dangerous-code-pattern', sensitiveTransfer,
    'The matched instruction directs sensitive values to an external destination.');
  if (!limited) scanMatches('dangerous-code-pattern', persistence,
    'The matched instruction requests persistent or unauthorized access.');
  if (!limited) scanMatches('financial-execution', payment,
    'This instruction can move money or create a financial obligation. Review its approval and account limits.', 'capability');
  if (!limited) scanMatches('third-party-content', publicData,
    'The agent can encounter third-party instructions through this input. Review the boundary before acting on it.', 'capability');
  if (!limited) scanMatches('system-modification', systemChange,
    'This instruction can change host state. Review the permission boundary and the scope of the change.', 'capability');

  if (!limited) for (const match of source.matchAll(urlPattern)) {
    const urlText = match[0].replace(/[.,;:\]}]+$/, '');
    let url;
    try {
      url = new URL(urlText);
    } catch {
      continue;
    }
    const start = match.index;
    const before = source.slice(Math.max(0, start - 170), start).split(/\n[ \t]*\n/).at(-1);
    const after = source.slice(start + urlText.length, start + urlText.length + 165).split(/\n[ \t]*\n/, 1)[0];
    const actions = [...before.matchAll(new RegExp(downloadAction.source, 'gi'))];
    const action = actions.at(-1);
    if (!action || /[.!?;]\s/.test(before.slice(action.index + action[0].length)) ||
        negated(source, start - before.length + action.index)) continue;
    const obscured = shortener.test(url.hostname) || downloadHost.test(url.hostname) || url.username !== '' ||
      /^\[|^\d+\.\d+\.\d+\.\d+$/.test(url.hostname);
    const executableArtifact = artifact.test(url.pathname) ||
      /^(?:install|execute|launch|run)$/i.test(action[0]) && /\b(?:helper|script|binary|executable)\b/i.test(before);
    const verified = /\b(?:verify|check|pin)\b[^.!?;\r\n]{0,65}\b(?:signature|checksum|sha-?256|digest|commit hash)\b/i.test(before + ' ' + after);
    if (obscured || (executableArtifact && (url.protocol !== 'https:' || !verified))) {
      add('suspicious-download', start, urlText.length,
        obscured ? 'The destination obscures provenance or uses an intermediary download host.' :
          'The instruction references an executable or archive without an evident integrity check.');
    }
    const runtime = runtimeUse.test(before + ' ' + after) ||
      /^(?:install|execute|launch|run|load)$/i.test(action[0]) ||
      /^\s*['"\x60]?\s*\|\s*(?:bash|sh|zsh|pwsh)\b/i.test(after);
    if (runtime && !verified) add('runtime-dependency', start, urlText.length,
      'The referenced source can change after installation and affect the instructions or code the agent uses.');
    if (limited) break;
  }

  if (!limited) for (const match of source.matchAll(hiddenCharacter)) {
    if (match.index === 0 && match[0] === '\uFEFF') continue;
    const text = match.index === 0 && match[0].startsWith('\uFEFF') ? match[0].slice(1) : match[0];
    const codes = new Set();
    for (const character of text) {
      codes.add('U+' + character.codePointAt(0).toString(16).toUpperCase().padStart(4, '0'));
      if (codes.size === 5) break;
    }
    add('hidden-unicode', match.index + match[0].length - text.length, text.length,
      'Invisible Unicode: ' + [...codes].join(', ') + '. Review whether this formatting belongs in the skill.');
    if (limited) break;
  }
  return { findings: results, limited, secrets };
}

export function maskEvidence(findings, secrets, source) {
  if (!secrets.size) return;
  const ranges = [...secrets.entries()].sort(([a], [b]) => a - b);
  const maskedSections = new Map();
  for (const finding of findings) for (const span of finding.evidence) {
    const section = span.section;
    if (section && !maskedSections.has(section)) {
      let masked = section;
      for (const [start, length] of ranges) {
        if (length <= section.length) masked = masked.replaceAll(source.slice(start, start + length), '[credential redacted]');
      }
      maskedSections.set(section, masked);
    }
    if (section) span.section = maskedSections.get(section);
    if (span.text === '[credential redacted]') continue;
    let cursor = span.start;
    let masked = '';
    for (const [start, length] of ranges) {
      if (start >= span.end) break;
      const from = Math.max(span.start, start);
      const to = Math.min(span.end, start + length);
      if (to <= cursor) continue;
      masked += span.text.slice(cursor - span.start, Math.max(cursor, from) - span.start) + '[credential redacted]';
      cursor = to;
    }
    if (cursor !== span.start) span.text = masked + span.text.slice(cursor - span.start);
  }
}
