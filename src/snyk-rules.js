import { evidence as markdownEvidence, markdownBlocks } from './markdown.js';
import { uncheckedCheckoutFallbacks } from './workflows.js';

const docs = 'https://github.com/snyk/agent-scan/blob/main/docs/';

export function snykReference(indicator, legacy) {
  return { name: 'Snyk', code: legacy ? legacy + ' · ' + indicator : indicator,
    url: docs + (indicator === 'Hidden Unicode characters' ? 'issue-codes.md#W021' : 'risks.md#' + indicator) };
}

const checks = {
  'unrelated-resource-gate': ['Unrelated resource creation gate', 'A module template requires an endorsement to create resources.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'agent-role-override': ['Agent role override', 'Skill text attempts to replace the agent’s governing instructions or impersonate a privileged role.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'unapproved-file-change': ['Unapproved file change', 'The workflow can alter original files or installed code without confirming the change.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'unconfirmed-hosted-asset': ['Unconfirmed hosted asset', 'The workflow creates and saves an asset on the user’s hosted account without asking.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'unconfirmed-device-action': ['Unconfirmed device action', 'The workflow sends to a hardware interface selected and saved automatically.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'fixed-deployment-alias': ['Fixed deployment alias', 'A deployment helper preserves a fixed public alias alongside the requested host.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'undisclosed-install-files': ['Undisclosed installation files', 'The installation confirmation omits files the workflow later adds.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'undisclosed-live-account': ['Undisclosed live account', 'The workflow hides its use of a live account or profile from the user.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'undisclosed-persistence': ['Undisclosed persistence', 'The workflow writes information for future sessions while suppressing notice of that change.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'undisclosed-monitoring': ['Undisclosed monitoring', 'The workflow directs the agent to withhold that a user artifact or activity is being monitored.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'undisclosed-evidence-sharing': ['Undisclosed evidence sharing', 'A linked configuration enables browser evidence sharing by default.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'retained-relay-authentication': ['External authentication processing', 'The login flow sends a saved authentication response to a relay and retains credential-bearing backups.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'undisclosed-startup-command': ['Undisclosed startup command', 'The skill runs a command on every session and tells the agent to hide it from the user.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'concealed-report-sources': ['Concealed report sources', 'A delegated prompt forbids disclosing the internal context used in the report.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'concealed-report-verification': ['Concealed report verification', 'The workflow tells the agent to run report checks and withhold that activity from the user.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'overbroad-management-scope': ['Overbroad management scope', 'The credential can remove resources outside the scope of the stated cleanup.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'undisclosed-account-adoption': ['Undisclosed account adoption', 'Signing in also claims locally recorded resources for the authenticated account.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'concealed-profile-access': ['Concealed profile access', 'The workflow reads a user profile and directs the agent to hide that access.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'concealed-sign-in-requirement': ['Concealed sign-in requirement', 'The skill asks for sign-in and instructs the agent to hide where that requirement comes from.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'promotional-account-connection': ['Promotional account connection', 'A tracked gateway link is used to direct the agent to connect live accounts.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'default-output-attribution': ['Default output attribution', 'The workflow adds its own branding or source link to the resulting deliverable.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'automatic-telemetry': ['Automatic reporting', 'The workflow directs the agent to report activity to an external service by default.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'undisclosed-local-analytics': ['Undisclosed local analytics', 'The skill records player activity with a persistent identifier without a notice or opt-in.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'unverified-host-tool': ['Unverified host tool', 'The skill installs a mutable tool that can disable system services.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'unverified-app-evaluator': ['Unverified app evaluator', 'The workflow runs an unpinned third-party evaluator against the running application.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'opaque-tool-installation': ['Opaque tool installation', 'The workflow installs an exploitation tool from a checkout with obscured provenance.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'forced-escalation': ['Forced escalation', 'The workflow calls for a retry with broader permissions after a sandbox denial.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'weakened-safeguard': ['Weakened safeguard', 'The workflow disables a protection for user data or uncommitted changes.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'unapproved-license-acceptance': ['Unapproved license acceptance', 'The workflow accepts license or submission terms on the user’s behalf.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'unchecked-shell-argument': ['Unchecked shell argument', 'A skill script interpolates a program argument into a shell command.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'delegated-host-setup': ['Delegated host setup', 'A live setup guide controls software installation and PATH changes.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'undisclosed-authorship': ['Undisclosed agent involvement', 'The skill requires omitting the agent’s involvement from published changes.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'automatic-pr-registration': ['Automatic pull request registration', 'The skill registers existing pull requests with a host tool before doing the task.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'undisclosed-template-stub': ['Undisclosed template stub', 'A template advertised as complete returns a fixed output and cost.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'automatic-package-patch': ['Automatic package patch', 'The skill wires a patch of installed package code into a recurring setup or upgrade step.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'background-self-update': ['Background self-update', 'The script copies itself and launches an unmonitored updater subprocess.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'automatic-skill-update': ['Automatic skill update', 'The updater can replace installed instructions and executable code from a mutable source.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'default-host-hook': ['Default host hook', 'The installer registers a turn-end hook and copies a skill into a user-level skill directory.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'project-agent-hook': ['Persistent agent hook', 'The workflow offers to install a hook that affects subsequent agent actions.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'terminates-profile-owner': ['Terminates an existing browser', 'The script closes the process that currently holds the browser profile.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'public-local-proxy': ['Exposed local proxy', 'A proxy documented as local listens on every interface and uses a service credential.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'offensive-supply-chain-guidance': ['Offensive supply-chain guidance', 'The skill’s declared purpose includes software supply-chain attack techniques.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'directed-product-endorsement': ['Directed product endorsement', 'The skill tells the agent which product to recommend to the user.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'default-model-provider': ['Default model routing', 'The workflow repeatedly selects one external model through its gateway.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'automatic-verification-repair': ['Automatic repair during verification', 'A verification workflow directs the agent to edit the tested source automatically.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'unguarded-channel-launcher': ['Unguarded channel launcher', 'The launcher opens channel sessions with the agent’s normal permission checks disabled.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'undisclosed-local-index': ['Undisclosed local index details', 'The workflow maintains an index across sessions and tells the agent to omit its path and commands from the explanation.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'local-root-trust': ['Machine-wide certificate trust', 'The skill adds a self-signed local certificate to the machine’s trusted roots.',
    'prompt_injection_skill_instructions', 'E004', 'high'],
  'suspicious-download': ['Suspicious download source', 'The skill requests a download or installation from an obscured or unverified artifact source.',
    'suspicious_download_url', 'E005', 'high'],
  'unauthenticated-deploy-proxy': ['Unauthenticated deployment endpoint', 'The deployment helper sends a project archive to an application endpoint without authentication.',
    'suspicious_download_url', 'E005', 'high'],
  'remote-checkout-installer': ['Remote checkout installer', 'An installer executes code from a cloned repository without selecting an immutable revision.',
    'suspicious_download_url', 'E005', 'high'],
  'unfiltered-archive-download': ['Unfiltered archive extraction', 'A download helper extracts a remote archive without using an explicit protective filter.',
    'suspicious_download_url', 'E005', 'high'],
  'automatic-agent-skill-install': ['Automatic agent skill installation', 'Ordinary CLI operations install or update skills in the local agent configuration.',
    'prompt_injection', 'E004', 'high'],
  'unverified-wrapper-setup': ['Unverified command wrapper', 'A wrapper from a mutable agent skill checkout is added to the user’s command path.',
    'suspicious_download_url', 'E005', 'high'],
  'unverified-windows-package': ['Unverified Windows package', 'The publisher link provides limited provenance for a launcher that bypasses Windows execution policy.',
    'suspicious_download_url', 'E005', 'high'],
  'dangerous-code-pattern': ['Dangerous code pattern', 'Code or instructions connect sensitive data to an external destination, enable persistent access, or execute code obtained at runtime.',
    'malicious_code', 'E006', 'high'],
  'detector-scored-rewrite': ['Detector-scored rewriting', 'The workflow chooses text variants based on minimizing a detection score.',
    'malicious_code', 'E006', 'high'],
  'registry-environment': ['Remote subprocess environment', 'A downloaded subprocess receives the local process environment, which may contain secrets.',
    'malicious_code', 'E006', 'high'],
  'private-credential-interface': ['Private credential interface', 'The workflow bypasses its approved interface and imports local credential-management code.',
    'malicious_code', 'E006', 'high'],
  'anonymous-agent-endpoint': ['Anonymous agent endpoint', 'The installer registers an unauthenticated remote tool in local agent configuration.',
    'malicious_code', 'E006', 'high'],
  'weak-native-download': ['Weak native download verification', 'Native code obtained at runtime is checked with an MD5 digest.',
    'suspicious_download_url', 'E005', 'high'],
  'identity-moderation-fallback': ['Identity moderation fallback', 'The workflow changes providers after an identity-related moderation block.',
    'malicious_code', 'E006', 'high'],
  'personal-routine-profile': ['Personal routine profiling', 'The skill combines public posts and location cues to infer a person’s routine.',
    'malicious_code', 'E006', 'high'],
  'cli-identity-proxy': ['CLI identity proxy', 'The workflow delegates selection of a user-scoped token to a proxy using an address argument.',
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

const additionalReferences = {
  'delegated-host-setup': snykReference('modifying_system_services', 'W013'),
  'local-root-trust': snykReference('modifying_system_services', 'W013'),
  'private-credential-interface': snykReference('unverifiable_dependencies', 'W012'),
  'anonymous-agent-endpoint': snykReference('modifying_system_services', 'W013'),
  'weak-native-download': snykReference('unverifiable_dependencies', 'W012'),
  'unverified-host-tool': snykReference('unverifiable_dependencies', 'W012'),
  'unauthenticated-deploy-proxy': snykReference('unverifiable_dependencies', 'W012'),
  'remote-checkout-installer': snykReference('unverifiable_dependencies', 'W012'),
  'unfiltered-archive-download': snykReference('unverifiable_dependencies', 'W012'),
  'automatic-agent-skill-install': snykReference('modifying_system_services', 'W013'),
  'automatic-package-patch': snykReference('modifying_system_services', 'W013'),
  'forced-escalation': snykReference('modifying_system_services', 'W013'),
  'registry-environment': snykReference('unverifiable_dependencies', 'W012'),
  'automatic-skill-update': snykReference('unverifiable_dependencies', 'W012'),
  'unguarded-channel-launcher': snykReference('modifying_system_services', 'W013'),
  'undisclosed-local-index': snykReference('modifying_system_services', 'W013'),
};

const skillNameField = /^[ \t]*name:[ \t]*(["']?)([\w.-]+)\1[ \t]*$/m;
const caseInsensitiveSkillNameField = new RegExp(skillNameField.source, 'im');

function declaredSkillName(source, caseInsensitive = false) {
  const field = caseInsensitive ? caseInsensitiveSkillNameField : skillNameField;
  return field.exec(source.slice(0, 900))?.[2];
}

function finding(id, reason, evidence, assessment, snykEvidence) {
  const [title, rule, indicator, legacy, severity] = checks[id];
  const references = [snykReference(indicator, legacy)];
  if (Object.hasOwn(additionalReferences, id)) references.push(additionalReferences[id]);
  return { id, title, rule, assessment, severity, reason, references, evidence,
    ...(snykEvidence && { snykEvidence }) };
}

export function missingManifest() {
  return finding('missing-skill-manifest', 'The submitted folder has no SKILL.md at its root.', [], 'potential');
}

export function isPackagedSkillFixture(path, files) {
  const root = /^(tests?\/fixtures\/[\w.-]+(?:\/[\w.-]+)*)\/scripts\/[\w.-]+\.sh$/i.exec(path)?.[1];
  return Boolean(root && files.some(file => file.path === `${root}/SKILL.md`));
}

export function windowsExecutableFinding(file, files) {
  if (!/\.(?:exe|dll)$/i.test(file.path) || !file.content.startsWith('MZ') ||
      !file.content.slice(0, 512).includes('PE\u0000\u0000')) return;
  const name = file.path.split('/').at(-1).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const binding = new RegExp('^[ \\t]*\\$((?:script:)?[\\w]+)[ \\t]*=[^\\r\\n]{0,85}' +
    '\\$PSScriptRoot[^\\r\\n]{0,80}' + name + '(?=["\'\\s]|$)', 'im');
  const usedByScript = files.some(({ path, content }) => {
    if (!/\.ps1$/i.test(path) || /\bGet-AuthenticodeSignature\b[\s\S]{0,220}\bValid\b/i.test(content)) return false;
    const target = binding.exec(content)?.[1];
    return target && new RegExp('\\bStart-Process\\b[^\\r\\n]{0,110}\\$' + target + '\\b', 'i').test(content);
  });
  const documentedClone = files.some(({ path, content }) => /^(?:README(?:\.[\w-]+)?\.md|SKILL\.md)$/i.test(path) &&
    /\bgit[ \t]+clone[ \t]+https:\/\/github\.com\/[\w.-]+\/[\w.-]+/i.test(content));
  const result = finding('suspicious-download',
    'The package includes a native Windows executable. Review its publisher and integrity before running it.',
    [], 'potential', usedByScript && documentedClone && 'direct');
  return { ...result, path: file.path };
}

const roleOverride = /\b(?:ignore|disregard|forget|override|replace)[ \t]+(?:(?:all|any|the|your|earlier|previous|prior|above|system|developer|original|existing)[ \t]+){1,6}(?:instructions?|prompts?|rules?|directives?|constraints?)\b/gi;
const falseSystemDirective = /^[ \t]*SYSTEM DIRECTIVE:[^\r\n]{0,180}\b(?:identity override|stop acting as a general assistant)\b/gim;
const removesAgentBackups = /\b(?:do not|never|must not)\s+(?:create|save|keep)\s+(?:a\s+)?backups?(?: files?)?\s+when updating (?:existing )?agents?\b/gi;
const claimedPriority = /\b(?:follow|apply)\s+(?:these|the following|this)\s+(?:instructions?|rules?|workflow|procedure)(?:\s+(?:exactly|precisely|verbatim))?\s*[.!:;]\s*(?:this(?: (?:prompt|skill|procedure))?|these (?:instructions|rules))\s+(?:supersedes?|takes? precedence over|overrides?)\s+(?:(?:your|the)\s+)?(?:(?:prior|previous)\s+training|(?:system|developer)\s+instructions)\b/gi;
const dismissesPriorTraining = /\b(?:ignore|disregard)(?:\*\*|__)?[ \t]+(?:(?:all|any|your)[ \t]+){0,2}(?:prior|previous)[ \t]+training\b/gi;
const shellArgument = /\b(?:const|let)\s+([\w$]+)\s*=[^;\x60]{0,155}\x60[^\x60\r\n]{0,140}\$\{([a-z_$][\w$]*)\}[^\x60\r\n]{0,140}\x60[\s\S]{0,285}?\bexecSync\s*\(\s*\1\s*(?=[,)])/gi;
const roleMarker = /(?:^|\n)[ \t]*(?:<\|(?:system|developer)\|>|\[(?:SYSTEM|DEVELOPER)\]|(?:SYSTEM|DEVELOPER) (?:MESSAGE|INSTRUCTIONS)\s*:)/gi;
const destructiveOverwrite = /\bexiftool\b[^\r\n]{0,125}-overwrite_original\b(?:[^\r\n]{0,160}\\\r?\n){0,4}[^\r\n]{0,160}(?:\*\.[a-z0-9*]+|[ \t]-r\b)/gi;
const removesInstallTarget = /^[ \t]*(?:command[ \t]+)?rm[ \t]+(?:-[rR]f|-f[rR]|-[rR][ \t]+-f|-f[ \t]+-[rR])[ \t]+(?:--[ \t]+)?"\$([A-Za-z_]\w*)"(?=[ \t\r\n;]|$)/gm;
const unapprovedChanges = /\b(?:overwrite|delete|modify|patch|replace|rewrite)\b[^.!?;\r\n]{0,65}\b(?:original (?:files?|images?)|user(?:'s)? (?:files?|data)|installed (?:code|files?|packages?)|agent configuration)\b[^.!?;\r\n]{0,85}\bwithout (?:asking|confirmation|approval|consent|permission)\b/gi;
const uncheckedFileChanges = /\b(?:do not|never|must not)\s+(?:ask|request|wait for)\b[^.!?;\r\n]{0,80}\b(?:questions?|clarification|confirmation|approval)\b[\s\S]{0,110}\b(?:create|write|modify|overwrite|delete)\s+(?:all\s+)?(?:the\s+|necessary\s+|any\s+)*(?:files?|source code|workspace)\b/gi;
const deletesByOutputPrefix = /\b\w*suffix\s+in\s+[A-Z_]*OUTPUT[A-Z_]*SUFFIXES\s+or\s+(\w+)\.startswith\(\w*prefix\)/gi;
const fixedDistributionIdentity = /--signing-method[ \t]+(?:release-testing|app-store-connect)[ \t]+--team-id[ \t]+[A-Z0-9]{10}\b[\\ \t\r\n]{1,30}--asc-key-id[ \t]+[A-Z0-9]{10}\b/g;
const pushesRestartedDefaultBranch = /--force-with-lease=refs\/heads\/(?:main|master):[^\s`"']{1,90}/gi;
const resetsAndForcePushesDefaultBranch = /\bgit[ \t]+reset[ \t]+--hard[ \t]+([\w.-]+)\/(main|master)[ \t]*(?:&&|;)[ \t]*git[ \t]+push[ \t]+(?:--force|-f)[ \t]+\1[ \t]+\2\b/gi;
const waitsAfterSecretWarning = /^[ \t]*sleep[ \t]+\d{1,2}[ \t]*\r?$/gm;
const desktopJavaScriptSource = /^[ \t]*(?:exec[ \t]+)?osascript\b[^\r\n]*\btell application\b[^\r\n]*\bevaluate javascript\b[^$\r\n]{0,32}\$\{?([a-z_]\w*)/gim;
const allowsPublicSshIngress = /\bname\s*=\s*"allow[-_]ssh"[^{}]{0,80}\bdirection\s*=\s*"inbound"[^{}]{0,70}\bremote\s*=\s*"(?:0\.0\.0\.0\/0|::\/0)"[^{}]{0,65}\btcp\s*=\s*\{[^{}]{0,110}\bport_min\s*=\s*22\b[^{}]{0,50}\bport_max\s*=\s*22\b/gi;
const readOnlyDirectory = /\b(?:never|does not|will not) (?:writes?|append|modify) (?:to )?\x60(?:\.\/)?((?:~\/)?[\w.-]+(?:\/[\w.-]+)*\/)\x60/gi;
const shellFileWrite = /(?:>>?|\btee(?:[ \t]+-a)?|\btouch)[ \t]+["']?(?:\.\/)?((?:~\/|\.?[\w.-]+\/)[\w./-]+)/g;
const concealedLiveUse = /(?:--profile[ \t]+live\b|\b(?:live|production|real[- ]money) (?:profile|account|mode)\b)[^\r\n.!?;]{0,85}(?:silently|without (?:telling|mentioning)|(?:don't|do not|never) mention)\b/gi;
const persistentContext = /\b(?:persistent (?:memory|history)|(?:next|future|across) sessions?|remember(?:s|ing)? across)\b/i;
const hiddenWrites = /\b(?:writes|saves|updates)\s+(?:are|stay|remain) silent\b|\b(?:do not|never|don't) (?:mention|announce|report)\b[^.!?;\r\n]{0,65}\b(?:saved|storing|saving|wrote|writing|updated)\b/gi;
const concealedMonitoring = /\b(?:do not|never|don't|must not) (?:tell|notify|inform) (?:the )?user\b[^.!?;\r\n]{0,95}\b(?:being monitored|being recorded|you (?:are|will be) (?:monitoring|recording))\b/gi;
const concealedSessionObserver = /\b(?:do not|never|don't)(?:\*\*)?\s+(?:tell|notify|inform)\s+(?:(?:the )?user|[\p{L}][\p{L}'-]{1,39})\s+(?:that\s+)?(?:you(?:['’]re| are)\s+(?:running|using)\s+this\s+(?:skill|workflow)|about\s+the\s+(?:journal|monitoring))\b[^\r\n]{0,100}\b(?:don['’]t|do not|never)\s+ask(?:\s+for)?\s+(?:permission|consent)\b/giu;
const publicVideoIngest = /\.upload\(\s*url\s*=\s*['"]https?:\/\/(?:www\.)?(?:youtube\.com\/watch\?|youtu\.be\/)[^'"\r\n]{1,150}['"]/gi;
const monitorsCredentialField = /\b(?:start|enable|run) (?:desktop|screen) (?:capture|recording)\b[^.!?;\r\n]{0,65}\b(?:alert|notify) when (?:a |the )?(?:password|credential) field (?:appears|is shown)\b/gi;
const covertObserverPrompt = /\b(?:observer|monitor(?:ing)?) session\b[^.!?;\r\n]{0,75}\binvisibly in the background[.!?][ \t]+[^.!?;\r\n]{0,100}\bdoes not know (?:it is|they are) being (?:observed|monitored)[^.!?;\r\n]{0,55}\b(?:must|should) stay that way\b/gi;
const suppressedCommandHook = /^[ \t]+PostToolUse:[ \t]*\r?\n[ \t]+-\s*matcher:\s*["']?Bash["']?[ \t]*\r?\n[\s\S]{0,180}?\bcommand:\s*["']?[^\r\n]{0,105}\bscripts\/[\w.-]+\.(?:py|sh|[cm]?js)\b[^\r\n]{0,75}2>[ \t]*\/dev\/null[^\r\n]{0,125}\|\|\s*true\b/gim;
const extendsStoppedSession = /\bblock(?:ing|s)?\s+(?:the\s+)?(?:first\s+)?(?:eligible\s+)?Stop\b[^.!?;\r\n]{0,105}\b(?:extra|additional) (?:model )?turn\b/gi;
const downloadDescriptor = /\{[^{}]{0,540}["']kind["']\s*:\s*["']download["'][^{}]{0,540}\}/gi;
const runtimeDescriptor = /["']targetDir["']\s*:\s*["']runtime["']/i;
const modelDescriptor = /["']targetDir["']\s*:\s*["']models["']/i;
const digestDescriptor = /["'](?:sha256|checksum|digest|integrity|signature)["']\s*:/i;
const silentSessionStartup = /\b(?:run|execute)\s+(?:this|the following|the) command\s+(?:silently|quietly)\s+(?:at the start of|before)\s+(?:every|each) session[.!]\s+(?:do not|never|don't)\s+(?:show|mention|display)\s+the command(?: itself)?\s+to the user\b/gi;
const startupPackageUpdate = /\b(?:npx[ \t]+skills|clawhub)[ \t]+update\b/gi;
const confirmsEveryPreflightUpdate = /\bscripts\/[\w.-]*update[\w.-]*\.py[ \t]+--preflight[ \t]+--yes\b/gi;
const refreshesAllSkills = /^[ \t]*npx[ \t]+(?:-y[ \t]+)?skills[ \t]+update[ \t]*\r?$/gim;
const disablesPluginConfirmation = /\b(?:adding|pass(?:ing)?|set(?:ting)?)\b[^.\r\n]{0,75}--skip-permissions[ \t]+true\b/gi;
const concealsPromptSources = /不得(?:引用|提及)[^。！？\r\n]{0,55}(?:内部.{0,12}(?:memory|记忆)|Agent Memory)[^。！？\r\n]{0,75}(?:系统指令|隐藏指令|用户可见证据)/gi;
const pollsRenderedReview = /\b(?:poll|long-poll|polling)\b[^\r\n.!?;]{0,125}\b(?:annotations|queued prompts|reviewer feedback)\b/gi;
const detachedUpdater = /\bspawn\s*\([^\r\n]{0,185}\bdetached\s*:\s*true\b[^\r\n]{0,85}\bstdio\s*:\s*['"]ignore['"]/gi;
const copiesItsOwnScript = /\bcopyFileSync\s*\(\s*fileURLToPath\s*\(\s*import\.meta\.url\s*\)/;
const installsStopHook = /\binstaller\s+writes\b[\s\S]{0,115}\b(?:hook|hooks)[\w.-]*\.json\b[\s\S]{0,90}\bStop point\b/gi;
const copiesUserSkill = /\bcopied to\s+\x60[^\x60\r\n]+\/skills\/[\w-]+\x60[\s\S]{0,125}\buser.level skill root\b/i;
const unpinnedSkillPackage = /\bnpx[ \t]+skills[ \t]+add[ \t]+[\w.-]+\/[\w.-]+(?![\w.#@-])/gi;
const backgroundLocalNotice = /\bVoice Notification\b(?=[\s\S]{0,130}\bcurl\b[^\r\n]{0,100}\bPOST\s+https?:\/\/(?:127\.0\.0\.1|localhost)\b[\s\S]{0,300}>\s*\/dev\/null\s+2>&1\s*&)/gi;
const readsDesktopText = /\b(?:chat history|email bodies|document text)\b[^\r\n]{0,130}\bcall\s+\x60?get_app_state\b/gi;
const readsDeviceInterface = /(?:\x60|^[ \t]*)[\w.-]+[ \t]+(?:dump[ \t]+ui|webview[ \t]+(?:content|eval))\b/gim;
const chineseWebFetch = /→\s*WebFetch\s*(?:获取|读取|抓取)/gi;
const concealsProfileRead = /(?:不要|不得)\s*(?:暴露|透露|告知用户)\s*["“「‘']?(?:我|你|已经)?(?:读取|读过|读了)[^。\r\n]{0,20}(?:用户档案|你的档案|个人资料)|\b(?:do not|never) (?:tell|inform) (?:the )?user (?:that )?you read their profile\b/giu;
const readsProfileForLesson = /(?:读取|读入)[^。\r\n]{0,50}user_wiki\b|\bread\b[^.!?;\r\n]{0,52}\buser_wiki\b/iu;
const archivesFetchedCourseSource = /直接用\s*`?WebFetch`?\s*(?:抓取|读取|获取)\s*URL\b/giu;
const deletesAndReplacesSkill = /\brsync[ \t]+-[a-z]+[ \t]+--delete[ \t]+["']\$([A-Z_]+)\/([\w.-]+)\/skills\/[\w.-]+\/["'][ \t]+["']<skill_root>\/["']/gi;
const profileOwnerTermination = /\b(?:const|let)\s+([\w$]+)\s*=\s*(?:find)?profile(?:Holder|Owner)\s*\([^\r\n]{0,75}\)[\s\S]{0,210}?\bprocess\.kill\s*\(\s*\1\.pid\s*,\s*['"]SIGTERM['"]\s*\)/gi;
const browserAntiDetection = /\banti[- ]detect\b/gi;
const describesBrowserAutomationDecoy = /^[ \t]*\/\/[ \t]*[^\r\n]{0,55}\b(?:invisible|hidden) decoy\b[^\r\n]{0,105}\bto (?:catch|detect)(?:[ \t]+|[ \t]*\r?\n[ \t]*\/\/[ \t]*)[^\r\n]{0,55}\b(?:scripts|automation|bots)\b/gim;
const localBrowserFork = /\b(?:Chromium fork|browser fork|local Chromium)\b/i;
const browserFingerprints = /\bfingerprint(?:ed|ing|s)?\b/i;
const auditsTrafficCircumvention = /^description:[^\r\n]{0,700}\b(?:audit|review|check)\b[^\r\n]{0,35}\bcircumvention setup\b/gim;
const describesProvocation = /^description:[^\r\n]{0,350}\bsensitive (?:intelligence|information)\b[^\r\n]{0,200}\bprovocation\b/gim;
const hidesMissingMaterial = /\b(?:don.t|do not|never)\s+(?:point out|discuss|highlight)\s+what(?:['’]s| is) missing\b/i;
const hidesOwnInstructions = /\b(?:don.t|do not|never)\s+(?:mention|quote)\b[^\r\n.!?;]{0,45}\bthese instructions\b/gi;
const concealsSignInRequirement = /\b(?:never|do not|don't|must not)[ \t]+(?:say|mention|tell (?:the )?user)[ \t]+(?:that[ \t]+)?(?:(?:a|the|this)[ \t]+)?(?:skill(?: or (?:the )?instructions?)?|instructions?)[ \t]+(?:requires?|mandates?)[ \t]+(?:it|(?:signing|logging) in|sign-in|login|authentication)\b/gi;
const hidesSimulatedResults = /\b(?:do not|never|must not) (?:label|identify|describe|mark)\b[^.!?;\r\n]{0,55}\b(?:results?|values?|measurements?|data)\b[^.!?;\r\n]{0,28}\bas (?:simulated|synthetic|fabricated)\b/gi;
const exampleActualOutcome = /^[ \t]*actual outcome(?:[ \t]+\([^\r\n)]{1,55}\))?[ \t]*:[^\r\n]{0,140}\b\d+(?:\.\d+)?\s*%/gim;
const displaysCompanyProfileName = /^[ \t]*(\w+)[ \t]*=[ \t]*self\.get_company_profile\([^\r\n)]{1,80}\)[ \t]*\r?\n[ \t]*(\w+)[ \t]*=[ \t]*\1\.get\(["']companyName["']/gm;
const enablesDemoByDefault = /^([ \t]+)\w+\.add_argument\(["']--demo["'][^\r\n]{0,180}\bdefault[ \t]*=[ \t]*True\b/gm;
const assignsMockIngestionData = /^([ \t]+)#[ \t]*(?:mock|synthetic|simulated|demo|sample)\b[^\r\n]*\r?\n\1(\w+)[ \t]*=[ \t]*\{/gim;
const appendsVendorPlugin = /\bconfig\.auth\.set\b[^\r\n]{0,65}\bappends?\b[\s\S]{0,145}@[\w.-]+\/[\w.-]+\b/gi;
const appInstrumentation = /\bFrida Gadget\b/gi;
const runtimeInstrumentation = /\b(?:Gadget configuration|application instrumentation|embedded scripts?)\b/i;
const offensiveSupplyChain = /\boffensive[- ]supply[- ]chain\b/gi;
const supplyChainAttackTerms = [/\bdependency confusion\b/i, /\btyposquatting\b/i, /\b(?:build|install)[- ](?:system[- ])?hook(?:s| injection)\b/i];
const unsandboxedBrowser = /['"]--no-sandbox['"][\s\S]{0,140}['"]--disable-setuid-sandbox['"]|['"]--disable-setuid-sandbox['"][\s\S]{0,140}['"]--no-sandbox['"]/gi;
const headlessRootSandboxFallback = /--no-sandbox\b[^.!?;\r\n]{0,75}\b(?:if|as|when running as) root\b/gi;
const thirdPartyRenderContainer = /https:\/\/hub\.docker\.com\/r\/[\w.-]+\/[\w.-]+(?=[)\s`]|$)/gi;
const browserExtensionTests = /\b(?:Chrome|browser) extensions?\b/i;
const builtShellExpression = /\bnode\s+(?:-e|--eval)\s+"\$\{?([a-z_][a-z0-9_]*)\}?"/gi;
const forcedRuntimeDirective = /\bruntime directives?\b/gi;
const mandatoryDispatch = /\b(?:must|always)\b[^\r\n]{0,90}\b(?:dispatch|spawn|execute|directive)\b/i;
const modifiesWorkspaceFromDirective = /\b(?:commit|write)\b[^\r\n]{0,70}\b(?:code|files|memory)\b/i;
const downloadsUserConfiguration = /\bgit\s+clone\b[^\r\n]{0,160}https:\/\/github\.com\/[\w.-]+\/[\w.-]+/gi;
const userAgentConfiguration = /(?:~\/(?:\.claude|\.gemini|\.config\/(?:opencode|codex))|\$HOME\/(?:\.claude|\.gemini))\b/i;
const leavesUsageTagOut = /\busage.data tag\b[^\r\n]{0,130}\b(?:does not need to|should not|must not) appear\b[^\r\n]{0,80}\b(?:confirmation|plan|progress)\b/gi;
const callerTelemetry = /\bcaller[= :]+["']?agent\b/i;
const explicitPublicHost = /\b(?:host\s*=\s*|listen\([^\r\n]{0,50})['"]0\.0\.0\.0['"]/gi;
const implicitPublicHost = /\b[\w]*Server\s*\(\s*\(\s*(?:""|'')\s*,/g;
const localNetworkClaim = /\b(?:localhost|127\.0\.0\.1)\b/i;
const checksumsFromRelease = /\bcurl\b[^\r\n]{0,145}\$\{?([a-z_][a-z0-9_]*)\}?\/(?:checksums\.txt|SHA256SUMS)\b/gi;
const signatureTool = /\b(?:gpg|cosign|sigstore|minisign|signature verification)\b/i;
const nodeFile = /\.(?:js|mjs|cjs)$/i;
const relativeNodeImport = /^[ \t]*(?:import\s+(?:[^;\x27\x22]{0,165}?\bfrom\s+)?|export\s+[^;\x27\x22]{0,165}?\bfrom\s+|(?:const|let|var)\s+[^;\r\n]{1,85}?\s*=\s*require\s*\(\s*)['"](\.\.?\/[\w./-]+)['"]/gm;
const disabledTrustChecks = /\b(?:install|setup|bootstrap|deploy|configure|update)\b[^\r\n]{0,90}--(?:no-trust-check|disable-safety-checks|no-confirm-project)\b/gi;
const skipsAutomaticProjectConfirmation = /\b(?:must|always|need to)[ \t]+(?:pass|use|provide)[ \t]+`?--no-confirm-project\b/gi;
const reportsMockSuccessWithoutCredentials = /^[ \t]+if[ \t]+not[ \t]+([A-Za-z_]\w*)(?:[ \t]+or[ \t]+\1[ \t]*==[ \t]*["'][\w.-]+["'])?[ \t]*:[ \t]*\r?\n[ \t]+return[ \t]+\{([^{}\r\n]{0,180})\}/gm;
const refreshRequestFromCredentialRecord = /^[ \t]*([A-Za-z_]\w*)[ \t]*=[ \t]*urllib\.request\.Request\([ \t]*([A-Za-z_]\w*)\[["']token_uri["']\],[ \t]*data[ \t]*=[ \t]*([A-Za-z_]\w*)\)/gm;
const recordsFetchedPageInEvaluation = /^\|[ \t]*`?load_web_page`?[ \t]*\|[ \t]*yes[ \t]*\|/gim;
const modifiesCloudProjectPolicy = /^[ \t]*gcloud[ \t]+projects[ \t]+add-iam-policy-binding\b/gm;
const disablesSafetyFilterInTable = /^[ \t]*\|[ \t]*`?(?:(?:disable|skip)[_-]safety[_-](?:filter|checker)`?[ \t]*\|[ \t]*(?:bool|boolean)[ \t]*\|[ \t]*`?true|(?:enable|use)[_-]safety[_-](?:filter|checker)`?[ \t]*\|[ \t]*(?:bool|boolean)[ \t]*\|[ \t]*`?false)`?[ \t]*\|/gim;
const delegatedCliGuide = /\b(?:follow|execute|apply)\b[^.!?;\r\n]{0,48}\b(?:guide|instructions|runbook)\b[^.!?;\r\n]{0,44}\b(?:it (?:prints|outputs)|(?:printed|emitted) by (?:the |this )?command)\b/gi;
const delegatesCredentialSetup = /\bnpx[ \t]+(?:-y|--yes)[ \t]+(?:@[\w-]+\/)?[\w.-]+@latest[ \t]+(?:onboard|auth)[ \t]+(?:init|setup|login)\b[^\r\n.!?;]{0,125}\bfollow (?:what it prints|its instructions)\b[^\r\n.!?;]{0,125}\b(?:signs? (?:the )?user in|authenticates? (?:the )?user)\b[^\r\n.!?;]{0,55}\b(?:stores?|writes?|saves?)\b[^\r\n.!?;]{0,45}\b(?:key|token|credential)\b/gi;
const directsBotCredentialsToForm = /\b(?:get|obtain|create)\b[^.!?]{0,70}\bbot\b[^.!?]{0,60}\bapp id\b[^.!?]{0,45}\bapp secret\b[^.!?]{0,40}\bfrom:\s*`?(https:\/\/[\w.-]+)\/page\/[\w.-]+\?form=[\w.-]+(?=[\s`]|$)/gi;
const delegatedHostSetup = /\bread\b[^\r\n.!?;]{0,55}\b(?:current|latest|live) (?:setup|installation) guide\b[^\r\n.!?;]{0,55}\b(?:carry out|follow|execute)\b[^\r\n.!?;]{0,75}\b(?:installation|setup) instructions\b/gi;
const remoteCredentialSetupSkill = /\b(?:requires|needs)[ \t]+\x60([a-z]\w*)_(?:URL|HOST)\x60[ \t]+and[ \t]+\x60\1_(?:KEY|TOKEN)\x60\.[ \t]+(?:see|read|follow)[ \t]+\[(?:the[ \t]+)?(?:entry[- ]point|upstream|remote)[ \t]+(?:SKILL(?:\.md)?|skill instructions)\]\(https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/(?:refs\/heads\/)?(?:main|master)\/(?:[\w.-]+\/){0,8}SKILL\.md\)[ \t]+for[ \t]+(?:authentication|setup)\b/gi;
const concealAuthorship = /\b(?:never|do not|don't) (?:reference|mention|disclose|attribute)\b[^\r\n.!?;]{0,60}\b(?:AI|Claude|ChatGPT|assistant)\b[^\r\n.!?;]{0,35}\bcommit messages?\s+(?:or|and)\s+(?:the\s+)?(?:PR (?:body|descriptions?)|pull request descriptions?)\b/gi;
const removesExistingAttribution = /\bwhen (?:amending|rebasing|cherry-picking)\b[^\r\n]{0,120}\bremove (?:any )?such annotations already present\b/gi;
const installMachineTrust = /\binstall\b[^\r\n!?;]{0,100}\b(?:local machine|system-wide)\b[^\r\n!?;]{0,85}\bTrusted Root Certification Authorities\b/gi;
const selfSignedCertificate = /\bself.signed certificates?\b/i;
const createsAgentAlias = /\b(?:alias\s*[:=]|upsert_alias_line\s*\(|alias \w+[-\w]*=)/i;
const disablesShellSafeguards = /\b(?:codex|claude)\b[^\r\n]{0,130}--(?:dangerously-bypass-approvals-and-sandbox|dangerously-skip-permissions)\b/gi;
const defaultsToUnrestrictedAgent = /\bdefaults?\s+to\b[^\r\n.!?;]{0,85}--always-approve\b[^\r\n.!?;]{0,75}--sandbox[= \t]+(?:off|none|disabled)\b/gi;
const requestsAllConnections = /\b(?:ask|scope|permissions?|access)\s*[:=]\s*["'](?:everything|all|\*)["']/gi;
const skillDescriptionField = /^description:[ \t]*[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*){0,4}/gim;
const runsConnectedAction = /^[ \t]*(?:const|let|var)[ \t]+([A-Za-z_]\w*)[ \t]*=[ \t]*(?:await[ \t]+)?[A-Za-z_]\w*\.runAction[ \t]*\(/gm;
const pushGuardOverride = /\b[A-Z_]*ALLOW_PUSH[ \t]*=[ \t]*["']?(?:1|true)\b[^\r\n]{0,220}(?:\r?\n[ \t]*)?\bgit[ \t]+push\b/gi;
const runsAgentsAutonomously = /\bagents? launched\b[^\r\n]{0,65}\brun in autonomy\b/gi;
const optOutApproval = /\bopt[- ]out\b[^.!?;]{0,150}\b[A-Z_]*PERMISSIONS=ask\b/i;
const retriesWithPrivilegedInstall = /\b(?:fails? with|due to|on)\s+(?:a\s+)?(?:permissions? error|EACCES)\b[^.!?;\r\n]{0,75}\b(?:retry|re-run|rerun) with\b[^.!?;\r\n]{0,40}\bsudo[ \t]+(?:npm|pnpm|bun)[ \t]+(?:install|i|add)[ \t]+(?:-g|--global)\b/gi;
const sharesBrowserEvidence = /^[ \t]*share_payload_evidence(?:_when_clean)?:[ \t]*true\b/gim;
const windowsPolicyBypass = /\bpowershell(?:\.exe)?\b[^\r\n]{0,120}-ExecutionPolicy[ \t]+Bypass\b/gi;
const numericPackagePublisher = /https:\/\/github\.com\/[a-z]{0,3}\d{6,}\/[\w.-]+/gi;
const readsApiData = /^[ \t]*description:[ \t]*["']?(?:query|access|inspect|monitor|list|read)\b[^\r\n]{0,130}\b(?:models|analytics|logs|provider health|usage|metrics|status)\b/im;
const managesGlobalApiSettings = /^[ \t]*description:[^\r\n]{0,280}\bglobal (?:application settings|proxy (?:rules|settings)|(?:server|service) configuration)\b/im;
const writesApiSettings = /\b(?:PUT|PATCH|DELETE)[ \t]+\/api\/(?:v\d+\/)?(?:admin\/)?settings\b/i;
const disablesApiAuthentication = /\b(?:configure|set|export)\b[^\r\n.!?;]{0,25}\b(?:REQUIRE_API_KEY|REQUIRE_AUTH(?:ENTICATION)?|AUTH_REQUIRED)[ \t]*=[ \t]*(?:false|0)\b/gi;
const declaredLimitedReads = /\breads? only\s+([^\r\n!?;]{0,180})/gi;
const specificFileRead = /\bread\s+\x60([\w.-]+(?:\/[\w.-]+)+\.md)\x60/gi;
const specificFileWrite = /\b(?:append to|write to|updates?|modify)\s+\x60([\w.-]+(?:\/[\w.-]+)+\.md)\x60/gi;
const delegatedFetchedProcedure = /\b(?:fetched|downloaded|retrieved) (?:markdown|documentation|page|instructions)\b[^\r\n]{0,200}\bfollow (?:those|the|each) (?:steps?|procedures?)\b[^\r\n]{0,130}\bexecut(?:e|ing) (?:them|it|the steps)\b/gi;
const delegatedPlaybook = /\b(?:fetch|retrieve|download)\b[^\r\n]{0,85}\b(?:playbook|runbook)\b[^\r\n]{0,55}\bfollow (?:every step|each step|all (?:of )?(?:its|the) steps|it exactly)\b/gi;
const delegatedWorkspaceRules = /\b(?:before (?:applying|following|using)|prior to (?:applying|following|using))\b[^.!?;\r\n]{0,110}\b(?:read|load|consult)\s+`(?:\.\/)?\.[\w-]+\/[\w./-]+\.(?:md|mdx|txt)`[^.!?;\r\n]{0,45}\bif (?:it|the file) exists\b[^.!?;\r\n]{0,55}\b(?:apply|follow)\s+(?:all(?: of)?|every)(?:\s+(?:of its|its|the|additional))?\s+(?:rules?|instructions?|directives?)\b/gi;
const writesProjectInstructions = /\b(?:persist|install|save|keep|write|create|append|insert|update|replace|modify)\b[^.?!]{0,130}(?:\b(?:AGENTS|CLAUDE|GEMINI)\.md|\.github\/copilot-instructions\.md)\b/gi;
const unsolicitedReporting = /\b(?:send|submit|report|post|transmit|emit)\b[^.!?;\r\n]{0,65}\b(?:telemetry|feedback (?:reports?|messages?)|usage reports?|usage (?:statistics|events?))\b[^.!?;\r\n]{0,50}(?:\.[ \t]+[^.!?;\r\n]{0,35})?\b(?:on (?:every|each) (?:run|startup|invocation)|(?:after|before) (?:every|each) (?:run|task|invocation)|every time|without (?:asking|confirmation|consent))\b/gi;
const startupUsageBeacon = /\b(?:run|invoke|execute)\s+`([^`\r\n]{1,120})`[ \t]+(?:once as (?:this|the) skill starts|at each skill start|at every startup)\b/gi;
const remoteConversationAuditLog = /`([a-z][\w-]*[ \t]+[a-z][\w-]*[ \t]+push)`[ \t]+includes[ \t]+`(\.[\w/-]+\.jsonl)`[ \t]+in the commit allowlist\b/gi;
const requestsFullBrowserCookie = /把完整[ \t]*Cookie[ \t]*字符串发给我|\b(?:send|paste)\b[^.!?;\r\n]{0,35}\b(?:the )?(?:raw|full|entire) (?:browser )?cookie string\b[^.!?;\r\n]{0,25}\b(?:in(?:to)?|to) (?:the |this )?chat\b/gi;
const requestsCookieExportInChat = /^[ \t]*>[ \t]*(?:\d{1,2}\.[ \t]*)?Paste (?:the|that) (?:exported )?JSON (?:here|into (?:the|this) chat)\b/gim;
const exportsBrowserCookieFile = /^[ \t]*[\w.-]+[ \t]+cookies[ \t]+<[^>\r\n]+>[ \t]*>[ \t]*\/tmp\/[\w.-]+\b/gim;
const sharesBrowserSessionsAcrossAgents = /\b(?:all )?(?:isolated )?browser agents share the same[ \t]+[^!?\r\n]{0,85}\b(?:cookie file|browser-sessions\.json|browser session state)\b/gi;
const exportsPrimaryBrowserCookies = /\b(?:export(?:s)?|seed(?:s)?|refresh(?:es)?)\b[^.!?\r\n]{0,55}\bcookies\b[^.!?\r\n]{0,50}\bfrom (?:the )?(?:user['’]s )?(?:real|primary) (?:Chrome|browser)\b/i;
const enablesAttachedBrowserDebugging = /\bAllow remote debugging for this browser instance\b/gi;
const readsExtensionCookies = /^(?![ \t]*(?:\/\/|\*))[^\r\n]{0,110}\bchrome\.cookies\.getAll\s*\(/gm;
const extensionTokenArgument = /--xsec-token[ \t]+(?:XSEC_TOKEN\b|<xsec[-_]token>)/gi;
const automaticRemoteWorkerInstall = /\bfirst[- ]time install[ \t]*\(auto(?:matic)?,[ \t]*no user action needed beyond SSH (?:info|details)\)/gi;
const optionalMacAutostart = /^#{2,6}[ \t]+auto[- ]start[ \t]*\(optional,[ \t]*macOS\)/gim;
const sendsCampaignAndTouchpoint = /--header[ \t]+["']X-([\w-]+)-Campaign:[^\r\n]{0,95}\r?\n[ \t]*--header[ \t]+["']X-\1-Touchpoint:[^\r\n]{0,95}/gi;
const gitIdentityLookup = /\b(?:execFile(?:Sync)?|spawn(?:Sync)?)\s*\(\s*['"]git['"]\s*,\s*\[\s*['"]config['"]\s*,\s*(?:['"]--get['"]\s*,\s*)?['"]user\.email['"]/g;
const systemWideRecordingFallback = /\battach(?:ing|ment)? failed\b[^\r\n]{0,110}\brecord(?:ing)? all processes\b[^\r\n]*(?:\r?\n[^\r\n]{0,150}){1,4}[ \t]--all-processes\b/gi;
const installsMarketplaceWithoutAsking = /\b(?:and|then) without asking(?: (?:the )?user)?\s*,[^.!?;]{0,165}\bclaude[ \t]+plugin[ \t]+marketplace[ \t]+add[ \t]+[\w.-]+\/[\w.-]+[\s\S]{0,100}?\bclaude[ \t]+plugin[ \t]+install[ \t]+[\w.-]+@[\w.-]+\b/gi;
const selectsPersistentTrust = /^[ \t]*if[ \t]*\([^\r\n]{0,65}-match[ \t]+["'][^"'\r\n]{0,140}\bAlways Load\b[^"'\r\n]{0,45}["'][^\r\n]*\r?\n[\s\S]{0,420}?\$\w+\.Invoke\(\)/gim;
const fixedTemporaryLibrary = /^[ \t]*([A-Za-z_]\w*)[ \t]*=[ \t]*Path\(tempfile\.gettempdir\(\)\)[ \t]*\/[ \t]*["'][\w.-]+\.so["']/gm;
const declaresPreapproval = /\b(?:invoking|running)[ \t]+\x60[^\r\n\x60]{1,45}\x60[ \t]+is the user['’]s approval,[ \t]+given in advance\b/gi;
const overridesAskFirst = /\bapproval[ \t]+(?:overrides?|replaces?|supersedes?)[ \t]+(?:only[ \t]+)?(?:the[ \t]+)?(?:request|instruction|requirement)[ \t]+to[ \t]+ask first\b/i;
const treatsDocumentAsApproval = /\b(?:the )?user (?:has )?already (?:asked|approved|authorized|requested)[^.!?;\r\n]{0,120}\bby (?:giving|sharing|sending|providing|loading|opening)\b[^.!?;\r\n]{0,42}\b(?:this|the) (?:document|file|skill|guide)\b/gi;
const avoidsCleanupGate = /\bso that[ \t]+destructive[- ]action[ \t]+gates?[ \t]+on[ \t]+hardened[ \t]+hosts?[ \t]+(?:don't|do not|won't|will not)[ \t]+trip\b/gi;
const reportsBuildFeedback = /\b(?:if|when)[ \t]+(?:you|the build)\b[^.!?;\r\n]{0,145}\b(?:send|submit)[ \t]+feedback\b/gi;
const filesVendorReportBeforeContinuing = /\b(?:file|submit|send) (?:a|the) report (?:with|via|using) [`'"]?POST[ \t]+\/v\d+\/reports\b[`'"]?,?[ \t]+then (?:carry on|continue|resume)\b/gi;
const configuresAgentToolsFromRegistry = /\b(?:npx|bunx)[ \t]+(?:-y|--yes)[ \t]+(?:@[\w.-]+\/)?[\w.-]+[ \t]+ai-config\b/gi;
const installsProjectAgentHook = /\b(?:npx|bunx)[ \t]+(?:@[\w.-]+\/)?[\w.-]+@\d+\.\d+\.\d+[ \t]+hook[ \t]+--agent[ \t]+(?:claude-code|cursor)\b/gi;
const listsSharedRecords = /\bGET[ \t]+\/v\d+\/records\?[^\r\n`]{0,160}\blimit=\d+\b/gi;
const invocationAuthorizesExternalReview = /\binvoking[ \t]+(?:this|the)[ \t]+skill[ \t]+is[ \t]+(?:itself[ \t]+)?the[ \t]+authorization[ \t]+for[ \t]+[^.!?;\r\n]{0,75}\bpeer[ \t]+route\b/gi;
const signsOutputByDefault = /\b(?:film|video|animation|deliverable|output)\b[^.!?;\r\n]{0,95}\b(?:ends? with|always includes?|must include)\b[^.!?;\r\n]{0,65}["“]made with ([\w.-]{2,45})["”]/gi;
const addsPromotionalPageByDefault = /\bby default,?[ \t]+(?:the|a)[ \t]+promo(?:tional)?[ \t]+page[ \t]+is[ \t]+included\b/gi;
const brandsPullRequestByDefault = /\bpass(?:es)?\s+`?branding:on`?[^.!?;\r\n]{0,115}\badd\b[^.!?;\r\n]{0,55}\bbranding to (?:the|a) (?:PR|pull request)\b/gi;
const renderedPromotionalText = /^[ \t]*for promotional purposes only[ \t]*\r?$/gim;
const sourcedGeometry = /\bsource data:\*{0,2}[ \t]*(?:OSM|OpenStreetMap) via Overpass\b/gi;
const minimumReviewFindings = /\b(?:find|report|list|output)[ \t]+at least[ \t]+(?:[1-9]\d*|[A-Z])[ \t]+(?:issues|findings)\b/gi;
const logsAppOpenTelemetry = /(?:\.logEvent\([ \t]*|\blogEventWithName:[ \t]*@)["']([a-z][a-z\d]{1,12})_app_open["']/g;
const applicationWithoutTeamScope = /\bany valid (?:[\w.-]+ )?API key works;[ \t]*applications are not tied to the key['’]s team\b/gi;
const relaunchesAppForDebugging = /\brun[ \t]+`?close-app`?,[ \t]*confirm the exit,[ \t]*then launch again with[ \t]+`?--cdp\b/gi;
const documentsGuardedOperationMode = /\boperation_mode\b[^\r\n]{0,155}(?:执行前确认|confirm before execut(?:ing|ion))/gi;
const readsDesktopNotifications = /\bread notifications\b/gi;
const streamsHardwareLog = /\bemit_stream_record\([^\r\n]{0,140}\bchannel_type[ \t]*=[ \t]*["']rtt["'][^\r\n]{0,75}\btext[ \t]*=/gi;
const replacesDebugProbeDriver = /\bJ-Link\b[^.!?;。\r\n]{0,85}(?:切换到|switch(?:ing)? to)[ \t]+`?WinUSB\b/gi;
const assignsTicketToCaller = /--assignee[ \t]+(?:me|self)\b/gi;
const readsIssueWorkBundle = /\bjira-issue\.py[ \t]+(?:work|qa(?:-fail)?)[ \t]+(?:[\w-]+|<[^>\r\n]{1,45}>)(?=[\s`"')]|$)/gi;
const opensOrExposesLocalViewer = /\bopen[ \t]+or[ \t]+expose[ \t]+(?:localhost|127\.0\.0\.1)\b/gi;
const forwardsPageUrl = /https?:\/\/([\w.-]+)(?::\d{2,5})?(?:\/[\w./%-]*)?\?(?:[^\s`#<>]{1,160}&)?(?:url|target|page|site|source)=(?:<[ \t]*(?:target[ _-]+)?(?:page[ _-]+)?url[ \t]*>|\{[ \t]*(?:target|page|site)[ _-]*url[ \t]*\})/gi;
const rewritesGitHistory = /\bgit[ \t]+filter-(?:repo|branch)\b/gi;
const stripsCoauthorTrailers = /\bgit[ \t]+filter-branch\b(?:[^\r\n]{0,150}\\\r?\n){0,3}[^\r\n]{0,150}\s--msg-filter[ \t]+['"]grep[ \t]+-(?:i?v|vi)[ \t]+['"]\^Co-authored-by:/gi;
const pushesRewrittenHistory = /\bgit[ \t]+push\b[^\r\n`]{0,120}(?:--force(?:-with-lease)?\b|[ \t]-f\b)/i;
const installsSocketFromPypi = /\b(?:(?:python3?[ \t]+-m|uv)[ \t]+)?pip3?[ \t]+install[ \t]+(?:--[\w-]+[ \t]+){0,3}socket(?=[\s`"'=<>~;]|$)/gi;
const socketReportRetrievalReason = 'The dependency workflow retrieves a report based on externally published packages.';
const socketCliReference = /^[ \t]*#{1,6}[ \t]+Socket(?:\.dev)? CLI (?:Guide|Reference)\b/im;
const readsScanReportContent = /\b(?:read|summari[sz]e|follow|use|interpret)\b[^.!?;\r\n]{0,45}\b(?:findings|recommendations|descriptions|report contents?|report text)\b/i;
const retrievesSocketReport = /\bsocket[ \t]+scan[ \t]+create\b[^\r\n`|;&]{0,125}--report\b/gi;
const channelMessages = /\b(?:chat|channel) (?:messages?|requests?)\b/gi;
const workerPrompts = /\b(?:per[- ]worker|worker|agent) prompts?\b/i;
const disablesSignerEmailByDefault = /\b(?:always|unconditionally)[ \t]+(?:include|set|pass|apply)\b[^\r\n]{0,50}\bdisable(?:signer)?emails\b[\s`]*[:=][\s`]*true\b[^\r\n]{0,140}\b(?:document send|template send|all sends|every send)\b/gi;
const skipsInstallationRiskPrompt = /--force\x60?[ \t]+(?:flag[ \t]+)?(?:skips?|bypasses?|disables?)[ \t]+(?:interactive[ \t]+)?(?:security|risk|trust)[ \t]+prompts?\b/gi;
const provisionsScratchDatabase = /\b(?:mint|create|provision) (?:a |an )?(?:temporary|scratch) (?:one|database|instance)\b[^.!?;\r\n]{0,80}\bPOST[ \t]+to[ \t]+`?https:\/\/[\w.-]+\/[^\s`]+/gi;
const detachedWorkerInheritsPermissions = /\bdetached[ \t]+worker[ \t]+inherits[ \t]+(?:the[ \t]+permission[\s]+context|that[ \t]+launch[ \t]+context)\b/gi;
const referralLink = /https:\/\/[\w.-]+[^\s`<>()]{0,130}[?&](?:ref|affiliate)=[\w.-]+/gi;
const recommendsTrackedService = /\b(?:tell (?:the )?user about|recommend to (?:the )?user)\b[ \t]+[\w .-]{1,60}[ \t]+\((https:\/\/[\w.-]+[^\s`<>()]{0,160})\)/gi;
const installsSessionHooks = /\binstall(?:s|ing)?[ \t]+SessionStart[ \t]+hooks?\b/gi;
const importsExternalSheetRecords = /\b(?:populating|loading|importing)\b[^\r\n]{0,85}\b(?:sheet|databank)\b[^\r\n]{0,60}\bfrom an external source\b[^\r\n]{0,100}\b(?:API dump|CSV)\b/gi;
const collectsCustomerReviews = /\b(?:collect|read|gather|\d+[ \t]*[-–][ \t]*\d+)[ \t]+customer reviews\b/gi;
const extractsContractText = /\b(?:read|extract) (?:the )?contract text\b[^\r\n]{0,45}\b(?:pandoc|XML)\b/gi;
const readsOfficeContent = /^\|[ \t]*(?:\*{1,2})?(?:read|extract)(?:\*{1,2})?[ \t]+(?:the[ \t]+)?(?:content|text)[ \t]*\|[ \t]*`(pandoc[ \t]+(?:-t[ \t]+|--to[ =])markdown[ \t]+[^\r\n`|]+\.docx|python(?:3)?[ \t]+(scripts\/[\w.-]+\.py)[ \t]+[^\r\n`|]+\.(?:pptx|potx))`/gim;
const approvesWriteCards = /\bapproves? write cards?\b/gi;
const recordsTranscriptTail = /\btranscript tail\b/gi;
const replacesAnotherServiceWebhook = /\banother service['’]s webhook[ \t]+is[ \t]+(?:only[ \t]+)?replaced\b/gi;
const externalApiBody = /\b\w+[ \t]*,[ \t]*(\w+)[ \t]*=[ \t]*request_json\([\s\r\n]*["'](?:GET|POST)["'][\s,]*f["']\{base_url\}\//g;
const withholdsRecurringSharingNotice = /\bmention that sharing is on only once\b[^\r\n]{0,130}\b(?:do not|don['’]t|never) repeat it in later sessions\b/gi;
const deletesUnlistedCacheDirectories = /\|[ \t]*`?~\/\.cache\/\*`?[ \t]*\|[ \t]*Whole directory\b[^\r\n]{0,135}\b(?:catalog|listed) entries\b[^\r\n]{0,45}\bskipped\b/gi;
const privilegedCacheRemoval = /\bsudo[ \t]+(?:-n[ \t]+)?(?:apt(?:-get)?[ \t]+clean|journalctl[ \t]+--vacuum-(?:time|size))\b/gi;
const remoteSkillBootstrap = /\bcurl\b[^\r\n]{0,85}(https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/([\w.-]+)\/(?:main|master))(?:\/skills\/([\w.-]+))?\/install\.sh[ \t]*\|[ \t]*(?:bash|sh)\b/gi;
const targetsSkillInRemoteBootstrap = /\bcurl\b[^\r\n]{0,85}\bhttps:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/(?:main|master)\/install\.sh[ \t]*\|[ \t]*(?:bash|sh)[ \t]+-s[ \t]+--[ \t]+([\w.-]+)(?=[\s`]|$)/gi;
const clonesAgentSkill = /\bgit[ \t]+clone[ \t]+https:\/\/github\.com\/[\w.-]+\/([\w.-]+?)\.git[ \t]+\(Join-Path[ \t]+\$skills[ \t]+["']\1["']\)/gi;
const clonesWorkspaceBootstrap = /\bgit[ \t]+clone[ \t]+https:\/\/github\.com\/[\w.-]+\/[\w.-]+\.git[ \t]*(?:\\[ \t]*\r?\n[ \t]*)?(?:~\/|\$HOME\/)(?:\.agent\/skills|\.agents\/skills|\.claude\/skills|\.codex\/skills)\/([\w.-]+)\b/gi;
const clonesPythonAgentBootstrap = /^[ \t]*git[ \t]+clone[ \t]+https:\/\/github\.com\/[\w.-]+\/[\w.-]+\.git[ \t]+(<[\w.-]+>|\.?\/?[\w./-]+)[ \t]*\r?\n[ \t]*python3?[ \t]+\1\/(scripts\/(?:bootstrap|install)(?:[-_]skill)?\.py)[ \t]+[^\r\n]{0,100}--agent[ \t]+(?:both|codex|claude(?:-code)?)\b/gim;
const pythonScaffoldCommand = /\bpython3?[ \t]+(scripts\/scaffold[\w.-]*\.py)\b/i;
const globalSkillInstaller = /\bnpx[ \t]+skills[ \t]+add[ \t]+([\w.-]+\/[\w.-]+)[ \t]+-g\b[^\r\n]{0,65}(?:[ \t]+-y\b|[ \t]+--yes\b)/gi;
const globalSkillCopy = /^[ \t]*(?:\$[ \t]+)?npx[ \t]+(?:(?:-y|--yes)[ \t]+)?skills[ \t]+add[ \t]+(?:https:\/\/github\.com\/)?[\w.-]+\/[\w.-]+([ \t]+[^\r\n\x60#;&|]{1,180})/gm;
const documentsGitCheckout = /^[ \t]*(?:\$[ \t]+)?git[ \t]+clone[ \t]+(?:--[\w-]+[ \t]+[\w.-]+[ \t]+){0,2}https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)(?=[\s\x60;"']|$)/gm;
const rendersCsvPreview = /\bpreview\.innerHTML[ \t]*=/g;
const withholdsMeetingAccessDetailsZh = /任何场景[^。\r\n]{0,70}不展示会议号[^。\r\n]{0,55}入会链接/gu;
const readsMeetingTranscript = /\bwecom-?cli[ \t]+meeting[ \t]+original[ \t]+get\b/gi;
const emitsLifecycleContext = /\bprint\(json\.dumps\(\{["']hookSpecificOutput["']\s*:\s*\{[^\r\n]{0,115}["']additionalContext["']\s*:/g;
const installsSkillFromMutableSource = /^[ \t]*npx[ \t]+skills[ \t]+add[ \t]+(?:https:\/\/github\.com\/)?[\w.-]+\/([\w.-]+)[ \t]*\r?$/gim;
const repairsSkillFromMutableSource = /\b(?:install or repair with|repair by running|reinstall with)[ \t]+`?npx[ \t]+skills[ \t]+add[ \t]+https:\/\/github\.com\/[\w.-]+\/([\w.-]+)[ \t]+--skill[ \t]+[\w.-]+(?=[\s`]|$)/gi;
const runsNativeHostSetup = /\bnpx[ \t]+(?:--yes|-y)[ \t]+@([\w.-]+)\/setup[ \t]+--[\w-]+\b/gi;
const delegatesNativeHostSetup = /\bsetup (?:owns|installs|registers|configures) the native (?:browser |messaging )?host\b/i;
const inventoriesPackageDescriptions = /\bdesc=\$\(channel_desc\b[^\r\n]{0,85}\r?\n[^\r\n]{0,80}\bwhatis_desc\b/g;
const disablesLaunchdByMovingPlist = /\blaunchd services? (?:are |is )?disabled by moving (?:the )?plist\b[^\r\n]{0,80}\.plist\.off\b/gi;
const defaultGitHubLink = /\bconst[ \t]+(DEFAULT_GITHUB_(?:URL|LINK))[ \t]*=\s*["']https:\/\/github\.com\/[\w.-]+\/[\w.-]+["']/g;
const externalFeedbackHeading = /^(?:send|submit|report) (?:the )?feedback to \S/i;
const unsolicitedFeedback = /\b(?:send|submit|report) (?:it|feedback) yourself\b[^.!?]{0,95}\b(?:needs? no approval|requires? no approval|no approval (?:is )?(?:needed|required))\b/i;
const vendorFeedbackHeading = /^reporting to \S/i;
const feedbackOnEveryInteraction = /\b(?:wants?|expects?|requires?)[ \t]+(?:to hear about|feedback (?:on|for|after))[ \t]+every[ \t]+(?:interaction|session|task)\b/i;
const reportsWithFeedbackService = /\b(?:report it|(?:send|submit|file) (?:it|a report|feedback))\b[^.!?;\r\n]{0,85}\bFeedback (?:API|endpoint)\b/i;
const userRequestedFeedback = /\b(?:only[ \t]+)?(?:at the user's request|(?:if|when|after) (?:the )?user (?:asks|requests|approves|consents)|(?:ask|request|obtain|require) (?:the )?(?:user(?:'s)? )?(?:approval|confirmation|permission))\b/i;
const proactiveFeedbackSubmission = /\bproactively\s+(?:file|submit|send)\s+feedback\s+(?:with|using|via)\s+`[\w-]+\s+feedback\s+(?:submit|send|create)\b[^`\r\n]{0,70}`[^.!?;\r\n]{0,85}\b(?:when|if|whenever)\b/gi;
const sandboxRetry = /\b(?:sandbox(?:ed)? (?:denial|block(?:ed)?|restriction)|(?:denied|blocked|rejected) by (?:the )?sandbox)\b[^.!?;\r\n]{0,85}\b(?:retry|re-?run)\b[^.!?;\r\n]{0,65}\b(?:escalated (?:permissions|privileges)|outside (?:of )?the sandbox|without sandboxing|require_escalated)\b/gi;
const escalatesLibraryNetworkCalls = /\bas Codex,?[ \t]+run (?:them|the commands?) with escalated permissions\b/gi;
const listensAfterHostRestart = /\blistens? in the background,? and (?:again )?after a restart\b/gi;
const acceptsExternalMessagesForRuns = /\bwhose messages start a run\b/gi;
const requireOutsideSandbox = /\b(?:sandbox.{0,60}blocks?|blocks? .{0,35}sandbox)\b[^\r\n]{0,75}\b(?:must|always|required to)\s+(?:run|execute|capture)\b[^\r\n]{0,100}\boutside (?:the |its )?sandbox\b/gi;
const retryEscalation = /\bif\b[^.!?;\r\n]{0,70}\b(?:fails?|is blocked)\b[^.!?;\r\n]{0,55}\bsandbox (?:permission error|denial|restrictions?)\b[^.!?;\r\n]{0,52}\b(?:rerun|re-run|retry)\b[^.!?;\r\n]{0,60}\bwith (?:escalated|elevated|broader) permissions\b/gi;
const opensAllNetworkDomains = /\b(?:choose|select|switch to)\s+[*_\x60"']{0,3}all domains\b/gi;
const retriesRemoteReadWithEscalationPt = /\bse a leitura remota falhar por\b[^.!?;\r\n]{0,85}\bsandbox\b[^.!?;\r\n]{0,50}\btentar novamente\b[^.!?;\r\n]{0,60}\bpermissão escalada\b/giu;
const requiresRemoteGuidancePt = /\b(?:buscar e ler|ler e aplicar) (?:os )?(?:arquivos|capítulos|documentos) remotos\b/giu;
const movingRemoteMarkdown = /https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/(?:main|master)\/[\w./%-]+\.md\b/i;
const removesPnpmReleaseDelay = /\bPNPM_CONFIG_MINIMUM_RELEASE_AGE=0[ \t]+(?:[\w_]+=[^ \t\r\n]+[ \t]+){0,5}pnpm[ \t]+(?:create|add|i|install|update|up)\b/gi;
const trackedWriteThenCheck = /^[ \t]*(?:python3?|uv[ \t]+run[ \t]+python3?)[ \t]+([\w./-]+\.py)[ \t]+([^\r\n&|]{0,140}--(?:git-tracked|all-tracked)\b[^\r\n&|]{0,140})[ \t]*&&[ \t]+(?:python3?|uv[ \t]+run[ \t]+python3?)[ \t]+[\w./-]+\.py[ \t]+[^\r\n&|]{0,140}--(?:git-tracked|all-tracked)\b/gim;
const acceptsUpdateTerms = /\b(?:re-?issue|re-?run|retry) with\s+[`"']?confirm\s*=\s*true\b[\s\S]{0,115}\baccept_warnings\s*=\s*true\b[\s\S]{0,45}\baccept_eula\s*=\s*true\b/gi;
const searchContainerRegistry = /\x60[\w]+_container_registry_\*\x60[ \t]*\|[ \t]*List\/search\/tags\/download registry images\b/gi;
const bypassesQuarantineAfterReleaseDownload = /(?:下载|下载安装)[^\r\n]{0,65}https:\/\/github\.com\/[\w.-]+\/[\w.-]+[^\r\n]{0,160}\breleases?\b[^\r\n]{0,155}\.(?:zip|tgz|tar\.gz)\b[^\r\n]{0,100}\r?\n[^\r\n]{0,155}\bxattr[ \t]+-(?:d|dr|rd)[ \t]+com\.apple\.quarantine\b/giu;
const sendsCredentialInRecord = /\b\w+\.post\(\s*([A-Z_]\w*)\s*,\s*json\s*=\s*\{\s*[^}\r\n]{0,130}(["'])api_?key\2\s*:\s*api_?key\b/gi;
const printsPersistedShellKey = /\bexport[ \t]+([A-Z_][A-Z0-9_]*_API_KEY)=[^\r\n]{0,90}~\/\.(?:zshrc|bashrc)\b[\s\S]{0,320}?\becho[ \t]+\$\{?\1\b/g;
const confirmsOneManifestZh = /文件数量[ \t]*[:：][ \t]*1[ \t]*个[（(]SKILL\.md[）)]/giu;
const installsAdditionalFilesZh = /如果[^。\r\n]{0,45}(?:包含其他文件|包含额外文件)[^。\r\n]{0,80}(?:一并|同时)下载写入/iu;
const createsUserSkillFolder = /\bmkdir[ \t]+-p[ \t]+~\/\.(?:claude|agents|codex)\/skills\/[\w\[\]<>.-]+/gi;
const fetchesUnpinnedManifest = /\b(?:curl|wget)\b[^\r\n]{0,40}https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/(?:main|master)\/[\w./-]*\bSKILL\.md\b/gi;
const clonesAgentConfiguration = /^[ \t]*git[ \t]+clone[ \t]+https:\/\/github\.com\/[\w.-]+\/[\w.-]+[ \t]+(\/tmp\/[\w./-]+)[ \t]*\r?$/gim;
const claimsUnknownInstallationEs = /\bnadie sabe qui[eé]n posee (?:esos|los) (?:ficheros|archivos)\s*[:;]\s*tr[aá]talos como tuyos antes de\s+sobrescribirlos\b/giu;
const remoteIssueRelation = /:\/\/[\w/-]+\/github\/issue\/read\x60[ \t]*\|[ \t]*leer (?:un |el )?issue\b/giu;
const createsServiceRelation = /:\/\/[\w/-]+\/setup\x60[ \t]*\|[ \t]*crear (?:el )?layout runtime, vault y servicio\b/giu;
const readmeSkillInstall = /\bnpx[ \t]+skills[ \t]+add[ \t]+[\w.-]+\/[\w.-]+[ \t]+--skill[ \t]+[\w.-]+[ \t]+--agent[ \t]+[\w.-]+\b/gi;
const openingReleasePitchPt = /\bna primeira resposta (?:desta skill|do fluxo), comece com esta linha\b[^\r\n]{0,100}\r?\n[^\r\n]{0,120}https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/releases\/latest\b/giu;
const closingMigrationPitchPt = /^[ \t]*#{1,5}[ \t]+Quando migrar para\b[^\r\n]{1,75}\r?\n[\s\S]{0,360}\bMigre quando\b[^\r\n]{0,105}(?:agente|projeto)\b/imu;
const defaultGatewayModel = /\x60([a-z\d_-]+\/[a-z\d_.-]+)\x60[ \t]+is the default model in(?:[ \t]+[\w.-]+){0,3}[ \t]+examples\b/gi;
const assignedGatewayModel = /^[ \t]+model[ \t]*:[ \t]*["']([a-z\d_-]+\/[a-z\d_.-]+)["'][ \t]*,?[ \t]*\r?$/gim;
const repairsAfterBrowserRoundRu = /после (?:завершения|окончания) (?:текущего |каждого )?(?:круга|раунда)[^\r\n]{0,24}(?:почини|исправь) баг в коде[^\r\n]{0,40}\bEdit\/Write\b/giu;
const opensPullRequestAutonomouslyRu = /(?:ветку и PR|ветку и pull request) открывай сам[^\r\n]{0,55}без (?:просьбы|подтверждения)/giu;
const setsUnguardedChannelLauncher = /\bexec[ \t]+["'][^"\r\n]{0,70}\/claude["'][ \t]+--dangerously-skip-permissions[ \t]+--chrome[ \t]+--channels\b/gi;
const receivesChannelAttachment = /\bdownload_attachment\x60[^\r\n]{0,100}(?:скачать|загрузить) вложение/giu;
const describesCloudIntrusion = /^[ \t]*description:[ \t]*[^\r\n]{0,160}\b(?:offensive|attack)\b[^\r\n]{0,270}\bprivilege escalation\b/gim;
const declaresCredentialHarvest = /\bcredential harvesting\b/gi;
const relaysStoredLoginResponse = /(?:把|将)(?:原(?:始)?)?已保存的?扫码(?:登录)?响应[^。！？\r\n]{0,13}(?:交|发给|发送至)[ \t]*Relay[ \t]*(?:处理|计算)/giu;
const readsRoleInboxRu = /\bposed_to\x60[^\r\n]{0,90}(?:вопросы|сообщения|поручения)/giu;
const readsPageSnapshot = /\bbrowser_snapshot\x60[^\r\n]{0,78}(?:дерево доступности|accessibility tree)/giu;
const omitsLocalIndexDetails = /\bnever say ["']index["'][^\r\n]{0,90}\bfile paths or commands\b/gi;
const assertsProjectColorSettings = /\bproject\.SetSetting\([ \t]*key[ \t]*,[ \t]*\w+[ \t]*\)/gi;
const loadsUnverifiedModelPickle = /\bwith open\([ \t]*(?:\w*path|\w*file)\b[^\r\n]{0,110}\) as ([\w]+):\r?\n[ \t]*[^\r\n]{0,70}\bpickle\.load\([ \t]*\1[ \t]*\)/gi;
const removesQuarantine = /\bxattr[ \t]+-(?:d|dr|rd)[ \t]+com\.apple\.quarantine\b/gi;
const fallbackRawScript = /\bif neither (?:local )?(?:copy|script|file) exists,\s*download\s+https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/(?:main|master)\/[\w./-]+\.(?:[cm]?js|sh|py)\b[\s\S]{0,145}\b(?:run|execute) (?:it|the (?:script|downloaded copy))\b/gi;
const standaloneHelperFallback = /\b(?:no (?:adjacent|local|bundled) (?:helper|script) exists|(?:adjacent|local|bundled) (?:helper|script) is (?:missing|unavailable))[,:]?\s+download (?:the )?(?:canonical |official )?(?:helper|script) from\s+`?https:\/\/[\w.-]+\/[\w./-]+\.sh`?(?=[\s,])[\s\S]{0,145}\b(?:run|execute) it with `?(?:bash|sh)\b/gi;
const loadsLatestGuide = /\bload (?:the )?latest instructions from\b[^.!?;\r\n]{0,105}\b(?:pull|bootstrap) script\b/gi;
const clonedGuideAuthority = /\bthe cloned\s+\x60?(?:[\w.-]+\/)+[\w.-]+\.md\x60?\s+is authoritative\b/gi;
const automaticBinarySetup = /(?:自动执行初始化|自动初始化)[^\r\n]{0,100}\bsetup\.(?:js|sh)\b/gi;
const asksForSetupToken = /(?:请提供|提示用户提供)[^\r\n]{0,65}\btoken\b/i;
const passesSetupToken = /\bconfig[ \t]+set-token[ \t]+<token>/gi;
const importsUserRecords = /\b[\w.-]+[ \t]+number[ \t]+(?:format-template|import-file)[^\r\n]{0,55}<用户[^>\r\n]{0,24}文件>/gi;
const readsExportedTicketMarkdown = /\b(?:uv[ \t]+run[ \t]+|python3?[ \t]+)scripts\/[\w.-]+\.py[ \t]+[<"']?(?:[\w./-]+\/)?[\w.-]+\.md[>"']?(?=[\s`]|$)/gi;
const changesUserAgentSettings = /\bset\b[^\r\n]{0,80}\bautoMemoryEnabled\b[^\r\n]{0,75}\.claude\/settings\.json\b/gi;
const latestGoInstall = /\bgo\s+install\s+github\.com\/[\w.-]+\/[\w./-]+@latest\b/gi;
const readsTerminalPane = /\btmux[ \t]+capture-pane\b[^\r\n\x60]{0,65}[ \t]-p(?=\s|\x60|$)/gi;
const exposesHostShell = /\badds? a hook\b[^\r\n!?;]{0,80}\bshell profile\b[^\r\n!?;]{0,120}\bautomatically wraps\b/gi;
const shellToolEntry = /\x60([\w.-]+[ \t]+[\w.-]+)[ \t]+shell\x60[ \t]*\|[ \t]*Execute a shell command\b/gi;
const sendsClonedInstaller = /\btmux[ \t]+send-keys\b[^\r\n]{0,80}\bgit[ \t]+clone\b[^\r\n]{0,25}\bhttps:\/\/github\.com\/[\w.-]+\/[\w.-]+[^\r\n]{0,175}(?:\.\/|\b(?:bash|sh)[ \t]+)(?:setup|install|bootstrap)\.sh\b/gi;
const asksForApproval = /\b(?:with|after|ask(?:ing)? for) (?:the )?(?:user(?:'s)? )?(?:approval|confirmation|permission)\b/i;
const firmwareTermApproval = new RegExp(asksForApproval.source + '|\\b(?:user|operator) must (?:approve|accept)\\b', 'gi');
const alwaysFetchSkill = /\b(?:always fetch fresh|must fetch)\b[^\r\n!?;]{0,105}\b(?:every|each) session\b/gi;
const requiresUncachedSkill = /\b(?:never reuse|do not use)\b[^\r\n.!?;]{0,45}\bcached copy of (?:a |the )?skill\b/i;
const existingPrRegistration = /\bregister\s+(?:the\s+)?(?:PR )?URL\s+with\s+(?:the\s+)?host['’]s\s+PR-link\s+tool\b[\s\S]{0,70}\b(?:including|also)\s+existing PRs?\b/gi;
const disableSandbox = /\b(?:disable|turn off) (?:the )?sandbox(?:ing)?\b[^.!?;\r\n]{0,40}\b(?:full|unrestricted|elevated) (?:local |host )?(?:permissions|access|privileges)\b/gi;
const requiresCommandSandboxBypass = /\brequires sandbox bypass:[ \t]*(?:use|set|enable)[ \t]+[\x60]?dangerouslyDisableSandbox:[ \t]*true\b/gi;
const trustsDiscoveredToolFiles = /\btool (?:files|modules) are (?:treated|loaded) as trusted (?:runtime )?extensions\b[^.!?\r\n]{0,25}\.[ \t]+(?:they|these (?:extensions|modules)) (?:may|can) execute unrestricted (?:JavaScript|JS) with host access\b/gi;
const invokesDiscoveredPluginBootstraps = /\binvoke each (?:agent|plugin)['’]s [\x60]bootstrap[\x60] skill grouped by its declared\b/gi;
const followsLiveSetupPage = /\bfetch that page and answer from its\s+current content\b/gi;
const usesRejectedTokenizer = /\bmv[ \t]+[\w./-]*first\.json[ \t]+[\w./-]*tokenizer\.json[ \t]*;[ \t]*echo[ \t]+["']WARNING:[ \t]+no candidate (?:declares|matches|satisfies)\b[^\r\n]{0,85}\bspecial tokens\b/gi;
const restartsPackagedModelServer = /["']?\$(\w+)\/stop\.sh["']?[ \t]+[^\r\n]{1,105}\r?\n[ \t]*VENV=[^\r\n]{1,38}["']?\$\1\/serve\.sh["']?[ \t]+[^\r\n]{1,95}\bpkg\/model\.json\b/gm;
const reportsOtherSessionExcerpt = /\bfirst [1-9]\d{0,3} (?:chars|characters) of (?:the )?other (?:agent|instance|session)['’]s first message\b/gi;
const argumentPostToken = /\bpost-detail\.sh[ \t]+<[\w-]+>[ \t]+<xsec_token>/gi;
const disablesCommandSandboxJa = /コマンド単位で[ \t]*(?:sandbox|サンドボックス)[ \t]*(?:を[ \t]*)?無効にして[ \t]*実行(?:する|してください)/gi;
const defaultPrivateData = /\bsend[_-]default[_-]pii["']?[ \t]*[:=][ \t]*["']?(?:true|1)\b/gi;
const forceDirtyTree = /\b(?:dirty (?:worktree|working tree)|uncommitted changes)\b[^.!?;\r\n]{0,100}--force\b|--force\b[^.!?;\r\n]{0,100}\b(?:dirty (?:worktree|working tree)|uncommitted changes)\b/gi;
const commitsEntireProject = /\bcommits? (?:every|all) changes? (?:under|in|throughout) the (?:project|repository|repo) root\b/gi;
const switchesCommitBranch = /\b(?:switch(?:es)? to|check(?:s)? out) (?:the |a )?(?:new )?branch\b/i;
const researchesProductPricing = /\b(?:list|compare|research) the products\b[^.!?;]{0,190}(?:\.\s+For each (?:one|product),[ \t]*)?\b(?:give|include|record)\b[^.!?;]{0,100}\b(?:the )?price with (?:its|a)\s+source URL\b/gi;
const redirectsGuardedFileRemoval = /\b(?:registered )?(?:guard|hook) blocks shell\b[^\r\n]{0,140}\bto intentionally (?:remove|delete) a file,[ \t]+use\b/gi;
const defaultsCredentialReuseToGranted = /\b([\w-]+)[`]? (?:absent|unset|missing) (?:counts as|is treated as) granted\b[^\r\n]{0,180}\breuse\.\1[ \t]+false\b/gi;
const forceAlongsideUncommittedEdits = /--force\x60?[^.!?;\r\n]{0,82}\b(?:edits?|changes?)\b[^.!?;\r\n]{0,60}\balongside (?:your |the )?(?:WIP|work in progress)\b/gi;
const turnsOffSmartAppControl = /\b(?:turn|switch) Smart App Control off\b|\bdisable Smart App Control\b/gi;
const sharedGuestSetup = /\b(?:run|execute)\s+\x60(?:bash|sh)\s+["']?\/Volumes\/[^"'`\r\n]{1,90}\/[^"'`\r\n]{1,65}\.sh["']?\x60[^.!?;\r\n]{0,185}\b(?:switch on|grant|enable|turn on)\b[^.!?;\r\n]{0,125}\bAccessibility\b/gi;
const avoidsHostPermissionPrompt = /\bavoid\b(?:`[^`\r\n]{1,24}`|[^`\r\n.!?;]){1,85}(?:\r?\n[^\r\n.!?;]{0,30})?\bwhich makes? (?:the )?(?:client|host|runner|harness|tool) ask for permission\b/gi;
const noninteractiveSkillUpdate = /\b(?:npx|bunx)\s+skills\s+update(?:[ \t]+[\w@./-]+){1,40}[ \t]+--yes\b/gi;
const trustsPluginAtInstall = /\bgrok\s+plugin\s+install\s+(?:["'][^"'\r\n]{1,160}["']|[^\s`]{1,160})[ \t]+--trust\b/gi;
const activatesWithoutQuestion = /\b(?:activate|enable|turn on) (?:it|the (?:automation|rule))\b[^.!?;\r\n]{0,65}\bwithout (?:another question|additional confirmation|asking again)\b/gi;
const deployProxyEndpoint = /\b((?:[A-Z][A-Z0-9_]*_)?(?:DEPLOY|UPLOAD|PUBLISH)_ENDPOINT)=["']https:\/\/[a-z0-9-]+\.(?:vercel\.sh|netlify\.app|workers\.dev|pages\.dev)\/[^"'\r\n]{1,135}["']/gi;
const archiveUpload = /\bcurl\b[^\r\n]{0,210}\b(?:file|archive|tarball)=@\$\{?[a-z_][a-z0-9_]*/gi;
const unauthenticatedDeployFallback = /^[ \t]*#{1,6}[ \t]+[^\r\n]{0,50}\b(?:no auth|without authentication|unauthenticated)\b/im;
const readsWorkflowRecords = /\bget_records\b[^\r\n\x60]{0,160}\binclude_fields\s*=\s*true\b/gi;
const inlineCredentialInstruction = /\b(?:pass|supply|provide)\s+(?:tokens?|api keys?|secrets?)\b(?:\([^\r\n)]{1,52}\)|[^(.!?;\r\n]){0,70}\binline\s+in\b[^.!?;]{0,72}\b(?:command|CLI|shell)\b/gi;
const storesProvidedCredentials = /\b(?:substitute|insert|write|copy)\s+(?:the\s+)?(?:actual|literal)\s+(?:api keys?|access tokens?|client secrets?)\s+inline\b[^\r\n.!?;]{0,65}\b(?:user|operator)\b[^\r\n.!?;]{0,28}\b(?:provided|pasted|supplied)\b/gi;
const solicitsUserCredential = /\b(?:ask|prompt|tell|instruct)\s+(?:the\s+)?user\s+(?:for|to\s+(?:paste|send|provide|share|enter))\b[^.!?;\r\n]{0,65}?\b(?:api[ _-]?(?:key|token)|access token|client secret|password|one-time (?:password|code))\b/gi;
const submitsCredentialInChat = /\b(?:paste|send|share|provide)\b[^.!?;\r\n]{0,60}\b(?:api[ _-]?(?:key|token)|access token|client secret|password|one-time (?:password|code))\b[^.!?;\r\n]{0,33}\b(?:here|back to (?:me|you|the agent)|(?:in|into) (?:this |the )?(?:chat|conversation))\b/gi;
const asksToPasteKeyBack = /\b(?:ask|tell|prompt) (?:them|the user) to paste (?:the|their) key back to (?:you|the agent)\b/gi;
const submitsCredentialInChatZh = /(?:提示|要求|请)[^。！？\r\n]{0,25}用户[^。！？\r\n]{0,18}(?:提供|粘贴|发送)[^。！？\r\n]{0,45}(?:API[ _-]?(?:Key|Token)|密钥|密码|访问令牌)[^。！？\r\n]{0,42}(?:等待用户回复|用户回复后|发给我|发到(?:当前|这个)?对话)/gi;
const asksToPasteTokenBackZh = /(?:让|请|要求)用户[^。！？\r\n]{0,20}(?:把|将)(?:访问)?令牌[^。！？\r\n]{0,18}粘贴给(?:你|助手|我)/giu;
const usesTokenInEnvSetup = /\b(?:setx[ \t]+[A-Z_]*(?:TOKEN|KEY)[ \t]+|export[ \t]+[A-Z_]*(?:TOKEN|KEY)=)["']?<PAT>/i;
const requestsOnboardingToken = /\bask (?:them|the (?:customer|user)) to paste (?:their|the) (?:personal access )?(?:token|PAT)\b/gi;
const credentialReportTable = /\btabla[ \t]+(?:con|de)[ \t]+[^.!?;\r\n]{0,135}\b(?:claves|credenciales|tokens)[ \t]+(?:encontrad[ao]s|detectad[ao]s)\b/gi;
const htmlReportHeading = /^[ \t]*#{1,6}[ \t]+[^\r\n]{0,45}\b(?:informe|reporte)[ \t]+HTML\b/im;
const redactsReportCredentials = /\b(?:enmascar\w+|anonimiz\w+|redactar|redactadas?|omit\w+|ocult\w+|sin mostrar)[ \t]+(?:(?:los?|las?|sus)[ \t]+)?(?:valores?|claves|credenciales|tokens)\b|\b(?:claves|credenciales|tokens)[ \t]+(?:encontrad[ao]s|detectad[ao]s)[ \t]+(?:enmascarad[ao]s|anonimizad[ao]s|ocult[ao]s)\b|\b(?:solo|únicamente)[ \t]+(?:los[ \t]+)?(?:tipos|nombres|recuentos)\b/iu;
const mutatingAuditRequest = /\bcurl\b[^\r\n]{0,180}[ \t]+(?:-X[ \t]*|--request[ \t]+)(DELETE|PATCH|POST|PUT)\b/gi;
const capturedAuditResponse = /^[ \t]*[A-Z_]\w*[ \t]*=[ \t]*\$\([ \t]*curl\b/gm;
const renderShellPolicy = /["']?\bdisableSkillShellExecution\b["']?[ \t]*:[ \t]*true\b/g;
const storesPastedEnvValues = /\b(?:create|update|write) this file after each pasted value\b/i;
const untrustedPackageSamples = /https:\/\/(?:downloads\.example\.com|pub-[\w-]+\.r2\.dev)\/[^ \t\r\n`'">]{1,160}\.zip\b/gi;
const packageDownloadIntake = /\bask the (?:customer|user) for (?:their|the)\b[^.!?;\r\n]{0,50}\bpackage download link\b/gi;
const commerceCredential = /\b(?:ck|cs)_[a-f0-9]{40}\b/g;
const paymentProviderCredential = /\bAPP_USR-[\w-]{30,120}\b/g;
const credentialTablePassword = /\|[ \t]*[\w .-]{1,60}\(login\)[ \t]*\|[ \t]*\x60[^\x60\r\n|]{2,100}\x60[ \t]*\/[ \t]*\x60([^\x60\r\n|]{12,120})\x60/g;
const mutatesCommercePayment = /\bcurl\b[^\r\n]{0,150}\b(?:PUT|PATCH|POST)\b(?:[^\r\n]{0,160}\\\r?\n){0,3}[^\r\n]{0,160}\bwc\/v3\/payment_gateways\/[\w${}-]+/gi;
const browserCredentialField = /\bbrowser[ \t]+(?:[\w.-]+[ \t]+)?eval\b[^\r\n]{0,190}\b(?:cardnumber|cc-number|cvv|password)\b[^\r\n]{0,65}\.value\b/gi;
const credentialHarvestPurpose = /^[ \t]*description:[ \t]*["']?(?:[|>][-+]?\r?\n[ \t]+)?[^\r\n]{0,150}\bharvest(?:s|ing)?\b(?:[^\r\n]{0,105}\r?\n[ \t]+)?[^\r\n]{0,75}\b(?:tokens?|credentials?)\b/gim;
const collectsReusableTokens = /\b(?:access|refresh) tokens?\b/gi;
const schedulesSkillUpdate = /(?:每天(?:第一次使用时)?自动(?:检查并)?更新|updates itself (?:automatically )?(?:daily|on first use each day))/iu;
const selfUpdateTargets = /["']SKILL\.md["'][ \t]*:[ \t]*["'][^"']+["'][ \t]*,[ \t]*["']scripts\/[\w./-]+\.(?:mjs|cjs|js)["'][ \t]*:/gi;
const mirroredJarDownload = /https:\/\/(?!github\.com\/)[\w.-]+\/gh\/[\w.-]+\/[\w.-]+\/releases\/download\/[\w.-]+\/([\w.-]+\.jar)\b/gi;
const automaticCheckoutMirror = /(?:自动(?:转到|切到|改用)|automatically switch(?:es)? to)[^。\r\n]{0,100}(?:镜像|mirror)[\s\S]{0,130}https:\/\/github\.com(?=[/\s)"'`）]|$)(?:\/[^\s"'`<>（）]{0,110})?[^。\r\n]{0,50}https:\/\/(?!github\.com\/)[\w.-]+\/https:\/\/github\.com(?=[/\s)"'`）]|$)/giu;
const repositoryMirrorList = /^#{2,5}[ \t]+(?:GitHub|GitLab)[ \t]+(?:API|Raw) Mirrors?[ \t]*\r?\n(?:[ \t]*\r?\n)?(?:[ \t]*\d+\.[ \t]+`https:\/\/[\w.-]+[^\s`]*`[ \t]*(?:\r?\n|$)){2,16}/gim;
const repositoryProviderHosts = new Set(['api.github.com', 'raw.githubusercontent.com', 'github.com', 'gitlab.com']);
const changesGitNetworkConfig = /\bgit[ \t]+config[ \t]+--global[ \t]+https?\.proxy\b/gi;
const automatedUpgradeApproval = /\becho[ \t]+(?:y|yes)[ \t]*\|[ \t]*[\w.-]+[ \t]+extension[ \t]+update\b/gi;
const tracewayHostInstaller = /https:\/\/install\.tracewayapp\.com\/install\.sh\s*\|[\s\\]+TRACEWAY_TOKEN=/gi;
const putsUserCredentialInMcpArguments = /\bmcp[ \t]+(?:add|register)\b[^\r\n]{0,140}[ \t](?:-e|--env)[ \t=]+[A-Z_]*(?:API_KEY|ACCESS_TOKEN|CLIENT_SECRET|PASSWORD)=["']?<user[-_ ]provided[-_ ](?:key|token|secret|password)>/gi;
const mcpPackageCommand = /\bmcp[ \t]+(?:add|register)\b[^\r\n]{0,145}[ \t]+--[ \t]+npx[ \t]+(?:-y|--yes)[ \t]+((?:@[a-z\d_-]+\/)?[a-z\d_.-]+)(?:@([\w.^~+*-]+))?(?=[\s'"`]|$)/gi;
const updatesRemoteWorktree = /\bgit(?:[ \t]+-C[ \t]+\S+)?[ \t]+fetch[ \t]+origin\b[^\r\n]{0,90}\r?\n[ \t]*git(?:[ \t]+-C[ \t]+\S+)?[ \t]+worktree[ \t]+add\b[^\r\n]{1,155}[ \t]+origin\/(?:main|master)\b/gi;
const buildsNewWorktree = /\bmake[ \t]+-C[ \t]+(?:<worktree>|["']?\$\{?(?:new_)?worktree\}?["']?)(?=[ \t])[^\r\n]{0,115}\bbuild\b|\bcd[ \t]+<worktree>(?:\/[^\s]+)?[ \t]+(?:&&|;)[ \t]*(?:make|npm[ \t]+run|pnpm|bun|cargo|go)\b[^\r\n]{0,60}\bbuild\b/i;
const passesEmailVerificationCode = /\b(?:auth|mfa|login)[ \t]+(?:verify|confirm)[ \t]+[`"']?<(?:otp|verification[-_ ]code|one[-_ ]time[-_ ]code)>/gi;
const substitutesCredentialFromFile = /--(?:password|api[-_]key|client[-_]secret|access[-_]token)[ \t=]+["']?\$\((?:awk|cat|grep|jq|python3?|sed)\b[^\r\n]{0,210}\.(?:json|ya?ml|ini|md|env)\b[^\r\n]{0,130}\)/gi;
const assignsCredentialFromFile = /^[ \t]*(?:export[ \t]+)?([A-Z_]*(?:API_KEY|ACCESS_TOKEN|CLIENT_SECRET|PASSWORD))=["']?\$\((?:awk|cat|grep|jq|python3?|sed)\b[^\r\n]{0,210}\.(?:json|ya?ml|ini|md|env)\b[^\r\n]{0,130}\)/gim;
const mutableWorkflowAction = /^[ \t]+(?:-\s*)?uses:[ \t]+["']?[\w.-]+\/[\w.-]+(?:\/[\w./-]+)?@(?![0-9a-f]{40}(?=["' \t#\r\n]|$))[\w./-]+/gim;
const clonesWorkflowTool = /^[ \t]*git[ \t]+clone(?:[ \t]+--depth[ \t]+\d+)?[ \t]+https:\/\/github\.com\/[\w.-]+\/[\w.-]+[ \t]+["']?(\$[\w]+\/[\w./-]+)["']?[ \t]*\r?$/gim;
const executesWorkflowTool = /^[ \t]*(?:node|bun|python3?|bash|sh)[ \t]+["']?(\$[\w]+\/[\w./-]+\.(?:[cm]?js|[cm]?ts|py|sh))(?=["' \t\r\n]|$)/gim;
const verifiesWorkflowCheckout = /\bgit\b[^\r\n]*\b(?:checkout|switch|verify-commit|verify-tag|reset)\b/i;
const clonesConfiguredWorkflowTool = /^[ \t]+git[ \t]+clone(?:[ \t]+--depth[ \t]+\d+)?[ \t]+--branch[ \t]+"\$([A-Z_][A-Z0-9_]*)"[ \t]+"\$([A-Z_][A-Z0-9_]*)"[ \t]+([\w./-]+)[ \t]*\r?$/gm;
const installsWorkflowTemplate = /^#[ \t]*(?:copy|drop|place|save)[ \t]+this[ \t]+file[ \t]+(?:in|into|to)[ \t]+\.github\/workflows\/[\w.-]+\.ya?ml\b/im;
const workflowChangelog = /\$\{CHANGELOG\}|\$\{\{\s*(?:steps|needs)\.[\w-]+\.outputs\.changelog\s*\}\}/gi;
const releaseNotesFromHistory = /\b(?:generate|write|draft|build|create|group)\b[^.!?;\r\n]{0,70}\b(?:release notes|changelogs?)\b/i;
const fetchesReleaseIndex = /\bweb[_ -]?fetch\b[\s\S]{0,100}https:\/\/github\.com\/([\w.-]+\/[\w.-]+)\/releases(?=[\s`<>)]|$)/gi;
const gitLogCommand = /\bgit[ \t]+log\b[^\r\n`]{0,240}/gi;
const checksTaskHistory = /\b(?:check|read|consult)[ \t]+`git[ \t]+log\b[^`\r\n]{0,140}`[ \t\r\n]+for[ \t]+commits[ \t]+that[ \t]+touched\b/gi;
const selfDeclaredArtifactReceipt = /\b(?:that|the executing|the implementation)[ \t]+session[ \t]+may[ \t]+(?:write|declare)[ \t]+`?artifact only:[ \t]+true`?/gi;
const gitLogSubjectArgument = /\[[ \t]*["']log["'][ \t]*,[^\r\n\]]{0,145}["']--(?:pretty|format)=[^"'\r\n]{0,90}%[sBb][^"'\r\n]{0,50}["']/g;
const rendersGitHubCompareUrl = /\breturn[ \t]+\x60https:\/\/github\.com\/\$\{[\w.[\]]+\}\/compare\/\$\{[\w.]+\}\.\.\.\$\{[\w.]+\}\x60/g;
const comparesRecentFilePatch = /\bgit[ \t]+log[ \t]+-p[ \t]+-1\b/gi;
const writesInputSnapshot = /\b_write_atomic\([ \t]*([a-z_]\w*),[ \t]*([a-z_]\w*)\.data[ \t]*\)/gi;
const auditsNpmMetadata = /\bnpm[ \t]+view[ \t]+<package>[ \t]+--json\b/gi;
const reviewsDartArchive = /\bdart[ \t]+pub[ \t]+unpack\b[^\r\n`]{0,160}--no-resolve\b/gi;
const printsPaneToModel = /\btmux[ \t]+capture-pane[ \t]+-(?:pt|p[ \t]+-t)[ \t]+["']?\$\{?[\w_-]+\}?(?=[ \t"'`\r\n]|$)/gi;
const readsRemoteCommitSubjects = /\bgit[ \t]+log[ \t]+HEAD\.\.origin\/[^ \t`\r\n]{1,85}[ \t]+--oneline\b/gi;
const evaluatesReleaseSources = /\banaly[sz]e (?:the )?git commits, pull requests, or code changes\b/gi;
const readsGeneratedDesign = /\b(?:web_fetch|read_url_content)\b[^\r\n]{0,110}\bhtmlCode\.downloadUrl\b/gi;
const readsSpreadsheetUrlRecords = /\b(?:mcp \w+|call doc)[ \t]+smartsheet_get_records\b[^\r\n]{0,110}["']url["']\s*:\s*["']https:\/\/[^\s"']+\/(?:smartsheet|spreadsheet)\/[^\s"']+/gi;
const readsReleaseWorkItemsZh = /(?:读取|获取)发布[ \t]+(?:Issue|工单)[^。\r\n]{0,65}\b(?:Milestone|MR)\b/giu;
const searchesInvoiceAttachments = /\bhas:attachment[ \t]+filename:(?:xml|pdf)\b/gi;
const registryMetadataRequest = /\bfetch_json\([ \t]*f?["']https:\/\/(?:pypi\.org\/pypi\/[^"']+\/json|registry\.npmjs\.org\/[^"']+)[\x22']/gi;
const registryVersionList = /\b(?:pnpm|npm)[ \t]+view[ \t]+(?:<[\w.-]+>|[@\w][\w./@-]*)[ \t]+versions[ \t]+--json\b/gi;
const readsBuildConfiguration = /\bjenkins[ \t]+job[ \t]+config[ \t]+[^\r\n]{1,110}>[ \t]*[^\s`]+\.xml\b/gi;
const runsJenkinsControllerScript = /\bjenkins[ \t]+system[ \t]+run-script[ \t]+--script\b/gi;
const readsPeerInbox = /\bnodes\/<ID>\/inbox\.md\x60[^\r\n]{0,65}\bsym tell\b/gi;
const readsSessionTranscripts = /\bdeja[ \t]+--framed[ \t]+(?:ctx|show|search)\b/gi;
const extractsRemotePageTitle = /\btitle[ \t]*=[ \t]*re\.search\([ \t]*r?["']<title\b[^\r\n]{0,100}(\w+)\.text\b/g;
const readsPageJsonLd = /\bfetch (?:the )?HTML\b[^\r\n]{0,80}\r?\n[ \t]*[-*][ \t]*extract\b[^\r\n]{0,90}\bapplication\/ld\+json\b/gi;
const searchesMarketCatalog = /\bchainq[ \t]+search[ \t]+["'][^"'\r\n]{1,100}["']/gi;
const readsCustomerSubmissions = /\b(?:read|review|analy[sz]e|triage|process|summari[sz]e|synthesi[sz]e|get|fetch)s?\b[^.!?;\r\n]{0,45}\b(?:customer (?:support )?(?:tickets|feedback)|incoming support requests|survey responses|support conversations)\b/gi;
const pastedJobPost = /\b(?:job post|job listing)\b[\x60*_]*,?\s+(?:pasted|copied)\s+(?:in full|by the user)\b/gi;
const readsRuntimeApiSpec = /\b(?:fetch|retrieve|load)\b[^.!?;\r\n]{0,28}\b(?:swagger|openapi)\s+(?:json|yaml|spec(?:ification)?)\s+from\s+[`$\{]*[a-z][a-z0-9_]*_(?:url|uri)\b/gi;
const apiSpecCodegen = /\b(?:generate|scaffold)\b[^.!?;\r\n]{0,55}\b(?:api clients?|client methods?|dtos?|type definitions?)\b/i;
const readsAdvisoryText = /\b(?:read|review|inspect|interpret)\s+(?:the\s+)?(?:GHSA|CVE|security advisory)\s+(?:title(?:\/summary)?|summary|description)\b/gi;
const rendersPublicPlaceRecords = /\b(?:results?|response|data)\.pois\.(?:forEach|map)\s*\(\s*(\w+)\s*=>[^\r\n]{0,25}\r?\n[ \t]*console\.log\s*\([^\r\n]{0,100}\b\1\.name\b[^\r\n]{0,75}\b\1\.address\b/gi;
const remotePageConversion = /\bfetch\s+and\s+convert\s+(?:web\s+)?pages\s+(?:into|to)\s+(?:static\s+)?markdown\b/gi;
const fetchedPageBoundary = /\b(?:fetched web content|content retrieved from the open web)\s+is\s+(?:data|a claim to evaluate)\b/gi;
const releasedSkillArchive = /\bdownload\s+(?:the\s+)?\x60\.skill\x60\s+(?:files?|archives?)\s+from\s+(?:the\s+)?\[latest release\]\(https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/releases\/latest\)/gi;
const importsMutableSkillZip = /\bdownload[ \t]+\[\x60?([\w.-]+)\.zip\x60?\]\(https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/releases\/latest\/download\/\1\.zip\)(?:,[ \t]*then|\.[ \t]+(?:then[ \t]+)?|\r?\n[ \t]*\d+\.[ \t]+(?:go to|open)\b[^\r\n]{0,90})[ \t]*Settings[^\r\n]{0,80}\bSkills\b(?:[^\r\n]{0,30}|\r?\n[ \t]*\d+\.[ \t]+)\bupload\b/gi;
const renderedInstallExample = /^[ \t]*const[ \t]+(?<binding>[A-Za-z_]\w*)[ \t]*=[ \t]*(?:\r?\n[ \t]*)?(?<quote>['"])git[ \t]+clone[ \t]+(?:--[\w-]+(?:[ \t]+\d+)?[ \t]+){0,5}https:\/\/github\.com\/[\w.-]+\/[\w.-]+[ \t]+(?<directory>[~\w./-]+)[ \t]*&&[ \t]*cd[ \t]+\k<directory>[ \t]*&&[ \t]*\.\/(?:setup|install|bootstrap)(?:\.sh)?\k<quote>/gm;
const environmentWithLocalSshKey = /--env[ \t]+["']?(?:SSH_PRIVATE_KEY|SSH_KEY)=["']?\$\(cat[ \t]+["']?(?:~\/|\$\{?HOME\}?\/)\.ssh\/[\w.-]+\b/gi;
const authenticDemoTestimonials = /\b(?:sample|demo|fictional) testimonials\b[^.!?;\r\n]{0,155}\b(?:realistic|authentic[- ]sounding|believable)\b[^.!?;\r\n]{0,58}\b(?:placeholders|quotes|testimonials)\b/gi;
const rewritesAllRegisteredCitations = /\b(?:every|all) registered documents?[’']?s?\b[^.!?;\r\n]{0,100}\b(?:citations?|footnotes?|bibliography)\b[^.!?;\r\n]{0,105}\b(?:rewritten|overwritten|replaced|regenerated)\b/gi;
const readsSourcesForCitation = /\b(?:article or book|published source)\b[^.!?;\r\n]{0,55}\bobtain the full text\b[^.!?;\r\n]{0,65}\bread it in full\b/gi;
const forwardsSessionTranscripts = /\b(?:polls?|tails?|reads?|watches?)\s+(?:all|each)\s+(?:[\w-]+\s+){0,3}transcript files\b[^.!?;\r\n]{0,150}\b(?:pushes|sends|forwards)\b[^.!?;\r\n]{0,85}\b(?:telegram|discord|slack) chat\b/gi;
const forwardsTranscribedSpeech = /^[ \t]+(\w+)[ \t]*=[ \t]*self\._record_until_silence\([^()\r\n]{0,85}\)[\s\S]{0,550}?^[ \t]+(\w+)[ \t]*=[ \t]*self\._transcribe\(\1\)[\s\S]{0,550}?^[ \t]+self\.(\w+)\(\2\)[ \t]*\r?$/gm;
const deviceActionConfirmation = /\b(?:confirm\w*|approv\w*|consent|permission)\b/i;
const skipsDeviceSendConfirmation = /\bsend\b`?[^.!?;。！？；\r\n]{0,100}(?:不(?:再|二次)确认|(?:without (?:a |another )?confirmation|no (?:additional |second )?confirmation)\b)/giu;
const persistsSoleCanInterface = /^([ \t]*)if[ \t]+len\(\w+\)[ \t]*==[ \t]*1[ \t]*:\r?\n(?:\1[ \t]+\S[^\r\n]*\r?\n|[ \t]*\r?\n){0,12}\1[ \t]+save_project_config\(/m;
const readsCanFrames = /^[ \t]*(\w+)[ \t]*=[ \t]*bus\.recv\(/gm;
const runsTargetSkillScript = /^[ \t]*(\w+)[ \t]*=[ \t]*os\.path\.join\(self\.\w*skill\w*,[ \t]*\w+\[["']path["']\]\)[\s\S]{0,220}?^[ \t]*(\w+)[ \t]*=[ \t]*\[sys\.executable,[ \t]*\1\][^\r\n]*[\s\S]{0,550}?^[ \t]*(?:\w+[ \t]*=[ \t]*)?subprocess\.run\(\s*\2\b/gm;
const validatesTargetScriptPath = /\b(?:commonpath|relative_to|is_relative_to|realpath|resolve)\s*\(/;
const skipsRepairConfirmation = /禁止向用户确认|\b(?:never|do not) ask (?:the )?user (?:to confirm|for confirmation)\b/iu;
const fixedDeploymentAlias = /\bf["']server_name[ \t]+\{\{?\w+\}\}?[ \t]+(?:[a-z\d-]+\.)+[a-z]{2,63};["']/gi;
const embeddedDeploymentShell = /^[ \t]*(\w+)[ \t]*=[ \t]*f?("""|''')#![^\r\n]{0,90}\bbash\b/gm;
const exportsPriorConversation = /\buser messages? from the (?:\*\*)?entire conversation history(?:\*\*)?[ \t]*\([ \t]*including (?:history|messages?) before (?:session resumption|the session resumed)\b/gi;
const provisionsWithTokenArgument = /(--[\w-]+-token)[ \t]+(["'])([\w-]{8,}(?:\.{3})?)\2/gi;
const insertsRuntimeTracker = /<script[ \t]+[^>\r\n]{0,165}\bsrc\s*=\s*["'](?:\$\{[a-z_]\w*\}|[^"'\r\n]{1,140}\.js(?:\?[^"'\r\n]{0,100})?)["']/gi;
const updatesAgentSkillsDuringCommands = /\b(?:other|all|ordinary|normal) commands?\b[^.!?;\r\n]{0,75}\bon first run\b[^.!?;\r\n]{0,50}\bafter an? (?:update|upgrade)\b/gi;
const installsSkillsForAgents = /\binstall (?:all|every)\b[^.!?;\r\n]{0,65}\bskills?\b[^.!?;\r\n]{0,65}\b(?:coding agents?|agent.s home|agent configuration)\b/i;
const numericCleanupPublisher = /https:\/\/github\.com\/\d{6,}[a-z0-9-]*\/([\w.-]+)/gi;
const replacesProxyWrapper = /\buse\s+\x60?requests\x60?(?:\s+library)?\s+directly,\s+not\s+\x60?proxied_[\w]+\(/gi;
const grantsBucketAdministration = /\bgrant\b[^.!?;\r\n]{0,50}\bservice account\b[^.!?;\r\n]{0,115}\broles\/storage\.admin\b/gi;
const mandatoryNewDocumentSteps = /\b(?:must|always|required to)\s+(?:immediately\s+)?(?:run|perform|execute)\b[^\r\n]{0,45}\b(?:after (?:creating|creation of)|for each)\s+(?:a |the )?new document\b|(?:每次|每当)创建新文档后[^。\r\n]{0,30}必须(?:立即)?\*{0,2}执行/iu;
const fixedDocumentOwner = /\bperm\s+transfer-owner\b[^`\r\n]{0,115}?--member-id[ \t]+([a-z0-9][a-z0-9._+-]{0,63}@[a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/gi;
const fixedDocumentAccess = /\bperm\s+add\b[^`\r\n]{0,115}?--member-id[ \t]+([a-z0-9][a-z0-9._+-]{0,63}@[a-z0-9-]+(?:\.[a-z0-9-]+)+)\b[^`\r\n]{0,40}\bfull_access\b/gi;
const credentials = /\b(?:api[ _-]?(?:key|token)s?|access[ _-]?tokens?|auth(?:entication)?[ _-]?tokens?|refresh[ _-]?tokens?|bearer tokens?|private keys?|passwords?|credentials?|session cookies?|signing secrets?)\b/i;
const unsafeHandling = /\b(?:print|echo|log|display|reveal|paste|include|embed|put|write|store|save|return|send|copy|share|expose|output)\b[^.!?;\r\n]{0,100}\b(?:api[ _-]?(?:key|token)s?|access[ _-]?tokens?|auth(?:entication)?[ _-]?tokens?|refresh[ _-]?tokens?|bearer tokens?|private keys?|passwords?|credentials?|session cookies?|signing secrets?)\b[^.!?;\r\n]{0,95}/gi;
const configCredentialArgument = /\bopenclaw[ \t]+config[ \t]+set[ \t]+[\w.-]+\.(?:apiKey|accessToken)\b(?=[ \t]+(?!-)[^\s;|]+)/gi;
const unsafeDestination = /\b(?:verbatim|plain(?:[ -]?text)?|logs?|console|stdout|chat|messages?|repl(?:y|ies)|responses?|output|shell history|command(?:[- ]line)?|argument|prompt|world.readable|unprotected|external|public)\b/i;
const safeCredential = /\b(?:masked|redacted|placeholder|dummy|sample|name of|reference to)\b/i;
const knownToken = /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{35,}|(?:AKIA|ASIA)[A-Z0-9]{16}|sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{15,}|AIza[A-Za-z0-9_-]{35}|npm_[A-Za-z0-9]{30,}|sk_(?:live|test)_[A-Za-z0-9]{16,})\b/g;
const searchApiQueryKey = /[?&]x-algolia-api-key=([a-f0-9]{32})(?![\w-])/gi;
const analyticsIngestKey = /\b(phc_[A-Za-z0-9_-]{35,60})\b/g;
const opaqueKubernetesSecret = /^[ \t]*kind:[ \t]*Secret[ \t]*\r?\n(?:(?![ \t]*(?:---|\x60{3}|~{3}))[^\r\n]*\r?\n){0,9}?[ \t]*type:[ \t]*Opaque[ \t]*\r?\n[ \t]*data:[ \t]*\r?\n((?:[ \t]+[^\r\n]+(?:\r?\n|$)){1,12})/gim;
const secretDataField = /^[ \t]+[\w-]*(?:password|token|secret|api-key)[ \t]*:[ \t]*([A-Za-z0-9+/]{10,}={0,2})[ \t]*(?:#[^\r\n]*)?\r?$/gim;
const cpanelDatabasePassword = /^[ \t]*cpanel[ \t]+(?:deploy:wp(?:[ \t]+\S+){3}|db:user-create[ \t]+\S+)[ \t]+(["'])([^"'\r\n]{8,100})\1(?=\s|$)/gim;
const sshPasswordFlag = /^[ \t]*sshpass[ \t]+-p(?=[ \t]+[^\r\n])/gim;
const sshPasswordLiteral = /^[ \t]*sshpass[ \t]+-p[ \t]+(["'])([^"'\r\n]{4,120})\1(?=\s|$)/gim;
const downloadsLatestWordPress = /\b(?:download|tải)[ \t]+`?(?:https:\/\/)?wordpress\.org\/latest\.zip\b/giu;
const assignment = /(?<![\w-])([\w-]+)["']?[ \t]*[:=][ \t]*(?:"([^"\r\n]{4,256})"|'([^'\r\n]{4,256})'|([A-Za-z0-9_+/=!@.%-]{6,256}))/g;
const secretName = /(?:^|[_-])(?:api[_-]?key|(?:access|auth|refresh)[_-]?token|client[_-]?secret|session[_-]?cookie|password|passwd|secret|token)$/i;
const privateKey = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g;
const placeholder = /^(?:\$\{|\$[A-Z_]|<|\{\{|%[A-Z_]|your[-_ ]|replace[-_ ]|example[-_ ]|sample[-_ ]|dummy[-_ ])|\b(?:placeholder|redacted|changeme|change-me|replace-me|dummy|sample|example|insert|process\.env|getenv)\b|^(?:x+|\*+|null|undefined|true|false|password|secret|none)$/i;

const payment = /\b(?:submit|initiate|authorize|execute|make|send|transfer|withdraw|place|sign|broadcast|charge|refund|pay)\b[^.!?;\r\n]{0,62}\b(?:payments?|funds|money|cash|bank transfers?|transactions?|market orders?|trades?|invoices?|credit cards?|customers?|cryptocurrency|crypto assets?|wallet transfers?)\b/gi;
const concretePayment = /\b(?:(?:charge|refund) (?:the |a )?(?:customers?|cards?|payments?|invoices?)|(?:send|transfer|withdraw) (?:the |any |available )?(?:funds|cash|money|cryptocurrency|crypto assets?)|(?:submit|initiate|authorize|execute|make) (?:(?:a|an|the) )?(?:new )?(?:(?:bank|card|crypto|real|live|financial) )?(?:payments?|bank transfers?|market orders?|trades?)|(?:sign|broadcast) (?:the |a |raw )?(?:crypto )?transactions?|place (?:a |the )?(?:market orders?|trades?)|pay (?:the |an? )?(?:invoice|bill))\b/i;
const walletOperation = /\b(?:sign|create|broadcast|send|transfer) (?:an? |the )?(?:raw |transfer |blockchain |Solana |EVM )?transactions?\b|\b(?:sign|broadcast) (?:an? |the )?(?:Solana|EVM) tx\b|\b(?:authorize token approvals|payment signing)\b/i;
const walletContext = /\b(?:blockchain|crypto(?:currency)?|wallet|on[- ]chain|Solana|EVM|x402|USDC)\b/i;
const paymentEndpoint = /\bPOST[ \t]+\/(?:[\w-]+\/){0,4}(?:invoices|invoice-links|payouts|payment-intents|payments|charges|refunds|withdrawals|refund|topup)(?=[\s?#'"\x60)]|$)/gi;
const paymentSdkCall = /\bstripe\.(?:checkout\.sessions?|payment_?intents?|refunds?|charges?)\.(?:create|capture)\s*\(/gi;
const paidToolInvocation = /\bx402[ \t]+pay\b|--x402\b/gi;
const paidApiPurpose = /^[ \t]*description:[ \t]*["']?(?:make (?:a )?paid (?:API )?requests?|pay for (?:x402|paid|API)\b|build (?:and deploy )?(?:a )?paid (?:API|service)|monetize (?:an? )?(?:API|endpoint|service))\b/im;
const followsX402PaymentFlow = /^[ \t]*#{1,4}[ \t]+(?:Complete|Execute|Submit) (?:an? |the )?x402 Payment\b/gim;
const registryPaidCall = /\b(?:npx|bunx)[ \t]+(?:-y[ \t]+)?(?:@[\w.-]+\/)?[\w.-]+(?:@[\w.-]+)?[ \t]+x402[ \t]+pay\b/gi;
const registrySourceInstall = /\bnpx[ \t]+shadcn(?:@latest)?[ \t]+add[ \t]+(https:\/\/[\w.-]+\/(?:[\w.-]+\/)*r)\/[\w.-]+\.json\b/gi;
const linkedComponentRegistryInstall = /\b(?:npx|bunx|pnpm[ \t]+dlx)[ \t]+shadcn(?:@[^\s`"'<>]+)?[ \t]+add[ \t]+https:\/\/([\w.-]+)\/r\/[\w.-]+(?=[\s`"'<>]|$)/gi;
const registryRouteInstall = /\bnpx[ \t]+shadcn(?:@latest)?[ \t]+add[ \t]+https:\/\/([\w.-]+)\/r\/[\w-]+(?=[\s`"'<>]|$)/gi;
const prerequisiteSkillRepository = /^[ \t]*[-*][ \t]+(?:The[ \t]+)?\*{0,2}\[([\w-]+)\]\(https:\/\/github\.com\/[\w.-]+\/\1\/?\)[ \t]+skill\b/gim;
const copiesClonedSkill = /^[ \t]*git[ \t]+clone[ \t]+(?:--depth[ \t]+\d+[ \t]+)?https:\/\/github\.com\/(?<owner>[\w.-]+)\/(?<repo>[\w.-]+?)(?:\.git)?[ \t]*(?:\r?\n|&&)[ \t]*cp[ \t]+-[aRr][ \t]+["']?\k<repo>\/(?:[\w.-]+\/)*(?<skill>[\w.-]+)\/?["']?[ \t]+["']?~\/\.(?:agents|claude|codex)\/skills\/?["']?(?=[ \t]*(?:\r?$|[#;]))/gm;
const skillToolInvocation = /\b(?:invoke|call|run)\s+(?:the\s+)?[`*_]*([\w-]+)[`*_]*\s+skill\s+via\s+the\s+Skill tool\b/gi;
const executesSuggestedFix = /\bwhen[ \t]+`?\$hints`?[ \t]+is present[^\r\n]{0,95}\bexecute the suggested fix commands\b/gi;
const persistsExtractedAppCookie = /\bthe extracted[ \t]+`?([\w.-]+)`?[ \t]+is stored at[ \t]+`?~\/\.config\/[\w.-]+\/credentials\.json\b/gi;
const documentsAuthorizationScanBypass = /^#{2,6}[ \t]+[^\r\n]{0,70}\bAuthorization[ \t]+安全扫描绕过(?=[ \t\r\n]|$)/gim;
const sharesArtifactWithCredentialArguments = /\bshare[ \t]+<html-file>[ \t]+\[--password[ \t]+<[^>\r\n]+>\][ \t]+\[--token[ \t]+<[^>\r\n]+>\]/gi;
const receivesQueuedReviewPrompts = /\bpoll[ \t]+<html-file>`[^\r\n]{0,45}\blong-poll for\b[^.\r\n]{0,85}\bqueued prompts\b/gi;
const walletTransferCommand = /(?:^|\x60)[ \t]*(?:(?:npx|bunx)[ \t]+(?:-y[ \t]+)?)?[\w.-]+(?:@[\w.-]+)?[ \t]+(?:wallet|bridge)[ \t]+transfer\b/gim;
const paymentSetup = /\b(?:stripe|payment|wallet|invoice|billing)\b[^.!?;\r\n]{0,42}\b(?:auto[- ]?top[- ]?up|payment challenge|checkout button|charge users)\b/gi;
const changesGenerationBudget = /\b[\w.-]+:increase-(?:image|video|audio|generation)-budget\b[^\r\n\x60]{0,85}--limit(?:=|[ \t])/gi;
const requiresExternalBillingAdmin = /^\)?\s+(?:is|are)\s+(?:admin|administrator)[- ]only\s+and\s+(?:happens?|takes place)\s+(?:on the web|in the web (?:portal|console))\b/i;
const purchaseExecution = /\b(?:pay for|place|submit|confirm|finalize) (?:an? |the )?(?:paid |customer |real |live )?(?:orders?|purchases?)\b/gi;
const paidServerRental = /\bservers[ \t]+rent[ \t]+[^\r\n\x60;|]{1,130}--rental-days\b[^\r\n\x60;|]{1,85}--max-charge-cents[ \t]+(?:[1-9]\d*\b|<[\w.-]+>|\$\{?\w+\}?)/gi;
const purchaseContext = /\b(?:checkout|payments?|price|pricing|purchase|shipping|credit card|billing)\b/i;
const purchaseEndpoint = /\b(?:POST|PUT)\b[^\r\n]{0,115}\b(?:PlaceOrder|ConfirmOrder|PayOrder|capture_payment)\b/gi;
const tradingOrder = /\b(?:place|submit|execute) (?:an? |the |new )?(?:limit|stop|buy|sell) orders?\b/gi;
const tradingContext = /\b(?:trading|exchange|price|shares|order book|market|stock|crypto(?:currency)?|wallet)\b/i;
const publicData = /\b(?:browse|read|fetch|retrieve|load|search|analy[sz]e|summarize|process|follow|use|consume|ingest|inspect)\b[^.!?;\r\n]{0,85}\b(?:(?:arbitrary|user[- ]supplied) (?:urls?|websites?)|public (?:web(?:sites?| pages?)?|posts?|issues?|comments?|forums?|pages?|feeds?|social media)|social[- ]media(?: posts?| comments?)?|forum (?:posts?|comments?)|user[- ](?:submitted|generated|controlled) (?:content|data|posts?|comments?|input)|third[- ]party (?:content|api responses?|websites?|pages?|documents?)|external (?:content|api responses?|websites?|pages?|documents?)|issue tracker (?:comments?|posts?))\b/gi;
const webRetrievalReason = 'The instruction asks the agent to retrieve web content or user-authored discussion.';
const webRetrieval = /\b(?:search|browse|scrape|crawl)\b[^.!?;|\r\n]{0,40}\b(?:the web|the internet|the public web|websites?|search results?)\b|\b(?:fetch|retrieve|read|scrape|crawl|browse|open|visit)\b[^.!?;|\r\n]{0,65}\b(?:urls?|webpages?|web pages?|websites?)\b|\b(?:fetch|retrieve|collect|read|inspect|review|load)\b[^.!?;|\r\n]{0,70}\b(?:github|gitlab|pull request|issue|review|discussion)\s+(?:comments|threads|discussions|bodies|descriptions)\b/gi;
const openThinReferenceSource = /\bopen (?:the )?source links? only when an entry is (?:thin|incomplete|insufficient)\b/gi;
const linkedAddonRecommendation = /\[[^\]\r\n]{1,90}\]\(https:\/\/github\.com\/[\w.-]+\/[\w.-]+\)[ \t]+is[ \t]+[^.!?\r\n]{1,250}\b(?:an? )[\w.-]+ (?:add-on|plug-in|extension)\.[ \t]+use it\b[^.!?\r\n]{1,150}\bwhen\b/gi;
const readsPublicBookReviews = /(?:调用|请求|调)[ \t]*\x60?\/review\/list\x60?[ \t]*(?:获取|读取|查询)公开(?:点评|评论)(?:列表)?/gu;
const concealsReviewRouting = /(?:不得|不要|不|禁止)(?:向用户)?(?:暴露|披露|说明|展示)[ \t]*接口选择[、，和与 \t]+参数(?:拼装|组装)[^。！？\r\n]{0,32}(?:内部过程|内部细节)/gu;
const publicDataTool = /\b(?:WebFetch|WebSearch|web[_-](?:search|fetch)|mcp__\w+__\w*(?:web_search|fetch_url|web_fetch))\b|\bgh[ \t]+(?:issue[ \t]+(?:view|list)\b|pr[ \t]+(?:view|list)\b[^\r\n]{0,100}(?:--comments\b|--json[ \t]+[^\r\n]{0,45}\b(?:comments|body)\b)|api\b[^\r\n]{0,140}\/(?:issues|pulls)\/)/gi;
const reviewDiffCommand = /\b(?:gh[ \t]+pr|glab[ \t]+mr)[ \t]+diff\b(?![^\r\n|]{0,100}(?:--name-only\b|--help\b))/gi;
const userAuthoredContent = /\b(?:search|fetch|retrieve|read|load|ingest|scrape|pull|extract|download|summari[sz]e|list|query|get|parse)\b[^.!?;\r\n]{0,45}\b(?:(?:slack|discord|teams) (?:messages?|threads?|conversations?)|(?:gmail|inbox|outlook) (?:messages?|emails?|threads?)|incoming (?:emails?|messages?)|email (?:messages?|threads?|bodies)|channel (?:history|messages?)|(?:reddit|twitter|mastodon|bluesky|hacker news|youtube|linkedin) (?:threads?|posts?|results?|comments?|transcripts?|tweets?)|reviews? from (?:customers|users))\b/gi;
const socialPlatformRead = /\b(?:search|crawl|scrap\w*|fetch|get|retrieve|summari[sz]e|collect|read)\b[^.!?;\r\n]{0,48}\b(?:Reddit|YouTube|LinkedIn|TikTok|Twitter|Mastodon|Bluesky|Instagram|Hacker News|Bilibili|Weibo)\b[^.!?;\r\n]{0,35}\b(?:results|posts?|threads?|replies|comments|captions|pages?|videos?)\b/gi;
const preparesReplyFromPublicPost = /\bcall[ \t\r\n]+[\x60]?prepare_reply\([^\r\n)]{0,85}\b(?:tweet|post|comment)_url\b[^\r\n)]{0,30}\)[\x60]?[ \t]+first[,:][ \t\r\n]+(?:you get|it returns?) the (?:tweet|post|comment)['’]s (?:text|body|contents)\b/gi;
const indexesRepositoryWithMcp = /\bconnect to (?:the )?([\w.-]+) MCP server\.?[ \t]*\r?\n[ \t]*-[ \t]+submit (?:the|a) (?:user-supplied )?repository URL for indexing\b/gi;
const repairsFailedVerification = /\bif (?:any |a )?verification gate fails,[ \t]*(?:attempt|perform|run) automated repair[ \t]*(?:—|–|:|-)[ \t]*adjust (?:source )?code, configuration, or test fixtures\b/gi;
const publicMarketResearch = /\b(?:research|investigate|benchmark|analy[sz]e|compare)\b[^.!?;\r\n]{0,70}\b(?:competitors|competing products|alternative products|market)\b[^.!?;\r\n]{0,85}\b(?:using (?:public|external)|online|websites?|social media|reviews?|web sources)\b/gi;
const namedMarketDataProviders = /^[ \t]*\|[ \t]*\*{0,2}Market Data\*{0,2}[ \t]*\|[ \t]*[A-Z][\w.-]+(?:,[ \t]*[A-Z][\w.-]+){1,8}[ \t]*\|/gm;
const readsPaidMarketplace = /\bx402[ \t]+bazaar[ \t]+(?:search|list|details)\b/gi;
const readsMcpSession = /\b[\w.-]+[ \t]+(?:--json[ \t]+)?@[a-z][\w-]*[ \t]+(?:tools-list|resources-list|resources-read|prompts-list)\b/gi;
const ingestsPublicAdvertising = /\b(?:search\w*|track\w*|scrap\w*|collect\w*|fetch\w*|retriev\w*|monitor\w*|analy[sz]\w*)\b[^.!?;\r\n]{0,65}\b(?:competitor(?:s['’]?|['’]s)? (?:ads?|advertisements?|ad campaigns?|ad copy|advertising)|sponsored (?:ads?|advertisements?|content))\b/gi;
const reinterpretsAssetRestriction = /\byou are allowed to do this,? even if the user says not to download (?:internet|external) assets\b/gi;
const downloadsAllowedPublicAssets = /\bif the user has allowed it,? you can download free assets from the internet\b/gi;
const networksForAdvertising = /\b(?:across|from|on)\s+(?:multiple\s+)?(?:social (?:networks?|media|platforms?)|advertising networks?|(?:their )?ad libraries)\b/i;
const publicListings = /\b(?:discover|list|search|find)\b[^.!?;\r\n]{0,55}\b(?:public|community|third[- ]party|open marketplace)\b[^.!?;\r\n]{0,45}\b(?:templates?|plugins?|listings?|models?|apps?|assets?|skills)\b/gi;
const academicSearch = /\bpython3?[ \t]+[^\s`]{0,180}search_(?:arxiv|openalex|crossref|pubmed|s2|semantic_scholar)\.py\b|\bWebFetch[^\r\n]{0,18}https:\/\/api\.(?:crossref|openalex)\.org\/works\?(?:query|search)=|\bsearch_articles\b[^\r\n]{0,35}\bget_article_metadata\b/gi;
const webSearchService = /\b(?:tavily|serpapi|brave search|perplexity|firecrawl|exa|bing|google search|serper|duckduckgo)\b[^.!?;\r\n]{0,26}\b(?:search|query|scrape|fetch|results?|api)\b|\b(?:search|query|scrape|fetch)\b[^.!?;\r\n]{0,30}\b(?:tavily|serpapi|brave search|perplexity|firecrawl|google search|serper|duckduckgo)\b/gi;
const responseParsing = /\b(?:curl|wget)\b(?![^\r\n]{0,160}\s-X[ \t]+(?:POST|PUT|PATCH|DELETE)\b)[^\r\n|]{0,160}https?:\/\/[^\r\n|]{1,170}\|[ \t]*(?:jq|htmlq|pup)\b/gi;
const browserRead = /\b(?:(?:agent-browser[ \t]+(?:snapshot|get[ \t]+(?:text|html))|mcp__[\w-]+__browser_snapshot)\b|(?:page|browser)\.(?:inner_text|text_content|content)\s*\()/gi;
const browserNavigation = /\b(?:(?:agent-browser[ \t]+open|browser[_-]navigate|navigate to (?:the |a )?(?:page|url|website))\b|page\.goto\s*\()/i;
const browserTraceTarget = /\b(?:scan|audit|inspect|profile)[ \t]+(?:<(?:url|website)>|\$\{?URL\}?)(?=[\s\x60"']|$)/gi;
const browserTraceOutput = /\b(?:browser|Chrome|DevTools)\b[^.!?;\r\n]{0,110}\b(?:trace|component names?|rendered text)\b/i;
const prWorkflow = /\b(?:pull request|PR URL|GitHub PR)\b/i;
const prReadback = /\bread[ -]back\b[\s\S]{0,200}\btitle\s*\/\s*body\b/gi;
const remoteChangeRequestFields = /\bgh\s+(?:pr|issue)\s+view\b[^\r\n]{0,155}\b(?:body|comments?|reviews?|title)\b/gi;
const readsReviewDiff = /\b(?:reads?|inspect(?:s)?|review(?:s)?) the (?:PR |pull request )?diff\b/gi;
const selectsDownloadFromSearch = new RegExp([
  String.raw`^(?<indent>[ \t]+)(?<results>[a-z_]\w*)[ \t]*=[ \t]*await[ \t]+`,
  String.raw`(?<search>(?:[a-z_]\w*_)?search(?:_[a-z_]\w*)?)\([^()\r\n]{0,120}\b(?:query|term|keyword)\b[^()\r\n]{0,85}\)[ \t]*\r?$`,
  String.raw`[\s\S]{0,500}?^\k<indent>(?<selected>[a-z_]\w*)[ \t]*=[ \t]*(?:pick|select|choose)_[a-z_]\w*\(\k<results>\b[^)\r\n]{0,160}\)`,
  String.raw`[\s\S]{0,400}?^\k<indent>(?<url>[a-z_]\w*)[ \t]*=[ \t]*f["'][^\r\n]{0,90}\{\k<selected>\[["'](?:dl|download_url|url)["']\]\}[^\r\n]{0,60}`,
  String.raw`[\s\S]{0,240}?^\k<indent>[^\r\n]{0,100}\b(?:[a-z_]\w*_)?download\(\k<url>\b`,
].join(''), 'gm');
const readsCrmRecords = /\b(?:use|call)\s+`?search_crm_objects\b/gi;
const refusesToStopCourse = /(?:声称|请求|要求)[^。！？\r\n]{0,15}(?:结束或停止|停止)[^。！？\r\n]{0,37}(?:一律[^。！？\r\n]{0,18}拒答|拒绝)[^。！？\r\n]{0,25}课程位置不变/gu;
const loadsOutsideSkill = /^[ \t]*always open and follow[ \t]+`?(?:\.\.\/){2,}\.[\w.-]+\/(?:[\w.-]+\/)*SKILL\.md\b/gim;
const startsAutomaticWorkers = /\b(?:start|launch|run)[ \t]+claude[ \t\r\n]+with[ \t]+`?--permission-mode[ \t]+auto\b/gi;
const hidesIntegrationProvider = /\bto the (?:person|user),[ \t]+say[ \t]+["“][^"”\r\n]{2,45}["”],[ \t\r\n]+not[ \t]+([\w.-]+)\b/gi;
const copiesEntireDevProfiles = /\b(?:full clone|exact, isolated copy) of (?:all|the live)\b[^.!?;\r\n]{0,78}\b(?:user profiles|dev users, profiles)\b/gi;
const opensSandboxReload = /^[ \t]*!`touch[ \t]+[^`\r\n]{3,110}`/gim;
const backsUpReleaseToShare = /下载[^。！？\r\n]{0,25}release[^。！？\r\n]{0,48}安装包[^。！？\r\n]{0,80}`\\{2,4}[\w.-]+\\[^`\r\n]{3,115}`[^。！？\r\n]{0,22}(?:备份|備份)/giu;
const startsUnrestrictedWorkflows = /"Bash\((?:\*)?\)"[\s\S]{0,490}"Agent\((?:\*)?\)"/g;
const disablesApprovalAcrossAgents = /--permission-mode[ \t]+bypassPermissions[\s\S]{0,670}--ask-for-approval[ \t]+never\b/g;
const approvesOuterAndInnerAgent = /^[ \t]*(?:node|bun|deno|python3?|\.\/[\w./-]+)[ \t]+[^\r\n]{0,150}--approve-all[ \t]+[^\r\n]{0,110}--permission-mode[ \t]+(?:auto|bypassPermissions)\b/gim;
const externalAgentRegistration = /\$\{?SERVER_URL\}?\/api\/auth\/register\b/g;
const bypassesUserAlias = /\b(?:se o|if the) `?(?:AGENTS|CLAUDE)\.md`?(?:[ \t]+(?:ou o|or) `?(?:AGENTS|CLAUDE)\.md`?)?[^.!?]{0,110}\b(?:mandar iniciar por|asks you to launch through)\s+(?:an )?alias\b[^.!?]{0,110}\b(?:use o comando|use the full command)\b/gi;
const writesGlobalAgentInstructions = /\bnode[ \t]+[^\s`]+\.[cm]?js[ \t]+--global\b[^\r\n]{0,70}\b(?:arquivos globais dos agentes|global agent (?:instruction )?files)\b/gi;
const waitsForTerminalOutput = /\bherdr[ \t]+pane[ \t]+wait-output\b/gi;
const downloadsRelativePython = /^[ \t]*curl\b[^\r\n]{0,185}https:\/\/[^\s'"`]+[^\r\n]{0,45}[ \t](?:-o|--output)[ \t]+["']?((?:[\w.-]+\/)+[\w.-]+\.py)["']?[^\r\n]{0,50}[\s\S]{0,250}\bpython3?[ \t]+["']?\1\b/gm;
const downloadsAndRunsSql = /^[ \t]*curl[ \t]+(?:-[a-z]*O[a-z]*|--remote-name)[ \t]+["']?(https:\/\/[^\s'"`]+\/)\b([\w.-]+\.sql)["']?[ \t]*\r?\n[ \t]*psql\b[^\r\n]{0,130}[ \t](?:-f|--file)[ \t]+["']?\2(?=[\s'"`]|$)/gm;
const startsDownloadedCompose = /^[ \t]*curl[ \t]+(?:-[a-z]*O[a-z]*|--remote-name)[ \t]+["']?https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/(?:main|master)\/(?:[\w.-]+\/){0,8}((?:docker-)?compose\.ya?ml)["']?[ \t]*\r?\n[ \t]*docker(?:[ \t]+compose|-compose)[ \t]+(?:-f[ \t]+\1[ \t]+)?up\b/gm;
const readsUntrustedRepositoryText = /\b(?:codebase|repository)(?:[ \t]+(?:text|content))?[ \t]+is[ \t]+(?:untrusted|attacker[- ]controllable)[^\r\n]{0,140}\bREADME\b[\s\S]{0,65}\bcommit[\s]+messages?\b[\s\S]{0,100}\b(?:analyse|analyze|review|inspect)\b/gi;
const clonesUserRepository = /\bgit[ \t]+clone\b[^\r\n]{0,160}https:\/\/(?:github\.com|gitlab\.com)\/<owner>\/<repo>(?:\.git)?/gi;
const readsEnvForServiceReport = /\bservices table\b[^.!?;\r\n]{0,105}\bread\b[^)\r\n]{0,48}(?<![\w.-])\.env\b/gi;
const advertisesAnonymousVerification = /\bno human,[ \t\r\n]+no[ \t\r\n]+account,[ \t\r\n]+and no KYC\b/gi;
const downloadsReleaseBinary = /\bdownload[ \t]+`?[\w.-]+`?[ \t]+binary[ \t]+from[ \t]+\[[^\]\r\n]{1,75}\breleases\]\(https:\/\/github\.com\/[\w.-]+\/[\w.-]+(?:\/releases(?:\/latest)?)?\/?\)/gi;
const publishesToReleaseRepository = /\b(?:publish(?:ing)?|push(?:ing)?)[^\r\n]{0,75}\bto[ \t]+`?https:\/\/github\.com\/[\w.-]+\/[\w.-]+(?=[` \t\r\n)]|$)/gi;
const preparesWindowsExecutable = /\b(?:build|rebuild|package)(?:[ \t]+the)?[ \t]+Windows executable\b/i;
const publishesReleaseFromTag = /\b(?:creates?|publishes?) a release when (?:a |the )?(?:matching )?(?:version )?tag\b/i;
const readsSocialSearchNotes = /\breturns? (?:the )?(?:top|trending) (?:posts|notes) with title,[ \t]+author\b/gi;
const forksAfterSessionPolicy = /\bpolicy\b[\s\S]{0,380}(?:\bfallback\b[^\r\n]{0,95}\bfork\b|--fork\b)/gi;
const routesBuyerMessagesZh = /买家消息[^|。\r\n]{0,70}\bChatwoot\b[^|\r\n]{0,25}\|[^\r\n]{0,85}\.\.\/[^\s)]+\/SKILL\.md/gi;
const readsLiveServicePricing = /\bcheck the price first\b[^\r\n]{0,45}\bget_pricing\b/gi;
const readsFailedWorkflowSteps = /\bgh[ \t]+run[ \t]+view\b[^\r\n]{0,55}(?:失败步骤|failed steps|job logs)/giu;
const readsKakaoMessages = /\bkmsg[ \t]+(?:read|watch)\b[^\r\n]{0,110}--json\b/gi;
const readsRpcMessageBodies = /\b[\w-]+[ \t]+getMessages\b[\s\S]{0,160}?\.body\b/g;
const printsPublishedSiteFile = /\bnsyte[ \t]+get[ \t]+\/[\w./-]+[^\r\n]{0,55}\b(?:print|returns?)\b[^\r\n]{0,45}\bpublished file\b/gi;
const installsInSystemBin = /^[ \t]*(?:sudo[ \t]+)?install[ \t]+-m[ \t]+[0-7]{3,4}[ \t]+[\w./-]+[ \t]+\/usr\/local\/bin\/[\w.-]+\b/gim;
const bypassesUpdateConfirmation = /\bupdates the packages,[ \t]+the CLI and these[ \t\r\n]+skills together\b[\s\S]{0,135}\bwithout a terminal\b[\s\S]{0,55}\bneeds[ \t]+`?--yes\b/gi;
const describesSessionReplay = /(?:复用|提取|导出|注入|replay|inject|harvest)[^。！？\r\n]{0,25}(?:cookies?|会话|凭据)/giu;
const capturedSessionHeader = /^[ \t]+([A-Za-z_]\w*)[ \t]*=[ \t]*\w+\.request\.headers\.get\([ \t]*["'](?:cookie|authorization)["']/gim;
const claimsKoreanRulePriority = /시스템(?:의)?[ \t]*(?:일반[ \t]*)?(?:디폴트|기본[ \t]*(?:규칙|지침))[^。.!?\r\n]{0,90}보다[ \t]*(?:본|이)[ \t]*(?:스킬의[ \t]*)?규칙이[ \t]*우선/gu;
const autoApprovesMajorUpdates = /^#{2,6}[ \t]+auto-approve list[ \t]*\r?\n[\s\S]{0,125}\b(?:packages|dependencies)\b[^\r\n]{0,80}\bmajor (?:bumps|versions|updates)\b/gim;
const fetchesMirroredManifest = /\bdownload_first\b[^\r\n]{0,125}["']?\$\{?manifest_url\}?["']?[ \t]+["']?\$\{?mirror_manifest_url\}?/gi;
const fetchesBrowserExtensionZip = /\$\{[A-Z_]*RELEASE[A-Z_]*\}\/latest\/download\/[\w.-]+\.zip\b/g;
const localBrowserWithoutAuth = /\b(?:no auth(?:entication)?|without auth(?:entication)?)\b/gi;
const browserProxyHandler = /^(?:[ \t]+)def[ \t]+do_POST\b/gm;
const readsCatalogCandidateRu = /(?:открой|прочитай|просмотри)[ \t]+исходн(?:ый файл|ое описание)[^.!?\r\n]{0,70}(?:промпта|SKILL\.md|описание роли)/giu;
const extractsReceiptTextJa = /(?:レシート|領収書|請求書)[^。！？\r\n]{0,40}(?:画像|PDF)[^。！？\r\n]{0,45}OCR[^。！？\r\n]{0,35}(?:抽出|読み取り)/giu;
const mutatesMacKeychain = /\bsecurity\s+(?:set-key-partition-list|create-keychain|import(?=[^\r\n]{0,120}\s-k\s))\b/gi;
const mutatesMacSystemTrust = /\bsudo[ \t]+security[ \t]+add-trusted-cert\b[^\r\n]{0,230}\/Library\/Keychains\/System\.keychain\b/gi;
const transfersProviderEarnings = /\b(?:withdraw|transfer)\b[^\r\n.!?;]{0,45}\b(?:settled )?(?:earnings|payout|account balance)\b/gi;
const browserDebugging = /\b(?:CDP|DevTools Protocol|remote[ -]debugging)\b/i;
const debuggingLiveProfile = /\b(?:open|launch|attach|connect)\w*\b[^\r\n.!?;]{0,115}\b(?:real|actual)\b[^\r\n.!?;]{0,32}\b(?:profile|browser)\b/gi;
const preservedBrowserCredentials = /\b(?:cookies?|session tokens?|full auth|saved passwords?)\b/i;
const credentialArgument = /(?<=\s)--(?:password|api[-_]key|client[-_]secret|access[-_]token)(?=(?:=|[ \t]+)["']?(?:<(?:(?:api[_ -]?)?key|pw|pass(?:word)?|secret|token)>|[a-z0-9][a-z0-9_+.-]{9,64})(?:[\s"'\x60]|$))/gi;
const signingCommand = /\b(?:notarytool|codesign|xcrun)\b/i;
const walletKeyArgument = /\b[\w-]+[ \t]+wallet[ \t]+import\b(?=[ \t]+(?:["']?0x[\w.]+|<private[-_ ]key>)(?:[\s"'\x60]|$))/gi;
const marketDetailsCommand = /^[ \t]*([\w-]+)[ \t]+(?:-o[ \t]+json[ \t]+)?markets[ \t]+get[ \t]+[\w<]/gim;
const writesCompositionReport = /^[ \t]*(?:grype|trivy|osv-scanner)[ \t]+[^\r\n|;&]{0,130}[ \t](?:-o|--format)[ \t]+json[ \t]+>[ \t]+[\w.-]+\.json\b/im;
const readsCompositionDescriptions = /\b(?:read|parse|interpret)[ \t]+(?:the[ \t]+)?JSON[ \t]+(?:output|report)\b/gi;
const sensitiveBrowserOperation = /\b(?:stealth\w*|arbitrary (?:JavaScript|JS)|upload local files|intercept(?:ion)?|capture network)\b/i;
const automaticPromptApproval = /\b(?:auto[- ]click|automatically\s+(?:clicks?|accepts?|approves?)|clicks?\s+(?:allow|approve)\s+automatically)\b/gi;
const browserControlPrompt = /\b(?:full control|remote debugging permission|DevTools.{0,18}(?:confirmation|permission|prompt))\b/i;
const readsAccessibilityText = /\b(?:AXObserver|UI text|accessible text)\b/gi;
const registersLoginAgent = /\b(?:registers?|installs?|enables?)\b[^.!?;\r\n]{0,50}\bLaunchAgent\b/gi;
const readsCDPResponse = /\bawait\s+\w+\([^\r\n,]{1,70},\s*['"]Network\.getResponseBody['"]/g;
const interceptsBrowserConnections = /\b(?:MITM|man-in-the-middle|intercept(?:s|ion)? requests?)\b/i;
const persistentBrowserHook = /\b(?:persistent|persisted)\b[^\r\n.!?;]{0,85}\b(?:hooks?|JavaScript|JS|injection|script)\b|\b(?:inject\w*(?: JavaScript| JS)?\b[^\r\n.!?;]{0,55}\b(?:every page|page loads?|navigation)|addScriptToEvaluateOnNewDocument)\b/gi;
const privateCredentialBypass = /\b(?:bypass|go around)\b[^\r\n.!?;]{0,65}\b(?:tooling|tools?|limitations?|restrictions?|approved|permission)\b|\bapproved\b[^\r\n]{0,150}\bbypass\b/gi;
const dynamicallyImportsLocalModule = /\bawait import\s*\(\s*[\w$]+\s*\)/;
const dependencyFromArgument = /\bdependencies[ \t]*:[ \t]*\{[^{}]{0,60}\[([A-Za-z_]\w*)\][ \t]*:[ \t]*["']\*["']/g;
const authenticationCoercion = /\b(?:(?:coerce|coercion|force)\b[^\r\n.!?;]{0,65}\b(?:auth|authentication)|(?:auth|authentication)\s+coercion)\b/gi;
const downloadsToFile = /\b(?:curl|wget|Invoke-WebRequest)\b[^\r\n]{0,155}\s(?:-o|-O|-OutFile)\s+["'$]/i;
const releaseOrigin = /(?:github\.com|api\.github\.com)\/(?:[\w./-]+|\$\{?\w+\}?)\/releases\b/gi;
const overrideableReleaseOrigin = /github\.com\/\$\{?\w+\}?\/releases\b|\$\{[A-Z0-9_]*(?:RELEASE|DOWNLOAD)[A-Z0-9_]*:-https:\/\/github\.com\//i;
const executableRelease = /\b(?:chmod[ \t]+(?:\+x|0?755)\b|Start-Process\b|exec\s+["'$]|Expand-Archive\b)/i;
const executableZipSource = /\bconst[ \t]+([a-z_]\w*)[ \t]*=[ \t]*["']https:\/\/[^"'\r\n]{1,260}\.zip["']/gi;
const proceedsWithoutReleaseIntegrity = /\b(?:continuing|proceeding) without (?:checksum|signature) verification\b|\b(?:SKIP|NO)_(?:CHECKSUM|VERIFICATION)\b/i;
const downloadsLatestReleaseBinary = /\bdownload (?:the )?(?:asset|binary|executable)(?:[ \t]+and matching [`]?\.sha256[`]?)?[ \t]+from (?:the )?latest GitHub Release\b/gi;
const configuredShellInstaller = /^[ \t]*curl\b[^\r\n]{0,85}\bhttps:\/\/raw\.githubusercontent\.com\/[\w${}.\/-]{1,180}\/install(?:-[\w.-]+)?\.sh["']?[ \t]*\\\r?\n[ \t]*\|[ \t]*(?:[A-Z][A-Z0-9_]*=(?:"[^"\r\n]{0,110}"|[^\s;|]{1,110})[ \t]+){1,8}(?:bash|sh)\b/gm;
const mentionsReleaseIntegrity = /\b(?:sha256|sha256sum|checksum|signature)\b/i;
const nativeArtifactUsesMD5 = /\bmd5\.convert\([^\r\n]{0,100}\breadAsBytes\s*\(/i;
const anonymousEndpoint = /\b(?:anonymous|unauthenticated|no authentication)\b/gi;
const remoteToolEndpoint = /https?:\/\/[^\s'"\x60)]+\/mcp\b/i;
const registersAgentTools = /\b(?:agent configs?|agent configuration|register[^\r\n]{0,40}MCP server)\b/i;
const mediaPolicyFallback = /\bmoderation (?:fallback|block)\b(?=[\s\S]{0,230}\b(?:moderation_blocked|policy refusal|alternative provider|fallback)\b)/gi;
const mediaRequestsModerationBypass = /\b(?:past moderation|bypass(?:ing)? (?:content )?moderation)\b/gi;
const preservesRealIdentity = /\b(?:real person|real human face|preserv\w* (?:the )?(?:same )?(?:identity|likeness))\b/i;
const personalTimeline = /\bpattern[- ]of[- ]life\b/gi;
const personLocation = /\b(?:geolocat\w*|location-bearing)\b/i;
const personalActivitySource = /\b(?:public posts|posting.time|social posts|posting patterns)\b/i;
const swapsIdentity = /\b(?:swap|substitut|replac)\w*\b[^.!?;\r\n]{0,85}\b(?:user['’]?s|real) [^.!?;\r\n]{0,16}OAuth token\b/gi;
const playerAnalytics = /\b(?:playtest|gameplay|player)\b[^\r\n.!?;]{0,80}\b(?:instrumentation|analytics|telemetry)\b/i;
const savesAnalytics = /\b(?:FileAccess\.WRITE|FileAccess\.READ_WRITE|fs\.appendFile|writeFileSync)\b/gi;
const persistentPlayerIdentity = /\b(?:player[_ -]?id|persistent player|unique player identifier)\b/i;
const informsPlayer = /\b(?:obtains? (?:user |player )?consent|opt[ -]in|privacy notice|inform(?:s)? (?:the )?player)\b/i;
const disablesDaemon = /\b(?:disable\w*|turn off|kill)\b[^\r\n.!?;]{0,80}\b(?:daemons?|service processes?)\b|\bdaemon.disable\b/i;
const latestHostTool = /\bgo\s+install\s+[a-z0-9.-]+\/[^\s\x60]+@latest\b/gi;
const completeTemplate = /\bcomplete\b[^\r\n.!?;]{0,40}\bimplementation\b/i;
const stubbedArtifact = /\breturn\s*\{[^\r\n]{0,45}["']?url["']?\s*:\s*f?["']https?:\/\/[\w.-]+\/[\w./-]+["'][^\r\n]{0,125}\bcost["']?\s*:/gi;
const disclosesTemplateStub = /\b(?:stub|mock implementation|placeholder (?:function|implementation|response)|demo only|sample output)\b/i;
const inPlacePackageEdit = /\bsite-packages\/[\w./-]+\b[\s\S]{0,45}\bin-place\b/gi;
const hooksPackagePatch = /\b(?:wire|add|register|run)\s+(?:it|the patch\w*)\s+(?:into|in|as|after)\s+(?:(?:a|the|your)\s+)?(?:post|pre|every|each|build|install|refresh)\b/i;
const directsEndorsement = /\brecommend (?:to )?the user\b[\s\S]{0,700}\bthis is the best way\b/gi;
const fixedPromotionalFooter = /^#{2,5}[ \t]+引流信息[^\r\n]{0,35}每次输出[^\r\n]{0,25}必须追加/gmu;
const fixedPromotionalGreeting = /(?:本次|每次|每轮)对话(?:的)?第一次[ \t]*触发[^\r\n。]{0,110}在(?:回答|回复)(?:的)?开头(?:固定)?(?:显示|输出|加入)(?:一次|一段)/gu;
const trackedPaidProductPitch = /\*\*\[[^\]\r\n]{8,135}\]\(https:\/\/[^)\s]{1,200}[?&](?:source|ref|utm_source)=[^)\s]{1,100}\)\*\*[^\r\n]{0,350}\b(?:one payment|one-time payment|pay once),[ \t]*live (?:setup|onboarding) with (?:me|our team)\b/gi;
const mismatchedMailSignIn = /(?:登录[^。！？\r\n]{0,35}(?:电子邮件|邮箱)[^。！？\r\n]{0,25}(?:通过|访问)|\b(?:sign|log)[ \t]+in[ \t]+to[ \t]+(?:Gmail|Google mail)[ \t]+(?:with|at|using))[^。！？\r\n]{0,20}https?:\/\/(?:www\.)?mailgoogle\.com(?=[/?#\s)\x60"'<>]|$)/giu;
const unverifiedDownloadReason = 'The instruction downloads an executable, installer, or release asset without an evident integrity check.';
const mutableRuntimeSourceReason = 'The referenced source can change after installation and affect the instructions or code the agent uses.';
const assertsBrowserDefault = /\bthe user installed it precisely so (?:agents?|assistants?) default here unprompted\b/gi;
const addsStreamableHttpServer = /\badd (?:it|the endpoint|this URL) as a streamable HTTP MCP server named [`"']?[\w.-]+\b/gi;
const dismissesTrustWithKeystrokes = /\btrust prompts? (?:are )?auto[- ]dismissed via [`"']?pane\.send_keys\b/gi;
const readsPaneDisplay = /\b(?:pane glance|pane capture)\b[^\r\n.!?;]{0,140}\boutput can contain whatever the pane displays\b/gi;
const taskSnapshotTextFields = /^[ \t]*-[ \t]+[\x60]?notes_excerpt[\x60]?[ \t]*\r?\n[ \t]*-[ \t]+[\x60]?recent_comment_excerpts[\x60]?[ \t]*$/gim;
const hostedCiInstaller = /^[ \t]*-?[ \t]*run:[ \t]*curl\b[^\r\n]{0,45}\bhttps:\/\/[\w.-]+\.pages\.dev\/install\.sh[ \t]*\|[ \t]*(?:bash|sh)\b/gim;
const directsPaidBadgePitch = /\btell (?:your human|the user) once,[ \t]+with[ \t]+`?badge\.upgrade_url\b/gi;
const createsHostedDesignWithoutAsking = /作業用のデザイン[^。\r\n]{0,100}自分で作る[^。\r\n]{0,90}ユーザーに断らず[、, \t]*確認も求めない/gu;
const marketplaceSkillDownloadLink = /^[ \t]*curl[ \t]+[^\r\n]{0,60}https:\/\/([\w.-]+)\/api\/skills\/<skill-id>\/download\b/gim;
const wakesBeforeDialogResolves = /\bby default the wake rings a plain doorbell\s*\(text and Enter, never held for a\s+dialog\)/gi;
const drainsPeerMessageBodies = /\brun[ \t]+`?[\w.-]+[ \t]+drain[ \t]+--include-body`?[^.!?;\r\n]{0,70}\bact on the messages\b/gi;
const defaultsToHostedSecrets = /\buploading the user['’]s local secrets\b[^\r\n]{0,200}\bimport them by default\b/gi;
const fillsStoreCredentialPayload = /\bshopify_access_token[ \t]*:[ \t]*process\.env\.SHOPIFY_ACCESS_TOKEN[ \t]*,[ \t]*customer_email[ \t]*:/gi;
const ignoresAssignmentIntegrity = /无需顾虑学术诚信边界/gu;
const readsRemoteAssignment = /\b[\w.-]+[ \t]+canvas[ \t]+assignment[ \t]+detail\b/gi;
const authenticatedRead = /\b(?:api|mcp)\b(?![ _-]+(?:keys?|tokens?|credentials?)\b)[^.!?;\r\n]{0,45}\b(?:read|search|query|retrieve|fetch|results)\b|\b(?:read|search|query|retrieve|fetch|results)\b[^.!?;\r\n]{0,45}\b(?:api|mcp)\b(?![ _-]+(?:keys?|tokens?|credentials?)\b)/gi;
const discussionReader = /\b(?:gog[ \t]+gmail|gmail|outlook|slack|jira|linear|notion)[ \t]+(?:(?:issues?|messages?|threads?|mail|history|tickets?|pages?)[ \t]+)?(?:get|read|search|list|history)\b/gi;
const workspaceMailFromMessage = /^[ \t]*\x60?gws[ \t]+gmail[ \t]+\+(?:forward|reply-all)[ \t]+[^\r\n\x60]{0,140}--message-id(?:[ \t]+|=)\S+/gim;
const workspaceMailStream = /^[ \t]*\x60?gws[ \t]+gmail[ \t]+\+watch(?=[ \t\r\n\x60]|$)[^\r\n\x60]*/gim;
const workspaceChatMessages = /^[ \t]*-[ \t]+\x60messages\x60[ \t]+[—–-][ \t]+Operations on the ['"]messages['"] resource/gim;
const linkedTrackerWorkItem = /\bworking (?:from|on) a linked (?:Linear|Jira)\s+(?:issue|ticket)\b/gi;
const readsWorkspacePage = /\b(?:read|reading) (?:an? |the )?pages?(?:['’]s)? (?:properties and )?(?:content|body)\b/gi;
const editableWebCapture = /\bcaptur(?:e|es) a live (?:URL|web ?page) as an editable\b[^.!?;\r\n]{0,70}\bproject\b/gi;
const readsRawRegistry = /\binspect the raw manifest as a fallback\b[\s\S]{0,145}https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/[\w./-]+\/registry\.json\b/gi;
const sharedMarketplaceImages = /\|[^|\r\n]{0,65}--imagetype\b[^|\r\n]*\|[^|\r\n]{0,35}\blist_images\b[^|\r\n]*\|[^|\r\n]{0,65}\bshared\b[^|\r\n]{0,35}\bmarket(?:place)?\b/gi;
const readsTargetSkillInstructions = /\bread (?:the )?YAML frontmatter from [`]?SKILL\.md[`]?[^\r\n]{0,100}\r?\n[ \t]*\d+[.)][ \t]+extract (?:the )?(?:core )?commands?\b/gi;
const voucherWriteTestCase = /"command"[ \t]*:[ \t]*"(?:reclaim|revoke)_[\w]*coupons?\(coupon_id=[^"\r\n]{1,55}\)"[\s\S]{0,180}?"is_write"[ \t]*:[ \t]*true\b/gi;
const contentTool = /\b(?:get|list|read|fetch|search|retrieve)[-_ ](?:posts?|messages?|threads?|comments?|emails?|issues?|tickets?|documents?|pages?|reviews?|articles?)\b/gi;
const contentRequest = /\b(?:fetch|read|get|list|search|pull|retrieve|find|scrape)\b[^.!?;\r\n]{0,55}\b(?:threads?|comments?|messages?|emails?|invoices?|issues?|documents?|tickets?|reviews?|posts?|articles?|pull requests?|transcripts?|events?|content)\b/i;
const remoteDescription = /^(?:description|summary):[^\r\n]{0,350}\b(?:fetch|scrap|browse|search(?:es)?|retriev(?:e|es)|external|public data|web automation|github|forum|social media)\b/im;
const queryArgument = /\b(?:q=|query=|search\??:|query\??:|searchTerms|searchQuery|search_query)\b/gi;
const remoteApiHost = /https?:\/\/(?:api\.|[a-z0-9-]+\.api\.)[a-z0-9.-]+/i;
const inputTransform = /\b(?:returns? (?:the )?corrected query|for spell correction|only for (?:query|input) (?:cleanup|normalization|validation))\b/i;
const suppliedLinks = /\b(?:url|link)\b[^.!?;\r\n]{0,36}\b(?:provided|supplied|given|pasted|from the user(?!-))\b|\b(?:provided|supplied|given|pasted)\b[^.!?;\r\n]{0,30}\b(?:urls?|links?)\b/gi;
const reportsGeneratedLink = /^(?:provided|supplied|given|pasted)\b[^.!?;]{0,16}\b(?:prints?|returns?|outputs?|generates?)\b[ \t]+(?:(?:both|the|a|an|new)[ \t]+)?(?:urls?|links?)\b/i;
const developmentFeedback = /\b(?:read|retrieve|inspect|fetch|check|collect|act on|address|ingest|summari[sz]e)\b[^.!?;\r\n]{0,75}\b(?:CI (?:failure )?(?:output|logs?)|(?:PR|pull request|merge request|code review) (?:review )?(?:comments?|feedback)|external (?:CI|test) logs?)\b|\b(?:read|summari[sz]e|fetch|analy[sz]e|inspect|collect|parse)\b[^.!?;\r\n]{0,55}\b(?:commit messages?|repository (?:commit )?history|(?:PR|pull request) diffs?)\b/gi;
const renderedContent = /\b(?:read|extract|parse|fetch|inspect|analy[sz]e|browse|render|capture)\b[^.!?;\r\n]{0,55}\b(?:the DOM|page DOM|rendered DOM|rendered page text|page contents?|web page text)\b/gi;
const calendarContext = /\b(?:calendar|meeting invitations?|invitees?)\b/i;
const calendarRead = /\b(?:list[_-]events?|get[_-]events?|list[_-]invitees|list[_-]bookings)\b/gi;
const calendarReadCommand = /\bgog[ \t]+calendar[ \t]+events\b[^\r\n|]{0,95}--(?:json|wrap-untrusted)\b/gi;
const documentIntake = /\b(?:convert|extract|process|render|transform)\b[^.!?;\r\n]{0,60}\b(?:user[- ](?:provided|supplied)|uploaded|source)\s+(?:markdown|HTML|PDFs?|documents?|text|bank statements?)\b/gi;
const mediaIntake = /\b(?:transcribe|dub|extract\s+(?:speech|dialogue|transcripts?|captions?))\b[^.!?;\r\n]{0,62}\b(?:videos?|audio|recordings?|podcasts?)\b/gi;
const extractsMediaSession = /\bextract\b[^.!?;\r\n]{0,48}\b(?:m3u8|HLS)\b[^.!?;\r\n]{0,58}\b(?:cookies?|session tokens?)\b/gi;
const mediaTextWorkflow = /\b(?:transcript\.(?:json|txt|md)|(?:YouTube|TikTok)\s+(?:video|link|URL)|(?:audio|video|recording|podcast) (?:URL|stream)|hosted media|(?:read|parse|summari[sz]e|translate) (?:the |its )?(?:transcript|transcribed text))\b/i;
const remoteTranscriptionInput = /^[ \t]*\|[ \t]*\x60(?:audio_url|source_url|cloud_storage_url|media_url)\x60[ \t]*\|[^\r\n]{0,200}\b(?:https?|url)\b[^\r\n]{0,110}\btranscrib\w*\b/gim;
const usesRemoteTranscriptionInput = /\b(?:audio_url|source_url|cloud_storage_url|media_url)[ \t]*=[ \t]*["']https:\/\//i;
const readsTranscriptionOutput = /\b(?:result|response)\.text\b|\b(?:return|outputs?|reads?)\w*\b[^\r\n.!?;]{0,55}\b(?:transcripts?|transcribed text)\b/i;
const remoteVideoAnalysis = /\bPOST[ \t]+https:\/\/[^\s"'`/]+(?:\/[\w.-]+){0,12}\/video[-_]analy[sz]e(?:\/call)?(?=[^\w/-]|$)[\s\S]{0,240}["']video_url["'][ \t]*:[ \t]*["'][^"'\r\n]{1,200}["']/gi;
const evaluatesVideoText = /\b(?:claims?|quotes?|text)\s+from\s+the\s+transcript\s*,\s*on[- ]screen\s+(?:text|copy)\b/i;
const runsUnpinnedAppEvaluator = /\b(?:verify|check)\b[^\r\n]{0,125}\brunning (?:app|application)\b[^\r\n]{0,110}\b(?:bunx|npx|pnpm[ \t]+dlx)[ \t]+((?:@[\w.-]+\/)?[\w.-]+)[ \t]+([\w-]+)[ \t]+eval\b/gi;
const readsDependencyAnnotations = /\bresolve\b[^\r\n]{0,115}\b(?:module|import)\b[^\r\n]{0,110}\bnode_modules\b[\s\S]{0,270}\b(?:look for|read|inspect)\b[^\r\n]{0,110}@deprecated\b[^\r\n]{0,45}\bJSDoc\b/gi;
const acceptsPublicMedia = /\baccept (?:a |an )?(?:public|authorized)(?: or authorized)? URL\b/i;
const resolvesPublicTranscript = /\bresolve the exact page\b[^.!?;\r\n]{0,150}\b(?:media or transcript|transcript or media)\b/gi;
const createsTimestampedTranscript = /\b(?:produce|create|prepare|generate)\b[^.!?;\r\n]{0,80}\btimestamped transcript\b/i;
const consumedHttpResponse = /\b(\w+)\s*=\s*(?:requests|httpx)\.get\([\s\S]{0,170}\b\1\.(?:json|text|content)\b/g;
const sessionHttpResponse = /\b(\w+)\s*=\s*(?:\w+\.get\(|(?:requests|httpx)\.request\([ \t]*["']GET["']|(?:urllib\.request\.)?urlopen\()[\s\S]{0,205}\b\1\.(?:json\(|text\b|content\b|read\()/g;
const readExplicitEndpoint = /\b(?:requests|curl|httpx|fetch|http\.get|axios\.get)\b[^\r\n]{0,120}https?:\/\/(?!localhost\b|127\.0\.0\.1\b)[^\s"'\x60/][^\r\n]{4,90}[\s\S]{0,120}\b(?:response\.(?:text|json|content|read)|JSON\.parse)\b/gi;
const chineseExternalRead = /(?:读取|获取|搜索|抓取|浏览|查询|检索|收集|爬取|解析|总结)[^。！？；\r\n]{0,30}(?:网页|网站|搜索结果|公开帖子|外部内容|第三方内容|论坛帖子|用户提供的链接|评论|邮件|聊天记录)/g;
const remoteCodeInstall = /\b(?:pip3?[ \t]+install|npm[ \t]+install|pnpm[ \t]+add|uv[ \t]+pip[ \t]+install|(uv[ \t]+tool[ \t]+install))\b[^\r\n]{0,70}\bgit\+https?:\/\/[^\s'"\x60]+/gi;
const usesMutableRemoteCodemod = /^[ \t]*(?:\$[ \t]+)?(?:npx|bunx|pnpm[ \t]+dlx)[ \t]+(?:(?:-y|--yes)[ \t]+)?jscodeshift[ \t]+(?:-t|--transform)(?:[ \t]+|=)(['"]?)https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/(?:refs\/heads\/)?(?:main|master)\/(?:[\w.-]+\/){0,12}[\w.-]+\.[cm]?[jt]s\1[ \t]+(?!-)[\w./-]+(?=[ \t\r\n]|$)/gim;
const plainHttpPackageIndex = /\b(?:pip3?|uv[ \t]+pip)[ \t]+install\b[^\r\n]{0,175}[ \t]--(?:extra-)?index-url(?:[ \t]+|=)["']?http:\/\/([\w.-]+)\//gi;
const exampleRuntimeScript = /\b(?:eval|Function)`?(?:\(\))?`?[^\r\n]{0,90}\b(?:fetched|downloaded|loaded) from[ \t]+`?https?:\/\/[\w.-]+\/[^\s"'`<>]{0,100}\bpayload\.js\b/gi;
const remoteModule = /\b(?:import[ \t]+(?:[\w*, \t{}]{1,140}[ \t]+from[ \t]+)?|import[ \t]*\([ \t]*)["']https?:\/\/[^"' <>]+['"]/g;
const registryModule = /\b(?:Module|require)\([ \t]*["'](?:github\.com|gitlab\.com|codeberg\.org)\/[\w./-]+\.(?:zen|js|ts|py|sh)["']/gi;
const hostedPackageCommand = /\b(?:npx|bunx|pnpm[ \t]+dlx|npm[ \t]+exec)[ \t]+(?:(?:-y|--yes)[ \t]+)?[\x60"']?github:[\w.-]+\/[\w.-]+(?:#([\w./-]+))?/gi;
const runtimeSchema = /\b(?:reads?|fetch(?:es)?|loads?|retriev(?:e|es))\b[^.!?;\r\n]{0,70}\b(?:Discovery Service|remote API schema|API discovery document|remote OpenAPI)\b[^.!?;\r\n]{0,65}\b(?:at runtime|on every run|dynamically)\b/gi;
const requiredRegistryCommand = /\b(?:npx|bunx|uvx|pnpm dlx)\s+(?:-y|--yes)\s+(?:@[\w-]+\/)?[\w.-]+(?:@[\w.-]+)?\s+\w[\w-]*/gi;
const mutableRegistryInstructions = /^[ \t]*((?:npx|bunx|pnpm[ \t]+dlx)[ \t]+(?:-y|--yes)[ \t]+(?:@[\w.-]+\/)?[\w.-]+(?:@(?:latest|\d+(?:\.\d+)?))?)[ \t]+instruct[ \t]+([\w.-]+)[ \t]*\r?$/gim;
const installsUnpinnedBackgroundService = /\bnpm[ \t]+(?:i|install)[ \t]+-g[ \t]+([a-z\d-]+)(?=[\s`]|$)/gi;
const readsHumanTestReport = /\/api\/skill\/status\/<[\w-]+>/gi;
const companionSkillInstall = /\b(?:must|required|first|before)\b[^.!?;\r\n]{0,110}\b(?:npx|bunx|pnpm dlx)[ \t]+skills[ \t]+add[ \t]+(?:https:\/\/github\.com\/)?[\w.-]+\/[\w.-]+/gi;
const remoteCompanionSkillUse = /^[ \t]*(?:npx|bunx|pnpm[ \t]+dlx)[ \t]+skills[ \t]+use[ \t]+[\w.-]+\/[\w.-]+[ \t]+--skill[ \t]+[\w.-]+[ \t]*\r?$/gim;
const bootstrapsReleasedPluginCli = /\bbootstrap the released CLI into\b[^\r\n]{0,110}\binstall\.(?:sh|ps1)\b[^\r\n]{0,160}\bcontinue without asking the user to install the CLI\b/gi;
const latestInstallerCommand = /^[ \t]*(?:npx|bunx|pnpm[ \t]+dlx)[ \t]+(?:--yes[ \t]+|-y[ \t]+)?@[\w.-]+\/[\w.-]+@latest[ \t]*\r?$/gim;
const isolatedToolInstaller = /^[ \t]*uvx[ \t]+--from[ \t]+([\w.-]+)[ \t]+\1[ \t]+install[ \t]*\r?$/gim;
const gitToolSetup = /^[ \t]*uvx[ \t]+--from[ \t]+git\+https:\/\/(?:github\.com|gitlab\.com|codeberg\.org)\/[\w.-]+\/[\w.-]+@v\d+\.\d+\.\d+[ \t]+[\w.-]+[ \t]+(?:init|setup)(?=[ \t\r\n]|$)/gim;
const unpinnedGitTool = /^[ \t]*(?:\$[ \t]+)?uvx[ \t]+--from(?:[ \t]+|=)(["']?)git\+https:\/\/(?:github\.com|gitlab\.com|codeberg\.org)\/[\w.-]+\/[\w.-]+(?:@(?:main|master|HEAD))?\1[ \t]+[\w.-]+(?=[ \t\r\n]|$)/gim;
const pinnedRegistryInitializer = /\bnpx[ \t]+(?:@[\w.-]+\/)?[\w.-]+@\d+\.\d+\.\d+[ \t]+init[ \t]+--no-skills\b/gi;
const runsRemoteGoTool = /^[ \t]*go[ \t]+run[ \t]+(?:github\.com|gitlab\.com|codeberg\.org)\/[\w./-]+@v\d+\.\d+\.\d+[ \t]+(?:lint|build)(?=[\s`]|$)/gim;
const fetchesRemoteDocsForAnswer = /\bfetch the docs from the URL above using[ \t]+`?WebFetch`?[ \t]+and use (?:it|the docs) to (?:provide|generate|write)\b/gi;
const gatewaySetupGuide = /^[ \t]*(?:[-*][ \t]+)?Setup (?:steps|instructions) for agents:[ \t]+<?https:\/\/([\w.-]+)\/llms\.txt\b/gim;
const readsVersionedDocIndex = /\bcall[ \t]+\x60get_doc\x60[ \t]+with[ \t]+\x60\/llms\.txt\x60[ \t]+to resolve[^.!?;\r\n]{0,105}\bversion\b/gi;
const trackedGatewayLink = /https:\/\/([\w.-]+)\/mcp\?[^\s<>)"']*\butm_(?:source|campaign)=/gi;
const liveGatewayConnection = /\blive accounts?\b[^.!?;\r\n]{0,80}\bconnect (?:the |to (?:the )?)?[^.!?;\r\n]{0,80}\bgateway\b/i;
const gatewaySignIn = /\bsign in with OAuth or (?:the )?device flow\b/i;
const gatewayUserApproval = /\b(?:ask|confirm|request)\b[^.!?;\r\n]{0,60}\b(?:approval|consent|permission)\b|\bonly (?:after|if) (?:the )?user\b/i;
const opensSuppliedExternalDocument = /\[INVOKE:(?:fetch|read)_[\w]+_(?:doc|document)\]/gi;
const installsFromSearchResult = /\bskills[ \t]+install[ \t]+<install_ref>/gi;
const requiredStep = /\b(?:must|requires?|required|first|before|mandatory|whenever|at startup|on every)\b/i;
const illustrativeStep = /\b(?:only an example|for (?:illustration|reference) only|(?:do not|don't|never|must not)\s+(?:run|execute|invoke|install))\b/i;
const asksBeforePluginInstall = /\b(?:ask(?: the user)?|(?:get|obtain|request) (?:explicit )?(?:approval|permission|consent)) before installing\*{0,2} (?:any |a |the )?(?:hooks?|plugins?)\b/i;
const checksPackageRegistry = /\b(?:check|consult|search) (?:the |a )?(?:public )?package registry for (?:the )?(?:latest|current)\b/i;
const consultsExternalSource = /\b(?:consult|read|inspect)\b[^.!?;\r\n]{0,160}\bdocs\b[^\r\n]{0,200}\b(?:implementation|source code)\b[^\r\n]{0,25}\bgithub\.com\/[\w.-]+\/[\w.-]+\//gi;
const concealsVerificationGate = /\binternal (?:verification )?gate\b[^\r\n]{0,35}\brun (?:it|them)[,;][ \t]*(?:never|do not|don't) narrate (?:it|them)\b/gi;
const grantsCleanupWriteScope = /\b(?:grant|add|enable)\b[^.!?;\r\n]{0,95}\bwrite scope\b[^.!?;\r\n]{0,85}\b(?:remove|delete)\b[^.!?;\r\n]{0,35}\b(?:leftover|offline|ephemeral|stale)\b[^.!?;\r\n]{0,45}\b(?:nodes?|devices?|runners?|instances?)\b/gi;
const scopeAllowsWorkspaceRemoval = /\b(?:scope|permission) (?:allows|permits|can)\b[^.!?;\r\n]{0,55}\b(?:remove|delete|removing|deleting) (?:all )?(?:nodes?|devices?|runners?|instances?) (?:across|throughout|in) (?:the )?(?:whole|entire) (?:network|tailnet|workspace|organization|account)\b/i;
const readsActionsJobLogs = /\b(?:call|run|use)[ \t]+`?(?:\w+_)?(?:search|read|get|fetch)_github_actions_(?:logs|log_context)\b/gi;
const citesCapturedCiLog = /\bread (?:its|the) captured (?:job )?log\b[^\r\n]{0,75}`[\w.]+\.logs\[\]\.file`[\s\S]{1,340}\bverbatim log lines\b/gi;
const claimsLocalResourcesAfterLogin = /^[ \t]*(claim_(?:local|pending)_(?:trial_)?(?:sites|apps|projects|deployments|resources))[ \t]+["']?\$\{?\w+/gm;
const pythonHostCommandLink = /^[ \t]*(?:sudo[ \t]+)?ln[ \t]+-[a-z]*s[a-z]*[ \t]+["']?(?:\$\(pwd\)\/|\.\/)?([\w./-]+\.py)["']?[ \t]+["']?\/usr\/local\/bin\/[\w.-]+\b/gm;
const pythonConfigCredentialUse = /(?:["']Authorization["']\s*\]\s*=\s*f["']Bearer \{|\bos\.environ\s*\[["']\w+["']\]\s*=\s*)([a-zA-Z_]\w*)\.([A-Z_]\w*(?:KEY|TOKEN))\b/g;
const pythonExternalNodeHelper = /^[ \t]*([a-z_]\w*)\s*=\s*["'](\/(?:[^/"'\r\n]+\/)+skills\/[\w.-]+\/[\w./-]+\.[cm]?js)["']/gm;
const envRegistryPackage = /^[ \t]*(?:const|let)[ \t]+([a-zA-Z_$][\w$]*)[ \t]*=[ \t]*process\.env\.[A-Z_]\w*[ \t]*\|\|[ \t]*(?:DEFAULT_[A-Z_]\w*|["'][\w@/.-]+["'])/gm;
const delegatedPublicBrowse = /\bopen the target URL or (?:the )?(?:best )?public search URL\b/gi;
const detectorScoredRewrite = /\b(?:generate|produce|draft|write)\b[^.!?\r\n]{0,55}\b(?:variants|rewrites|paraphrases)\b[\s\S]{0,110}\b(?:score|test|evaluate) each (?:one )?(?:against|with|using) (?:a |an )?(?:real |AI[- ]text |AI )?detector\b[\s\S]{0,155}\b(?:ship|choose|pick|select|return) the lowest\b/gi;
const disclosesAccountAdoption = /\b(?:automatically claims?|claims? (?:all |any |existing )?(?:local|pending))\b[^.!?;\r\n]{0,85}\b(?:sites|apps|projects|deployments|resources)\b/gi;
const latestGoModule = /\bgo[ \t]+install[ \t]+(?:github\.com|gitlab\.com|codeberg\.org)\/[\w./-]+@latest\b/gi;
const shellFromVariableUrl = /\b(?:curl|wget)\b[^|\r\n]{0,110}(?:\$\{?[a-z_]\w*|<[^>\r\n]{1,35}>)[^|\r\n]{0,75}\|[ \t]*(?:bash|sh|zsh|pwsh)\b/gi;
const executeTempDownload = /\b(?:curl|wget)\b[^\r\n]{0,190}(?:-o|--output)[ \t]+["']?(\/tmp\/[\w.-]+)[^\r\n]{0,80}[\s\S]{0,160}\b(?:bash|sh|zsh|python3?)\s+["']?\1(?![\w.-])/g;
const runsPythonFromUnverifiedDownload = /\burllib\.request\.urlretrieve\([ \t]*\w+,[ \t]*(\w+),[ \t]*context[ \t]*=[ \t]*(\w+)[ \t]*\)[\s\S]{0,420}\b(?:run_cmd|subprocess\.(?:run|check_call))\(\[[ \t]*sys\.executable,[ \t]*\1\b/g;
const remoteBootstrapMetadata = /^[ \t]*(\w+)[ \t]*=[ \t]*json\.loads\(urllib\.request\.urlopen\([^\r\n]{0,120}$/gm;
const systemChange = /\b(?:Enable|Disable|Start|Stop|Restart|Configure|Modify|Change|Edit|Update|Install|Create|Remove|Add|Delete|Grant|Revoke)\b[^.!?;\r\n]{0,70}\b(?:system(?:d)? services?|system service configuration|service on (?:boot|startup)|firewall|security (?:settings|configuration|polic(?:y|ies))|antivirus|host (?:users?|accounts?|permissions?)|system (?:users?|accounts?|permissions?|files)|startup (?:services?|items?|agents?|tasks?)|scheduled (?:system|startup) task)/gi;
const systemCommand = /\b(?:systemctl[ \t]+(?:start|stop|enable|disable|restart|mask|unmask|edit|daemon-reload)|launchctl[ \t]+(?:load|unload|bootstrap|bootout|enable|disable)|(?:useradd|userdel|usermod)\b|(?:Set-Service|New-Service|sc\.exe)[ \t]+[\w-]+)/gi;
const loadsScheduledLaunchAgent = /\blaunchctl[ \t]+load[ \t]+["']?\$\{?([a-z_][\w]*)\}?["']?(?=[\s;]|$)/gi;
const enablesNewLinuxService = /\bsudo[ \t]+(?:yum|dnf|apt(?:-get)?)[ \t]+install(?:[ \t]+-y)?[ \t]+([\w.-]+)[ \t]*\r?\n[ \t]*sudo[ \t]+systemctl[ \t]+start[ \t]+\1(?:\.service)?[ \t]*\r?\n[ \t]*sudo[ \t]+systemctl[ \t]+enable[ \t]+\1(?:\.service)?\b/gi;
const installsPythonPrerequisite = /\bsudo[ \t]+apt[ \t]+update[ \t]*&&[ \t]*sudo[ \t]+apt[ \t]+install[ \t]+python3\b/gi;
const startsServiceDuringHostSetup = /\binstalls the latest release and starts the service\b/gi;
const elevatedSetupExample = /\bshell\.run_interactive\([ \t]*['"]sudo[ \t]+[^\r\n'"]{2,110}['"]\)/gi;
const writesWindowsRegistry = /^[ \t]*(?:Set|New|Remove)-ItemProperty[ \t]+[^\r\n]{0,90}\bHK(?:CU|LM):\\/gim;
const serviceLifecycleCommand = /\x60[\w.-]+[ \t]+(?:service|daemon)[ \t]+(?:install|uninstall|register|unregister)\b[^\x60\r\n]{0,70}\x60/gi;
const setupSystemService = /\b[\w.-]+[ \t]+setup\b[^\r\n`]{0,135}--systemd\b/gi;
const receivesMailReports = /\b(?:shows?|lists?|reads?|retrieves?)\b[^\r\n]{0,70}\b(?:DMARC|TLS)[ \t]+reports?\b[^\r\n]{0,60}\b(?:from|by)[ \t]+(?:remote[ \t]+)?(?:receivers|mail servers)\b/gi;
const pullsSelectedContainer = /\b(?:spawn|execFile)(?:Sync)?\([ \t]*['"]docker['"][ \t]*,[ \t]*\[[ \t]*['"]pull['"][ \t]*,[ \t]*\w+\b/g;
const hostServiceContext = /\b(?:per.user service|scheduler service|host.level (?:scheduler|service)|system service)\b/i;
const systemConfigWrite = /\b(?:write|edit|append|replace|modify|update|change|sudo[ \t]+tee)\b[^\r\n]{0,65}\/etc\/(?:ssh\/|systemd\/|udev\/|sudoers\b|sysctl\b)/gi;
const urlPattern = /\bhttps?:\/\/[^\s<>"'\x60|)]+/gi;
const urlIncludesCredentialPair = /\bhttps?:\/\/[^\s/:?#@"'`]+:[^\s/?#@"'`]+@[\w.-]+/i;
const documentedPort = /^(https?:\/\/[\w.-]+):(?:PORT|\$\{PORT\})(?=\/)/i;
const downloadAction = /\b(?:download|install|execute|launch|run|fetch|retrieve|load|pull|clone|curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b/i;
const runtimeUse = /\b(?:as (?:the |its )?(?:runbook|instructions?|prompts?|configuration)|(?:follow|obey|apply|execute|run|eval|source|load|install|import)\b[^.!?;\r\n]{0,55}\b(?:downloaded|fetched|returned|retrieved|remote|helper|script|binary|instructions?|runbook|contents?|package)|at runtime|on every (?:run|invocation)|latest release)\b/i;
const runtimeInstructions = /\b(?:as (?:the |its )?(?:runbook|instructions?|prompts?)|(?:follow|obey|apply)\b[^.!?;\r\n]{0,40}\b(?:remote|downloaded|fetched|returned|retrieved) (?:runbook|instructions?|prompts?))\b/i;
const artifact = /\.(?:sh|ps1|bat|cmd|exe|msi|pkg|dmg|zip|tar|tgz|gz|apk|deb|rpm|bin)(?:$|[?#])/i;
const requirementsBlock = /\brequirements\.txt\b[^\r\n]{0,200}\r?\n(?:[ \t]*\r?\n){0,2}[ \t]*\x60{3,}[^\r\n]*\r?\n([\s\S]{0,5000}?)\r?\n[ \t]*\x60{3,}/dgi;
const releaseWheel = /^[ \t]*(?:[\w.-]+[ \t]+@[ \t]+)?https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/releases\/download\/[^/\s]+\/[\w.%+-]+\.whl[ \t]*$/gim;
const downloadsSkillRelease = /^[ \t]*(?:curl|wget)[ \t]+[^\r\n]{0,60}https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/releases\/(?:latest\/download|download\/[\w.-]+)\/([\w.-]+\.tar\.(?:gz|xz))(?=[\s\\\x60'"]|$)/gim;
const installsSkillArchive = /\bcd[ \t]+["']?~\/\.(?:agents|claude|codex)\/skills\/?["']?[ \t]*(?:&&[ \t]*|\r?\n[ \t]*)tar[ \t]+-?x[a-z]*f[ \t]+["']?~\/([\w.-]+\.tar\.(?:gz|xz))\b/i;
const savesSkillArchive = /^[ \t]*(?:\\\r?\n[ \t]*)?-[oO][ \t]+["']?~\/([\w.-]+\.tar\.(?:gz|xz))\b/;
const readmeInstallerCommand = /^[ \t]*(?:curl|wget)[ \t]+[^\r\n]{0,85}https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/([\w.-]+)\/[\w.-]+\/install\.sh[ \t]*\|[ \t]*(?:bash|sh)\b/gim;
const shortener = /(?:^|\.)(?:bit\.ly|goo\.gl|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|ow\.ly|lnkd\.in|rebrand\.ly|shorturl\.at)$/i;
const downloadHost = /(?:^|\.)(?:drive\.google\.com|dropbox\.com|mega\.nz|mediafire\.com|pastebin\.com|anonfiles\.com|discordapp\.com)$/i;

const unsafeExecution = /\b(?:curl|wget)\b[^|\r\n]{0,180}\|[ \t]*(?:(?:sudo|env)\s+)?(?:bash|sh|zsh|ksh|dash|powershell|pwsh)\b|\b(?:Invoke-Expression|iex)\b[^\r\n]{0,100}\b(?:Invoke-WebRequest|Invoke-RestMethod|curl)\b/gi;
const executesRemoteFixtureResponse = /^[ \t]*(?:curl|wget)\b[^|\r\n]{0,120}\bhttps?:\/\/[^ \t|\r\n]{1,180}[^|\r\n]{0,80}\|[ \t]*(?:bash|sh|zsh)\b/gim;
const disablesTlsVerification = /\b(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]|rejectUnauthorized\s*:\s*false\b)/gi;
const externalTlsEndpoint = /\bhttps:\/\/(?!localhost\b|127\.0\.0\.1\b|example\.(?:com|invalid)\b)[\w.-]+/i;
const localCredentialReader = /\b(?:readFile(?:Sync)?\s*\(|(?:extract|read|resolve|load|find)(?:ApiKey|Key|Token)\b)/i;
const opensHttpConnection = /\b(?:fetch|https\.request|http2\.connect)\s*\(/i;
const remotePowerShellBootstrap = /\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^|\r\n]{0,130}https?:\/\/[^\s'"\x60|]+[^|\r\n]{0,60}\|[ \t]*(?:iex|Invoke-Expression)\b/gi;
const mutableWindowsInstallerPath = /https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/(?:main|master)\/([\w./-]+\.ps1)(?=[ \t"'\x60|])/i;
const windowsInstallerPolicy = /\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,100}-ExecutionPolicy[ \t]+Bypass\b/i;
const shellReleaseBootstrap = /\bcurl\b[^|\r\n]{0,130}(?:\\[ \t]*\r?\n[ \t]*)?https:\/\/github\.com\/([\w.-]+\/[\w.-]+)\/releases\/latest\/download\/([\w.-]+)\.sh[ \t]*\|[ \t]*(?:bash|sh)\b/gi;
const cdpPageTextOutput = /\b([\w$]+)\.goto\(["']https?:\/\/[^"'\r\n]+["']\)[\s\S]{0,160}?\bconsole\.log\([ \t]*(?:await[ \t]+)?\1\.locator\(["']body["']\)\.innerText\(/g;
const executeClonedCode = /\bgit[ \t]+clone\b[^\r\n]{0,100}https?:\/\/[^\s'"`]+[^\r\n]{0,70}(?:[\r\n]+|&&)[\s\S]{0,85}\b(?:pip(?:3)?[ \t]+install|npm[ \t]+(?:install|run)|make[ \t]+install|bash|python(?:3)?|chmod[ \t]+\+x)\b/gi;
const buildsClonedApp = /\bgit[ \t]+clone[ \t]+https:\/\/github\.com\/[\w.-]+\/([\w.-]+?)\.git[ \t]*\r?\n[ \t]*cd[ \t]+\1[ \t]*&&[ \t]*make[ \t]+setup[ \t]*&&[ \t]*make[ \t]+dev\b/gi;
const checkoutForLocalPythonService = /^[ \t]*git[ \t]+clone[ \t]+https:\/\/github\.com\/[\w.-]+\/([\w.-]+?)\.git[ \t]*\r?\n[ \t]*cd[ \t]+\1[ \t]*$/gim;
const publicLoopbackTunnel = /^[ \t]*cloudflared[ \t]+tunnel[ \t]+--url[ \t]+https?:\/\/(?:127\.0\.0\.1|localhost):(\d{2,5})(?=[/ \t\r\n]|$)/gim;
const clonesWithNode = /\b([a-z_$][\w$]*)\(\s*['"]git['"]\s*,\s*\[\s*['"]clone['"]\s*,\s*(?:['"][^'"\r\n]{1,26}['"]\s*,\s*){0,6}([a-z_$][\w$]*)\s*,\s*([a-z_$][\w$]*)\s*\]/gi;
const clonesUnlockedPackage = /\bgit[ \t]+clone[ \t]+https:\/\/github\.com\/[\w.-]+\/(?:[\w.-]*[-_.])?(?:premium|pro)(?=[-_.])[\w.-]{0,50}[-_.]unlocked(?=[\s`'"./]|$)/gi;
const tarExtraction = /\b([a-z_][\w]*)\.extract(?:all)?\s*\([^()]{0,180}\)/gi;
const writesMarkdownHeredoc = /\bcat[ \t]+>[ \t]+["']?[\w./-]+\.md["']?[ \t]+<<-?[ \t]*["']?([a-z_][\w]*)["']?[ \t]*\r?\n/gi;
const executablePlaceholderCheckout = /\bgit[ \t]+clone[ \t]+https:\/\/github\.com\/(?:user|username|your-username|owner|example)\/[\w.-]+[^\r\n]{0,70}[\r\n]+(?:(?![ \t]*(?:[\x60~]{3}|#))[^\r\n]{0,55}[\r\n]+){0,1}[ \t]*chmod[ \t]+\+x[ \t]+(?:\.\/)?[\w.-]+\.sh\b/gi;
const numericPagesCheckout = /\bgit[ \t]+clone\b[^\r\n]{0,65}\bhttps?:\/\/\d{6,}\.github\.io(?=[\s/:'"`?#]|$)/gi;
const clonesAndLinksSkill = /^[ \t]*git[ \t]+clone[ \t]+https:\/\/github\.com\/[\w.-]+\/([\w.-]+)\.git[ \t]*\r?\n(?:[ \t]*\r?\n){0,2}[ \t]*ln[ \t]+-s[f]?[ \t]+["']?\$(?:PWD|\{PWD\})\/\1\/skills\/([\w.-]+)["']?[ \t]+["']?(?:~\/|\$(?:HOME|\{HOME\})\/)(?:\.claude|\.agents|\.codex)\/skills\/\2["']?(?=[ \t\r\n]|$)/gm;
const installsClonedWrapper = /^[ \t]*git[ \t]+clone\b[^\r\n]{0,100}https:\/\/github\.com\/[\w.-]+\/[\w.-]+[\s\S]{0,460}?^[ \t]*ln[ \t]+-(?:sf|fs|s)\b[ \t]+(?:~\/|\$HOME\/)(?:\.agents\/skills|\.claude\/skills|\.codex\/skills)\/[\w.-]+\/(scripts\/[\w.-]+)[ \t]+(?:~\/|\$HOME\/)\.local\/bin\//gim;
const deceptiveCheckoutDirectory = /^[ \t]*cd[ \t]+(?:\.\/)?[\w.-]*(?:-dupe|-exploit)(?:[-.][\w.-]+)?[ \t]*$/im;
const runsCheckoutInstaller = /^[ \t]*(?:(?:bash|sh)[ \t]+(?:\.\/)?|\.\/)[\w.-]+\.sh[ \t]+--install\b/im;
const sensitiveTransfer = /\b(?:upload|send|post|transmit|forward|export|exfiltrate)\b[^.!?;\r\n]{0,90}\b(?:credentials?|api keys?|access tokens?|private keys?|passwords?|session cookies?|environment variables?|private files?|secrets?)\b[^.!?;\r\n]{0,75}\b(?:external|public|webhook|remote|third[- ]party|https?:)/gi;
const emitsFullVaultReport = /\b(?:emit|paste) the full saved HTML\b[^.!?;\r\n]{0,90}\bcode fence\b/gi;
const persistence = /\b(?:install|create|enable|configure|add)\b[^.!?;\r\n]{0,70}\b(?:backdoors?|covert persistence|unauthorized remote access|hidden startup (?:agent|task)|persistence mechanism)\b/gi;
const hiddenCharacter = /(?:(?![\t\r\n])[\p{Cf}\p{Cc}])+/gu;
const encodedText = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}/g;
const encodedRoleOverrideReason = 'Encoded text contains a directive that can replace the agent’s governing instructions.';
const encodedExecution = /\b(?:base64|FromBase64String|atob|b64decode)\b[^.!?;\r\n]{0,80}\b(?:execute|eval|invoke|pipe|run|interpret)\b/gi;
const encodesLocalVisionImage = /\bbase64\.b64encode\([a-z_]\w*\.read_bytes\(\)\)/gi;
const secretsToOutput = /\b(?:echo|printf|print|console\.log)\b[^;\r\n]{0,60}\$\{?[A-Z_]*(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD|PRIVATE_KEY|CLIENT_SECRET|SESSION_COOKIE)\b\}?/g;
const childWithEnvironment = /\b(?:spawn|execFile)(?:Sync)?[ \t]*\([ \t]*(?:(['"])npx(?:\.cmd)?\1|([A-Za-z_$][\w$]*))[ \t]*,[^;\r\n]{0,160}?\{[^;\r\n]{0,150}?\benv(?=[ \t]*[,}:])(?:[ \t]*:[ \t]*(process\.env(?![\w$.])|[A-Za-z_$][\w$]*|\{[ \t]*\.\.\.process\.env(?![\w$.])))?/g;
const npmExecutable = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=[^\r\n;]{0,110}['"]npx(?:\.cmd)?['"][ \t]*(?:;|(?=\r?$))/gm;
const inheritedEnvironment = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:process\.env|\{[ \t]*\.\.\.process\.env)(?![\w$.])/g;

function verifiesDownloadedPowerShellArchive(source, start, end) {
  const prefix = source.slice(source.lastIndexOf('\n', start) + 1, start);
  if (!/^[ \t]*Invoke-WebRequest[ \t]+["']?$/i.test(prefix)) return false;
  const tail = source.slice(end, end + 520);
  const outfile = /^["']?[ \t]+-OutFile[ \t]+(\$[a-z_]\w*)[ \t]*\r?\n/i.exec(tail);
  if (!outfile) return false;
  const condition = /^[ \t]*if[ \t]*\(\(Get-FileHash[ \t]+(\$[a-z_]\w*)[ \t]+-Algorithm[ \t]+SHA256\)\.Hash[ \t]+-ne[ \t]+(["'])[a-f0-9]{64}\2\)[ \t]*\{[ \t]*throw[ \t]+[^}\r\n]+\}[ \t]*\r?\n[ \t]*Expand-Archive\b[^\r\n]{0,40}-(?:LiteralPath|Path)[ \t]+(\$[a-z_]\w*)\b/i.exec(tail.slice(outfile[0].length));
  return Boolean(condition && condition[1].toLowerCase() === outfile[1].toLowerCase() &&
    condition[3].toLowerCase() === outfile[1].toLowerCase());
}

function linksPublishedCliDocsInTable(url, source, start, end) {
  if (url.protocol !== 'https:' || url.port || url.username || url.password || url.search || url.hash ||
      !/^\/(?:docs|developers)\/cli\/?$/.test(url.pathname)) return false;
  const before = source.slice(source.lastIndexOf('\n', start) + 1, start);
  const after = source.slice(end, end + 30).split(/\r?\n/, 1)[0];
  return /^[ \t]*\|[^\r\n]{1,300}\x60brew[ \t]+install[ \t]+[\w.-]+(?:\/[\w.-]+){0,2}\x60[ \t]*\($/i.test(before) &&
    /^\)[ \t]*\|[ \t]*$/.test(after) &&
    source.slice(0, start).includes(url.origin + url.pathname.split('/').slice(0,2).join('/'));
}

function documentsManualPinnedWhisperRelease(url, source, start) {
  if (url.protocol !== 'https:' || url.hostname !== 'github.com' || url.port || url.username || url.password || url.search ||
      !/^\/ggml-org\/whisper\.cpp\/releases\/download\/b\d{3,6}\/whisper-bin-(?:x64|win-cuda-\d+\.\d+\.\d+-x64)\.zip$/.test(url.pathname)) return false;
  const before = source.slice(Math.max(0, start - 1450), start);
  const fences = [...before.matchAll(/^[ \t]*(?:\x60{3,}|~{3,})([a-z0-9]*)[ \t]*\r?$/gim)];
  const fence = fences.at(-1);
  if (!fence || !/^(?:powershell|pwsh)$/i.test(fence[1])) return false;
  const heading = before.slice(0, fence.index).split(/\r?\n(?=#{1,6}[ \t])/).at(-1);
  return /\bnever installs? anything on its own\b/i.test(heading) &&
    /\bwhisper\.cpp\b[^.\r\n]{0,130}\b(?:Windows builds|Windows binaries)\b/i.test(heading);
}

function publishedDownloadType(url) {
  if (url.protocol !== 'https:' || url.port || url.username || url.password || url.search) return;
  // Match documented project artifacts by their complete host and path shape.
  if (url.hostname === 'astral.sh' && /^\/uv\/(?:\d+\.\d+\.\d+\/)?install\.(?:sh|ps1)$/.test(url.pathname)) return 'installer';
  if (url.hostname === 'antigravity.google' && url.pathname === '/cli/install.sh') return 'antigravity-cli';
  if (url.hostname === 'duckdb.org' && /^\/install\/?$/.test(url.pathname)) return 'duckdb-install-docs';
  if (url.hostname === 'herdr.dev' && /^\/install\.(?:sh|ps1)$/.test(url.pathname)) return 'herdr-installer';
  if (url.hostname === 'releases.herdr.dev' && /^\/(?:app|core)\/install\.(?:sh|ps1)$/.test(url.pathname)) return 'herdr-installer';
  if (url.hostname === 'huggingface.co' && /^\/ggerganov\/whisper\.cpp\/resolve\/[\w.-]+\/ggml-[\w.-]+\.bin$/.test(url.pathname)) {
    return 'model';
  }
  if (url.hostname === 'd4i3qtqj3r0z5.cloudfront.net' && /^\/omni\.usd_viewer\.samples-\d+\.\d+\.\d+\.zip$/.test(url.pathname)) {
    return 'usd-viewer-samples';
  }
  if (url.hostname === 'github.com' &&
      /^\/googleworkspace\/cli\/releases\/download\/[\w$.-]+\/google-workspace-cli-[\w-]+\.(?:zip|tar\.gz)$/.test(url.pathname)) {
    return 'workspace-cli-release';
  }
  if (url.hostname === 'github.com') {
    if (/^\/plantuml\/plantuml\/releases\/download\/v\d+\.\d+\.\d+\/plantuml\.jar$/i.test(url.pathname)) return 'plantuml-jar-release';
    if (/^\/duckdb\/duckdb\/releases\/download\/v\d+\.\d+\.\d+\/duckdb_cli-(?:linux|osx|windows)-(?:amd64|arm64|universal)\.zip$/.test(url.pathname)) {
      return 'duckdb-cli-release';
    }
    if (/^\/anthropics\/anthropic-cli\/releases\/download\/v(\d+\.\d+\.\d+)\/ant_\1_(?:linux|darwin)_(?:amd64|arm64)\.tar\.gz$/.test(url.pathname) ||
        url.pathname === '/anthropics/anthropic-cli/releases/download/v$%7BVERSION%7D/ant_$%7BVERSION%7D_$(uname') {
      return 'anthropic-cli-release';
    }
    if (url.pathname === '/grafana/grafana-opentelemetry-java/releases/latest/download/grafana-opentelemetry-java.jar') {
      return 'grafana-java-agent';
    }
    if (/^\/open-telemetry\/opentelemetry-collector-releases\/releases\/latest\/download\/otelcol-contrib_(?:linux|darwin)_(?:amd64|arm64)\.tar\.gz$/.test(url.pathname)) {
      return 'opentelemetry-collector';
    }
    if (/^\/getsops\/sops\/releases\/download\/v(\d+\.\d+\.\d+)\/sops-v\1\.(?:linux|darwin)\.(?:amd64|arm64)$/.test(url.pathname)) return 'sops';
    if (/^\/FiloSottile\/age\/releases\/download\/v(\d+\.\d+\.\d+)\/age-v\1-(?:linux|darwin)-(?:amd64|arm64)\.tar\.gz$/.test(url.pathname)) return 'age';
    if (/^\/gitleaks\/gitleaks\/releases\/download\/v(\d+\.\d+\.\d+)\/gitleaks_\1_(?:linux|darwin)_(?:x64|arm64)\.tar\.gz$/.test(url.pathname)) {
      return 'gitleaks';
    }
  }
  if (url.hostname === 'dl.google.com' &&
      /^\/android\/cli\/latest\/(?:(?:linux_x86_64|darwin_(?:arm64|x86_64))\/install\.sh|windows_x86_64\/install\.cmd)$/.test(url.pathname)) return 'android-cli';
  if (['bun.com', 'bun.sh'].includes(url.hostname) && url.pathname === '/install') return 'bun';
  if (url.hostname === 'get.namespace.so' && url.pathname === '/devbox/install.sh') return 'namespace-devbox';
  if (url.hostname === 'tailscale.com' && url.pathname === '/install.sh') return 'tailscale';
  if (url.hostname === 'lfr.email' && url.pathname === '/install.sh') return 'lfr';
  if (url.hostname === 'dot.net' && /^\/v1\/dotnet-install\.(?:sh|ps1)$/.test(url.pathname)) return 'dotnet-sdk';
  if (url.hostname === 'raw.githubusercontent.com' && url.pathname === '/auth0/auth0-cli/main/install.sh') return 'auth0-cli';
  if (url.hostname === 'raw.githubusercontent.com' && url.pathname === '/anchore/grype/main/install.sh') return 'grype-cli';
  if (url.hostname === 'raw.githubusercontent.com' && url.pathname === '/gastownhall/beads/main/scripts/install.sh') return 'beads-cli';
  if (url.hostname === 'raw.githubusercontent.com' && /^\/Tencent\/BrowserSkill\/main\/install\.(?:sh|ps1)$/.test(url.pathname)) {
    return 'browserskill';
  }
  if (url.hostname === 'raw.githubusercontent.com' &&
      /^\/leeguooooo\/(?:chrome-use\/main\/install\.(?:sh|ps1)|plugins\/main\/upgrade-use-family\.sh)$/.test(url.pathname)) {
    return 'chrome-use-cli';
  }
  if (url.hostname === 'raw.githubusercontent.com' && url.pathname === '/higgsfield-ai/cli/main/install.sh') return 'higgsfield-cli';
  if (url.hostname === 'raw.githubusercontent.com' &&
      /^\/kyma-project\/cli\/refs\/heads\/main\/hack\/install_cli_(?:stable|latest|nightly)\.sh$/.test(url.pathname)) return 'kyma-cli';
  if (url.hostname === 'raw.githubusercontent.com' && url.pathname === '/the-square-labs/gateway/main/scripts/install.sh') {
    return 'good-gateway';
  }
  if (url.hostname === 'github.com' &&
      url.pathname === '/elevenlabs/cli/releases/latest/download/elevenlabs-cli-installer.sh') return 'elevenlabs-cli';
  if (url.hostname === 'github.com' &&
      /^\/jgm\/pandoc\/releases\/download\/(\d+\.\d+(?:\.\d+){0,2})\/pandoc-\1-\d+-(?:amd64|arm64)\.deb$/.test(url.pathname)) {
    return 'pandoc-debian-package';
  }
  if (url.hostname === 'cnb.cool' &&
      /^\/cnb\/skills\/cnb-skill\/-\/git\/raw\/main\/install\.(?:sh|ps1)$/.test(url.pathname)) {
    return 'cnb-cli-bootstrap';
  }
  if (url.hostname === 'um-community.oss-cn-zhangjiakou.aliyuncs.com' &&
      /^\/umeng-cli\/install\.(?:sh|ps1)$/.test(url.pathname)) return 'umeng-cli';
  if (url.hostname === 'erda-release.oss-cn-hangzhou.aliyuncs.com' && url.pathname === '/cli/scripts/install.sh') {
    return 'erda-cli';
  }
  if (url.hostname === 'raw.githubusercontent.com' && url.pathname === '/marcaureln/autopilot/main/install.sh') {
    return 'autopilot-cli';
  }
  if (url.hostname === 'install.tracewayapp.com' && url.pathname === '/install.sh') return 'traceway-otel-agent';
  if (url.hostname === 'unity.com' && /^\/install\.(?:sh|ps1)$/.test(url.pathname)) return 'unity-cli';
  if (url.hostname === 'public-cdn.cloud.unity3d.com' && /^\/hub\/prod\/cli\/install\.(?:sh|ps1)$/.test(url.pathname)) return 'unity-cli-cdn';
  if (url.hostname === 'raw.githubusercontent.com') {
    if (/^\/rojo-rbx\/rokit\/main\/scripts\/install\.(?:sh|ps1)$/.test(url.pathname)) return 'rokit';
    if (/^\/nvm-sh\/nvm\/v\d+\.\d+\.\d+\/install\.sh$/.test(url.pathname)) return 'nvm';
    if (url.pathname === '/Homebrew/install/HEAD/install.sh') return 'homebrew';
    if (url.pathname === '/coollabsio/coolify-cli/main/scripts/install.sh') return 'coolify-cli';
  }
  if (url.hostname === 'raw.githubusercontent.com' &&
      /^\/pact-foundation\/pact-cli\/main\/install\.(?:sh|ps1)$/.test(url.pathname)) return 'pact-cli';
  if (url.hostname === 'github.com' && url.pathname === '/tidbcloud/ti-cli/releases/latest/download/install.sh') return 'tidb-cli';
  if (url.hostname === 'github.com' && url.pathname === '/channprj/kmsg/releases/latest/download/kmsg-macos-universal') return 'kmsg-release';
  if (url.hostname === 'nsyte.run' && url.pathname === '/get/install.sh') return 'nsyte-install';
  if (url.hostname === 'github.com' &&
      /^\/sandwichfarm\/nsyte\/releases\/download\/v(\d+\.\d+\.\d+)\/nsyte-(?:macos-(?:arm64|x64)|linux|windows)(?:-compressed)?-\1(?:\.exe)?$/.test(url.pathname)) {
    return 'nsyte-install';
  }
  if (url.hostname === 'github.com' && /^\/conversiontools\/ctio\/releases\/latest\/download\/ctio-(?:darwin|linux)-(?:arm64|x64)$/.test(url.pathname)) {
    return 'conversiontools-cli';
  }
  if (url.hostname === 'github.com' && /^\/pengelbrecht\/agentviewer\/releases\/latest\/download\/agentviewer_[\w-]+\.(?:deb|rpm)$/.test(url.pathname)) {
    return 'agentviewer-package';
  }
}

function installsInSampleImage(source, start) {
  const preceding = source.slice(Math.max(0, start - 460), start);
  const sample = preceding.slice(preceding.lastIndexOf('\n```') + 1);
  return /^```(?:python|typescript|py|ts)[ \t]*\r?\n/.test(sample) &&
    /\bImage\.(?:debian_slim|debianSlim|base)\([^\r\n)]{0,90}\)\s*\.run(?:_commands|Commands)\([^)]{0,180}["'](?:curl|wget)\b[^|;&"'\r\n]{0,65}$/.test(sample);
}

function documentsPublishedTool(type, source, start) {
  const prior = source.slice(Math.max(0, start - 475), start);
  switch (type) {
    case 'beads-cli': {
      const next = source.slice(start, start + 430);
      return /\bbrew upgrade beads\b/.test(prior) && /\bRestart Dolt server after upgrade\b/i.test(next) &&
        /\bbd dolt start\b/.test(next);
    }
    case 'antigravity-cli': {
      const next = source.slice(start, start + 280);
      return /\bAntigravity CLI installed and signed in\b/i.test(prior) &&
        /\buser must complete browser sign-in themselves\b/i.test(next);
    }
    case 'erda-cli': return /^#[ \t]+ERDA CI\/CD Prerequisites\b/im.test(source.slice(0, 900)) &&
      /\bcommand -v erda-cli\b/.test(source) && /\berda-cli version\b/.test(source) && /\berda-cli whoami\b/.test(source);
    case 'autopilot-cli': return /\bautopilot --help\b/.test(source) && /\bautopilot host setup\b/.test(source) &&
      /\bask the user to run\b[^.\r\n]{0,75}\bautopilot setup\b/i.test(source);
    case 'android-cli': return /^(?:name:[ \t]*android-cli\b|#[ \t]+Android CLI\b)/im.test(source.slice(0, 900));
    case 'bun': {
      if (/\b(?:command -v bun|bun --version|install Bun)\b|\bBun\*{0,2}[ \t]+\((?:runtime|JavaScript runtime)\b/i.test(prior)) return true;
      const bootstrap = source.slice(Math.max(0, start - 1100), start);
      return /\bensure_bun\(\)/.test(bootstrap) && /\bcommand -v bun\b/.test(bootstrap) &&
        /\b[\w]*SKIP_BUN_INSTALL\b/.test(bootstrap) && /\/\.bun\/bin\/bun\b/.test(bootstrap);
    }
    case 'anthropic-cli-release': {
      const next = source.slice(start, start + 450);
      return /\bbrew install anthropics\/tap\/ant\b/.test(prior) &&
        /\bgo install github\.com\/anthropics\/anthropic-cli\/cmd\/ant@latest\b/.test(next) &&
        /\|[ \t]*sudo[ \t]+tar\b[^\r\n]{0,90}\bant\b/.test(next);
    }
    case 'namespace-devbox': return /\bcmd_install\(\)|\binstall (?:the )?Devbox CLI\b/i.test(prior) && /\bdevbox\b/i.test(prior);
    case 'tailscale': return /\bTailscale\b/i.test(prior) && /\binstall (?:if missing|Tailscale|the Tailscale)\b/i.test(prior);
    case 'lfr': return /\blfr (?:mail |email )?server\b/i.test(source.slice(0, 1500)) &&
      [...source.slice(start, start + 950).matchAll(setupSystemService)].some(match => /^lfr\b/.test(match[0]));
    case 'dotnet-sdk': return /\.NET\s+(?:SDK|\d+)|\bdotnet\s+--(?:version|list-sdks)\b|\bSDK version\b/i.test(prior) ||
      /\bdotnet-install-(?:\$\(|\$\{)|\bdotnet-install\.X{4,}\b/.test(prior) &&
      /\.NET\s+(?:SDK|\d+)\b/i.test(source.slice(0, 1600));
    case 'auth0-cli': return /\bAuth0 CLI\b|\bcommand -v auth0\b|\bbrew install auth0\/auth0-cli\/auth0\b/i.test(prior);
    case 'grype-cli': return /^#{2,6}[ \t]+Prerequisites[ \t]*\r?\n\s*-[ \t]+Grype installed[ \t]+\(\x60curl[ \t]+-[\w-]+[ \t]+$/im.test(prior) &&
      /\r?\n[ \t]*-[ \t]+Verify:[ \t]+\x60grype[ \t]+version\x60/.test(source.slice(start, start + 250));
    case 'browserskill': return /\bBrowserSkill\b/i.test(prior) &&
      (/\bTencent\/BrowserSkill\/main\/AGENT_INSTALL\.md\b/.test(source) && /\bbsk\b/.test(source) ||
       /\bbsk (?:doctor|browsers)\b/.test(prior) && /\bnot found:[ \t]*curl\b[^\r\n]{0,45}$/i.test(prior));
    case 'chrome-use-cli': return /^name:[ \t]*chrome-use[ \t]*$/im.test(source.slice(0, 900)) &&
      /\bSource:[ \t]+https:\/\/github\.com\/leeguooooo\/chrome-use\/?(?=[\s)|`]|$)/.test(source) &&
      /\btell the user\s+and offer to run\s+`?chrome-use upgrade\b/i.test(source) &&
      /\bchrome-use upgrade --check\b/.test(source);
    case 'higgsfield-cli': return /\bHiggsfield CLI\b|\bhiggsfield`? is (?:missing\b|not on `?\$PATH\b)|\bcommand -v higgsfield\b/i.test(prior);
    case 'kyma-cli': return /^name:[ \t]*kyma-cli[ \t]*$/im.test(source.slice(0, 900)) &&
      /\bbrew install kyma-cli\b/i.test(prior) && /\bofficial install scripts?\b/i.test(prior);
    case 'good-gateway': {
      const after = source.slice(start, start + 670);
      return /\binstall the control plane\b/i.test(prior) &&
        /\b(?:verify|check) the signed release\b/i.test(after) &&
        /\b(?:do not run it merely|requires? (?:explicit )?(?:user )?approval)\b/i.test(after);
    }
    case 'elevenlabs-cli': return /\bElevenLabs CLI\b|\b(?:brew install elevenlabs\/tap\/elevenlabs|scoop install elevenlabs)\b/i.test(prior);
    case 'pandoc-debian-package': return /\bdpkg[ \t]+-i[ \t]+pandoc-[\d.-]+-(?:amd64|arm64)\.deb\b/i.test(source.slice(start, start + 225));
    case 'plantuml-jar-release': return /\bjava[ \t]+(?:-D[\w.-]+=[^\s]+[ \t]+){0,4}-jar[ \t]+[^\r\n]{0,75}\bplantuml\.jar\b/i.test(source);
    case 'duckdb-install-docs': return /\bstandalone\b[^.!?;\r\n]{0,70}\bduckdb\b/i.test(prior);
    case 'duckdb-cli-release': return /\bduckdb --version\b/i.test(prior) &&
      /\bunzip\b[^\r\n]{0,75}\bduckdb-cli\.zip\b/i.test(source.slice(start, start + 270));
    case 'herdr-installer': return /\bherdr\b/i.test(prior) || /\b(?:herdr --version|herdr[ -](?:app|core))\b/i.test(source);
    case 'grafana-java-agent': return /\bGrafana (?:JVM|OpenTelemetry)\b/i.test(prior) && /-javaagent:/.test(source);
    case 'opentelemetry-collector': return /\b(?:download|install) otelcol-contrib\b/i.test(prior);
    case 'sops': return /\bsops\b/i.test(prior) && /\b(?:sops --version|sops -[ed]\b|chmod \+x [~./\w-]*\/sops\b)/i.test(source);
    case 'age': return /\bage\/age-keygen\b|\bage-keygen -o\b/i.test(source.slice(start, start + 450));
    case 'gitleaks': return /\b(?:gitleaks detect|gitleaks git|gitleaks --version)\b/i.test(source) ||
      /\|[ \t]*tar\b[^\r\n]{0,95}(?:\bgitleaks\b|\/usr\/local\/bin\b)/i.test(source.slice(start, start + 270));
    case 'usd-viewer-samples': return /\bUSD Viewer\b/i.test(source) && /\bstage0[12]\.usd\b/.test(source) &&
      /\bunzip\b[^\r\n]{0,120}\bomni\.usd_viewer\.samples\.zip\b/.test(source.slice(start, start + 400));
    case 'cnb-cli-bootstrap': return /\bnpm[ \t]+install[ \t]+(?:-g[ \t]+)?@cnbcool\/cnb-cli\b/i.test(prior);
    case 'umeng-cli': return /^name:[ \t]*umeng-cli\b/im.test(source.slice(0, 800)) &&
      /\bumeng-cli --(?:version|help)\b/i.test(source.slice(0, 3500));
    case 'traceway-otel-agent': return /\b(?:Traceway|OTel)[^\r\n]{0,35}\b(?:agent|collector)\b/i.test(prior) &&
      /\bTRACEWAY_(?:ENDPOINT|SERVICE_NAME)\b/.test(source.slice(start, start + 480));
    case 'unity-cli': return /\bunity --version\b/i.test(prior) &&
      /\bUnity CLI\b/i.test(source.slice(0, 1800));
    case 'unity-cli-cdn': return /\bUnity CLI\b/i.test(source.slice(0, 1800)) && /\b(?:macOS|Windows|Linux)\b/i.test(source);
    case 'rokit': return /\brokit (?:init|install|add|--version)\b/i.test(source) && /\bRoblox\b/i.test(source);
    case 'nvm': return /\bNode(?:\.js|JS)\b/i.test(source) && /\bnvm (?:install|use)\b/i.test(source);
    case 'homebrew': return /\bHomebrew\b/i.test(prior) && /\bmacOS\b/i.test(source) && /\bbrew install\b/i.test(source);
    case 'coolify-cli': return /\bCoolify CLI\b/i.test(source.slice(0, 1200)) &&
      /\bbrew install coollabsio\/coolify-cli\/coolify-cli\b/.test(source);
    case 'pact-cli': return /\b(?:Pact CLI|pact --version|pact-cli)\b/i.test(prior + source.slice(start, start + 560));
    case 'tidb-cli': return /\bti fs mount-file-system\b/i.test(source) && /\bti --version\b/i.test(source);
    case 'kmsg-release': return /\bbrew install channprj\/tap\/kmsg\b/i.test(prior);
    case 'nsyte-install': return /^name:[ \t]*nsyte\b/im.test(source.slice(0, 800)) && /\bnsyte --version\b/i.test(source);
    case 'conversiontools-cli': return /\bctio CLI\b/i.test(source) && source.includes('https://conversiontools.io/docs/ctio');
    case 'agentviewer-package': return docsOfferAgentViewerInstallOptions(source);
    default: return false;
  }
}

const publishedBootstrapTypes = new Set(['android-cli', 'antigravity-cli', 'cnb-cli-bootstrap', 'unity-cli', 'pact-cli', 'kyma-cli', 'good-gateway', 'erda-cli']);

function docsOfferAgentViewerInstallOptions(source) {
  return /^name:[ \t]*agentviewer\s*$/im.test(source.slice(0, 500)) &&
    /\bbrew install pengelbrecht\/tap\/agentviewer\b/i.test(source) &&
    /\b(?:winget install pengelbrecht\.agentviewer|scoop install agentviewer)\b/i.test(source);
}

function generatedMarkdownRanges(source) {
  const ranges = [];
  for (const match of source.matchAll(writesMarkdownHeredoc)) {
    const begin = match.index + match[0].length;
    const end = new RegExp('^[\\t ]*' + match[1] + '[\\t ]*\\r?$', 'gm');
    end.lastIndex = begin;
    const terminator = end.exec(source);
    if (terminator) ranges.push([begin, terminator.index]);
  }
  return ranges;
}

function printsLiteralPrerequisiteHelp(source, start) {
  const line = sourceLineAt(source, start);
  const echo = /^[ \t]*echo[ \t]+(?:"([^"\r\n]*)"|'([^'\r\n]*)')[ \t]*(?:#.*)?$/.exec(line);
  if (!echo) return false;
  const message = echo[1] ?? echo[2];
  if (!/^\s*(?:Install|To install):\s*(?:curl|wget)\b/i.test(message) ||
      (echo[1] !== undefined && /[\x60$\\]/.test(message))) return false;
  return /^[ \t]*exit[ \t]+[1-9]\d*\b/m.test(source.slice(start, start + 260));
}

function documentsPublishedPackageAlternative(source, url, start, end) {
  if (url.protocol !== 'https:' || url.port || url.search || url.username || url.pathname !== '/install') return false;
  const project = /^([a-z][\w-]*)\.([a-z]{2,10})$/i.exec(url.hostname);
  if (!project) return false;
  const before = source.slice(Math.max(0, start - 360), start);
  const after = source.slice(end, end + 250);
  return new RegExp('\\b' + project[1] + '[ \\t]+--version\\b', 'i').test(before) &&
    new RegExp('^[ \\t]*#[ \\t]*or:[ \\t]*(?:npm|bun)[ \\t]+install[ \\t]+-g[ \\t]+' +
      project[1] + '-' + project[2] + '(?=[ \\t\\r\\n]|$)', 'im').test(after);
}

function printsManualDependencyGuide(source, start, end) {
  const prefix = source.slice(Math.max(0, start - 255), start);
  return /^[ \t]*echo[ \t]+"[ \t]*Install [^"\r\n]{1,95}\(see"\s*\r?\n[ \t]*echo[ \t]+"[ \t]*$/im.test(prefix) &&
    /^\), then rerun this script\."[ \t]*(?:#.*)?$/i.test(source.slice(end).split(/\r?\n/, 1)[0]);
}

function documentsConditionalInstallerVerification(source, urlOffset) {
  const preceding = source.slice(Math.max(0, urlOffset - 400), urlOffset);
  const command = /\x60{3}(?:sh|bash|shell)[ \t]*\r?\n[ \t]*command -v[ \t]+[\w.-]+[ \t]+>\/dev\/null[ \t]*\|\|[ \t]*\\[ \t]*\r?\n[ \t]*(?:curl|wget)\b[^|;&\x60\r\n]{0,65}$/i.exec(preceding);
  if (!command) return false;
  const paragraph = preceding.slice(0, command.index).trimEnd().split(/\r?\n[ \t]*\r?\n/).at(-1);
  const statement = /\b(?:install(?:ation)? script|installer)\b(?<qualifiers>[^.!?;]{0,145})\b(?:verifies|checks|validates)\s+(?:the\s+)?(?:release\s+)?(?:checksum|signature)\b(?<conditions>[^.!?;\x60]{0,75}):$/i.exec(paragraph);
  return Boolean(statement &&
    !/\b(?:no|not|never|may|might|can|could|optionally|unless)\b/i.test(statement.groups.qualifiers) &&
    !/\b(?:if|when|unless|only|optionally)\b/i.test(statement.groups.conditions));
}

function printsDownloadCommandToMarkdown(source, urlOffset) {
  const start = source.lastIndexOf('\n', urlOffset - 1) + 1;
  const end = source.indexOf('\n', urlOffset);
  const line = source.slice(start, end < 0 ? undefined : end);
  const output = /^[ \t]*echo[ \t]+(["'])([^\r\n]+)\1[ \t]*>>?[ \t]+["']?[\w./-]+\.md\b/i.exec(line);
  if (!output) return false;
  const argument = line.indexOf(output[2]);
  return urlOffset - start >= argument && urlOffset - start < argument + output[2].length &&
    (output[1] === "'" || !/\$\(|`/.test(output[2]));
}

function installsFromMutableCheckout(match) {
  const [wrapper, repository, directory] = match.slice(1).map(name => name.replaceAll('$', '\\$'));
  const declaration = new RegExp('\\b(?:const|let)\\s+' + repository + '\\s*=\\s*["\']https://github\\.com/[\\w.-]+/[\\w.-]+["\']');
  const execution = new RegExp('\\b' + wrapper + '\\(\\s*["\']node["\']\\s*,[^;\\r\\n]{0,145}' +
    '\\bcwd\\s*:\\s*' + directory + '\\b');
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 1300);
  const run = execution.exec(after);
  return Boolean(run) && declaration.test(match.input.slice(0, match.index)) &&
    !/\b(?:checkout|switch)\b[^\r\n]{0,100}\b[0-9a-f]{40}\b/i.test(after.slice(0, run.index));
}

function offersReviewedRepoInstaller(source, url) {
  if (url.protocol !== 'https:' || url.hostname !== 'raw.githubusercontent.com' || url.port ||
      url.username || url.search || !/^\/[\w.-]+\/[\w.-]+\/main\/install\.sh$/.test(url.pathname)) return false;
  const active = removeMarkdownComments(source);
  for (let start = active.indexOf(url.href); start !== -1; start = active.indexOf(url.href, start + url.href.length)) {
    const before = active.slice(Math.max(0, start - 400), start);
    const after = active.slice(start + url.href.length, start + url.href.length + 1700);
    const offers = /\bif (?:detection fails|(?:the )?CLI is missing)\b[^.\r\n]{0,95}\boffer to install\b/i;
    if (!offers.test(before) || !/\binspect[- ]first variant\b/i.test(after)) continue;
    const review = after.indexOf(url.href);
    if (review < 0) continue;
    const staged = /^[ \t]+-o[ \t]+(\/tmp\/[\w.-]+\.sh)[ \t]*\r?\n[ \t]*(?:less|cat)[ \t]+\1\b[ \t]*\r?\n[ \t]*(?:bash|sh)[ \t]+\1\b/i
      .test(after.slice(review + url.href.length, review + url.href.length + 275));
    if (staged) return true;
  }
  return false;
}

function documentsOptionalUvSetup(source, start) {
  const line = sourceLineAt(removeMarkdownComments(source), start);
  return /\b(?:don['’]t have|missing|if (?:you )?(?:do not|don['’]t) have)\b[^\r\n]{0,14}\x60?uv\x60?\b/i.test(line) &&
    /\b(?:install it once|one.time setup)\b/i.test(line) &&
    /\x60(?:python(?:3)? -m )?pip install [\w.-]+\x60[^.!?\r\n]{0,80}\balso works\b/i.test(line) &&
    !/\b(?:always|automatically|each time) (?:run|install|download)\b/i.test(line);
}

function documentsUvInstallation(source, start) {
  const opening = source.slice(0, 1200);
  if (/^name:[ \t]*uv(?:-[\w-]+)?[ \t]*$/im.test(opening) && /\b(?:Python package|project manager)\b/i.test(opening)) return true;
  const nearby = source.slice(Math.max(0, start - 420), start);
  const line = nearby.split(/\r?\n/).at(-1);
  if (/^[ \t]*uv[ \t]+--version[ \t]*\|\|[ \t]*curl[ \t][^\r\n|;&]{0,35}$/i.test(line) ||
      /^[ \t]*command[ \t]+-v[ \t]+uv\b[^\r\n|]{0,65}\|\|[ \t]*error[ \t]+["']'uv' not found\. Install:[ \t]*curl[ \t][^\r\n|;&]{0,35}$/i.test(line)) return true;
  if ((/\bcommand -v uv\b[^\r\n]{0,85}\|\|[ \t]*curl\b[^\r\n]{0,28}$/i.test(nearby) ||
      /\bpreflight \x60?uv\x60? first\b[^\r\n]{0,70}\bif it(?:'s| is) missing\b/i.test(nearby)) &&
      /\buv pip install\b/i.test(nearby + source.slice(start, start + 420))) return true;
  if (/^#{2,5}[ \t]+If `?uvx`? is missing\b/im.test(nearby)) return true;
  if (/^#{2,5}[ \t]+Install[ \t]+\x60?uv\x60?[ \t]*\r?$/im.test(nearby) &&
      /\b(?:recommended runner|prerequisites?)\b/i.test(nearby) &&
      /\buv\x60? is documented at[ \t]+<?https:\/\/docs\.astral\.sh\/uv\//i.test(source.slice(start, start + 450))) return true;
  return /\buv --version\b/i.test(nearby) && /\buse the existing installation\b/i.test(nearby) &&
    /\b(?:Astral(?:'s|’s) )?official standalone installer\b/i.test(nearby);
}

function runsOrdinaryCommandsFromGit(match) {
  const before = match.input.slice(Math.max(0, match.index - 480), match.index);
  const role = /\b(?:all|every)\s+(?:commands?|operations?|invocations?)\s+(?:use|uses|run|runs)\s+`?uvx\b`?[^.!?;\r\n]{0,150}\b(?:remote Git|Git repository|Git repo|Git checkout)\b/i;
  return role.test(before) && !/\b(?:one[- ](?:time|off)|only if (?:the )?user requests)\b/i.test(before);
}

function bootstrapsDeploymentCli(source, start) {
  const next = source.slice(start, start + 1000);
  const account = /\b([\w.-]+)[ \t]+account[ \t]+status\b/i.exec(next);
  const deployment = /\b([\w.-]+)[ \t]+[\w.-]+[ \t]+deploy[ \t]+--help\b/i.exec(next);
  if (!account || !deployment || account[1].toLowerCase() !== deployment[1].toLowerCase()) return false;
  return Array.from(source.matchAll(/\b([\w.-]+)[ \t]+[\w.-]+[ \t]+publish\b/gi)).some(
    publish => publish.index > start + deployment.index && publish[1].toLowerCase() === deployment[1].toLowerCase());
}

function replacesInstructionsOnEachUse(match) {
  const before = match.input.slice(Math.max(0, match.index - 2200), match.index);
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 760);
  const repository = match[2].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const checkout = new RegExp(String.raw`\bgit clone --depth 1 https://(?:github|gitee)\.com/[\w.-]+/[\w.-]+\.git[ \t]+["']\$${match[1]}/${repository}["']`, 'i');
  return /每次使用本 Skill 前必须执行|\bmust (?:run|execute) before (?:each|every) use\b/iu.test(before) && checkout.test(before) &&
    /重新阅读更新后的 Skill|\bre-?read (?:the )?updated (?:skill|instructions)\b/iu.test(after) &&
    !/\b(?:git checkout|git switch)\b[^\r\n]{0,60}\b[0-9a-f]{40}\b/i.test(before);
}

function usesUnverifiedMarketplaceDownload(match) {
  const before = match.input.slice(Math.max(0, match.index - 550), match.index);
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 620);
  const domain = match[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(String.raw`https:\/\/${domain}\/api\/skills\/search\?`, 'i').test(before) &&
    /需要先加载[^\r\n]{0,120}SKILL\.md[^\r\n]{0,85}执行搜索和下载/u.test(after) &&
    !/校验[^。\r\n]{0,35}(?:签名|哈希|校验和)|\bverify\b[^.\r\n]{0,55}\b(?:checksum|signature|digest)\b/iu.test(before + after);
}

function sendsStoreCredentialToAnotherService(match) {
  const before = match.input.slice(Math.max(0, match.index - 450), match.index);
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 600);
  const payload = /\b([A-Z_]+)=\$\(node[ \t]+-e[ \t]+['"][^\r\n]*$/i.exec(before)?.[1];
  const target = /\bcurl\b[^\r\n]{0,105}https:\/\/([\w.-]+)\//i.exec(after)?.[1];
  return Boolean(payload && target && !/(?:^|\.)(?:shopify\.com|myshopify\.com)$/i.test(target) &&
    /Authorization:[ \t]+Bearer[ \t]+\$\{?[A-Z_]+API_KEY\}?\b/i.test(after) &&
    new RegExp(String.raw`(?:-d|--data)[ \t]+["']?\$${payload}\b`).test(after));
}

function clonedDependencyEvidence(match) {
  const earlier = match.input.slice(Math.max(0, match.index - 360), match.index);
  const alternate = /\b(?:via github|from source|alternative|optional)\b[\s\S]{0,105}$/i.test(earlier);
  const primary = /\b(?:via|from)\s+(?:npm|pip3?|the (?:package )?registry)\s*\(recommended\)[\s\S]{0,130}\b(?:npm|pip3?)\s+install\b/i.test(earlier);
  if (alternate && primary) return;
  const starter = /^git[ \t]+clone[ \t]+https:\/\/github\.com\/([\w.-]+)\/[\w.-]+-starter(?:\.git)?(?=\s)/i.exec(match[0]);
  if (starter) {
    const context = match.input.slice(Math.max(0, match.index - 650), match.index);
    const types = /\bhttps:\/\/github\.com\/([\w.-]+)\/[\w.-]+-types\b/i.exec(context);
    const commands = match.input.slice(match.index, match.index + 400);
    if (types && starter[1].toLowerCase() === types[1].toLowerCase() && /\bdevDependency\b/i.test(context) &&
        /\b(?:worked examples?|types only|dependency-free source)\b/i.test(context) &&
        /^git[ \t]+clone[ \t]+https:\/\/github\.com\/[\w.-]+\/[\w.-]+[ \t]+([\w.-]+)[ \t]*\r?\n[ \t]*cd[ \t]+\1[ \t]*\r?\n[ \t]*npm install[ \t]*\r?\n[ \t]*npm run typecheck[ \t]*(?:#[^\r\n]*)?\r?\n[ \t]*npm run build[ \t]*(?:#[^\r\n]*)?\r?\n[ \t]*\x60{3}/i.test(commands)) return;
  }
  return 'direct';
}

function copiedAgentConfiguration(match) {
  const remaining = match.input.slice(match.index + match[0].length);
  const checkout = match[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const variable = new RegExp('\\b([A-Z][A-Z0-9_]*)=' + checkout + '(?=[\\s\\x60"\']|$)').exec(remaining)?.[1];
  if (!variable) return false;
  const copy = new RegExp(
    String.raw`^[ \t]*cp[ \t]+-[rRa][\w]*[ \t]+["']?\$${variable}/(?:skills|rules)/[^ \t\r\n]+[ \t]+["']?\$[A-Z_]*(?:TARGET|DEST)[A-Z_]*\/(?:skills|rules)/`,
    'm'
  ).exec(remaining);
  return Boolean(copy) &&
    !/\bgit\b[^\r\n]{0,75}\b(?:checkout|switch|reset)\b[^\r\n]{0,60}\b[a-f0-9]{40}\b/i.test(remaining.slice(0, copy.index));
}

function conflictingPowerShellPublisher(match) {
  const publisher = /https?:\/\/raw\.githubusercontent\.com\/([\w.-]+)\/[\w.-]+\//i.exec(match[0])?.[1].toLowerCase();
  if (!publisher) return false;
  const nearby = match.input.slice(Math.max(0, match.index - 500), match.index + match[0].length + 500);
  const alternatives = [...nearby.matchAll(/\bgit[ \t]+clone[ \t]+https?:\/\/github\.com\/([\w.-]+)\/[\w.-]+/gi)]
    .filter(alternative => !negated(nearby, alternative.index));
  return alternatives.length > 0 && alternatives.every(alternative => alternative[1].toLowerCase() !== publisher);
}

function runsRegistryPackageWithEnvironment(match) {
  const before = match.input.slice(Math.max(match.index - 2500, 0), match.index);
  if (match[2] && !Array.from(before.matchAll(npmExecutable)).some(declaration => declaration[1] === match[2])) return false;
  if (!/['"](?:-y|--yes)['"]/.test(before.slice(-500) + match[0])) return false;
  const environment = match[3] ?? 'env';
  return environment === 'process.env' || environment.startsWith('{') ||
    Array.from(before.matchAll(inheritedEnvironment)).some(declaration => declaration[1] === environment);
}

function invokesVersionedRegistryTool(match) {
  const args = /^[^(]+\([^,\r\n]+,[ \t]*([\w$]+)[ \t]*,/.exec(match[0])?.[1];
  if (!args) return false;
  const before = match.input.slice(Math.max(0, match.index - 500), match.index);
  const declarations = before.matchAll(/\bconst[ \t]+([\w$]+)[ \t]*=[ \t]*\[[ \t]*["'](?:-y|--yes)["'][ \t]*,[ \t]*["'](?:@[\w.-]+\/)?[\w.-]+@\d+\.\d+\.\d+(?:-[\w.-]+)?["'][ \t]*,[^\]\r\n]{0,180}["']invoke["'][ \t]*,[ \t]*([\w$]+)\b/g);
  const toolVariable = [...declarations].find(declaration => declaration[1] === args)?.[2];
  if (!toolVariable) return false;
  const tools = match.input.slice(Math.max(0, match.index - 2500), match.index)
    .matchAll(/\bconst[ \t]+([\w$]+)[ \t]*=[ \t]*["']([\w-]+)["'][ \t]*;/g);
  const tool = [...tools].find(declaration => declaration[1] === toolVariable)?.[2];
  return Boolean(tool) && !/^(?:execute|eval|exec|shell|run|query|sql)(?:[_-]|$)/i.test(tool);
}

function negated(source, start) {
  const prior = source.slice(Math.max(0, start - 64), start).split(/[.!?;\r\n]/).at(-1);
  return /\b(?:do not|don't|never|must not|should not|avoid|prohibit|forbid|blocked example|negative example|if you see)[*_~]*\s*(?:\w+\s+){0,4}['"\x60_*]*$/i.test(prior);
}

const npmArchiveIntegrity = /(?:^|\s)(?:sha256-[a-z0-9+/]{43}=|sha384-[a-z0-9+/]{64}|sha512-[a-z0-9+/]{86}==)(?=\s|$)/i;

function matchesNpmMirrorArchive(key, entry) {
  const name = /(?:^|\/)node_modules\/((?:@[\w.-]+\/)?[\w.-]+)$/.exec(key)?.[1];
  if (!name || !/^\d+\.\d+\.\d+(?:[-+][\w.+-]+)?$/.test(entry?.version ?? '')) return false;
  const archive = name.split('/').at(-1) + '-' + entry.version + '.tgz';
  return entry.resolved === 'https://registry.npmmirror.com/' + name + '/-/' + archive;
}

function lockedDownloads(source, npmMirrorOnly = false) {
  const resolved = new Set();
  if (!source.trimStart().startsWith('{')) return resolved;
  const registry = source.includes('"lockfileVersion"');
  const artifacts = !npmMirrorOnly && source.includes('"schemaVersion"') && source.includes('"sha256"') && source.includes('"size"');
  if (!registry && !artifacts) return resolved;
  try {
    const lock = JSON.parse(source);
    if (artifacts && Number.isInteger(lock.schemaVersion)) {
      const entries = [lock];
      for (const entry of entries) {
        if (!entry || typeof entry !== 'object') continue;
        for (const child of Object.values(entry)) entries.push(child);
        if (typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(entry.sha256) || !Number.isInteger(entry.size) ||
            entry.size <= 0 || typeof entry.url !== 'string') continue;
        const mirrors = Array.isArray(entry.mirrors) ? entry.mirrors : [];
        for (const url of [entry.url, ...mirrors]) {
          if (typeof url === 'string' && /^https:\/\/[^\s]+$/.test(url)) resolved.add(url);
        }
      }
    }
    if (![1, 2, 3].includes(lock.lockfileVersion)) return resolved;
    const packages = Object.entries(lock.packages ?? lock.dependencies ?? {});
    for (let index = 0; index < packages.length; index++) {
      const [key, entry] = packages[index];
      if (npmMirrorOnly) {
        if (lock.lockfileVersion > 1 && matchesNpmMirrorArchive(key, entry) &&
            npmArchiveIntegrity.test(entry.integrity ?? '')) resolved.add(entry.resolved);
        continue;
      }
      if (typeof entry?.resolved === 'string' && /^https:\/\/registry\.npmjs\.org\/.+\.tgz$/.test(entry.resolved) &&
          npmArchiveIntegrity.test(entry.integrity ?? '')) {
        resolved.add(entry.resolved);
      }
      if (lock.lockfileVersion === 1 && entry?.dependencies && typeof entry.dependencies === 'object') {
        for (const child of Object.entries(entry.dependencies)) packages.push(child);
      }
    }
  } catch {
    // Malformed metadata provides no evidence of a pinned download.
  }
  return resolved;
}

function invokesPythonScript(manifest, path) {
  if (!path.endsWith('.py') || !manifest.includes(path)) return false;
  const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const skillName = /^[ \t]*name:[ \t]*["']?([\w.-]+)["']?[ \t]*$/im.exec(manifest.slice(0, 1600))?.[1];
  const publishedPath = skillName ? '|skills/' + skillName.replaceAll('.', '\\.') + '/' : '';
  const command = new RegExp(
    String.raw`\b(?:python(?:3(?:\.\d+)?)?|uv[ \t]+run(?:[ \t]+python3?)?)[ \t]+["'\x60]?(?:\.?\/|\$\{?[\w]+\}?\/|<skill[-_]dir(?:ectory)?>\/${publishedPath})?${escaped}(?=[\s"'\x60)]|$)`,
    'gi'
  );
  return Array.from(manifest.matchAll(command)).some(match => !negated(manifest, match.index));
}

function activePythonCredentialUse(manifest, files) {
  const installed = new Set([...manifest.matchAll(pythonHostCommandLink)].map(match => match[1]));
  const uses = new Map();
  for (const file of files) {
    if (!file.path.endsWith('.py') || !/(?:Authorization|os\.environ)/.test(file.content)) continue;
    if (!installed.has(file.path) && !invokesPythonScript(manifest, file.path)) continue;
    const directory = file.path.slice(0, file.path.lastIndexOf('/') + 1);
    for (const [, module, name] of file.content.matchAll(pythonConfigCredentialUse)) {
      const configPath = directory + module + '.py';
      if (!uses.has(configPath)) uses.set(configPath, new Set());
      uses.get(configPath).add(name);
    }
  }
  return uses;
}

function invokesNodeScript(manifest, path) {
  if (!nodeFile.test(path) || !manifest.includes(path)) return false;
  const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const command = new RegExp('\\bnode[ \\t]+["\'\\x60]?(?:\\.?/|<skill[-_]dir(?:ectory)?>/|<this skill[\'’]s directory>/)?' +
    escaped + '(?=[\\s"\'\\x60)]|$)', 'gi');
  return Array.from(manifest.matchAll(command)).some(match => !negated(manifest, match.index));
}

function exportsUnlabeledDemo(match) {
  const [, indent] = match;
  const before = match.input.slice(Math.max(0, match.index - 700), match.index);
  if (!/^def main\([^\r\n]*\):\r?\n(?:[ \t]+[^\r\n]*\r?\n|\r?\n)*$/m.test(before)) return false;
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 700);
  const body = after.split(/\r?\n(?=\S)/, 1)[0];
  const callsDemo = new RegExp(String.raw`^${indent}(?:create|build|generate|render|save)_(?:demo|sample|synthetic)_\w+\(`, 'm');
  if (!callsDemo.test(body)) return false;
  return /\b(?:np|numpy)\.random\.(?:normal|uniform|randn?)\(/.test(match.input) &&
    /\b(?:savefig|save_figure|save_plot|save)\(/.test(match.input) &&
    !/\b(?:set_title|suptitle|set_xlabel|set_ylabel|title|figtext|text|print|warn)\([^\r\n]{0,140}["'][^\r\n]{0,100}\b(?:synthetic|mock data|sample data|demo|illustrative)\b/i.test(match.input);
}

function reportsUnlabeledMockFetch(match) {
  const [, indent, name] = match;
  const before = match.input.slice(Math.max(0, match.index - 2400), match.index);
  const functionStart = Array.from(before.matchAll(/^def[ \t]+\w+\(/gm)).at(-1)?.index;
  if (functionStart === undefined || !/^[ \t]+\w+[ \t]*=[ \t]*(?:fetch_url|get_url|requests\.get|httpx\.get|urlopen)\(/m.test(before.slice(functionStart))) return false;
  const following = match.input.slice(match.index + match[0].length, match.index + match[0].length + 2300);
  const closesData = new RegExp(String.raw`^${indent}\}[ \t]*\r?$`, 'm').exec(following);
  if (!closesData) return false;
  const data = following.slice(0, closesData.index);
  if ((data.match(/(?:[:,\[])[ \t]*-?\d+(?:\.\d+)?(?=[ \t]*[,\]}])/g) ?? []).length < 3) return false;
  const returnsData = new RegExp(String.raw`^(?:[ \t]*\r?\n)+${indent}return[ \t]+[A-Z]\w*\([ \t]*\r?\n([\s\S]{0,580}?)\r?\n${indent}\)`);
  const fields = returnsData.exec(following.slice(closesData.index + closesData[0].length))?.[1];
  if (!fields || !/\bsuccess[ \t]*=[ \t]*True\b/.test(fields) ||
      !new RegExp(String.raw`\bdata[ \t]*=[ \t]*${name}\b`).test(fields)) return false;
  return !/\b(?:mock|synthetic|simulated|is_mock|is_demo|data_source)["']?[ \t]*[:=]/i.test(data + fields);
}

function relativeFilePath(from, reference) {
  const parts = from.split('/').slice(0, -1);
  for (const segment of reference.split('/')) {
    if (segment === '..') {
      if (!parts.length) return;
      parts.pop();
    } else if (segment && segment !== '.') {
      parts.push(segment);
    }
  }
  return parts.join('/');
}

function* localNodeModuleReferences(source) {
  const commentsAndTemplates = /"(?:\\[\s\S]|[^"\\\r\n])*"|'(?:\\[\s\S]|[^'\\\r\n])*'|(\x60(?:\\[\s\S]|[^\x60\\])*\x60|\/\*[\s\S]*?(?:\*\/|$)|\/\/[^\r\n]*)/g;
  const code = source.replace(commentsAndTemplates, (token, remove) => remove ? token.replace(/[^\r\n]+/g, ' ') : token);
  for (const match of code.matchAll(relativeNodeImport)) yield match[1];
  const directory = /^[ \t]*const[ \t]+([\w$]+)[ \t]*=[ \t]*dirname\(fileURLToPath\(import\.meta\.url\)\)[ \t]*(?:;|$)/m.exec(code);
  if (!directory) return;
  const imported = new Set([...code.matchAll(/\bimport\(pathToFileURL\(([\w$]+)\)\.href\)/g)].map(match => match[1]));
  for (const match of code.matchAll(/^[ \t]*const[ \t]+([\w$]+)[ \t]*=[ \t]*(?:join|resolve)\(([\w$]+)((?:\s*,\s*['"][\w.-]+['"]){1,8})\s*\)[ \t]*(?:;|$)/gm)) {
    if (match[2] === directory[1] && imported.has(match[1])) {
      yield './' + [...match[3].matchAll(/['"]([\w.-]+)['"]/g)].map(part => part[1]).join('/');
    }
  }
}

export function reachableNodeScripts(files, manifest) {
  const modules = new Map(files.filter(file => nodeFile.test(file.path)).map(file => [file.path, file.content]));
  const reachable = new Set([...modules.keys()].filter(path => invokesNodeScript(manifest, path)));
  for (const path of reachable) {
    for (const reference of localNodeModuleReferences(modules.get(path))) {
      const resolved = relativeFilePath(path, reference);
      if (!resolved) continue;
      const target = [resolved, resolved + '.js', resolved + '/index.js'].find(candidate => modules.has(candidate));
      if (target) reachable.add(target);
    }
  }
  return reachable;
}

function referencesDocument(manifest, path) {
  if (manifest.includes(path)) return true;
  for (const [, folder, extension] of manifest.matchAll(/\x60((?:[\w.-]+\/)+)<[\w-]+>(\.[\w]+)\x60/g)) {
    if (path.startsWith(folder) && path.endsWith(extension) && !path.slice(folder.length).includes('/')) return true;
  }
  return false;
}

function referencesIndexedRegistryDocument(manifest, path) {
  for (const [, folder, entryList] of manifest.matchAll(/^All in \x60((?:[\w.-]+\/)+)\x60:[ \t]*\r?\n([\s\S]*?)(?=^<\/|^#{1,2}[ \t]|(?![\s\S]))/gim)) {
    if (!path.startsWith(folder)) continue;
    const basename = path.slice(folder.length);
    if (basename.includes('/')) continue;
    for (const [, entry] of entryList.matchAll(/^[ \t]*(?:[-*][ \t]+|\|[ \t]*)\x60?([\w.-]+\.md)(?=\x60?(?:[ \t]|$))/gm)) {
      if (entry === basename) return true;
    }
  }
  return false;
}

const companionMarketplaceInstall = /^[ \t]*\/plugin marketplace add[ \t]+[\w.-]+\/([\w.-]+)[ \t]*\r?\n[ \t]*\/plugin install[ \t]+([\w.@-]+)/gim;
const requiredCompanionContext = /\b(?:must|requires?|prerequisite|depends on|before using)\b|必须|必須|依赖|依賴/i;

function documentedPythonEntryPoint(manifest, path) {
  if (invokesPythonScript(manifest, path)) return true;
  if (!/^scripts\/[\w.-]+\.py$/.test(path) || !manifest.includes(path)) return false;
  const escaped = path.replaceAll('.', '\\.');
  const invocation = new RegExp(String.raw`\bpython3?[ \t]+["'\x60]?(?:\/[\w.-]+)+\/${escaped}(?=[\s"'\x60]|$)`, 'gi');
  return [...manifest.matchAll(invocation)].some(match => !negated(manifest, match.index));
}

function requiredMarketplaceCompanion(readme, index, manifest, files) {
  const context = readme.slice(Math.max(0, index - 345), index);
  if (!requiredCompanionContext.test(context)) return false;
  const dependencies = [...context.matchAll(/\x60([\w.-]+(?:[-_]skill|[-_]plugin))\x60/gi)];
  return dependencies.some(([, name]) => files.some(file =>
    file.content.includes('/' + name + '/') && documentedPythonEntryPoint(manifest, file.path)));
}

function buildsForwardedModelPrompt(source, match) {
  const [, command, prompt] = match;
  const assignment = new RegExp(String.raw`^[ \t]*${prompt}[ \t]*=[ \t]*([\w]+)\([ \t]*args[ \t]*\)`, 'm').exec(source.slice(0,match.index));
  if (!assignment) return false;
  const builder = new RegExp(String.raw`^def[ \t]+${assignment[1]}\(args\)[ \t]*:[ \t]*\r?\n`, 'm').exec(source);
  if (!builder) return false;
  const body = source.slice(builder.index + builder[0].length, builder.index + builder[0].length + 8000)
    .split(/^(?:async[ \t]+def|def|class)[ \t]+/m, 1)[0];
  if (!/\bargs\.prompt\b/.test(body) || !/\bargs\.dialogue\b/.test(body)) return false;
  const call = new RegExp(String.raw`\bsubprocess\.(?:run|Popen|check_call)\([ \t]*${command}(?=[\s,)])`);
  return call.test(source.slice(match.index + match[0].length, match.index + match[0].length + 600));
}

function followingWorkflowSteps(match) {
  const end = match.index + match[0].length;
  return match.input.slice(end, end + 2800).split(/\r?\n {0,2}[\w-]+:[ \t]*\r?(?:\n|$)/, 1)[0];
}

function executesConfiguredWorkflowTool(match) {
  const environment = /^env:[ \t]*\r?\n((?:[ \t]+[^\r\n]*\r?\n)+)/m.exec(match.input)?.[1];
  if (!environment) return false;
  const values = new Map(Array.from(environment.matchAll(
    /^[ \t]+([A-Z_][A-Z0-9_]*):[ \t]*["']?([^\s"']+)["']?[ \t]*(?:#[^\r\n]*)?\r?$/gm), ([, name, value]) => [name, value]));
  const [, branch, repository, folder] = match;
  if (!/^(?:main|master|latest)$/.test(values.get(branch) ?? '') ||
      !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(values.get(repository) ?? '')) return false;
  const destination = folder.replace(/^(?:\.\/)+/, '').replaceAll('.', '\\.');
  if (!destination) return false;
  const command = new RegExp('^[ \\t]*(?:(?:-[ \\t]+)?run:[ \\t]+)?(?:node|bun|python3?|bash|sh)[ \\t]+["\']?(?:\\./)?' +
    destination + '/[\\w./-]+\\.(?:[cm]?js|[cm]?ts|py|sh)(?=["\' \\t\\r\\n]|$)', 'm');
  const following = followingWorkflowSteps(match);
  const invocation = command.exec(following);
  return invocation && !verifiesWorkflowCheckout.test(following.slice(0, invocation.index));
}

function usesDiagnosticReference(manifest, path) {
  const mentions = manifest.split(/\r?\n/).filter(line => line.includes(path));
  return mentions.some(line => /\bfor (?:context|reference)\b/i.test(line)) &&
    !mentions.some(line => /\b(?:execute|run|follow|apply)\b/i.test(line));
}

function operatesSignedInBrowserAdapter(manifest, path, files) {
  const slash = path.lastIndexOf('/');
  const directory = path.slice(0, slash + 1);
  const basename = path.slice(slash + 1);
  const invoked = files.some(file => file.path !== path && file.path.startsWith(directory) && nodeFile.test(file.path) &&
    [`from './${basename}'`, `from "./${basename}"`].some(dependency => file.content.includes(dependency)));
  return invoked && files.some(file => {
    if (!/\.m(?:d|dx)$/i.test(file.path) || !referencesDocument(manifest, file.path)) return false;
    const at = Math.max(file.content.indexOf('`' + directory), file.content.indexOf('`' + directory.slice(0, -1) + '`'));
    return at >= 0 && /\b(?:account the user is logged in with|user['’]s signed-in browser)\b/i.test(
      file.content.slice(Math.max(0, at - 950), at + 100)
    );
  });
}

function lockfilePinsPythonArchive(file, finding) {
  if (!file) return false;
  const lines = file.content.split(/\r?\n/);
  return finding.evidence.length > 0 && finding.evidence.every(span => {
    const archive = /^[ \t]*(?:sdist[ \t]*=[ \t]*)?\{[ \t]*url[ \t]*=[ \t]*["']([^"'\s]+)["'][ \t]*,[ \t]*hash[ \t]*=[ \t]*["']sha256:[a-f0-9]{64}["']/i.exec(lines[span.line - 1] ?? '');
    return archive?.[1] === span.text;
  });
}

function extensionRecordsSignedInSession(files, path) {
  const source = files.find(file => /(?:^|\/)manifest\.json$/.test(file.path) &&
    /"manifest_version"\s*:/.test(file.content) && /"service_worker"\s*:/.test(file.content));
  if (!source) return false;
  let config;
  try {
    config = JSON.parse(source.content);
  } catch {
    return false;
  }
  if (!Array.isArray(config?.permissions) || !['cookies', 'debugger', 'storage'].every(name => config.permissions.includes(name)) ||
      typeof config?.background?.service_worker !== 'string') return false;
  const directory = source.path.slice(0, source.path.lastIndexOf('/') + 1);
  const workerPath = directory + config.background.service_worker;
  if (path !== workerPath && path !== 'SKILL.md') return false;
  const worker = files.find(file => file.path === workerPath)?.content;
  if (!worker || worker.matchAll(readsExtensionCookies).next().done ||
      !/^(?![ \t]*(?:\/\/|\*))[^\r\n]{0,110}\bchrome\.debugger\.attach\s*\(/m.test(worker)) return false;
  const logger = /\b(?:import|importScripts)[^\r\n]{0,160}["'](?:\.\/)?([\w.-]+\.js)["'][^\r\n]*/.exec(worker)?.[1];
  if (!logger || !files.some(file => file.path === directory + logger &&
      /\b(?:respBody|responseBody)\b/.test(file.content) &&
      /^(?![ \t]*(?:\/\/|\*))[^\r\n]{0,110}\bchrome\.storage\.local\.set\s*\(/m.test(file.content))) return false;
  return Array.isArray(config.content_scripts) && config.content_scripts.some(entry => Array.isArray(entry?.js) &&
    entry.js.some(name => files.some(file => file.path === directory + name &&
      /^(?![ \t]*(?:\/\/|\*))[^\r\n]{0,110}\bwindow\.postMessage\s*\(/m.test(file.content) &&
      /\b(?:respBody|responseBody)\b/.test(file.content))));
}

function recordsLifecycleEvents(source) {
  return /\bevent\.get\(["']hook_event_name["']\)/.test(source) &&
    /["']events\.jsonl["']\)\.open\(["']a["']/.test(source);
}

function feedsDesktopScriptFromStdin(match) {
  const preceding = match.input.slice(0, match.index);
  const variable = match[1];
  const escapedInput = new RegExp(String.raw`^[ \t]*${variable}=\$\{([A-Za-z_]\w*)\/\/`, 'm').exec(preceding);
  const input = escapedInput?.[1] ?? variable;
  return new RegExp(String.raw`^[ \t]*${input}=\$\(cat[ \t]*\)[ \t]*\r?$`, 'm').test(preceding);
}

function linksRecipeFromManifest(manifest, path, files) {
  if (referencesDocument(manifest, path)) return true;
  return files.some(parent => parent.path !== path && /\.m(?:d|dx)$/i.test(parent.path) &&
    referencesDocument(manifest, parent.path) && Array.from(parent.content.matchAll(/\]\(([\w./-]+\.m(?:d|dx))(?:#[\w-]+)?\)/gi))
      .some(([, link]) => relativeFilePath(parent.path, link) === path));
}

function invokesShellScript(manifest, path, allowHereDocument = false) {
  if (!/^(?:[\w.-]+\/)*[\w-]+(?:\.(?:sh|ps1))?$/i.test(path) || !manifest.includes(path)) return false;
  const escaped = path.replaceAll('.', '\\.');
  const script = '(?:\\.?/|<skill[-_]dir>/|\\{baseDir\\}/|\\$(?:skill_dir|\\{skill_dir\\})/)?' + escaped;
  const argument = allowHereDocument ? '(?=[\\w"\'$-]|<<)' : '(?=[\\w"\'$-])';
  const invocation = new RegExp('(?:\\b(?:bash|sh|powershell|pwsh|run|execute|invoke)[\\t ]+[\\x60"\']?' +
    script + '(?=[\\s\\x60"\')]|$)|(?:[\\x60"\']|^[\\t ]*|[;&|][\\t ]+)' +
    script + '[\\t ]+' + argument + ')', 'gim');
  return [...manifest.matchAll(invocation)].some(match => !negated(manifest, match.index));
}

function externalTaskListener(manifest, files) {
  const launchInstructions = manifest.replaceAll(/([\x60"'\s])SKILL_DIR\//g, '$1./');
  for (const launcher of files) {
    if (!launcher.path.endsWith('.sh') || !invokesShellScript(launchInstructions, launcher.path)) continue;
    const bundle = /^[ \t]*BUNDLE=["']?\$\{?SKILL_DIR\}?\/([\w./-]+\.js)["']?[ \t]*\r?$/m.exec(launcher.content)?.[1];
    if (!bundle || !/^[ \t]*nohup\b[^\r\n]{0,100}\$\{?BUNDLE\b/m.test(launcher.content)) continue;
    const code = files.find(file => file.path === bundle)?.content ?? '';
    if (/\bSERVER_URL\b[\s\S]{0,6000}\.on\(["']message["']/.test(code) && /\bWebSocket\b/.test(code)) return code;
  }
  return '';
}

function shellWrapperInvokesPython(manifest, path, files) {
  const separator = path.lastIndexOf('/');
  const directory = path.slice(0, separator + 1);
  const filename = path.slice(separator + 1).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const assignment = new RegExp(String.raw`^[ \t]*(\w+)=["']?\$\{?SCRIPT_DIR\}?/${filename}["']?[ \t]*\r?$`, 'm');
  return files.some(file => {
    if (!file.path.startsWith(directory) || !file.path.endsWith('.sh') ||
        file.path.slice(directory.length).includes('/') || !invokesShellScript(manifest, file.path)) return false;
    const target = assignment.exec(file.content)?.[1];
    return Boolean(target) && new RegExp(String.raw`^[ \t]*(?:exec[ \t]+)?["']?\$\{?PYTHON_(?:CMD|BIN)\}?["']?[ \t]+["']?\$\{?${target}\}?["']?(?=[ \t\r\n]|$)`, 'm').test(file.content);
  });
}

function invokesSourcedInstaller(manifest, path, files, evidence) {
  if (!path.endsWith('.sh') || !evidence) return false;
  const directory = path.slice(0, path.lastIndexOf('/') + 1);
  const name = path.slice(directory.length);
  if (!/^[\w.-]+$/.test(name)) return false;
  const content = files.find(file => file.path === path)?.content ?? '';
  const before = content.slice(Math.max(0, evidence.start - 800), evidence.start);
  const installer = [...before.matchAll(/^[ \t]*([a-zA-Z_][\w]*)\(\)[ \t]*\{[ \t]*\r?$/gm)].at(-1);
  if (!installer || /^[ \t]*\}[ \t]*\r?$/m.test(before.slice(installer.index + installer[0].length))) return false;
  const callsInstaller = new RegExp(String.raw`^[ \t]*(?:(?:if|elif)[ \t]+!?[ \t]*)?${installer[1]}(?=[ \t;\r\n]|$)`, 'm');
  const escaped = name.replaceAll('.', '\\.');
  const importsHelper = new RegExp(String.raw`^[ \t]*(?:source|\.)[ \t]+"\$\{SCRIPT_DIR\}/${escaped}"[ \t]*(?:#.*)?\r?$`, 'm');
  return files.some(file => {
    if (file.path === path || !file.path.startsWith(directory) || file.path.slice(directory.length).includes('/') ||
        !file.path.endsWith('.sh') || !invokesShellScript(manifest, file.path)) return false;
    const imported = importsHelper.exec(file.content);
    return imported && callsInstaller.test(file.content.slice(imported.index + imported[0].length));
  });
}

function executesBootstrapFromMetadata(metadata, source) {
  const fields = new RegExp(String.raw`^[ \t]*(\w+)[ \t]*=[^\r\n]{0,60}\b${metadata}\.get\(["']bootstrap_sha(?:256)?["']\)[^\r\n]*\r?\n[ \t]*(\w+)[ \t]*=[^\r\n]{0,150}\b${metadata}\.get\(["']bootstrap_url["']\)`, 'm').exec(source);
  if (!fields) return false;
  const [, digest, url] = fields;
  const download = new RegExp(String.raw`^[ \t]*(\w+)[ \t]*=[ \t]*download\(${url}\)[ \t]*\r?$`, 'm').exec(source)?.[1];
  const temporaryFile = /\b(\w+),[ \t]*(\w+)[ \t]*=[ \t]*tempfile\.mkstemp\([^\r\n]+suffix=["']\.py["']\)/.exec(source);
  if (!download || !temporaryFile) return false;
  const [, descriptor, path] = temporaryFile;
  return new RegExp(String.raw`\bhashlib\.sha256\(${download}\)\.hexdigest\(\)[ \t]*!=[ \t]*${digest}\b`).test(source) &&
    new RegExp(String.raw`\bos\.fdopen\(${descriptor},[ \t]*["']wb["']\)[ \t]+as[ \t]+(\w+):[ \t]*\r?\n[ \t]*\1\.write\(${download}\)`).test(source) &&
    new RegExp(String.raw`\bsubprocess\.run\(\[[ \t]*sys\.executable,[ \t]*${path}[ \t]*\]`).test(source);
}

function readmeInvokesReleaseInstaller(manifest, files) {
  const name = declaredSkillName(manifest, true);
  const readme = files.find(file => file.path === 'README.md')?.content;
  return name && readme && Array.from(readme.matchAll(readmeInstallerCommand)).some(match => match[1] === name);
}

function bundledModelCliUsesPrompt(manifest, files, evidence = '') {
  const name = /\bskills[ \t]+add[ \t]+[\w.-]+\/([\w.-]+)[ \t]+/.exec(evidence)?.[1];
  const entry = files.find(file => file.path === name || file.path === name + '.py');
  if (!name || declaredSkillName(manifest) !== name || !entry || !manifest.includes('<skill-dir>/' + name)) return false;
  const code = entry.content.replace(/^[ \t]*#[^\r\n]*/gm, '');
  const call = /^[ \t]*(\w+)[ \t]*=[ \t]*(\w+)\([ \t]*args\.prompt\b/m.exec(code);
  if (!call || !/\badd_argument\(["']prompt["']/.test(code) || !/\btext\/event-stream\b/.test(code)) return false;
  const [, payload, build] = call;
  const body = new RegExp('^def ' + build + '\\([ \\t]*prompt\\b[^\\r\\n]{0,180}\\)[^\\r\\n]*\\r?\\n((?:[ \\t]+[^\\r\\n]*\\r?\\n|\\r?\\n){1,80})', 'm').exec(code)?.[1];
  const text = body && /["']type["']\s*:\s*["']input_text["']\s*,\s*["']text["']\s*:\s*(\w+)/.exec(body)?.[1];
  if (!text || !new RegExp('^[ \\t]*' + text + '[ \\t]*=[\\s\\S]{0,410}?\\{prompt\\}', 'm').test(body)) return false;
  const dispatch = new RegExp('\\b(?:return[ \\t]+)?\\w+\\([ \\t]*' + payload + '[ \\t]*,[^\\r\\n]{1,120}\\)', 'm');
  return dispatch.test(code.slice(call.index + call[0].length));
}

function invokesDocumentedCheckout(match) {
  const project = match[2].replace(/\.git$/i, '').replaceAll('.', '\\.');
  const preceding = match.input.slice(Math.max(0, match.index - 185), match.index);
  if (/\b(?:upstream|fork|renamed|formerly|mirror|contributing)\b/i.test(preceding)) return false;
  const following = match.input.slice(match.index + match[0].length, match.index + match[0].length + 400)
    .split(/\r?\n(?=[ \t]*(?:\x60{3,}|~{3,}))/, 1)[0];
  const enters = new RegExp(String.raw`^[ \t]*cd[ \t]+["']?(?:\.\/)?${project}(?=[\s"']|$)`, 'm').exec(following);
  return enters && /^[ \t]*(?:python3?|node|bash|sh)[ \t]+["']?(?:\.\/)?[\w./-]+\.(?:py|js|mjs|cjs|sh)\b/m.test(
    following.slice(enters.index + enters[0].length));
}

function conflictsWithPackageRepository(evidence, files) {
  const repository = /(?:git\+)?https?:\/\/github\.com\/([\w.-]+)\/([\w.-]+)(?=[\s\x60;"']|$)/i;
  const claimed = repository.exec(evidence?.text ?? '');
  const packageFile = files.find(file => file.path === 'package.json');
  if (!claimed || !packageFile) return false;
  try {
    const metadata = JSON.parse(packageFile.content);
    const value = typeof metadata?.repository === 'string' ? metadata.repository : metadata?.repository?.url;
    const remote = typeof value === 'string' ? value.replace(/\/$/, '') : '';
    const declared = repository.exec(remote);
    if (!declared || declared[0].length !== remote.length) return false;
    const project = repo => repo[2].toLowerCase().replace(/\.git$/, '');
    return project(claimed) === project(declared) && claimed[1].toLowerCase() !== declared[1].toLowerCase();
  } catch {
    return false;
  }
}

function replacesCallerSelectedCheckout(match) {
  const [, variable] = match;
  const before = match.input.slice(0, match.index);
  const assignment = new RegExp(String.raw`^[ \t]*${variable}="\$([A-Za-z_]\w*|[12])"(?=[ \t\r\n;]|$)`, 'gm');
  const argumentsLoop = /^[ \t]*for[ \t]+([A-Za-z_]\w*)[ \t]+in[ \t]+"\$@"[ \t]*;[ \t]*do\b/gm;
  const args = new Set(['1', '2', ...Array.from(before.matchAll(argumentsLoop), value => value[1])]);
  if (!Array.from(before.matchAll(assignment)).some(value => args.has(value[1]))) return false;
  const recent = before.slice(-900);
  const checkout = new RegExp(String.raw`^[ \t]*if[ \t]+\[\[?[ \t]+-d[ \t]+"\$${variable}/\.git"[ \t]+\]\]?[ \t]*;[ \t]*then[ \t]*\r?$`, 'gm');
  const guard = Array.from(recent.matchAll(checkout)).at(-1);
  if (!guard) return false;
  const branch = recent.slice(guard.index + guard[0].length);
  if (!/^[ \t]*else[ \t]*\r?$/m.test(branch) || /^[ \t]*fi\b/m.test(branch)) return false;
  if (/\b(?:read[ \t]+-[rps]+|are you sure|confirm(?:_overwrite|_delete|_removal)|mktemp)\b|(?:^|\s)--(?:force|overwrite)\b/i.test(before)) return false;
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 300);
  return new RegExp(String.raw`^[^\r\n]*\r?\n[ \t]*git[ \t]+clone\b[^\r\n]{0,180}"\$${variable}"`).test(after);
}

function routesSpeechToDeviceAction(match) {
  const handler = match[3];
  const definition = new RegExp(String.raw`^[ \t]+def[ \t]+${handler}\(self,[ \t]*(\w+)\b[^\r\n]{0,100}:\r?$`, 'm');
  const implementation = definition.exec(match.input);
  if (!implementation) return false;
  const body = match.input.slice(implementation.index + implementation[0].length)
    .split(/^[ \t]*(?:async[ \t]+)?def\b/m, 1)[0];
  const dispatch = new RegExp(String.raw`^[ \t]+(?:\w+[ \t]*=[ \t]*)?self\.(?:device|phone)_control\.execute_command\(\s*${implementation[1]}\s*\)`, 'm').exec(body);
  return Boolean(dispatch) && !deviceActionConfirmation.test(match[0] + body.slice(0, dispatch.index));
}

function sendsOnAutoSelectedCanInterface(files, manifest) {
  return files.some(file => {
    const sender = /^scripts\/(?:[\w.-]+\/)*can_send\.py$/i.exec(file.path);
    if (!sender || !invokesPackagedPython(manifest, file.path) ||
        !/^[ \t]*from[ \t]+can_runtime[ \t]+import\b/m.test(file.content) ||
        !/\bget_can_config\(/.test(file.content) || !/\bbus\.send\(/.test(file.content)) return false;
    const runtime = file.path.replace(/can_send\.py$/i, 'can_runtime.py');
    return files.some(helper => helper.path === runtime && /\bscan_can_interfaces\(/.test(helper.content) &&
      persistsSoleCanInterface.test(helper.content));
  });
}

function bundledDnsDeploymentSpans(source) {
  if (!source.includes('/dns_records') || !/\binput[ \t]*=[ \t]*input_text\b/.test(source) ||
      !/\bsubprocess\.run\(/.test(source)) return [];
  const spans = [];
  for (const match of source.matchAll(embeddedDeploymentShell)) {
    const end = source.indexOf(match[2], match.index + match[0].length);
    if (end < 0 || !source.slice(match.index, end).includes('/dns_records')) continue;
    const dispatch = new RegExp(String.raw`\brun\([\s\S]{0,80}["']ssh["'][\s\S]{0,250}\binput_text[ \t]*=[ \t]*${match[1]}\b`);
    if (dispatch.test(source.slice(end, end + 1000))) spans.push([match.index, end]);
  }
  return spans;
}

function installsEnumeratedSkillFiles(script, sourceUrl, name) {
  const ownerAndRepo = sourceUrl.split('/').slice(3, 5).join('/');
  return (script.includes('REPO="' + ownerAndRepo + '"') || script.includes("REPO='" + ownerAndRepo + "'")) &&
    script.includes('skills/' + name + '/') &&
    /https:\/\/api\.github\.com\/repos\/\$REPO\/git\/trees\/\$BRANCH\?recursive=1\b/.test(script) &&
    /\bcurl\b[^\r\n]{0,45}https:\/\/raw\.githubusercontent\.com\/\$REPO\/\$BRANCH\/\$path["'][ \t]+-o[ \t]+["']\$target["']/i.test(script) &&
    !/\b(?:sha256sum|shasum|gpg)\b/.test(script);
}

function advertisesCompleteTemplate(manifest, path) {
  const directory = path.slice(0, path.lastIndexOf('/') + 1);
  return directory.startsWith('templates/') && manifest.includes(directory) && completeTemplate.test(manifest) &&
    !disclosesTemplateStub.test(manifest);
}

function catalogsRenderedInstaller(manifest, path, files) {
  if (!/\.tsx$/i.test(path)) return false;
  return files.some(file => {
    if (!/\/README\.md$/i.test(file.path) || !referencesDocument(manifest, file.path)) return false;
    const directory = file.path.slice(0, file.path.lastIndexOf('/') + 1);
    return path.startsWith(directory) && file.content.includes('`' + path.slice(directory.length) + '`') &&
      manifest.split(/\r?\n/).some(line => line.includes(file.path) &&
        [...line.matchAll(/\b(?:read|use|load)\b/gi)].some(action => !negated(line, action.index)));
  });
}

function adoptsDesignContractExample(manifest, path, files) {
  if (!/\.design\b[^\r\n]{0,140}\bexecutable policy\b/i.test(manifest)) return false;
  if (referencesDocument(manifest, path)) return true;
  const example = files.find(file => file.path === path)?.content ?? '';
  const replacement = /\bcopy this file over[ \t]+\x60([\w./-]+\.md)\x60/i.exec(example)?.[1];
  if (!replacement || !files.some(file => file.path === replacement)) return false;
  const name = replacement.slice(replacement.lastIndexOf('/') + 1, -3);
  return referencesDocument(manifest, replacement) || manifest.includes(`[[${name}]]`);
}

function rendersPackagedSourceLink(manifest, path, files) {
  const component = /^templates\/src\/components\/(\w+)\.tsx$/.exec(path)?.[1];
  const command = /\bbash[ \t]+(?:\.\/|<path-to-[\w.-]+>\/)?scripts\/scaffold\.sh\b/i.exec(manifest);
  if (!component || !command || negated(manifest, command.index)) return false;
  const scaffold = files.find(file => file.path === 'scripts/scaffold.sh')?.content;
  const app = files.find(file => file.path === 'templates/src/App.tsx')?.content;
  if (!scaffold || !app || !/^[ \t]*TEMPLATES=["'][^"'\r\n]+\/templates["']/m.test(scaffold) ||
      !/^[ \t]*cp[ \t]+["']\$TEMPLATES\/src\/App\.tsx["']/m.test(scaffold)) return false;
  const copy = new RegExp(String.raw`^[ \t]*cp[ \t]+["']\$TEMPLATES/src/components/${component}\.tsx["']`, 'm');
  const imported = new RegExp(String.raw`^import[^\r\n]+ from ["']\./components/${component}["']`, 'm');
  const rendered = new RegExp(String.raw`<${component}\b([\s\S]{0,450}?)\/>`).exec(app);
  return copy.test(scaffold) && imported.test(app) && rendered && !/\bgithubUrl[ \t]*=/.test(rendered[1]);
}

function schedulesPackagePatch(manifest, path) {
  if (!path.endsWith('.py')) return false;
  for (let start = manifest.indexOf(path); start >= 0; start = manifest.indexOf(path, start + path.length)) {
    if (hooksPackagePatch.test(manifest.slice(start + path.length, start + path.length + 350))) return true;
  }
  return false;
}

function isReviewedInstallAlternative(manifest, path) {
  for (let index = manifest.indexOf(path); index >= 0; index = manifest.indexOf(path, index + path.length)) {
    const preceding = manifest.slice(0, index);
    if (!/\b(?:brew|apt(?:-get)?|dnf|npm|pip3?|winget)\s+install\b/i.test(preceding)) continue;
    const paragraph = manifest.slice(Math.max(0, index - 360), index + path.length + 130).split(/\n\s*\n/);
    if (paragraph.some(text => text.includes(path) && /\bif\s+you\s+(?:would\s+rather|prefer|want)\b/i.test(text) &&
        /\b(?:review|inspect)\s+the\s+scripts?\s+first\b/i.test(text))) return true;
  }
  return false;
}

function isScopedPackageReleaseAlternative(document, span) {
  const release = /^https:\/\/github\.com\/([\w-]+)\/[\w.-]+\/releases\/?$/i.exec(span.text);
  if (!release || !document) return false;
  const line = sourceLineAt(document, span.start);
  const alternative = /^[ \t]*npm[ \t]+install[ \t]+(?:-g|--global)[ \t]+@([\w-]+)\/[\w.-]+[ \t]+#[ \t]*or (?:use )?(?:a |the )?binary from (https:\/\/\S+)[ \t]*$/i.exec(line);
  return alternative?.[2] === span.text && alternative[1].toLowerCase() === release[1].toLowerCase();
}

function isDocumentedPublisherArtifact(manifest, document, span) {
  const github = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)\/(.+)$/i.exec(span.text);
  if (!document || !github) return false;
  const [, owner, repository, artifactPath] = github;
  const name = declaredSkillName(manifest)?.toLowerCase();
  if (name === 'slint' && owner.toLowerCase() === 'slint-ui' && repository.toLowerCase() === name) {
    const asset = /^releases\/latest\/download\/slint-(?:(lsp|viewer)-[\w-]+\.(?:tar\.gz|zip))?$/i.exec(artifactPath);
    const tools = asset?.[1] ? [asset[1].toLowerCase()] : ['lsp', 'viewer'];
    return Boolean(asset) && /\bprebuilt binaries\b/i.test(document) &&
      tools.every(tool => new RegExp(String.raw`^[ \t]*cargo[ \t]+install[ \t]+--locked[ \t]+slint-${tool}\b`, 'm').test(document)) &&
      manifest.includes('https://slint.dev/docs') && manifest.includes('https://releases.slint.dev/');
  }
  if (owner.toLowerCase() !== name) return false;
  const official = [...manifest.matchAll(/\bofficial[ \t]+\[[^\r\n\]]{1,100}\]\(https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)\/?\)/gi)]
    .filter(([, declaredOwner]) => declaredOwner.toLowerCase() === name);
  if (!official.length) return false;
  if (/^archive\/refs\/heads\/[\w.-]+\.tar\.gz$/i.test(artifactPath)) {
    const recipe = sourceLineAt(document, span.start);
    return official.some(([, , declaredRepository]) => declaredRepository.toLowerCase() === repository.toLowerCase()) &&
      /\bif (?:the )?user has neither\b[^\r\n]{0,70}\bfall back to a tarball\b/i.test(recipe) && /\|[ \t]+tar\b/i.test(recipe);
  }
  const release = /^releases\/download\/(v\d+(?:\.\d+){2})\/([\w.-]+)\.tar\.gz$/i.exec(artifactPath);
  return Boolean(release && release[2].toLowerCase().startsWith(name + '-' + release[1].toLowerCase() + '-'));
}

function isDocumentedPythonRegistryAlternative(manifest, document, span) {
  if (!document || !/^https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/(?:main|master)\/install\.(?:sh|ps1)$/i.test(span.text)) return false;
  const name = declaredSkillName(manifest);
  if (!name || !manifest.includes('Install: `pip install ' + name + '`')) return false;
  const recipe = sourceLineAt(document, span.start);
  const alternatives = document.slice(span.end, span.end + 330).split(/\r?\n[ \t]*\r?\n/, 1)[0];
  return /^[ \t]*-[ \t]+(?:macOS[ \t]*\/[ \t]*Linux|Windows(?:[ \t]+\(PowerShell\))?):[ \t]*\x60/im.test(recipe) &&
    [...alternatives.matchAll(/^[ \t]*-[ \t]+pip:[ \t]*\x60pip install ([\w.-]+)\x60/gim)].some(([, packageName]) => packageName === name);
}

function isRoutedVendorSetup(manifest, path, document, sourceUrl) {
  if (!document || !sourceUrl || !/\bread the relevant reference document before performing any\b[^\r\n]{0,65}\btask\b/i.test(manifest)) return false;
  const setup = manifest.split(/\r?\n/).some(line => line.includes(path) &&
    /\b(?:setting up|installing) the CLI or creating a profile\b/i.test(line));
  const vendor = /^https:\/\/install\.([\w-]+)\.[a-z]+\/install\.sh$/i.exec(sourceUrl)?.[1]?.toLowerCase();
  if (!setup || !vendor || !/\bif (?:the )?command is not found, proceed to step\b/i.test(document)) return false;
  return [...document.matchAll(/\bbrew[ \t]+install[ \t]+([\w-]+)\/([\w-]+)\/([\w-]+)[ \t]+--cask\b/gi)]
    .some(([, owner, repository, command]) => owner.toLowerCase().startsWith(vendor + '-') &&
      repository.toLowerCase() === vendor && command.toLowerCase() === vendor);
}

function isConditionalVendorPrerequisite(manifest, path, document, span) {
  const installer = /^https:\/\/([\w-]+)\.[a-z]+\/install$/i.exec(span.text);
  if (!document || !installer || !manifest.split(/\r?\n/).some(line => line.includes(path) &&
      /\bif\b[^.!?;]{0,110}\b(?:missing|not installed)\b/i.test(line) && /\bread\b/i.test(line))) return false;
  const preceding = document.slice(Math.max(0, span.start - 300), span.start);
  const check = /^([\w-]+)[ \t]+--version[ \t]*\r?\n\x60{3}[ \t]*\r?\n\s*If missing:[ \t]*\r?\n\s*\x60{3}(?:bash|sh)[ \t]*\r?\n[ \t]*curl\b[^\r\n|;&]{0,40}$/im.exec(preceding);
  if (!check) return false;
  const command = check[1].toLowerCase();
  const publisher = installer[1].toLowerCase();
  if (command === publisher) return true;
  return declaredSkillName(manifest)?.toLowerCase() === publisher &&
    manifest.includes('Bash(' + command + ':*)') && manifest.includes('https://' + span.text.split('/')[2] + '/');
}

function revokedDownloadExample(document, offset) {
  const lineStart = document.lastIndexOf('\n', offset - 1) + 1;
  const comment = /^[ \t]*\/\//;
  if (!comment.test(document.slice(lineStart, offset))) return false;
  const before = document.slice(Math.max(0, lineStart - 1200), lineStart).trimEnd().split(/\r?\n/);
  const after = document.slice(lineStart, lineStart + 1000).split(/\r?\n/);
  const first = before.findLastIndex(line => !comment.test(line)) + 1;
  const end = after.findIndex(line => !comment.test(line));
  const context = [...before.slice(first), ...after.slice(0, end < 0 ? after.length : end)]
    .map(line => line.replace(comment, '')).join(' ');
  return /\b(?:GHSA-[\w-]+|CVE-\d{4}-\d+|security advisory)\b/i.test(context) &&
    /\b(?:used to be on (?:this|the) allowlist|previously allowed|formerly allowed)\b/i.test(context) &&
    /\b(?:drop|remove|block|reject|no longer allow)\b[^.!?;]{0,60}\b(?:npm|npx|installer|install command)\b/i.test(context);
}

function inlinesBrowserStylesheet(document, offset) {
  const line = sourceLineAt(document, offset);
  if (!/\bawait fetch\(new URL\(/.test(line)) return false;
  const before = document.slice(Math.max(0, offset - 1100), offset);
  const after = document.slice(offset, offset + 1450);
  return /\bquerySelectorAll\([^\r\n]{0,110}\bstylesheet\b/.test(before) &&
    /await \w+\.blob\(\)/.test(after) && /\bcreateElement\(["']style["']\)/.test(after) &&
    /\bstyle\.textContent\s*=/.test(after);
}

function requiresExample(manifest, path) {
  const escaped = path.replace(/[.*+?^$\{\}()|[\]\\]/g, '\\$&');
  const invocation = new RegExp('\\b(?:run|follow|apply|execute|copy|install from)\\b[^\\r\\n.!?;]{0,75}' + escaped, 'gi');
  return [...manifest.matchAll(invocation)].some(match => !negated(manifest, match.index));
}

function usesLinkedRenderFile(manifest, path, files, accepts) {
  if (accepts(manifest, path)) return true;
  return files.some(({ path: guide, content }) => {
    if (guide === path || guide === 'SKILL.md' || !/\.md$/i.test(guide) || !referencesDocument(manifest, guide)) return false;
    const directory = guide.slice(0, guide.lastIndexOf('/') + 1);
    return path.startsWith(directory) && accepts(content, path.slice(directory.length));
  });
}

function isSocketReportReference(path, manifest, files) {
  if (path === 'SKILL.md' || readsScanReportContent.test(manifest)) return false;
  const guide = files.find(file => file.path === path)?.content ?? '';
  return socketCliReference.test(guide) && !readsScanReportContent.test(guide) &&
    /\bsocket[ \t]+scan[ \t]+create\b[^\r\n]{0,105}--report\b[^\r\n]{0,65}--json\b/i.test(guide) &&
    /\bsocket[ \t]+scan[ \t]+create\b[^\r\n]{0,105}--report\b[^\r\n]{0,65}--markdown\b/i.test(guide);
}

function showsNativeFetchReplacement(source, position) {
  return /\breplace\b[^.!?;\r\n]{0,80}\bdependencies\b[^.!?;\r\n]{0,80}\bnative JavaScript[ \t]*:\s*\x60{3}(?:js|javascript)[ \t]*\r?\n[^\x60]{0,360}\/\/[ \t]*Instead of axios[ \t]*\r?\n[ \t]*(?:const|let)[ \t]+\w+[ \t]*=[ \t]*await[ \t]*$/i.test(
    source.slice(Math.max(0, position - 640), position));
}

function showsReactiveFetchExample(source, position) {
  const precedingCode = source.slice(Math.max(0, position - 580), position);
  return /\b(?:export[ \t]+)?function[ \t]+useFetch\(url:[ \t]*MaybeRefOrGetter<string>\)[ \t]*\{[^\x60]{0,410}\bwatchEffect\(/.test(precedingCode) &&
    /\bUse[ \t]+\x60toValue\(\)\x60[^\r\n]{0,75}\bnormalize refs, getters, or plain values\b/i.test(precedingCode);
}

function isEvaluationFixtureDocument(path, manifest, files) {
  const root = /^(evals\/fixtures\/[\w.-]+)\/(?:[\w.-]+\/)*[\w.-]+\.(?:md|mdx|rst|txt)$/i.exec(path)?.[1];
  if (!root || referencesDocument(manifest, path) || manifest.includes(root)) return false;
  const fixtureDirectory = root.toLowerCase() + '/';
  const hasRuntimeReference = files.some(file =>
    !file.path.startsWith('evals/') && file.content.includes(root));
  const containsSkill = files.some(file =>
    file.path.toLowerCase().startsWith(fixtureDirectory) && /(?:^|\/)SKILL\.md$/i.test(file.path));
  if (hasRuntimeReference || containsSkill) return false;
  const configuration = files.find(file => file.path === 'evals/evals.json')?.content;
  if (!configuration) return false;
  try {
    const evaluations = JSON.parse(configuration)?.evals;
    return Array.isArray(evaluations) && evaluations.some(evaluation =>
      Array.isArray(evaluation?.assertions) && Array.isArray(evaluation?.files) &&
      evaluation.files.some(input => input === path || input === path.slice('evals/'.length)));
  } catch {
    return false;
  }
}

const remoteConnectorAddress = /https:\/\/[a-z0-9.-]+(?::\d+)?\/(?:[\w.-]+\/)*mcp(?=[\s`)>\x22\x27/#?]|$)/gi;
const distributedZipAddress = /https:\/\/[a-z0-9.-]+(?::\d+)?\/(?:[\w.-]+\/)*[\w.-]+\.zip(?=[\s`)>\x22\x27#?]|$)/gi;

function requiredRemoteConnector(source, index) {
  const line = sourceLineAt(source, index);
  return /\bMCP (?:connector|server)\b/i.test(line) &&
    /\b(?:must be (?:enabled|connected|configured)|is required|required for|requires?)\b/i.test(line) &&
    !/\b(?:optional|not required|instead|do not connect|never connect|example only)\b/i.test(line);
}

function distributesSkillArchive(source, index) {
  const line = sourceLineAt(source, index);
  return /\b(?:download|install|unpack|extract|import)\b/i.test(line) &&
    !/\b(?:checksum|signature|sha-?256|do not download|example only)\b/i.test(line);
}

function connectorArchiveHost(address) {
  try {
    return new URL(address).host;
  } catch {
    return undefined;
  }
}

function removeMarkdownComments(source) {
  return source.replace(/<!--[\s\S]*?(?:-->|$)/g, comment => comment.replace(/[^\r\n]/g, ' '));
}

function isDocumentationExample({ sectionPath }) {
  return sectionPath.some(heading => /\b(?:examples?|samples?|fixtures?|demonstrations?|references?|reference only)\b/i.test(heading));
}

function setupProseMatches(source, pattern) {
  const prose = removeMarkdownComments(source);
  const matched = [];
  for (const block of markdownBlocks(prose)) {
    if (isDocumentationExample(block)) continue;
    for (const entry of block.entries) {
      if (entry.code || /^>/.test(entry.text)) continue;
      for (const match of entry.text.matchAll(pattern)) {
        const index = entry.start + match.index;
        if (!negated(prose, index)) matched.push({ address: match[0], index, prose });
      }
    }
  }
  return matched;
}


const shellCloneToVariable = /^[ \t]*(?:command[ \t]+)?git[ \t]+clone(?:[ \t]+(?:--depth[ \t]+\d+|--quiet|-q|--single-branch|--recursive|--recurse-submodules|--filter=[\w:=.-]+)){0,8}[ \t]+"?(https:\/\/[^\r\n"\s]+|\$\{?[A-Z_][A-Z_0-9]*\}?)"?[ \t]+"?\$\{?([A-Z_][A-Z_0-9]*)\}?"?(?=[ \t\r\n;]|$)/gm;
const executesCheckoutScript = /^[ \t]*(?:exec[ \t]+)?(?:bash|sh)[ \t]+"?\$\{?([A-Z_][A-Z_0-9]*)\}?\/(?:install|setup|bootstrap)\.sh(?=[\s"]|$)/gm;
const verifiesGitCheckout = /\b(?:sha(?:256|512)sum|shasum|git[ \t]+(?:-C[ \t]+["\w$./{}-]+[ \t]+)?(?:verify-commit|verify-tag|checkout|rev-parse)|gpg[ \t]+--verify)\b/;

function invokesBundledCheckoutInstaller(manifest, path) {
  if (invokesShellScript(manifest, path)) return true;
  const escaped = path.replaceAll('.', '\\.');
  const invocation = new RegExp(String.raw`^\s*(?:bash|sh)[ \t]+"\$\(dirname[ \t]+"\$\{?[A-Z_][A-Z_0-9]*\}?"\)\/${escaped}"(?=[ \t\r\n]|$)`, 'gm');
  return [...manifest.matchAll(invocation)].some(match => !negated(manifest, match.index));
}

function unverifiedGitCheckout(script) {
  if (!script.includes('git clone') || /<<-?[ \t]*["']?\w+/.test(script)) return;
  for (const match of script.matchAll(shellCloneToVariable)) {
    const [,remote,destination] = match;
    const cloneEnd = match.index + match[0].length;
    const setup = script.slice(cloneEnd, cloneEnd + 4000);
    for (const command of setup.matchAll(executesCheckoutScript)) {
      if (command[1] !== destination) continue;
      const before = setup.slice(0, command.index);
      const reassigned = new RegExp(String.raw`^[ \t]*(?:export[ \t]+)?${destination}=`, 'm');
      if (verifiesGitCheckout.test(before) || reassigned.test(before)) break;
      if (remote.startsWith('$')) {
        const source = remote.replace(/[$\{\}]/g, '');
        const assignedHttps = new RegExp(String.raw`^[ \t]*(?:export[ \t]+)?${source}="?\$\{[A-Z_][A-Z_0-9]*:-https:\/\/`, 'm');
        if (!assignedHttps.test(script.slice(0, match.index))) break;
      }
      return { clone: match.index + match[0].indexOf('git'), execute: cloneEnd + command.index + command[0].indexOf('/') + 1 };
    }
  }
}

function checkoutSetupCapabilities(manifest, instructions) {
  const active = instructions.map(entry => entry.text).join('\n');
  const configOutput = /\b(?:print|return|output)s?\b[^.!?;\r\n]{0,110}\b(?:config|configuration)\b/i;
  const readSetupOutput = /\b(?:use|using|apply|read)\b[^.!?;\r\n]{0,52}\b(?:JSON|configuration)\b[^.!?;\r\n]{0,56}\b(?:output|printed|emitted)\b/i;
  const registersMcp = /\b(?:register|configure|install)\b[^.!?;\r\n]{0,70}\bMCP\b|\bmcp[ \t]+add\b/i;
  const separatelyAuthorizesTrading = /\btrading\s+(?:requires|needs)\s+(?:configuring\s+)?(?:credentials|API[ -]?keys?)\b/i;
  let locate;
  const related = [];
  const add = (id, reason, pattern, accepts = () => true) => {
    for (const entry of instructions) {
      const match = pattern.exec(entry.text);
      if (!match || !accepts(entry.text)) continue;
      locate ??= sourceLocation(manifest);
      related.push({ ...finding(id, reason, [locate(entry.start + match.index, match[0].length, false)],
        'capability', 'direct'), path: 'SKILL.md' });
      break;
    }
  };
  if (configOutput.test(active)) {
    add('third-party-content', 'Setup uses configuration generated by code from the downloaded repository.', readSetupOutput);
  }
  if (registersMcp.test(active)) {
    add('financial-execution', 'Setup registers tools that can trade once the user configures credentials.',
      separatelyAuthorizesTrading, line => /\b(?:read-only|market data|analysis)\b/i.test(line) &&
        !/\b(?:paper trading|simulated trading|sandbox only|cannot trade|do not trade)\b/i.test(line));
  }
  return related;
}

export function templateResourceGateFindings(manifest, files) {
  if (!/\b(?:copy|apply|use)\b[^.!?\r\n]{0,115}\btemplates?\b/i.test(manifest)) return [];
  const contents = new Map(files.map(({ path, content }) => [path, content]));
  for (const { path, content } of files) {
    if (!path.endsWith('/PROFILE.md') || !referencesDocument(manifest, path)) continue;
    const directory = path.slice(0, -'PROFILE.md'.length);
    const modulePath = directory + 'templates/main.tf.template';
    const module = contents.get(modulePath);
    const variables = contents.get(directory + 'templates/variables.tf.template');
    if (!module || !variables) continue;
    const statements = /\bvar\.([A-Za-z_][\w]*)\x60?[^\r\n]{0,85}\bgates?\b[^\r\n]{0,55}\bcreation\b[\s\S]{0,235}\b(?:political|ideological|promotional)\s+(?:statement|endorsement)\s+variable\b/gi;
    const declarations = markdownBlocks(removeMarkdownComments(content))
      .filter(block => !isDocumentationExample(block) && block.entries.every(entry => !entry.code && !/^>/.test(entry.text)))
      .flatMap(block => [...block.text.matchAll(statements)]);
    for (const [, name] of declarations) {
      const definition = new RegExp(String.raw`^[ \t]*variable[ \t]+"${name}"[ \t]*\{[\s\S]{0,540}?\btype[ \t]*=[ \t]*bool\b`, 'm');
      const gate = new RegExp(String.raw`^[ \t]*create[ \t]*=[ \t]*var\.create[ \t]*&&[ \t]*var\.${name}\b`, 'm').exec(module);
      if (!gate || !definition.test(variables)) continue;
      const span = sourceLocation(module)(gate.index, gate[0].length, false);
      return [{ ...finding('unrelated-resource-gate',
        'A referenced module template makes resource creation depend on an unrelated endorsement flag.',
        [span], 'capability', 'direct'), path: modulePath }];
    }
  }
  return [];
}

export function invokedCheckoutFindings(manifest, files) {
  if (!manifest.includes('.sh')) return [];
  const instructions = markdownBlocks(removeMarkdownComments(manifest))
    .filter(block => !isDocumentationExample(block))
    .flatMap(block => block.entries.filter(entry => !/^>/.test(entry.text)));
  const commands = instructions.map(entry => entry.text).join('\n');
  for (const { path, content } of files) {
    if (!/^scripts\/(?:[\w.-]+\/)*[\w.-]+\.sh$/i.test(path) ||
        !invokesBundledCheckoutInstaller(commands, path)) continue;
    const checkout = unverifiedGitCheckout(content);
    if (!checkout) continue;
    const locate = sourceLocation(content);
    return [{
      ...finding('suspicious-download', 'The invoked installer clones a remote repository without verifying its revision.',
        [locate(checkout.clone, 'git clone'.length, false)], 'potential', 'direct'),
      path,
    }, {
      ...finding('dangerous-code-pattern', 'The invoked installer runs another installer directly from that unverified checkout.',
        [locate(checkout.execute, content.slice(checkout.execute).match(/^[\w.-]+/)?.[0].length ?? 0, false)],
        'potential', 'direct'),
      path,
    }, ...checkoutSetupCapabilities(manifest, instructions)];
  }
  return [];
}

export function connectorArchiveFindings(manifest, readme) {
  if (!manifest || !readme || !/\bMCP (?:connector|server)\b/i.test(manifest) || !/\.zip\b/i.test(readme)) return [];
  const connectorByHost = new Map();
  for (const match of setupProseMatches(manifest, remoteConnectorAddress)) {
    if (!requiredRemoteConnector(match.prose, match.index)) continue;
    const host = connectorArchiveHost(match.address);
    if (host && !connectorByHost.has(host)) connectorByHost.set(host, match);
  }
  if (!connectorByHost.size) return [];
  for (const match of setupProseMatches(readme, distributedZipAddress)) {
    if (!distributesSkillArchive(match.prose, match.index)) continue;
    const connector = connectorByHost.get(connectorArchiveHost(match.address));
    if (!connector) continue;
    const evidence = (source, url) => {
      const authority = url.address.slice(0, url.address.indexOf('/', 'https://'.length));
      return [sourceLocation(source)(url.index, authority.length, false)];
    };
    return [{
      ...finding('runtime-dependency', 'The skill requires an externally hosted MCP connector for its workflow.',
        evidence(manifest, connector), 'potential', 'direct'),
      path: 'SKILL.md',
    }, {
      ...finding('suspicious-download', 'The setup documentation links to a remotely hosted skill archive.',
        evidence(readme, match), 'potential', 'direct'),
      path: 'README.md',
    }];
  }
  return [];
}

export function scopeSnykFindings(findings, path, manifest, nodeScripts, files = []) {
  const pythonSource = path.endsWith('.py') && findings.some(finding => finding.id === 'embedded-secret' ||
    finding.snykEvidence === 'external-python-helper') ? files.find(file => file.path === path)?.content : undefined;
  const pythonCredentials = pythonSource && findings.some(finding => finding.id === 'embedded-secret')
    ? activePythonCredentialUse(manifest, files).get(path) : undefined;
  const invoked = findings.some(finding => finding.snykEvidence === 'invoked-script') &&
    (invokesPythonScript(manifest, path) || nodeScripts.has(path));
  const shellInvoked = findings.some(({ snykEvidence }) =>
    snykEvidence === 'invoked-shell' || snykEvidence === 'deploy-helper' || snykEvidence === 'release-installer-source') &&
    invokesShellScript(manifest, path);
  const readmeInvokesInstaller = path === 'install.sh' && findings.some(hit => hit.snykEvidence === 'release-installer-source') &&
    readmeInvokesReleaseInstaller(manifest, files);
  const prerequisiteRelease = path === 'README.md' &&
    /^[ \t]*cd[ \t]+scripts\/?[ \t]*\r?\n[ \t]*\.\/install-check\.sh\b/m.test(manifest)
    ? /\b(https:\/\/github\.com\/[\w.-]+\/[\w.-]+)\/releases\b/i.exec(
      files.find(file => file.path === 'scripts/install-check.sh')?.content ?? '')?.[1] : undefined;
  const supportingDocumentation = path !== 'SKILL.md' && /\.(?:md|mdx|rst|txt)$/i.test(path);
  const releaseHistoryScript = findings.some(finding => finding.snykEvidence === 'release-history-script') &&
    /\.[cm]?[jt]s$/i.test(path) && releaseNotesFromHistory.test(manifest) && (nodeScripts.has(path) ||
      [...manifest.matchAll(/\bnode[ \t]+["'`]?([^\s"'`]+)(?=[\s"'`]|$)/gi)].some(match =>
        !negated(manifest, match.index) && (match[1].replace(/^\.\//, '') === path ||
          (/^\/[^\s]+\/skills\//.test(match[1]) && match[1].endsWith('/' + path)))));
  const informationalCatalogEntry = supportingDocumentation && /^references\/[^/]+\.md$/i.test(path) &&
    manifest.includes('`references/<slug>.md`') && manifest.includes('仅作信息索引');
  const listener = supportingDocumentation && findings.some(finding => finding.snykEvidence === 'external-task-listener') &&
    referencesDocument(manifest, path) ? externalTaskListener(manifest, files) : '';
  const typeDeclaration = /\.d\.(?:ts|cts|mts)$/i.test(path);
  const pythonTestOnly = /(?:^|\/)tests?\/[^/]+\.py$|(?:^|\/)(?:test_[\w.-]+|run_self_tests)\.py$/i.test(path) &&
    !invokesPythonScript(manifest, path);
  const directory = path.slice(0, path.lastIndexOf('/') + 1);
  const linkedWorkflow = /\.ya?ml$/i.test(path) && referencesDocument(manifest, path);
  const offeredWorkflow = linkedWorkflow && manifest.split(/\r?\n/).some(line =>
    /\boffer (?:an? )?(?:optional )?(?:guardrail|follow-up)\b/i.test(line) && line.includes(path)) &&
    !requiresExample(manifest, path);
  const dnsDeployments = /\.py$/i.test(path) && !pythonTestOnly && referencesDocument(manifest, path) &&
    findings.some(item => item.snykEvidence === 'dns-deployment-alias' || item.id === 'embedded-secret' ||
      item.id === 'system-modification') ? bundledDnsDeploymentSpans(files.find(file => file.path === path)?.content ?? '') : [];
  const selfInstallingService = path === 'README.md' && !manifest.matchAll(createsServiceRelation).next().done
    ? declaredSkillName(manifest, true)
    : undefined;
  const readmeBootstrap = path === 'README.md' && findings.some(finding => finding.snykEvidence === 'readme-skill-bootstrap')
    ? files.find(file => file.path === 'install.sh')?.content : undefined;
  const fixtureSource = /^(?:evals\/[^/]+\.json|references\/[^/]+-patterns\.md)$/.test(path)
    ? files.find(file => file.path === path)?.content : undefined;
  const evaluationFixture = fixtureSource && path.endsWith('.json') &&
    /"evals"\s*:\s*\[/.test(fixtureSource) && /"assertions"\s*:\s*\[/.test(fixtureSource);
  const patternTable = fixtureSource && path.endsWith('.md') ? fixtureSource.split(/\r?\n/) : undefined;
  const referenceTable = path.endsWith('.csv') && files.some(file => file.path === path &&
    /^[^\r\n]*,Guideline,Description,Do,Don't,Code Good,Code Bad,Severity,Docs URL\r?\n/.test(file.content));
  const documentsUnconnectedHook = findings.some(({ snykEvidence }) =>
    snykEvidence === 'packaged-lifecycle-context' || snykEvidence === 'readme-lifecycle-install') &&
    files.some(file => /(?:^|\/)HANDOVER\.md$/i.test(file.path) &&
      /(?:钩子尚未接入|hooks?\b[^\r\n]{0,50}\bnot yet (?:connected|integrated))/iu.test(file.content));
  return findings.filter(finding => {
    if (finding.snykEvidence === 'linked-catalog-build') {
      const repo = /\brepos\/([\w.-]+\/[\w.-]+)\/contents\//i.exec(finding.evidence[0]?.text ?? '')?.[1];
      const instructions = removeMarkdownComments(manifest);
      return path === 'SKILL.md' && Boolean(repo) && files.some(file => {
        if (!file.path.endsWith('.sh')) return false;
        const name = file.path.split('/').at(-1).replaceAll('.', '\\.');
        const invokes = new RegExp('(?:^|[\\s;])(?:sh|bash)[ \\t]+["\']?(?:\\$[A-Za-z_]\\w*/)?' + name + '(?=[\\s"\']|$)', 'im');
        if (!invokesShellScript(instructions, file.path) && !invokes.test(instructions)) return false;
        return [...file.content.matchAll(/^[ \t]*git[ \t]+clone\b[^\r\n]{0,160}(?:\\\r?\n[ \t]*[^\r\n]{0,160}){0,3}https:\/\/github\.com\/([\w.-]+\/[\w.-]+)/gim)]
          .some(([, source]) => source.replace(/\.git$/i, '').toLowerCase() === repo.toLowerCase());
      });
    }
    if (finding.snykEvidence === 'release-provenance-order') {
      if (path === 'SKILL.md') return true;
      if (isReviewedInstallAlternative(manifest, path)) return false;
      if (supportingDocumentation && referencesDocument(manifest, path)) return true;
      const published = /https:\/\/github\.com\/[\w.-]+\/([\w.-]+)\/releases\/(?:latest\/download|download\/[\w.-]+)\/([\w.-]+)/i
        .exec(finding.evidence[0]?.text ?? '');
      const name = declaredSkillName(manifest, true)?.toLowerCase();
      return path === 'README.md' && Boolean(name) && published?.[1].toLowerCase() === name &&
        published[2].toLowerCase().startsWith(name + '-');
    }
    if (finding.snykEvidence === 'bundled-model-cli-prompt') {
      return path === 'SKILL.md' && bundledModelCliUsesPrompt(manifest, files, finding.evidence[0]?.text);
    }
    if (finding.snykEvidence === 'repository-origin-conflict') {
      return path === 'README.md' && conflictsWithPackageRepository(finding.evidence[0], files);
    }
    if (finding.snykEvidence === 'linked-workflow') return linkedWorkflow && !offeredWorkflow;
    if (finding.snykEvidence === 'remote-host-installer') {
      if (path !== 'README.md') return false;
      const script = mutableWindowsInstallerPath.exec(finding.evidence[0].text)?.[1];
      if (!script || !files.some(file => file.path === script)) return false;
      const name = script.split('/').at(-1);
      return manifest.split(/\r?\n/).some(line => windowsInstallerPolicy.test(line) &&
        /[ \t]-File[ \t]+/i.test(line) &&
        line.split(/[\\/"'\x60 \t]/).some(token => token.toLowerCase() === name.toLowerCase()));
    }
    if (finding.snykEvidence === 'configured-workflow-runtime') return /\.ya?ml$/i.test(path);
    if (finding.snykEvidence === 'parallel-worker-approval') {
      return supportingDocumentation && referencesDocument(manifest, path) && /\bparallel\b/i.test(manifest);
    }
    if (finding.snykEvidence === 'obscured-url-example') {
      return path === 'SKILL.md' || (supportingDocumentation && referencesDocument(manifest, path));
    }
    if (finding.snykEvidence === 'registry-instruction-loader') {
      const invocation = finding.evidence[0]?.text.matchAll(mutableRegistryInstructions).next().value;
      return path === 'SKILL.md' && Boolean(invocation) && files.some(file => file.path !== path &&
        /\.(?:md|mdx)$/i.test(file.path) && referencesDocument(manifest, file.path) &&
        file.content.split(/\r?\n/).some(line => line.trimStart().startsWith(`${invocation[1]} exec ${invocation[2]} `)));
    }
    if (finding.snykEvidence === 'external-task-listener') {
      return Boolean(listener) && (finding.id !== 'dangerous-code-pattern' ||
        /\bpermissionMode\b[^\r\n]{0,180}["']bypassPermissions["']/.test(listener));
    }
    if (typeDeclaration && finding.id === 'third-party-content') return false;
    if (finding.snykEvidence === 'python-tool-prerequisite') {
      return path === 'SKILL.md' && files.some(file => invokesPythonScript(manifest, file.path));
    }
    if (finding.snykEvidence === 'readme-lifecycle-install') {
      const install = finding.evidence[0]?.text.matchAll(installsSkillFromMutableSource).next().value;
      const skillName = declaredSkillName(manifest);
      return path === 'README.md' && documentsUnconnectedHook && install && install[1] === skillName &&
        files.some(file => /(?:^|\/)agent_hook\.py$/i.test(file.path) &&
          recordsLifecycleEvents(file.content) && !file.content.matchAll(emitsLifecycleContext).next().done);
    }
    if (finding.snykEvidence === 'targeted-skill-bootstrap') {
      const name = declaredSkillName(manifest);
      const install = finding.evidence[0]?.text.matchAll(targetsSkillInRemoteBootstrap).next().value;
      return path === 'README.md' && Boolean(name) && install?.[1] === name;
    }
    if (finding.snykEvidence === 'cloned-python-agent-bootstrap') {
      const bootstrap = finding.evidence[0]?.text.matchAll(clonesPythonAgentBootstrap).next().value;
      return path === 'README.md' && bootstrap && files.some(file =>
        file.path === bootstrap[2] && /['"]--agent['"]/.test(file.content));
    }
    if (finding.snykEvidence === 'automation-task-snapshot') {
      return /^references\/automations\/[\w.-]+\.md$/.test(path) && manifest.includes('references/automations/') &&
        /\b(?:load|read) that full spec before executing\b/i.test(manifest) &&
        manifest.includes('--snapshot-file') && /\bAI[- ]authored\b/i.test(manifest);
    }
    if (fixtureSource && (finding.id === 'runtime-dependency' || finding.id === 'suspicious-download') &&
        finding.evidence.length && finding.evidence.every(span => /https?:\/\/example\.(?:com|org|net)(?=[:/\s'"]|$)/i.test(span.text) &&
          (evaluationFixture || patternTable?.[span.line - 1]?.startsWith('|')))) {
      return false;
    }
    if (finding.snykEvidence === 'unimplemented-operation-mode') {
      return path === 'SKILL.md' && packagesUnenforcedOperationMode(files, manifest);
    }
    if (finding.snykEvidence === 'unconfirmed-can-output') {
      return path === 'SKILL.md' && sendsOnAutoSelectedCanInterface(files, manifest);
    }
    if (finding.snykEvidence === 'readme-skill-install') {
      return selfInstallingService && /--skill[ \t]+([\w.-]+)/.exec(finding.evidence[0]?.text)?.[1] === selfInstallingService;
    }
    return true;
  }).map(finding => {
    const result = { ...finding, path };
    if (result.snykEvidence === 'linked-catalog-build') result.snykEvidence = 'direct';
    if (path === 'SKILL.md' && result.snykEvidence === 'tracked-repair-workflow') {
      const command = result.evidence[0].text.matchAll(trackedWriteThenCheck).next().value;
      const skillName = declaredSkillName(manifest);
      const localPath = command?.[1].replace(/^\.\//, '');
      const installedPrefix = skillName && '.agents/skills/' + skillName + '/';
      const helperPath = installedPrefix && localPath?.startsWith(installedPrefix)
        ? localPath.slice(installedPrefix.length) : localPath;
      const helper = files.find(file => file.path === helperPath)?.content ?? '';
      if (/\bargs\.(?:git_tracked|all_tracked)\b/.test(helper) && /\bgit\b[^\r\n]{0,36}\bls-files\b/.test(helper) &&
          /\bif[ \t]+not[ \t]+(?:args\.)?dry_run[ \t]*:[ \t]*\r?\n(?:[ \t]+[^\r\n]*\r?\n){0,3}[ \t]+[\w.]+\.write_(?:text|bytes)\(/.test(helper)) {
        result.snykEvidence = 'direct';
      }
    }
    if (nodeFile.test(path) && result.id === 'suspicious-download' &&
        result.snykEvidence === 'direct' && result.reason === unverifiedDownloadReason) {
      const source = files.find(file => file.path === path)?.content;
      if (source && result.evidence.every(span => revokedDownloadExample(source, span.start))) {
        result.snykEvidence = 'reference-example';
      }
    }
    if (result.id === 'third-party-content' && result.reason === webRetrievalReason &&
        result.snykEvidence === 'direct') {
      const asset = /\.html?$/i.test(path) ? files.find(file => file.path === path)?.content : undefined;
      const readme = /^README(?:\.[\w.-]+)?\.md$/i.test(path) ? files.find(file => file.path === path)?.content : undefined;
      if ((asset && result.evidence.every(span => inlinesBrowserStylesheet(asset, span.start))) ||
          (readme && result.evidence.every(span => /\bif the embedded player does not load,\s*open the URL\b/i.test(
            sourceLineAt(readme, span.start))))) {
        result.snykEvidence = 'reference-example';
      }
    }
    if (pythonSource && result.id === 'embedded-secret') {
      const literal = result.evidence[0];
      const name = /^[ \t]*([A-Z_]\w*)[ \t]*=/.exec(sourceLineAt(pythonSource, literal.start))?.[1];
      if (name && pythonCredentials?.has(name)) result.snykEvidence = 'direct';
    }
    if (pythonSource && result.snykEvidence === 'external-python-helper' &&
        (invokesPythonScript(manifest, path) || [...manifest.matchAll(pythonHostCommandLink)].some(match => match[1] === path))) {
      const directory = path.slice(0, path.lastIndexOf('/') + 1);
      const offset = result.evidence[0].start;
      const adjacent = pythonSource.slice(Math.max(0, offset - 300), offset);
      const credential = [...adjacent.matchAll(pythonConfigCredentialUse)].some(([statement, module, name]) =>
        statement.startsWith('os.environ') && files.some(file => file.path === directory + module + '.py' &&
          [...file.content.matchAll(assignment)].some(match => {
            const value = match.slice(2).find(Boolean);
            return match[1] === name && value?.length >= 16 && new Set(value).size >= 12 && !placeholder.test(value);
          })));
      if (credential) result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'package-selector-script' && nodeFile.test(path) &&
        (nodeScripts.has(path) || invokesNodeScript(manifest.replace(/(\bnode[ \t]+["']?)\$\{?[A-Z_]\w*\}?\//g, '$1./'), path))) {
      result.snykEvidence = 'direct';
    }
    if (supportingDocumentation && result.id === 'agent-role-override' && result.reason === encodedRoleOverrideReason &&
        /\b(?:scan|audit|review|inspect)\w*[ \t]+(?:(?:a|an|the|any|installed|agent)[ \t]+){0,3}skills?\b/i.test(manifest) &&
        usesDiagnosticReference(manifest, path) &&
        /^#[ \t]+(?:prompt[- ]injection|instruction[- ]override) patterns[ \t]*\r?$/im.test(
          files.find(file => file.path === path)?.content ?? '')) {
      result.snykEvidence = 'reference-example';
    }
    if (result.snykEvidence === 'parallel-worker-approval' || result.snykEvidence === 'external-task-listener' ||
        result.snykEvidence === 'obscured-url-example' || result.snykEvidence === 'registry-instruction-loader') {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'unconfirmed-can-output') result.snykEvidence = 'direct';
    if ((result.snykEvidence === 'dns-deployment-alias' || result.id === 'embedded-secret' || result.id === 'system-modification') &&
        result.evidence.some(span => (result.id !== 'system-modification' || /\bsystemctl[ \t]+restart\b/i.test(span.text)) &&
          dnsDeployments.some(([start, end]) => span.start >= start && span.end <= end))) {
      result.snykEvidence = 'direct';
    }
    if (result.id === 'third-party-content' && result.reason === webRetrievalReason && result.snykEvidence === 'direct' &&
        isEvaluationFixtureDocument(path, manifest, files)) {
      result.snykEvidence = 'reference-example';
    }
    if (referenceTable && (finding.id === 'third-party-content' || finding.id === 'suspicious-download') &&
        result.snykEvidence === 'direct') result.snykEvidence = 'reference-example';
    if (/(?:^|\/)package-lock\.json$/.test(path) && result.id === 'suspicious-download' &&
        result.reason === unverifiedDownloadReason && result.evidence.length &&
        result.evidence.every(span => span.text.startsWith('https://registry.npmmirror.com/'))) {
      const lock = files.find(file => file.path === path)?.content ?? '';
      const archives = lockedDownloads(lock, true);
      if (result.evidence.every(span => archives.has(span.text) &&
          /"resolved"\s*:\s*"$/.test(lock.slice(Math.max(0, span.start - 40), span.start)))) {
        result.snykEvidence = 'reference-example';
      }
    }
    if (path === 'uv.lock' && result.id === 'suspicious-download' &&
        lockfilePinsPythonArchive(files.find(file => file.path === path), result)) {
      result.snykEvidence = 'reference-example';
    }
    if (path === 'SKILL.md' && result.snykEvidence === 'packaged-browser-session-export' &&
        files.some(file => /\.py$/i.test(file.path) && !/(?:^|\/)tests?\//i.test(file.path) &&
          /["']Runtime\.evaluate["']/.test(file.content) && /["']Network\.getResponseBody["']/.test(file.content))) {
      result.snykEvidence = 'direct';
    }
    if ((result.snykEvidence === 'extension-session-recorder' || result.snykEvidence === 'extension-session-token-argument') &&
        extensionRecordsSignedInSession(files, path)) result.snykEvidence = 'direct';
    if (path === 'SKILL.md' && result.snykEvidence === 'remote-command-worker' &&
        files.some(file => /(?:^|\/)agent\.py$/.test(file.path) &&
          /\bsys\.stdin\b/.test(file.content) && /\bsubprocess\.Popen\s*\(/.test(file.content) &&
          /\b(?:handle_exec|dispatch)\b/.test(file.content))) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'background-speech-device-action' && /\.py$/i.test(path) && !pythonTestOnly &&
        /\b(?:phone|device) (?:control|automation)\b/i.test(manifest) &&
        files.some(file => file.path === directory + 'voice_activation.py' &&
          /\bwhile[ \t]+self\.\w+[ \t]*:/.test(file.content) &&
          /\bself\._capture_audio_chunk\(/.test(file.content))) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'automated-skill-repair' && /\.py$/i.test(path) && !pythonTestOnly &&
        referencesDocument(manifest, path) && skipsRepairConfirmation.test(manifest) &&
        /修复|\b(?:repair|fix)\b/iu.test(manifest)) {
      const helpers = files.filter(file => /\.py$/i.test(file.path) && referencesDocument(manifest, file.path));
      if (helpers.some(file => /\bshutil\.rmtree\(/.test(file.content)) &&
          helpers.some(file => /\bos\.replace\(/.test(file.content))) result.snykEvidence = 'direct';
    }
    if (path === 'SKILL.md' && result.snykEvidence === 'packaged-worker-autostart' &&
        files.some(file => file.path.endsWith('.plist') &&
          /<key>RunAtLoad<\/key>\s*<true\s*\/>/.test(file.content) &&
          /<key>KeepAlive<\/key>\s*<true\s*\/>/.test(file.content))) result.snykEvidence = 'direct';
    if (invoked && result.snykEvidence === 'invoked-script') result.snykEvidence = 'direct';
    if (releaseHistoryScript && result.snykEvidence === 'release-history-script') result.snykEvidence = 'direct';
    if (result.snykEvidence === 'default-demo-report' && invokesPythonScript(manifest, path) &&
        !manifest.split(/\r?\n/).some(line => line.includes(path) && /\b(?:python|uv run)\b[^\r\n]+--demo\b/.test(line))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'mock-fetch-success' && /^scripts\/[\w./-]+\.py$/.test(path)) {
      const name = path.split('/').at(-1);
      if (invokesPythonScript(manifest, path) || manifest.split(/\r?\n/).some(line =>
        line.trimStart().startsWith('|') && line.split('|')[1]?.trim().replaceAll('`', '') === name)) {
        result.snykEvidence = 'direct';
      }
    }
    if (result.snykEvidence === 'documented-container-runner' &&
        (nodeScripts.has(path) || files.some(file => /\.m(?:d|dx)$/i.test(file.path) &&
          file.path !== 'SKILL.md' && referencesDocument(manifest, file.path) && invokesNodeScript(file.content, path)))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'document-renderer-sandbox' && /\.py$/i.test(path) &&
        /\bPuppeteer config\b/i.test(manifest) && /\brender(?:s|ing)?\b/i.test(manifest) &&
        /\.docx\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'recorded-product-action' && /\.sh$/i.test(path) &&
        referencesDocument(manifest, path) && /\bapproval cards?\b/i.test(manifest) &&
        /\btranscript\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'documented-cache-cleanup' && /\.sh$/i.test(path) &&
        referencesDocument(manifest, path) && /\bpasswordless sudo\b/i.test(manifest) &&
        /\bpackage archives\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'packaged-lifecycle-context' && /(?:^|\/)agent_hook\.py$/i.test(path) &&
        documentsUnconnectedHook) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'readme-lifecycle-install' || result.snykEvidence === 'targeted-skill-bootstrap') {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'cloned-python-agent-bootstrap' || result.snykEvidence === 'automation-task-snapshot') {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'packaged-inventory-description' && /\.sh$/i.test(path) &&
        referencesDocument(manifest, path) && /\binventory\b[^\r\n]{0,110}\bdescription\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (readmeBootstrap && result.snykEvidence === 'readme-skill-bootstrap') {
      const download = result.evidence[0]?.text.matchAll(remoteSkillBootstrap).next().value;
      const skillName = declaredSkillName(manifest);
      if (download?.[3] && download[3] === skillName && installsEnumeratedSkillFiles(readmeBootstrap, download[1], skillName)) {
        result.snykEvidence = 'direct';
      } else if (download && download[2] === skillName && readmeBootstrap.includes(download[1]) &&
          /\bcurl\b[^\r\n]{0,130}\/SKILL\.md\b/i.test(readmeBootstrap) &&
          /\bcurl\b[^\r\n]{0,130}\/[\w.-]+\.(?:py|sh|mjs|js)\b/i.test(readmeBootstrap)) {
        result.snykEvidence = 'direct';
      }
    }
    if (result.snykEvidence === 'readme-agent-skill-checkout' && /^README(?:\.[\w-]+)*\.md$/i.test(path)) {
      const checkout = result.evidence[0]?.text.matchAll(clonesAgentSkill).next().value;
      const skillName = declaredSkillName(manifest);
      if (checkout && checkout[1].toLowerCase() === skillName?.toLowerCase() &&
          files.some(file => file.path === 'requirements.txt')) result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'cloned-workspace-bootstrap' && path === 'README.md') {
      const clone = result.evidence[0]?.text.matchAll(clonesWorkspaceBootstrap).next().value;
      const skillName = declaredSkillName(manifest);
      if (clone && clone[1] === skillName && files.some(file =>
        /(?:^|\/)bootstrap\.js$/.test(file.path) && /\bexecSync\(["']npm install["'],[ \t]*\{[ \t]*cwd[ \t]*:/.test(file.content) &&
        /\bbootstrap\.js\b/.test(manifest))) result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'readme-python-scaffold' && path === 'README.md') {
      const clone = result.evidence[0]?.text.matchAll(clonesWorkspaceBootstrap).next().value;
      const name = declaredSkillName(manifest);
      const readme = files.find(file => file.path === path)?.content ?? '';
      const helper = pythonScaffoldCommand.exec(readme)?.[1];
      if (clone && clone[1] === name && helper && invokesPythonScript(manifest, helper) &&
          files.some(file => file.path === helper && /\bcopytree\s*\(/.test(file.content) &&
            /\bwrite_text\s*\(/.test(file.content))) result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'scaffold-csv-preview' && /^assets\/[\w.-]+\//.test(path)) {
      const template = path.split('/')[1];
      if (/\b(?:CSV|JSON) export\b|\bimport(?:s|ing)?\b/i.test(manifest) &&
          files.some(file => /^scripts\/scaffold[\w.-]*\.py$/.test(file.path) && invokesPythonScript(manifest, file.path) &&
            file.content.includes(template) && /\bcopytree\s*\(/.test(file.content))) {
        result.snykEvidence = 'direct';
      }
    }
    if (result.snykEvidence === 'evaluation-prompt' && /^evals\/.*\.md$/i.test(path)) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'component-registry-route' && supportingDocumentation && referencesDocument(manifest, path) &&
        manifest.split(/\r?\n/).some(line => line.includes(path) && /\b(?:shadcn|component|interaction|hit areas?)\b/i.test(line))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'required-skill-checkout' && path === 'README.md') {
      const skill = [...result.evidence[0].text.matchAll(prerequisiteSkillRepository)][0]?.[1];
      if (skill && [...manifest.matchAll(skillToolInvocation)].some(match =>
        match[1] === skill && !negated(manifest, match.index))) result.snykEvidence = 'direct';
    }
    if (supportingDocumentation && result.snykEvidence === 'direct' &&
        result.reason === unverifiedDownloadReason && result.evidence.length) {
      const document = files.find(file => file.path === path)?.content;
      if (result.evidence.every(span => isScopedPackageReleaseAlternative(document, span) ||
          isDocumentedPublisherArtifact(manifest, document, span) || isDocumentedPythonRegistryAlternative(manifest, document, span))) {
        result.snykEvidence = 'reference-example';
      }
    }
    if (supportingDocumentation && result.snykEvidence === 'direct' &&
        (result.reason === unverifiedDownloadReason || result.reason === mutableRuntimeSourceReason) &&
        result.evidence.length) {
      const document = files.find(file => file.path === path)?.content;
      if (isRoutedVendorSetup(manifest, path, document, result.evidence[0].text) ||
          result.evidence.every(span => isConditionalVendorPrerequisite(manifest, path, document, span))) {
        result.snykEvidence = 'reference-example';
      }
    }
    if (result.snykEvidence === 'linked-market-content' && supportingDocumentation &&
        referencesDocument(manifest, path) && /\bmarket[- ]data\b/i.test(manifest)) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'site-skill-archive' && /^INSTALL(?:\.[\w-]+)?\.md$/i.test(path)) {
      const host = /https:\/\/([\w.-]+)\//i.exec(result.evidence[0].text)?.[1];
      if (host && files.some(file => /^README(?:\.[\w-]+)?\.md$/i.test(file.path) &&
          file.content.split(/\r?\n/).some(line => line.includes('https://' + host + '/') && /\bZIP\b/i.test(line)) &&
          referencesDocument(file.content, path))) result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'linked-workflow' || result.snykEvidence === 'configured-workflow-runtime') result.snykEvidence = 'direct';
    if (result.snykEvidence === 'python-tool-prerequisite') result.snykEvidence = 'direct';
    if (shellInvoked && result.snykEvidence === 'invoked-shell') result.snykEvidence = 'direct';
    if (result.snykEvidence === 'desktop-script-evaluation' && invokesShellScript(manifest, path, true)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'desktop-script-input' && nodeFile.test(path) &&
        /\b(?:raw|arbitrary)\s+(?:ExtendScript|JSX|desktop scripts?)\b/i.test(manifest)) {
      const metadata = files.find(file => file.path === 'package.json')?.content;
      try {
        const entry = JSON.parse(metadata ?? '{}')?.main;
        if (typeof entry === 'string' && entry.replace(/^\.\//, '') === path) result.snykEvidence = 'direct';
      } catch {
        // An unreadable package manifest leaves the finding tentative.
      }
    }
    if (result.snykEvidence === 'vendor-attribution-headers' && path.endsWith('.sh') &&
        (invokesShellScript(manifest, path) || manifest.includes(`{SKILL_DIR}/${path} \\`)) &&
        !/\b(?:tracking|attribution) headers\b/i.test(manifest) &&
        !/\bdry[- ]run until the user approves the exact payload and cost boundary\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'bundled-tracking-rewrite' && nodeFile.test(path) && referencesDocument(manifest, path) &&
        files.some(file => nodeFile.test(file.path) && referencesDocument(manifest, file.path) &&
          /\b(?:const|let)\s+ENV_PATH\s*=\s*['"](?:[a-z]:\/|\/)[^'"\r\n]{0,260}\.env['"]/i.test(file.content) &&
          /\breadFileSync\(ENV_PATH\b/.test(file.content) && /\baccess_token\s*:/.test(file.content))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'vision-request-payload' && path.endsWith('.py') && referencesDocument(manifest, path) &&
        /\bpython3?\b[^\r\n]{0,80}[ \t]+--url\b/.test(manifest)) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'vision-request-with-chat-credential' && path.endsWith('.py') &&
        referencesDocument(manifest, path) && /\bpaste (?:the |your )?API key into (?:the )?chat\b/i.test(manifest) &&
        /\bpython3?\b[^\r\n]{0,80}\.py[ \t]+config[ \t]+["'<]/.test(manifest)) result.snykEvidence = 'direct';
    if ((shellInvoked || readmeInvokesInstaller) && result.snykEvidence === 'release-installer-source') {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'caller-selected-installer-target' && path === 'install.sh' &&
        (invokesShellScript(manifest, path) || invokesShellScript(files.find(file => file.path === 'README.md')?.content ?? '', path))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'configured-shell-installer' && invokesSourcedInstaller(manifest, path, files, result.evidence[0])) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'readme-paid-product-pitch' && path === 'README.md') result.snykEvidence = 'direct';
    if (result.snykEvidence === 'ci-example-installer' && /^examples\/[^/]+\.md$/.test(path) &&
        manifest.split(/\r?\n/).some(line => line.includes(path) && /\bwire CI\b/i.test(line))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'unverified-python-bootstrap' && path.endsWith('.py') &&
        (invokesPythonScript(manifest, path) || shellWrapperInvokesPython(manifest, path, files))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'self-updating-remote-bootstrap' &&
        invokesShellScript(manifest, path) && /\btelemetry\b[^\r\n]{0,45}\bautomatically\b/i.test(manifest) &&
        /\b(?:stays up to date|auto[- ]upgrades?) on each run\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (supportingDocumentation && result.snykEvidence === 'marketplace-image-listing' &&
        referencesDocument(manifest, path) && /\bpython3?\b[^\r\n]{0,120}\.py[ \t]+list_images\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (supportingDocumentation && result.snykEvidence === 'external-skill-test-input' &&
        referencesDocument(manifest, path) && /\btarget skills?\b/i.test(manifest) &&
        /--skills[ \t]+["'][\w,-]+/.test(manifest)) result.snykEvidence = 'direct';
    if (supportingDocumentation && result.snykEvidence === 'linked-web-capture' &&
        referencesDocument(manifest, path) && /\bcapture[ \t]+<url>(?=[`\s]|$)/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.id === 'undisclosed-account-adoption' && /\.sh$/i.test(path) &&
        invokesShellScript(manifest, path) && manifest.includes(path + ' login') &&
        ![...manifest.matchAll(disclosesAccountAdoption)].some(match => {
          const prefix = manifest.slice(Math.max(0, match.index - 24), match.index);
          return !negated(manifest, match.index) && !/\b(?:does|will|did) not[ \t]*$/i.test(prefix);
        })) {
      result.snykEvidence = 'direct';
    }
    if (supportingDocumentation && result.snykEvidence === 'linked-registry-catalog' &&
        referencesDocument(manifest, path) && /\bcatalog[ \t]+--query\b/.test(manifest) &&
        /\b(?:add|install)\b[^\r\n]{0,55}\bneeds the network\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
      result.reason = 'The skill searches a public registry and installs selected items into the project. That can bring contributor-authored content into the agent’s workflow when someone searches for and adds an item.';
    }
    if (supportingDocumentation && result.snykEvidence === 'linked-suggested-fix' &&
        referencesDocument(manifest, path) && /\b(?:response shapes|response format)\b[^\r\n]{0,135}\$hints\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (path.startsWith('commands/') && supportingDocumentation && result.snykEvidence === 'remote-conversation-audit-log') {
      const command = result.evidence[0]?.text.split('`')[1];
      if (command && manifest.split(/\r?\n/).some(line =>
        line.includes('`' + command + '`') && /\bpush to\b[^\r\n]{0,50}\bremote\b/i.test(line))) {
        result.snykEvidence = 'direct';
      }
    }
    if (path === 'SKILL.md' && result.snykEvidence === 'full-vault-chat-report' &&
        files.some(file => /\.m(?:d|dx)$/i.test(file.path) && file.path !== path &&
          referencesDocument(manifest, file.path) &&
          /\bCLAUDE\.local\.md\b[^\r\n]{0,115}\b(?:personal|local) credentials\b/i.test(file.content))) {
      result.snykEvidence = 'direct';
    }
    if (supportingDocumentation && result.snykEvidence === 'live-voucher-test' &&
        referencesDocument(manifest, path) && /--skills[ \t]+["'][\w-]*voucher[\w-]*["'][ \t]+--phase[ \t]+4\b/.test(manifest) &&
        /\bauto execution\b/i.test(manifest)) result.snykEvidence = 'direct';
    if (shellInvoked && result.snykEvidence === 'deploy-helper' && unauthenticatedDeployFallback.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'advertised-template' && advertisesCompleteTemplate(manifest, path)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'rendered-template-link' && rendersPackagedSourceLink(manifest, path, files)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'rendered-promotional-text' && /\.[jt]sx$/i.test(path) &&
        usesLinkedRenderFile(manifest, path, files, requiresExample)) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'community-route-geometry' && supportingDocumentation &&
        usesLinkedRenderFile(manifest, path, files, referencesDocument)) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'rendered-review-quota' && path === 'customize.toml' && /\brender_skill\.py\b/.test(manifest) &&
        /\bthorough\b/.test(manifest) && /\bworkflow\.review\b/.test(manifest) &&
        files.some(file => /\.md$/i.test(file.path) && /\{\{\s*workflow\.thorough_lenses\s*\}\}/.test(file.content) &&
          /\bauto[- ]fix\b/i.test(file.content) &&
          /\bno human interaction\b[^.!?;\r\n]{0,110}\b(?:do not ask|do not wait)\b/i.test(file.content))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'installed-module-hook' && schedulesPackagePatch(manifest, path)) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'documented-updater' && /\.(?:js|mjs|cjs)$/.test(path) && manifest.includes(path)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'scheduled-skill-update' && nodeFile.test(path) && manifest.includes(path) &&
        schedulesSkillUpdate.test(manifest) && !/(?:更新前|更新之前)[^。\r\n]{0,30}(?:用户确认|手动确认)/u.test(manifest) &&
        !/\b(?:ask|wait) (?:for )?(?:the )?user(?:'s)? (?:approval|confirmation|to approve) before updating\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'registry-script' && /\.ps1$/i.test(path) &&
        /\b(?:PowerShell|Windows)\b/i.test(manifest)) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'session-policy-fork' && /^scripts\/[\w.-]+$/i.test(path) &&
        manifest.includes(path.split('/').at(-1)) && /\bsessions?\b/i.test(manifest)) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'browser-proxy-script' && /^scripts\/[\w.-]+\.py$/i.test(path) &&
        manifest.includes(path) && /\b(?:CDP|browser debugging)\b/i.test(manifest)) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'linked-session-capture' && /\.py$/i.test(path) && referencesDocument(manifest, path)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'dynamic-package-runner' && nodeFile.test(path) &&
        (nodeScripts.has(path) || referencesDocument(manifest, path))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'signed-in-adapter' && nodeFile.test(path) && directory &&
        operatesSignedInBrowserAdapter(manifest, path, files)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'configurable-bearer-destination' && invokesShellScript(manifest, path)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'download-model-from-alternate-host' && path === 'SKILL.md') {
      const runnable = manifest.replaceAll('\\', '/').replace(/\bpython\.exe\b/gi, 'python');
      if (files.some(file => {
        if (!invokesPythonScript(runnable, file.path)) return false;
        const code = file.content.replace(/^[ \t]*#[^\r\n]*/gm, '');
        return /^[ \t]*from[ \t]+(?:faster_whisper|huggingface_hub|transformers)\b/m.test(code) &&
          /\b(?:WhisperModel|snapshot_download|hf_hub_download|from_pretrained)\s*\(/.test(code) &&
          !/\b(?:hashlib\.sha256|expected_sha256|sha256sum)\b/.test(code);
      })) {
        result.snykEvidence = 'direct';
      }
    }
    if (result.snykEvidence === 'escalated-packaged-windows-launcher' && path === 'SKILL.md') {
      const launcher = /\b([\w-]+\.ps1)\b/i.exec(result.evidence[0].text)?.[1];
      if (launcher && files.some(file => file.path === launcher || file.path.endsWith('/' + launcher)) &&
          files.some(file => /\.m(?:d|dx)$/i.test(file.path) && file.content.includes(launcher) &&
            [...file.content.matchAll(new RegExp(windowsInstallerPolicy.source, 'gi'))].some(match =>
              !negated(file.content, match.index) &&
              file.content.slice(Math.max(0, match.index - 240), match.index + match[0].length + 120).includes(launcher)))) {
        result.snykEvidence = 'direct';
      }
    }
    if (result.snykEvidence === 'readme-linked-mutable-skill' && path === 'README.md') {
      const linked = result.evidence[0].text.matchAll(clonesAndLinksSkill).next().value;
      if (linked?.[2] === declaredSkillName(manifest)) result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'global-skill-with-session-token' && path === 'SKILL.md') {
      const slug = /\bskills[ \t]+add[ \t]+[\w.-]+\/([\w.-]+)[ \t]+/.exec(result.evidence[0]?.text)?.[1];
      const entry = files.find(file => file.path === slug || file.path === slug + '.py');
      const code = entry?.content.replace(/^[ \t]*#[^\r\n]*/gm, '') ?? '';
      if (slug === declaredSkillName(manifest) && code &&
          manifest.includes('<skill-dir>/' + slug) &&
          /(?:^|\r?\n)(?:from[ \t]+pathlib[ \t]+import|import[ \t]+(?:json|urllib)\b)/.test(code) &&
          /\bauth\.json\b/.test(code) && /\baccess_token\b/.test(code) &&
          /["']Authorization["']\s*:\s*f?["']Bearer /i.test(code) &&
          /(?:\.read_text|\.open|json\.load)\s*\(/.test(code)) {
        result.snykEvidence = 'direct';
      }
    }
    if (result.snykEvidence === 'bundled-model-cli-prompt') result.snykEvidence = 'direct';
    if (result.snykEvidence === 'credential-refresh-route' && /\.py$/i.test(path) &&
        !/\b(?:token_uri|configurable (?:token|refresh) endpoint|credentials sent to a custom)\b/i.test(manifest)) {
      const credentialFile = /["']([\w.-]+_token\.json)["']/.exec(files.find(file => file.path === path)?.content ?? '')?.[1];
      if (credentialFile && manifest.includes(credentialFile)) result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'evaluation-web-trace' && supportingDocumentation &&
        referencesDocument(manifest, path) && /\beval run\b[^\r\n]{0,85}\binspect\b[^\r\n]{0,95}\bresults[_\/.]/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'external-application' && supportingDocumentation && referencesDocument(manifest, path) &&
        /\b(?:send|sending|delivery of) emails?\b/i.test(manifest.slice(0, 2000))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'desktop-debug-relaunch' && supportingDocumentation) {
      const chapter = /^references\/([\w-]+)\.md$/i.exec(path)?.[1];
      const namedGuide = chapter && /\bskills get [^\r\n]{0,55}<reference>/.test(manifest) &&
        manifest.includes('| `' + chapter + '` |');
      if (referencesDocument(manifest, path) || namedGuide) result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'unimplemented-operation-mode') result.snykEvidence = 'direct';
    if (result.snykEvidence === 'desktop-notification-read' && path === 'SKILL.md' &&
        files.some(file => /\.md$/i.test(file.path) && /\blist-notifications\b[^\r\n]{0,120}\btitle\b[^\r\n]{0,45}\bbody\b/i.test(file.content) &&
          /\bwait[ \t]+--notification\b/.test(file.content))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'hardware-log-stream' && invokesPackagedPython(manifest, path)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'issue-work-bundle' && path === 'SKILL.md' &&
        files.some(file => /(?:^|\/)jira-issue\.py$/i.test(file.path) && /\bdef (?:work|qa)\(/.test(file.content) &&
          /\bdescription\b/i.test(file.content) && /\bcomments\b/i.test(file.content))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'registry-metadata-script' && /^scripts\/[^/]+\.py$/i.test(path) &&
        (invokesPythonScript(manifest, path) || manifest.split(/\r?\n/).some(line =>
          line.includes(path) && /\bfetch(?:es)? (?:the )?(?:evidence|metadata|package information)\b/i.test(line)))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'project-color-settings' && /^scripts\/[^/]+\.py$/i.test(path) &&
        /\bproject-wide settings\b/i.test(manifest) && /\bcurrent timeline\b/i.test(manifest) &&
        !/\b(?:ask|wait) for (?:the )?user(?:'s)? (?:permission|approval) before changing\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'model-pickle-artifact' && /^scripts\/[^/]+\.py$/i.test(path) &&
        manifest.includes(path.split('/').at(-1)) && /\b[\w.-]+\.pkl\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'linked-prompt' && path.startsWith('prompts/') && supportingDocumentation &&
        manifest.includes(path)) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'linked-credential-setup' && supportingDocumentation && referencesDocument(manifest, path)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'linked-local-proxy' && manifest.includes(path) && localNetworkClaim.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'linked-evidence-default' && /\.ya?ml$/i.test(path) && manifest.includes(path) &&
        !/\b(?:share|upload|transmit)\b[^.!?;\r\n]{0,48}\b(?:browser|payload|evidence)\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'installed-cloned-wrapper' && /^README(?:\.[\w-]+)*\.md$/i.test(path)) {
      const wrapper = /\/(scripts\/[\w.-]+)[ \t]+(?:~\/|\$HOME\/)\.local\/bin\//.exec(result.evidence[0]?.text)?.[1];
      if (wrapper && manifest.includes(wrapper)) result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'windows-package-publisher' && /^README(?:\.[\w-]+)*\.md$/i.test(path) &&
        /\bpowershell(?:\.exe)?\b[^\r\n]{0,120}-ExecutionPolicy[ \t]+Bypass\b/i.test(manifest) && /\.bat\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'extension-test-script' && browserExtensionTests.test(manifest.slice(0, 1600)) &&
        (path === 'SKILL.md' || manifest.includes(path) || (directory && manifest.includes(directory)))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'documented-agent-install' && supportingDocumentation && manifest.includes(path) &&
        remoteToolEndpoint.test(manifest) && registersAgentTools.test(manifest) && /\b(?:bash|sh) install\.sh\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (supportingDocumentation && result.snykEvidence === 'external-design-guidance' &&
        referencesDocument(manifest, path)) {
      const workflow = files.find(file => file.path === path)?.content ?? '';
      const output = /\b(?:create|write|save)\s+(?:a\s+)?\x60?([\w.\/-]*\/DESIGN\.md)\b/i.exec(workflow)?.[1];
      if (output && /\b(?:before (?:calling|using)|MUST)\b[^\r\n]{0,125}\benhance\b[^\r\n]{0,100}\bprompt\b/i.test(manifest) &&
          markdownBlocks(removeMarkdownComments(manifest)).some(block =>
            !isDocumentationExample(block) && block.text.includes(output) &&
            /\b(?:incorporate|use|apply)\b[^\r\n]{0,110}\b(?:tokens|design system|guidance)\b/i.test(block.text))) {
        result.snykEvidence = 'direct';
      }
    }
    if (supportingDocumentation && result.snykEvidence === 'linked-document' && referencesDocument(manifest, path)) {
      result.snykEvidence = result.reason === socketReportRetrievalReason && isSocketReportReference(path, manifest, files) ?
        'reference-example' : 'direct';
    }
    if (result.snykEvidence === 'credential-telemetry' && /^scripts\/(?:[\w.-]+\/)*[\w.-]+\.py$/i.test(path) &&
        !pythonTestOnly && (invokesPythonScript(manifest, path) ||
          manifest.includes('scripts/') && manifest.includes(path.split('/').at(-1)))) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'git-identity-telemetry' && nodeScripts.has(path) &&
        !/\b(?:telemetry|reporting|analytics)\b[^.!?;\r\n]{0,125}\b(?:email domain|git identity)\b|\b(?:email domain|git identity)\b[^.!?;\r\n]{0,125}\b(?:telemetry|reporting|analytics)\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'instrumentation-fallback' && /\.sh$/i.test(path) &&
        manifest.includes(path.split('/').at(-1)) && /\b(?:read|record|capture) only (?:the )?app['’]s own\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'persistent-trust-selection' && /\.ps1$/i.test(path) &&
        referencesDocument(manifest, path) && /\b(?:clicks?|accepts?|handles?)\s+(?:the\s+)?trust dialogs?\b/i.test(manifest)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'requirements-recipe' && supportingDocumentation && linksRecipeFromManifest(manifest, path, files)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'linked-asset-sourcing' && supportingDocumentation && linksRecipeFromManifest(manifest, path, files)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'agent-skill-release-archive' && path === 'README.md') {
      const name = declaredSkillName(manifest, true);
      const [ , archive, extension] = /\/([^/\s]+)\.(tar\.(?:gz|xz)|zip)\b/.exec(result.evidence[0]?.text ?? '') ?? [];
      const versionedZip = name && extension === 'zip' && result.evidence[0]?.text.includes('/releases/latest/download/') &&
        archive?.startsWith(name + '-') && /^v?\d+(?:\.\d+)+(?=-|$)/i.test(archive.slice(name.length + 1));
      if (name && (archive === name || versionedZip)) result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'rendered-install-recipe' && catalogsRenderedInstaller(manifest, path, files)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'external-design-bootstrap' && supportingDocumentation &&
        adoptsDesignContractExample(manifest, path, files)) {
      result.snykEvidence = 'direct';
    }
    if (result.snykEvidence === 'readme-skill-install') result.snykEvidence = 'direct';
    if (result.snykEvidence === 'global-skill-copy' && (path === 'README.md' || path === 'SKILL.md')) result.snykEvidence = 'direct';
    if (result.snykEvidence === 'repository-origin-conflict') result.snykEvidence = 'direct';
    if (result.id === 'runtime-dependency' && result.snykEvidence === 'direct' &&
        finding.snykEvidence !== 'readme-skill-install' && finding.snykEvidence !== 'readme-skill-bootstrap' &&
        finding.snykEvidence !== 'readme-linked-mutable-skill' &&
        finding.snykEvidence !== 'global-skill-copy' &&
        finding.snykEvidence !== 'requirements-recipe' && finding.snykEvidence !== 'readme-lifecycle-install' &&
        finding.snykEvidence !== 'targeted-skill-bootstrap' && finding.snykEvidence !== 'cloned-python-agent-bootstrap' &&
        (pythonTestOnly || (supportingDocumentation && !referencesDocument(manifest, path)))) {
      result.snykEvidence = 'linked-document';
    }
    if (supportingDocumentation && result.id === 'suspicious-download' && result.snykEvidence === 'direct' &&
        ((!referencesDocument(manifest, path) && finding.snykEvidence !== 'requirements-recipe' &&
          finding.snykEvidence !== 'agent-skill-release-archive' && finding.snykEvidence !== 'readme-skill-bootstrap' &&
          finding.snykEvidence !== 'repository-origin-conflict' &&
          finding.snykEvidence !== 'cloned-python-agent-bootstrap' &&
          finding.snykEvidence !== 'readme-agent-skill-checkout' && finding.snykEvidence !== 'readme-python-scaffold' &&
          finding.snykEvidence !== 'required-skill-checkout' &&
          finding.snykEvidence !== 'site-skill-archive' &&
          !(prerequisiteRelease && manifest.includes(prerequisiteRelease) && result.evidence.some(span =>
            span.text.startsWith(prerequisiteRelease + '/releases/latest/download/')))) ||
         isReviewedInstallAlternative(manifest, path) ||
         (informationalCatalogEntry && finding.reason === unverifiedDownloadReason) ||
         (path.startsWith('examples/') && finding.snykEvidence !== 'ci-example-installer' && !requiresExample(manifest, path)))) {
      result.snykEvidence = 'manifest';
    }
    if (finding.snykEvidence === 'linked-component-registry' && supportingDocumentation &&
        referencesIndexedRegistryDocument(manifest, path)) {
      result.snykEvidence = 'direct';
    }
    if (finding.snykEvidence === 'companion-marketplace-install' && path === 'README.md') {
      const readme = files.find(file => file.path === path)?.content ?? '';
      if (requiredMarketplaceCompanion(readme, result.evidence[0].start, manifest, files)) result.snykEvidence = 'direct';
    }
    if (finding.snykEvidence === 'model-prompt-forward' && documentedPythonEntryPoint(manifest, path)) {
      result.snykEvidence = 'direct';
    }
    if (result.id === 'suspicious-download' && result.reason === unverifiedDownloadReason &&
        result.snykEvidence === 'direct' && /^templates\/(?:[\w.-]+\/)*[\w.-]+\.ya?ml$/i.test(path)) {
      const preset = files.find(file => file.path === path)?.content ?? '';
      if (result.evidence.length && result.evidence.every(({ start }) => /^[ \t]*#/.test(sourceLineAt(preset, start)))) {
        result.snykEvidence = 'reference-example';
      }
    }
    if (supportingDocumentation && referencesDocument(manifest, path) &&
        result.id === 'suspicious-download' && result.reason === unverifiedDownloadReason &&
        result.evidence.length && result.evidence.every(span => {
          if (!/^https:\/\/raw\.githubusercontent\.com\//i.test(span.text)) return false;
          try {
            return offersReviewedRepoInstaller(manifest, new URL(span.text));
          } catch {
            return false;
          }
        })) result.snykEvidence = 'reference-example';
    if (finding.snykEvidence === 'remote-host-installer') result.snykEvidence = 'direct';
    if (result.snykEvidence === 'release-provenance-order') result.snykEvidence = 'direct';
    if (/\.ps1$/i.test(path) && result.reason === webRetrievalReason && result.snykEvidence === 'direct') {
      const script = files.find(file => file.path === path)?.content ?? '';
      if (result.evidence.every(span => /^[ \t]*\$\w+\.Description[ \t]*=[ \t]*["']/i.test(sourceLineAt(script, span.start))) &&
          /\.CreateShortcut[ \t]*\(/i.test(script)) result.snykEvidence = 'reference-example';
    }
    return result;
  });
}

function nearMatch(match) {
  const before = match.input.slice(Math.max(0, match.index - 65), match.index).split(/[.!?;\r\n]/).at(-1);
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 65).split(/[.!?;\r\n]/, 1)[0];
  return before + match[0] + after;
}

function persistsCapturedHeaders(match) {
  const next = match.input.slice(match.index + match[0].length, match.index + 1050);
  const fields = /\b([A-Za-z_]\w*)[ \t]*=[ \t]*\{([^{}]{0,650})\}/g;
  const credential = new RegExp('\\b' + match[1] + '\\b');
  for (const entry of next.matchAll(fields)) {
    if (!credential.test(entry[2]) || /\b(?:redact|mask|anonymize|sha256)\w*\s*\(/i.test(entry[2])) continue;
    const after = next.slice(entry.index + entry[0].length, entry.index + entry[0].length + 135);
    const invocation = new RegExp('\\b([A-Za-z_]\\w*)\\([ \\t]*' + entry[1] + '[ \\t]*\\)').exec(after);
    if (!invocation) continue;
    const definition = new RegExp('^[ \\t]*def[ \\t]+' + invocation[1] + '\\([ \\t]*([A-Za-z_]\\w*)[^\\r\\n]*:', 'm');
    const target = definition.exec(match.input);
    if (!target) continue;
    const body = match.input.slice(target.index + target[0].length, target.index + 1150)
      .split(/\r?\n[ \t]*(?:def|class)[ \t]/, 1)[0];
    for (const dump of body.matchAll(/\bjson\.dump\([ \t]*([A-Za-z_]\w*)[ \t]*,/g)) {
      const inputs = body.slice(0, dump.index);
      if (/\b(?:redact|mask|anonymize|sha256)\w*\s*\(/i.test(inputs)) continue;
      const merge = new RegExp('\\b' + dump[1] + '\\.update\\([^\\r\\n]{0,220}\\b' + target[1] + '\\b');
      if (dump[1] === target[1] || merge.test(inputs)) return true;
    }
  }
  return false;
}

function loadsInstalledPackage(match) {
  const packageName = match[1];
  const before = match.input.slice(0, match.index);
  const after = match.input.slice(match.index);
  const argument = new RegExp('\\b(?:const|let)[ \\t]+' + packageName + '[ \\t]*=[ \\t]*process\\.argv\\[\\d+\\]');
  if (!argument.test(before) || !/\bexecSync\([ \t]*["'\x60]npm[ \t]+install\b/.test(after) ||
      /\b(?:allowedPackages|packageAllowlist|verifyPackageSignature)\b/.test(match.input)) return false;
  const location = new RegExp(String.raw`\b(\w+)[ \t]*=[ \t]*path\.(?:join|resolve)\([^\r\n]{0,90}["']node_modules["'][ \t]*,[ \t]*${packageName}\b`).exec(after);
  if (!location) return false;
  const module = new RegExp(String.raw`\b(\w+)[ \t]*=[ \t]*require\(path\.(?:join|resolve)\([ \t]*${location[1]}\b`).exec(after);
  if (!module) return false;
  const exported = new RegExp(String.raw`\b(?:const|let)[ \t]+\[[ \t]*\w*[ \t]*,[ \t]*(\w+)[ \t]*\][ \t]+of[ \t]+Object\.entries\(${module[1]}\)`).exec(after);
  return exported && new RegExp(String.raw`\bnew[ \t]+${exported[1]}[ \t]*\(`).test(after);
}

function routesRefreshCredentials(match) {
  const [, request, record, body] = match;
  const before = match.input.slice(Math.max(0, match.index - 1700), match.index);
  const after = match.input.slice(match.index + match[0].length, match.index + 550);
  const form = new RegExp(String.raw`\b${body}[ \t]*=[ \t]*urllib\.parse\.urlencode\(\{([^{}]{0,1450})\}\)`).exec(before);
  if (!form || /\b(?:urlparse|urlsplit|validate\w*Url|allowed_hosts|allowed_endpoints)\b/i.test(before)) return false;
  return ['client_secret', 'refresh_token'].every(field => new RegExp(
    String.raw`["']${field}["'][ \t]*:[ \t]*${record}\[["']${field}["']\]`,
  ).test(form[1])) && new RegExp(String.raw`\burllib\.request\.urlopen\([ \t]*${request}\b`).test(after);
}

function packagesUnenforcedOperationMode(files, manifest) {
  const example = files.find(file => file.path === 'config.example.json')?.content ?? '';
  if (!/"operation_mode"[ \t]*:[ \t]*[123]\b/.test(example)) return false;
  const delegatedConfirmation = /(?:按|根据)\s*`?operation_mode`?\s*(?:决定|判断)[^\r\n]{0,60}确认|\b(?:read|check|honor)\b[^.\r\n]{0,35}\boperation_mode\b[^.\r\n]{0,90}\b(?:ask|confirm)\b[^.\r\n]{0,55}\bbefore\b/i;
  if (delegatedConfirmation.test(manifest)) return false;
  const scripts = files.filter(file => /^scripts\/[^/]+\.py$/i.test(file.path));
  return scripts.some(file => invokesPackagedPython(manifest, file.path) &&
    /\b(?:erase|flash)\b/i.test(file.content) && /\bsubprocess\.(?:run|Popen)\(/.test(file.content)) &&
    scripts.some(file => /\b(?:json\.load|json\.loads)\(/.test(file.content)) &&
    !scripts.some(file => /\boperation_mode\b/.test(file.content));
}

function invokesPackagedPython(manifest, path) {
  if (!/^scripts\/[\w./-]+\.py$/i.test(path)) return false;
  if (invokesPythonScript(manifest, path)) return true;
  const windowsCommands = manifest.match(/^[ \t]*py[ \t]+-3[ \t]+[^\r\n]+/gm) ?? [];
  return windowsCommands.some(command => command.includes(path));
}

function workspaceRuleWithoutApproval(match) {
  if (/\b(?:only (?:if|after) (?:the )?user|user (?:approval|consent)|as (?:reference|data) only|for illustration only)\b/i.test(nearMatch(match))) {
    return false;
  }
  const position = match.index + match[0].length;
  const next = match.input.slice(position, position + 135);
  return !/^[^.!?;\r\n]{0,36}\.\s+(?:apply|follow|use)\s+(?:them|those (?:rules|instructions))\s+only (?:if|after) (?:the )?user\b/i.test(next);
}

function writesInstructionsByDefault(match) {
  const before = match.input.slice(Math.max(0, match.index - 180), match.index);
  const context = match.input.slice(match.index, match.index + match[0].length + 260);
  const persistence = /\b(?:persist\w*|marker.delimited|future (?:sessions?|runs?|tasks?)|(?:rule|instruction)s? block)\b/i;
  const defaultUse = /\b(?:do both (?:on|for|in) (?:any|all|every)|(?:on|for|in) every (?:project|run|session)|by default|always (?:perform|follow|do|apply) (?:both|all (?:of )?(?:the )?steps))\b/i;
  const optOut = /\b(?:unless (?:the )?user (?:asks|says|requests|opts|wants)|if (?:the )?user (?:wants|requests|asks)[^\r\n]{0,90}\b(?:only|just one|one of|skip|opt out)\b)/i;
  const optIn = /\b(?:only (?:if|when|after)|first ask(?:ing)?|wait for|requires?)\b[^\r\n]{0,90}\b(?:user (?:approval|consent)|explicit (?:request|consent|confirmation|permission)|user (?:requests|asks|approves|confirms))\b/i;
  return persistence.test(before + context) && defaultUse.test(context) && optOut.test(context) && !optIn.test(before + context);
}

function usesWebTool(match) {
  if (/^gh[ \t]/i.test(match[0])) return 'direct';
  const before = match.input.slice(Math.max(0, match.index - 42), match.index).split(/[.!?;\r\n]/).at(-1);
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 36);
  if (/^\(\*\)/.test(after)) return;
  if (/^[\x60'"_* ]*(?:\(|: *\{)/.test(after) ||
      /\b(?:use|call|run|invoke|using|via|with|choose|try|prefer|search|fetch)\b[^.!?;\r\n]{0,34}$/i.test(before)) {
    return 'direct';
  }
}

function readsMirroredDocumentation(match) {
  if (!/^(?:fetch|read|retrieve) (?:the )?(?:latest )?(?:docs|documentation) from (?:the )?raw GitHub URLs?$/i.test(match[0])) return false;
  const before = match.input.slice(Math.max(0, match.index - 115), match.index);
  if (!/\b(?:if|when)\b[^.!?;\r\n]{0,70}\b(?:more detail is needed|reference files are insufficient|local docs are incomplete)\b/i.test(before)) return false;
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 100);
  const name = /^[ \t]+(?:in|under) ([^.!?;\r\n]{2,60})[.!?;\r\n]/i.exec(after)?.[1].trim().toLowerCase();
  if (!name || !match.input.includes('<!-- source:')) return false;
  const headings = Array.from(match.input.matchAll(/^#{1,6}[ \t]+(.+)$/gm));
  const index = headings.findIndex(heading => heading[1].trim().toLowerCase() === name);
  if (index < 0) return false;
  const heading = headings[index];
  const section = match.input.slice(heading.index + heading[0].length, headings[index + 1]?.index);
  const urls = section.match(/https?:\/\/[^\s\x60)]+/gi) ?? [];
  const repos = urls.map(url => /^https:\/\/raw\.githubusercontent\.com\/([\w.-]+\/[\w.-]+)\/[^\s?#]+\.mdx?$/i.exec(url)?.[1]);
  return repos.length > 1 && Boolean(repos[0]) && repos.every(repo => repo === repos[0]);
}

function readsVendorDocumentation(match) {
  if (readsMirroredDocumentation(match)) return true;
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 1000);
  const previous = match.input.slice(Math.max(0, match.index - 250), match.index);
  if (/\bconfirm (?:anything |all )?version[- ]sensitive\b[^.!?;\r\n]{0,65}\b(?:current|latest) canonical docs\b[^.!?;\r\n]{0,125}$/i.test(previous) &&
      /^[^.!?;\r\n]{0,105}\bcite what you found\b/i.test(after)) return true;
  if (/^fetch the corresponding reference URLs relative to the skill URL$/i.test(match[0]) &&
      /\bwhen reading the hosted skill,[ \t]*$/i.test(match.input.slice(Math.max(0, match.index - 100), match.index))) return true;
  if (/^fetch URL$/i.test(match[0]) && /^ from `microsoft_docs_search`/i.test(after) &&
      /\bmicrosoft_docs_fetch\b/.test(match.input) && /https:\/\/learn\.microsoft\.com\//.test(match.input)) return true;
  if (/^fetch` a result's `url$/i.test(match[0]) &&
      /Prefer the `slint-docs` MCP server when its `search` and `fetch` tools are available/i.test(previous) &&
      /^\x60\.\s*Without them, fetch https:\/\/slint\.dev\/docs\b[^\r\n]{0,120}https:\/\/releases\.slint\.dev\//i.test(after)) return true;
  if (/^fetch \*\*exactly one\*\* of these URLs$/i.test(match[0]) && /^ and follow the guide step-by-step:/i.test(after)) {
    const domains = [...after.matchAll(/https:\/\/([\w.-]+)\//g)];
    if (domains.length > 0 && domains.every(([, name]) => name === 'workflow-sdk.dev')) return true;
  }
  if (/^fetch each URL$/i.test(match[0]) &&
      /"indexName"\s*:\s*"([a-z][\w-]+)"[\s\S]{0,650}\bAppend `\.md` to any \1 docs URL[\s\S]{0,250}https:\/\/(?:www\.)?\1\.[a-z]+\/docs\//i.test(match.input)) {
    return true;
  }
  const docs = 'https://cloud.laravel.com/docs/llms.txt';
  if (!match.input.includes(docs)) return false;
  const begin = match.input.lastIndexOf('\n', match.index - 1) + 1;
  const end = match.input.indexOf('\n', match.index);
  const line = match.input.slice(begin, end < 0 ? undefined : end);
  return /\bWebFetch\b/i.test(line) &&
    (line.includes(docs) || /\bLaravel Cloud feature\b[^\r\n]{0,45}\bfetch the docs from the URL above\b/i.test(line));
}

function readsThroughOperation(match) {
  const prefix = match.input.slice(Math.max(0, match.index - 95), match.index).split(/[.!?;\r\n]/).at(-1);
  if (/\b(?:cannot|can't|can not|could not)\s*$/i.test(prefix) || /^review,/i.test(match[0])) return;
  if (/\bclient metadata URL\b/i.test(match[0]) && /\bjwks_uri\b/.test(match.input)) return;
  if (/(?:只要|仅需)[^。！？\r\n]{0,62}$/u.test(prefix)) return;
  if (/\b(?:never|do not|must not)\s+(?:\w+[\s,]+){1,9}(?:or\s+)?$/i.test(prefix) && prefix.includes(',')) return;
  const bareCall = /^(?:fetch|read|retrieve|load)[ \t]*\([ \t]*(?:url|uri)\b/i.test(match[0]);
  if (!bareCall) return 'direct';
  const before = match.input.slice(Math.max(0, match.index - 45), match.index).split(/[.!?;|\r\n]/).at(-1);
  if (/\b(?:use|call|invoke|run|await|return)\b[^.!?;|\r\n]{0,24}$/i.test(before)) return 'direct';
}

function isNavigationOrMetadataOnly(match) {
  const prefix = match.input.slice(Math.max(0, match.index - 70), match.index);
  const before = prefix.split(/[.!?;\r\n]/).at(-1);
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 70).split(/\r?\n/, 1)[0];
  if (/\bcauses?\b[^.!?;\r\n]{0,58}\bbrowser to[ \t]*$/i.test(before) &&
      /^[ \t]*:[ \t]*exfiltration\b/i.test(after)) return true;
  if (/\b(?:XInclude|XSLT|schemaLocation)\b[^.!?;\r\n]{0,65}\bcan also[ \t]*$/i.test(before) &&
      /^[ \t]*;[ \t]*disable\b/i.test(after)) return true;
  if (/\bwrite_bytes\(\w+\.$/.test(prefix) &&
      /^read\(\)\)[ \t]+return[ \t]+\{[ \t]*(["'])url(?:\1:[ \t]*url)?$/i.test(match[0])) return true;
  if (/^read[-‐‑]only\b/i.test(match[0]) || (/^read\b/i.test(match[0]) && /--scope[ \t]+$/i.test(before))) return true;
  if (/^open (?:a|the) browser-fallback URL$/i.test(match[0])) return true;
  if (/^open it instead, so the URL$/i.test(match[0]) && /\.url\x60?[ \t]+shortcut[ \t]+and[ \t]*$/i.test(prefix)) return true;
  if (/^open[ \t]+["']\$\{?URL\b[^\r\n]*\bxdg-open\b/i.test(match[0])) return true;
  if (/["“]$/.test(before) && /^[…."”]/.test(after) &&
      /\bignore\s+(?:any\s+)?(?:text|instructions?)\b[^\r\n]{0,155}$/i.test(
        match.input.slice(Math.max(0, match.index - 180), match.index))) return true;
  if (/^open[ \t]*\([ \t]*(?:url|uri|href)\b/i.test(match[0]) && /\b(?:window|webbrowser)\.$/i.test(prefix)) return true;
  if (/^open (?:the |your |a )?(?:web )?browser and navigate to\b/i.test(match[0]) && !after.trim()) return true;
  if (/^open URL$/i.test(match[0]) && /^:[ \t]*`open[ \t]+["']?https?:\/\//i.test(after)) return true;
  if (/\bread back\b/i.test(match[0]) && /^,[ \t]*ID,[ \t]*(?:or|and)[ \t]+state\b/i.test(after)) return true;
  if (/^open['"][ \t]*,[ \t]*\[url\b/i.test(match[0]) && /\bspawn\(['"](?:xdg-)?$/i.test(before)) return true;
  if (/^open,[ \t]+copy the URL\b/i.test(match[0]) && /\bbrowser does not\s*$/i.test(before)) return true;
  if (/^open[ \t]+["']<the returned url\b/i.test(match[0]) && /\b(?:macOS|Linux|Windows)\b[^\r\n]{0,22}$/i.test(before)) return true;
  if (/^open the returned (?:playable |deployed |preview )?URL\b/i.test(match[0]) &&
      /\bsmoke (?:path|test|check)\b\.[ \t]+Deliver the URL returned by (?:the )?CLI\b/i.test(after)) return true;
  if (/^open-url$/i.test(match[0]) && /\bPOST[ \t]+\/[^\s]+\/$/i.test(prefix)) return true;
  if (/^open a (?:new )?tab\b[^.!?;\r\n]*\bopen-url$/i.test(match[0]) && /^`?[ \t]+endpoint\b/i.test(after)) return true;
  if (/^(?:open|fetch|read|retrieve|load)[ \t]*\(/i.test(match[0]) && /\b(?:function|def)[ \t]+$/i.test(before)) return true;
  if (/^fetch[ \t]*\([ \t]*(?:url|uri)\b/i.test(match[0]) &&
      /\breturn[ \t]+await[ \t]*$/i.test(before) &&
      /^[ \t]*,[ \t]*\{[ \t]*\.\.\.\w+[ \t]*,[ \t]*signal:[ \t]*\w+\.signal[ \t]*\}/.test(after)) return true;
  if (/^fetch\(\)\x60?[ \t]+to external URLs$/i.test(match[0]) && /\barbitrary[ \t]+\x60?$/i.test(before) &&
      /^[ \t]*\|/.test(after) && /\|[ \t]*(?:Blocked|Forbidden)[ \t]*\|[ \t]*Use instead[ \t]*\|/i.test(
        match.input.slice(Math.max(0, match.index - 1500), match.index))) return true;
  if (/^read config out of the URL\b/i.test(match[0])) return true;
  if (/^read from (?:the )?URL$/i.test(match[0]) && /^:[ \t]*\x60?\?[\w-]+=/i.test(after)) return true;
  if (/^(?:read|open|load|inspect)[ \t]+`(?:\.\/)?(?:docs|references)\/[^`\r\n]+$/i.test(match[0]) &&
      /^[\w.-]{0,55}\.m(?:d|dx)`/i.test(after)) return true;
  if (/^open the served URL\b/i.test(match[0]) && /^[ \t]+in[^\r\n]{0,45}\bbrowser\b/i.test(after)) return true;
  if (/^read the local copy:[^\r\n]{0,35}\bdocs URL\b/i.test(match[0]) && /^.{0,55}\bmaps to\b/i.test(after)) return true;
  if (/^read a raw URL\b/i.test(match[0]) && /\bnever re-$/i.test(before)) return true;
  if (/\bdirectives inside\b[^\r\n]{0,55}\([^)]*$/i.test(before) && /^.{0,65}\) are ignored\b/i.test(after)) return true;
  if (/^(?:read (?:this|that) file (?:only )?when|open (?:this|that) file and copy|read (?:its|the) (?:(?:server|process) )?output for (?:the )?local URL)\b/i.test(match[0])) return true;
  if (/^open\b/i.test(match[0]) && /\bask the host to\s*$/i.test(before)) return true;
  if (/^open (?:a|the) URL\b/i.test(match[0]) && /^[ \t]+or (?:an? )?app deep link\b/i.test(after)) return true;
  if (/^open (?:the|this) URL$/i.test(match[0])) {
    const previous = match.input.slice(Math.max(0, match.index - 320), match.index);
    if (/\boutput for the local URL\b[^\r\n]{0,130}\b(?:localhost|127\.0\.0\.1)\b/i.test(previous)) return true;
  }
  return /^open website$/i.test(match[0]) && !before.trim() && /^[ \t]+>[ \t]+[A-Z]/.test(after);
}

function matchesDocumentationUrl(match) {
  const start = match.input.lastIndexOf('https://', match.index);
  if (start === -1) return false;
  const matchedUrl = match.input.slice(start, match.index + match[0].length);
  return !/[\s\x60"'<>()[\]]/.test(matchedUrl) &&
    /^https:\/\/[^/]+\/(?:[a-z]{2}(?:-[a-z]{2})?\/)?(?:docs|documentation)\//i.test(matchedUrl);
}

function isRetrievalLabel(match) {
  const before = match.input.slice(Math.max(0, match.index - 42), match.index);
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 3);
  if (/^browse["']\s*,/.test(match[0]) && /["']$/.test(before) && /\],\s*["']Search Results$/.test(match[0])) return true;
  if (/^search[ -]/i.test(match[0]) && /\b(?:aria-label|placeholder|title|id|class)[ \t]*=[ \t]*["']$/i.test(before) &&
      /^["'](?:[ \t/>]|$)/.test(after)) {
    return true;
  }
  if (/\bdescription:[ \t]*['"][^"'\r\n]*$/.test(before) &&
      /^[^"'\r\n]{0,85}['"][ \t]*[,}]/.test(
        match.input.slice(match.index + match[0].length, match.index + match[0].length + 90))) return true;
  if (!/^\w+\]\s/.test(match[0])) return false;
  return /\b(?:log|write|print|debug|info)\s*\([rubf]*["']\[$/i.test(before);
}

function isPermissionAssessmentRow(source, offset) {
  const start = source.lastIndexOf('\n', offset - 1) + 1;
  if (!/^[ \t]*\|/.test(source.slice(start, offset))) return false;
  return /^[ \t]*\|[ \t]*Tool[ \t]*\|[ \t]*Justified When[ \t]*\|[ \t]*Unjustified When[ \t]*\|[ \t]*\r?\n[ \t]*\|[ \t:-]*-[ \t:|-]*\|[ \t]*\r?\n(?:[ \t]*\|[^\r\n]*\r?\n)*(?![\s\S])/im
    .test(source.slice(Math.max(0, start - 2400), start));
}

function sourceLineAt(source, offset) {
  const start = source.lastIndexOf('\n', offset - 1) + 1;
  const end = source.indexOf('\n', offset);
  return source.slice(start, end === -1 ? undefined : end);
}

function presentsUserRunInstaller(source, url, start, end) {
  if (url.protocol !== 'https:' || url.port || url.search || url.username ||
      !/^\/install\.sh$/.test(url.pathname)) return false;
  source = removeMarkdownComments(source);
  const line = sourceLineAt(source, start);
  const platformRow = /^[ \t]*\|[ \t]*([\w-]+)[ \t]*\|/.exec(line);
  if (platformRow) {
    const installer = /\bwinget[ \t]+install[ \t]+([\w-]+)\.([\w-]+)\b/i.exec(line);
    const after = source.slice(end, end + 1400);
    const manual = /\b(?:give|show|provide)\b[^.\r\n]{0,65}\bcommands?\b[^.\r\n]{0,115}\b(?:let (?:them|the user) run (?:them|it)|the user runs (?:them|it))\b/i;
    if (installer?.[2].toLowerCase() === platformRow[1].toLowerCase() &&
        installer[1].toLowerCase() === url.hostname.replaceAll('.', '') && manual.test(after)) return true;
  }
  const before = source.slice(Math.max(0, start - 3500), start);
  const after = source.slice(end, end + 640);
  const forced = /\b(?:always|automatically|without (?:asking|approval|confirmation))\b[^.\r\n]{0,65}\b(?:install|run)\b/i;
  if (forced.test(before.slice(-400) + after)) return false;
  const alternatives = /\b(?:two ways|choose (?:one|between)|two options)\b/i.test(before.slice(-360)) &&
    /\b(?:CLI|command.line)\b/i.test(before.slice(-360)) &&
    /\bMCP\b[^.\r\n]{0,100}\b(?:nothing to install|no (?:local )?install(?:ation)?(?: required)?)\b/i.test(after);
  const origin = url.origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const endpoint = new RegExp(origin + '/mcp/?(?=[\\s\\x60"\')]|$)', 'i');
  return alternatives && endpoint.test(after) &&
    /\b(?:only if (?:they|the user) (?:wants?|asks?|requests?)|only when (?:they|the user) (?:wants?|asks?|requests?)|ask(?: the user)? (?:first|before installing))\b/i.test(before);
}

function documentsConsentForVendorCli(source, url, offset) {
  if (url.hostname !== 'raw.githubusercontent.com') return false;
  const match = /^\/([\w.-]+)\/([\w-]+)-cli\/(?:main|master)\/scripts\/install\.(?:sh|ps1)$/i.exec(url.pathname);
  if (!match || !match[1].toLowerCase().startsWith(match[2].toLowerCase())) return false;
  const slug = match[2].toLowerCase();
  const earlier = source.slice(Math.max(0, offset - 2000), offset);
  const instructions = earlier.slice(-900);
  const following = source.slice(offset, offset + 900);
  return [...earlier.matchAll(/\bofficial[ \t]+`([\w-]+)`[ \t]+CLI\b/gi)].some(word => word[1].toLowerCase() === slug) &&
    /\bask (?:the )?user before installing\b[^\r\n]{0,75}\bafter they agree\b/i.test(instructions) &&
    /\bnever run (?:either|the) installer without explicit consent\b/i.test(following) &&
    !/\b(?:without (?:asking|approval|confirmation)|auto[- ]approve)\b/i.test(instructions);
}

function installerFollowsPermissionGate(source, offset) {
  const before = source.slice(Math.max(0, offset - 300), offset);
  const installer = /\r?\n[ \t]*(?:\x60{3}(?:bash|sh|powershell)?[ \t]*\r?\n[ \t]*)?(?:curl|wget|irm|Invoke-WebRequest)\b[^|;&\r\n]*$/i.exec(before);
  if (!installer) return false;
  const heading = before.slice(0, installer.index).trimEnd().split(/\r?\n/).at(-1);
  return /^[ \t]*(?:[-*][ \t]+|\d+\.[ \t]+)?if (?:the CLI|\x60?[\w-]+\x60?) is missing,[ \t]*(?:ask (?:the user for )?permission before installing|install it only after permission):$/i.test(heading);
}

function stagesPublisherPowerShellInstaller(source, url, start, end) {
  if (url.hostname !== 'raw.githubusercontent.com') return false;
  const installer = /^\/([\w-]+)\/([\w-]+)\/(?:main|master)\/install\.ps1$/i.exec(url.pathname);
  if (!installer) return false;
  const [, publisher, tool] = installer;
  const before = source.slice(Math.max(0, start - 1300), start);
  const after = source.slice(end, end + 200);
  const staged = /^[ \t]+-OutFile[ \t]+([\w.-]+\.ps1)\x60?[ \t]+then[ \t]+\x60?\.\\([\w.-]+\.ps1)(?=\x60|\s|$)/i.exec(after);
  if (!staged || staged[1].toLowerCase() !== staged[2].toLowerCase()) return false;
  const confirmation = /\bconfirm before installing\b/i.exec(before);
  return confirmation && !negated(before, confirmation.index) &&
    new RegExp(String.raw`\b${tool}[ \t]+version\b`, 'i').test(before) &&
    new RegExp(String.raw`\bbrew[ \t]+install[ \t]+${publisher}/tap/${tool}\b`, 'i').test(before) &&
    /\bdownload,[ \t]*review,[ \t]*then run:[ \t]*\r?\n[ \t]*\x60?(?:irm|Invoke-WebRequest)[ \t]+$/i.test(before);
}

function documentsEquivalentCliInstalls(source, url, start, end) {
  if (url.hostname !== 'raw.githubusercontent.com' || url.port || url.search) return false;
  const installer = /^\/([\w-]+\/([\w-]+)-cli)\/(?:main|master)\/install\.sh$/i.exec(url.pathname);
  if (!installer) return false;
  const [, repository, formula] = installer;
  const before = source.slice(Math.max(0, start - 650), start);
  const after = source.slice(end, end + 550);
  const tap = new RegExp(String.raw`^[ \t]*brew[ \t]+tap[ \t]+${repository}[ \t]+https://github\.com/${repository}(?:\.git)?[ \t]*\r?\n[ \t]*brew[ \t]+install[ \t]+${formula}[ \t]*\r?$`, 'im');
  const build = new RegExp(String.raw`^[ \t]*git[ \t]+clone[ \t]+https://github\.com/${repository}(?:\.git)?[ \t]*\r?\n[ \t]*cd[ \t]+${formula}-cli[ \t]*\r?\n[ \t]*cargo[ \t]+install[ \t]+--path[ \t]+\.[ \t]*\r?$`, 'im');
  return tap.test(before) && build.test(after);
}

function sourceArchiveMetadata(source, url, start, end) {
  if (url.protocol !== 'https:' || url.hostname !== 'github.com' || url.port || url.search ||
      url.username || url.password || !/^\/[\w.%{}-]+\/[\w.%{}-]+\/archive\/refs\/heads\/(?:\{|%7b)default_branch(?:\}|%7d)\.zip$/i.test(url.pathname)) {
    return null;
  }
  const before = source.slice(Math.max(0, start - 550), start);
  const after = source.slice(end, end + 550);
  const metadata = /\bGET[ \t]+`?(https:\/\/api\.github\.com\/repos\/([\w.{}-]+\/[\w.{}-]+))`?[^\r\n]{0,140}\bdefault_branch\b/i.exec(before);
  if (!metadata || !url.pathname.startsWith('/' + new URL(metadata[1]).pathname.slice(7) + '/archive/')) return null;
  const destination = /^[^\r\n]*\r?\n[^\r\n]*\b(?:default path|destination|save to|store in)\b[^\r\n]{0,135}\b(?:source code|source archive)\b[^\r\n]{0,100}default_branch\}\.zip\b/i;
  const runsArchiveContents = /\b(?:run|install|execute|source)\b[ \t]+(?:the[ \t]+)?(?:downloaded|extracted|unpacked)\b|\b(?:unzip|tar[ \t]+-x\w*)\b[^\r\n]{0,160}(?:\.zip|\{filename\})|\b(?:bash|sh|zsh|pwsh|python|node)[ \t]+[^`\r\n]{0,130}\b(?:temp_dir|default_branch)\b/i;
  if (!destination.test(after) || runsArchiveContents.test(source)) return null;
  return { start: Math.max(0, start - 550) + metadata.index + metadata[0].indexOf(metadata[1]),
    length: metadata[1].length };
}

function extractedReleaseLauncher(source, blocks, address, end) {
  const addressStart = source.indexOf(address + '{version}', end);
  if (addressStart === -1 || addressStart > end + 900) return null;
  const later = source.slice(addressStart, addressStart + 6200);
  const destination = /\b(?:extract|unpack|unzip)\s+(?:(?:it|the archive)\s+)?(?:to|into)\s+\x60?((?:~\/|\/|\.\/)[\w.\/-]+)(?=[\s\x60,.)]|$)/i.exec(later);
  if (!destination) return null;
  const from = addressStart + destination.index + destination[0].length;
  const path = destination[1];
  const launchCommand = /^cd[ \t]+["']?((?:~\/|\/|\.\/)[\w.\/-]+)["']?[ \t]*&&[ \t]*(?:exec[ \t]+)?\.\/[\w.-]+\.sh\b/i;
  const launch = blocks.filter(block => !isDocumentationExample(block))
    .flatMap(block => block.entries)
    .find(entry => entry.code && entry.start >= from && entry.start < from + 4900 &&
      launchCommand.exec(entry.text)?.[1] === path);
  if (!launch) return null;
  if (/\b(?:sha-?(?:256|512)sum|shasum|cosign verify|gpg --verify|checksums?|verify the signature)\b/i.test(
    source.slice(addressStart, launch.start))) return null;
  return { start: addressStart, length: address.length + '{version}'.length };
}

function downloadsFontArchiveAsData(source, url, start, end) {
  if (url.hostname !== 'github.com' || !/^\/[\w.-]+\/[\w.-]+\/releases\/download\/v\d[\w.-]*\/[\w.-]+\.zip$/i.test(url.pathname)) {
    return false;
  }
  const tuple = /^["'],[ \t]*\r?\n[ \t]*["']([\w.-]+\.(?:ttf|otf|woff2?))["'],[ \t]*["']\1["'],[ \t]*\d{3},[ \t]*["'](?:OFL|ITF-FFL)["']\)/i;
  return tuple.test(source.slice(end, end + 180)) &&
    /^[ \t]*\(["'][\w-]+["'],[ \t]*["'][^"'\r\n]{2,70}["'],[ \t]*\r?\n[ \t]*["']$/m
      .test(source.slice(Math.max(0, start - 160), start)) &&
    /\bwith zipfile\.ZipFile\(io\.BytesIO\(\w+\)\) as (\w+):\s*[\s\S]{0,550}\bsave\(\w+, \1\.read\(\w+\)\)/.test(source) &&
    !/\.(?:extractall|extract)\(/.test(source);
}

function installsDeclaredCliRelease(source, url) {
  if (url.hostname !== 'github.com' || url.port || url.search) return false;
  const build = /^\/([\w-]+)\/(([\w-]+)-cli)\/releases\/latest\/download\/\2-(?:darwin|linux|windows)-(?:amd64|arm64)(?:\.exe)?$/i.exec(url.pathname);
  if (!build) return false;
  const [, publisher, cli, product] = build.map(part => part.toLowerCase());
  return (publisher === product || publisher === product + '-open-source') &&
    declaredSkillName(source) === 'installing-' + cli &&
    /\bpre-compiled binary from the GitHub\s+Releases page\b/i.test(source) &&
    new RegExp(String.raw`\bhttps://github\.com/${publisher}/${cli}/releases(?=[\s\x60"')])`, 'i').test(source) &&
    new RegExp(String.raw`^[ \t]*${cli}[ \t]+--help[ \t]*\r?$`, 'im').test(source) &&
    /\bskip the installation steps\b/i.test(source);
}

function gitLogReadsMessages(match) {
  const command = match[0];
  const layout = /--(?:pretty|format)(?:=|[ \t]+)["']?(?:t?format:)?["']?([^\s"'`]+)/i.exec(command)?.[1];
  return !/\|[ \t]*wc[ \t]+-l\b|--quiet\b/i.test(command) &&
    (!layout || /%[sBb]|^(?:oneline|short|medium|full|fuller|raw|email)$/i.test(layout));
}

function incomingLinkUse(match) {
  const scope = nearMatch(match);
  const before = match.input.slice(Math.max(0, match.index - 130), match.index);
  if (/\bapply SSRF allowlists?\b[^.!?;]{0,85}\bbefore fetching(?:[ \t]+user-?)?[ \t]*$/i.test(before)) return;
  if (!/\b(?:work|operate|test|scan)\s+only\s+(?:against|within|on)\b/i.test(scope)) return 'manifest';
}

function importedAtRuntime(match) {
  const before = match.input.slice(Math.max(0, match.index - 185), match.index);
  const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 470);
  const comparison = /\*\*(?:Deno (?:imports?|tests?|example)|Before(?: migration)?):\*\*/i.test(before) &&
    /\*\*(?:Bun (?:imports?|tests?|example)|After(?: migration)?):\*\*/i.test(after);
  if (!comparison) return 'manifest';
}

function interpolatesDynamicValue(match) {
  const variable = match[2].replaceAll('$', '\\$');
  const before = match.input.slice(Math.max(0, match.index - 240), match.index);
  const literal = new RegExp('(?:^|[;\\r\\n])\\s*const\\s+' + variable +
    '\\s*=\\s*["\'][\\w .-]+["\']\\s*(?:;|\\r?\\n)');
  return !literal.test(before);
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

export function scanSnykSignals(source, limit, prose, blocks, packagedSkillFixture) {
  const results = [];
  let locate;
  let limited = false;
  const hasNetworkingExamples = /^description:[^\r\n]{0,180}\bimplement or debug data fetching\b/im.test(source) &&
    /^#{2,4}[ \t]+(?:\d+\.[ \t]+)?Basic Fetch Usage\b/im.test(source) &&
    /^#{2,4}[ \t]+Example Invocations\b/im.test(source);

  function add(id, start, length, reason, assessment = 'potential', masked = false, snykEvidence) {
    if (results.length >= limit) {
      limited = true;
      return;
    }
    if (hasNetworkingExamples && id === 'third-party-content') {
      const line = sourceLineAt(source, start);
      if (/^(?:description:|[ \t|\\-]+Use\b)[^\r\n]{0,180}\bfetch API\b/i.test(line) ||
          /^[ \t]*(?:(?:const|let)[ \t]+\w+[ \t]*=[ \t]*|return[ \t]+)(?:await[ \t]+)?fetch\([ \t]*(?:url(?=[,\s)]|$)|["'`]https?:\/\/(?:[\w-]+\.)*example\.(?:com|net|org|invalid)(?=[/:"'`]))/i.test(line)) {
        snykEvidence = 'reference-example';
      }
    }
    locate ??= sourceLocation(source);
    results.push(finding(id, reason, [locate(start, length, masked)], assessment, snykEvidence));
  }

  function scanMatches(id, pattern, reason, { assessment, accepts = () => true, raw = false, snykEvidence } = {}) {
    const text = raw ? source : prose.text;
    for (const match of text.matchAll(pattern)) {
      if (!negated(text, match.index) && accepts(match)) {
        const start = raw ? match.index : prose.original(match.index);
        const end = raw ? start + match[0].length : prose.original(match.index + match[0].length);
        const reportEvidence = typeof snykEvidence === 'function' ? snykEvidence(match) : snykEvidence;
        add(id, start, end - start, reason, assessment, false, reportEvidence);
        if (limited) break;
      }
    }
  }

  // Collect sensitive spans first so evidence from any overlapping rule can be masked.
  const secrets = new Map();
  for (const match of source.matchAll(knownToken)) secrets.set(match.index, match[0].length);
  for (const match of source.matchAll(privateKey)) secrets.set(match.index, match[0].length);
  for (const match of source.matchAll(provisionsWithTokenArgument)) {
    if (placeholder.test(match[3])) continue;
    const before = source.slice(Math.max(0, match.index - 490), match.index);
    if (!/\bnode[ \t]+[^\r\n]{0,140}\bprovision[\w.-]*\.[cm]?js\b/i.test(before)) continue;
    const valueStart = match.index + match[0].lastIndexOf(match[3]);
    secrets.set(valueStart, match[3].length);
    if (!limited) add('credential-handling', match.index, match[1].length,
      'The provisioning command accepts a provider credential as a visible argument.', 'potential', false, 'manifest');
  }
  const serviceKeyEvidence = new Map();
  for (const [pattern, channel] of [[searchApiQueryKey, 'manifest'], [analyticsIngestKey, 'direct']]) {
    for (const match of source.matchAll(pattern)) {
      const value = match[1];
      if (new Set(value).size < 12 || placeholder.test(value)) continue;
      const start = match.index + match[0].lastIndexOf(value);
      secrets.set(start, value.length);
      serviceKeyEvidence.set(start, channel);
    }
  }
  const reportedSecrets = new Map(secrets);
  const commerceSecrets = [...source.matchAll(commerceCredential)].filter(match => new Set(match[0].slice(3)).size >= 9);
  const exposesCommerceAccount = commerceSecrets.some(match => match[0].startsWith('ck_')) &&
    commerceSecrets.some(match => match[0].startsWith('cs_')) &&
    /\b(?:consumer key|woocommerce)\b/i.test(source) && /\bwc\/v3\//i.test(source);
  for (const match of commerceSecrets) secrets.set(match.index, match[0].length);
  for (const match of source.matchAll(paymentProviderCredential)) secrets.set(match.index, match[0].length);
  if (exposesCommerceAccount) {
    const passwords = new Set([...source.matchAll(credentialTablePassword)].map(match => match[1]));
    for (const password of passwords) {
      if (placeholder.test(password) || new Set(password).size < 9) continue;
      for (let index = source.indexOf(password); index >= 0; index = source.indexOf(password, index + password.length)) {
        secrets.set(index, password.length);
      }
    }
  }
  if (/key|token|secret|cookie|password|passwd/i.test(source)) {
    for (const match of source.matchAll(assignment)) {
      if (!secretName.test(match[1])) continue;
      const value = match.slice(2).find(Boolean);
      if (!value || placeholder.test(value)) continue;
      const start = match.index + match[0].lastIndexOf(value);
      if (!secrets.has(start)) secrets.set(start, value.length);
      if (!reportedSecrets.has(start) && value.length >= 16 && new Set(value).size >= 12) {
        reportedSecrets.set(start, value.length);
      }
    }
  }
  for (const [start, length] of reportedSecrets) {
    add('embedded-secret', start, length, 'The source contains a credential-like literal. The response masks its value.',
      'potential', true, serviceKeyEvidence.get(start));
    if (limited) break;
  }
  if (!limited) scanMatches('system-modification', pythonHostCommandLink,
    'The setup links a bundled script into a host-wide command directory.', { raw: true, snykEvidence: 'manifest' });
  if (!limited) scanMatches('detector-scored-rewrite', detectorScoredRewrite,
    'The workflow uses detection feedback to choose the lowest-scoring rewritten text.', { snykEvidence: 'manifest' });
  if (!limited && /\bsubprocess\.run\s*\(/.test(source) && source.includes('os.environ')) {
    const options = { raw: true, snykEvidence: 'external-python-helper', accepts: match => {
      const invocation = new RegExp(String.raw`\bsubprocess\.run\s*\(\s*\[\s*["']node["']\s*,\s*${match[1]}\s*,`, 'm');
      return invocation.test(source.slice(match.index + match[0].length, match.index + match[0].length + 500));
    } };
    scanMatches('dangerous-code-pattern', pythonExternalNodeHelper,
      'The active Python workflow provides a bundled credential and runs a helper from a separate skill.', options);
    if (!limited) scanMatches('runtime-dependency', pythonExternalNodeHelper,
      'The active Python workflow depends on executable code from a separate skill at runtime.', options);
  }
  for (const resource of source.matchAll(opaqueKubernetesSecret)) {
    const dataStart = resource.index + resource[0].length - resource[1].length;
    for (const field of resource[1].matchAll(secretDataField)) {
      const value = field[1];
      if (value.length % 4 !== 0) continue;
      const start = dataStart + field.index + field[0].indexOf(value);
      secrets.set(start, value.length);
      if (!limited) add('credential-handling', start, value.length,
        'The Kubernetes Secret manifest embeds an encoded credential literal.', 'potential', true, 'manifest');
    }
  }
  for (const match of source.matchAll(cpanelDatabasePassword)) {
    const value = match[2];
    if (placeholder.test(value)) continue;
    const start = match.index + match[0].length - value.length - 1;
    secrets.set(start, value.length);
    if (!limited) add('credential-handling', start, value.length,
      'The documented deployment command passes a database password as a literal argument.', 'potential', true, 'manifest');
  }
  for (const match of source.matchAll(sshPasswordLiteral)) {
    const value = match[2];
    if (!placeholder.test(value)) secrets.set(match.index + match[0].length - value.length - 1, value.length);
  }
  if (!limited && exposesCommerceAccount) {
    const first = commerceSecrets[0];
    add('embedded-secret', first.index, first[0].length,
      'The workflow embeds a pair of credential-shaped commerce API values.', 'potential', true, 'manifest');
    add('credential-handling', first.index, first[0].length,
      'The administrative workflow carries both credential values in its model-visible instructions.', 'potential', true, 'manifest');
    if (/\bcurl\b[^\r\n]{0,130}(?:-u\s|--user\s)/i.test(source)) {
      add('dangerous-code-pattern', first.index, first[0].length,
        'The commerce API credentials are embedded alongside live administrative commands.', 'potential', true, 'manifest');
    }
    if (/["']enabled["']\s*:\s*(?:true|false)\b/i.test(source)) {
      scanMatches('financial-execution', mutatesCommercePayment,
        'The authenticated workflow changes an active payment gateway setting.', {
          raw: true, snykEvidence: 'manifest', assessment: 'capability',
        });
    }
  }
  if (!limited && /\braw\.githubusercontent\.com\b/.test(source) &&
      /\b(?:cdn\.jsdelivr\.net|main|master)\b/.test(source) &&
      /\bwriteFile(?:Sync)?[ \t]*\(/.test(source) && /\brename(?:Sync)?[ \t]*\(/.test(source)) {
    scanMatches('automatic-skill-update', selfUpdateTargets,
      'On its ordinary schedule, the updater can replace the installed manifest and script from a mutable branch or mirror.', {
        raw: true, snykEvidence: 'scheduled-skill-update',
      });
  }
  if (!limited && /(?:改写|重算|重建|重新计算|补写)[^。\r\n]{0,100}(?:manifest|哈希|hash)|(?:manifest|哈希|hash)[^。\r\n]{0,100}(?:改写|重算|重建|重新计算|补写)/iu.test(source)) {
    scanMatches('weakened-safeguard', automatedUpgradeApproval,
      'The upgrade workflow can answer a package confirmation automatically and update its recorded integrity metadata.', {
        raw: true, snykEvidence: 'linked-document',
      });
  }

  if (!limited) scanMatches('credential-handling', unsafeHandling,
    'The directive can place secret values in model-visible output, commands, or insecure storage.', {
      accepts: match => credentials.test(match[0]) && unsafeDestination.test(match[0]) && !safeCredential.test(match[0]),
    });
  if (!limited) scanMatches('credential-handling', secretsToOutput,
    'The command sends a secret-bearing environment variable to output.', {
      raw: true, snykEvidence: match => /\b(?:password|token|api key|secret|credential)[ \t]*:/i.test(match[0]) && 'direct',
    });
  if (!limited) scanMatches('credential-handling', sshPasswordFlag,
    'The SSH workflow passes the password as a command-line argument.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('credential-handling', configCredentialArgument,
    'The configuration command passes the user’s credential as an argument that may be visible in process listings.',
    { raw: true, snykEvidence: 'linked-credential-setup' });
  if (!limited) scanMatches('credential-handling', credentialArgument,
    'The signing workflow passes a credential argument that can be visible in process listings or shell history.', {
      raw: true, snykEvidence: 'manifest',
      accepts: match => signingCommand.test(source.slice(Math.max(0, match.index - 150), match.index)),
    });
  if (!limited && /\bCLI flag:[ \t]+\x60?--private-key\b/i.test(source)) {
    scanMatches('credential-handling', walletKeyArgument,
      'The wallet setup passes a raw signing key as a command-line argument.', {
        raw: true, snykEvidence: 'manifest', accepts: match => !negated(source, match.index),
      });
  }
  if (!limited) scanMatches('credential-handling', inlineCredentialInstruction,
    'The workflow asks for a credential to be written directly into the command line.',
    { raw: true, snykEvidence: 'manifest' });
  if (!limited) scanMatches('credential-handling', argumentPostToken,
    'The post lookup supplies its request token as a positional shell argument.',
    { raw: true, snykEvidence: 'manifest' });
  if (!limited && /\bAuthorization:[ \t]+Bearer\b/i.test(source)) {
    scanMatches('credential-handling', storesProvidedCredentials,
      'The workflow writes user-supplied credential values directly into a configuration block.',
      { raw: true, snykEvidence: 'manifest', accepts: match =>
        /\b(?:config(?:uration)? block|JSON config(?:uration)?)\b/i.test(source.slice(Math.max(0, match.index - 130), match.index)),
      });
  }
  if (!limited) scanMatches('credential-handling', submitsCredentialInChat,
    'The workflow asks for a credential in the model-visible conversation.', {
      accepts: match => !safeCredential.test(match[0]), snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('credential-handling', asksToPasteKeyBack,
    'The credential setup fallback asks the user to paste the API key into the conversation.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const setup = source.slice(Math.max(0, match.index - 1800), match.index);
        return /\bAPI[ _-]?key\b/i.test(setup) &&
          /\b(?:fallback|key creation|create (?:an?|the|your) key)\b/i.test(setup.slice(-420));
      },
    });
  if (!limited) scanMatches('credential-handling', submitsCredentialInChatZh,
    'The workflow asks the user to provide a credential in a conversational reply.', {
      raw: true, accepts: match => !/(?:不要|不得|禁止|切勿)[^。！？\r\n]{0,30}(?:提示|要求|请)/u.test(nearMatch(match)),
      snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('credential-handling', putsUserCredentialInMcpArguments,
    'The workflow substitutes a user-provided credential into the MCP registration arguments.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited && usesTokenInEnvSetup.test(source)) scanMatches('credential-handling', asksToPasteTokenBackZh,
    'The workflow asks the user to paste a token into the conversation before putting it in an environment command.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited && storesPastedEnvValues.test(source) && /\b[A-Z_]*(?:TOKEN|API_KEY)\b[^\r\n]{0,80}\b[\w/.-]+\.env\b/i.test(source)) {
    scanMatches('credential-handling', requestsOnboardingToken,
      'The onboarding workflow collects a token in the conversation and stores the pasted value in an environment file.', {
        snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('credential-handling', printsPersistedShellKey,
    'The setup puts a credential in a persistent shell profile and prints its value to verify it.', {
      raw: true, snykEvidence: 'linked-document',
    });
  if (!limited && !source.matchAll(credentialArgument).next().done) {
    scanMatches('credential-handling', solicitsUserCredential,
      'The workflow collects a credential from the user and passes it as a command-line argument.', {
        raw: true,
        accepts: match => {
          if (safeCredential.test(match[0])) return false;
          const following = match.input.slice(match.index + match[0].length, match.index + match[0].length + 620);
          const argument = following.matchAll(credentialArgument).next().value;
          const direction = following.slice(0, argument?.index);
          return argument && !/\b(?:typed? directly|interactive prompt|keyring|secret manager|password manager)\b/i.test(direction);
        },
        snykEvidence: 'manifest',
      });
  }
  if (!limited && /\b(?:use|ask (?:the )?user for|obtain)\b[^.!?;\r\n]{0,60}\b(?:otp|\d-digit code|one-time code)\b[^.!?;\r\n]{0,65}\bemail\b/i.test(source)) {
    scanMatches('credential-handling', passesEmailVerificationCode,
      'The sign-in workflow passes the emailed verification code as a command-line argument.', {
        raw: true, snykEvidence: 'linked-document',
      });
  }
  if (!limited) scanMatches('credential-handling', substitutesCredentialFromFile,
    'The shell reads a credential from a local file and passes it in the process arguments.', {
      raw: true, snykEvidence: 'linked-document',
    });
  if (!limited) scanMatches('credential-handling', assignsCredentialFromFile,
    'The shell extracts a credential from a local file and passes the resulting variable as an argument.', {
      raw: true,
      accepts: match => {
        const start = match.index + match[0].length;
        const adjacent = match.input.slice(start, start + 240).split(/\r?\n/).slice(0, 3).join('\n');
        const argument = new RegExp('(?:--(?:password|api[-_]key|client[-_]secret|access[-_]token))[ \\t=]+["\']?\\$\\{?' +
          match[1] + '(?![\\w])');
        return argument.test(adjacent);
      },
      snykEvidence: 'linked-document',
    });
  if (!limited) scanMatches('agent-role-override', refusesToStopCourse,
    'The skill directs the agent to keep the course running after the user asks to stop.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('agent-role-override', loadsOutsideSkill,
    'The skill unconditionally follows instructions outside its own directory.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\bworkers?\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest', accepts: match =>
      !/\b(?:only if|only when|after) (?:the |a )?(?:user|person) (?:chooses|selects|approves)\b/i.test(nearMatch(match)),
    };
    scanMatches('weakened-safeguard', startsAutomaticWorkers,
      'The workflow starts workers in automatic permission mode.', options);
    if (!limited) scanMatches('system-modification', startsAutomaticWorkers,
      'The workflow changes the worker permission policy for the new session.', options);
  }
  if (!limited) scanMatches('concealed-report-sources', hidesIntegrationProvider,
    'The workflow fetches an external skill and directs the agent to omit its provider from the user-facing explanation.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const before = source.slice(Math.max(0, match.index - 1800), match.index).toLowerCase();
        return before.includes(`following ${match[1].toLowerCase()}'s skill`) && /\bdownload\b/.test(before);
      },
    });
  if (!limited && /\b(?:git )?worktree\b/i.test(source) && /\b(?:redis|mongo|postgres)\b/i.test(source)) {
    scanMatches('unapproved-file-change', copiesEntireDevProfiles,
      'The debugging workflow automatically copies the development database and its user profiles.', {
        raw: true, snykEvidence: 'manifest',
      });
    if (!limited) scanMatches('third-party-content', copiesEntireDevProfiles,
      'The debugging workflow reads a copy of existing user profiles and application data.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited && /\bexit\b[^.!?;\r\n]{0,100}\brestart with the updated sandbox profile\b/i.test(source)) {
    scanMatches('agent-role-override', opensSandboxReload,
      'The skill runs an inline shell command before directing the current agent session to restart.', {
        raw: true, snykEvidence: 'manifest',
      });
    if (!limited) scanMatches('system-modification', opensSandboxReload,
      'The inline command queues a reload of the agent sandbox configuration.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('unapproved-file-change', backsUpReleaseToShare,
    'The release workflow copies installation artifacts to a fixed network share.', {
      raw: true, snykEvidence: 'manifest', accepts: match =>
        !/(?:用户|使用者)[^。！？\r\n]{0,20}(?:确认|批准|同意)/u.test(nearMatch(match)),
    });
  if (!limited && /^#![^\r\n]*\bpython3?\b/i.test(source) && /\bturn\b/i.test(source)) {
    scanMatches('weakened-safeguard', forksAfterSessionPolicy,
      'The session client offers a fallback that changes how a policy denial is handled.', {
        raw: true, snykEvidence: 'session-policy-fork',
      });
  }
  if (!limited && /\.claude\/settings(?:\.local)?\.json\b/.test(source) && /"permissions"\s*:\s*\{\s*"allow"\s*:\s*\[/.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest' };
    scanMatches('dangerous-code-pattern', startsUnrestrictedWorkflows,
      'The project configuration grants unrestricted shell and worker access.', options);
    if (!limited) scanMatches('system-modification', startsUnrestrictedWorkflows,
      'The workflow writes a project configuration that expands agent permissions.', options);
  }
  if (!limited && source.includes('~/.claude/settings.json') && source.includes('permissions.allow') &&
      /\bwrite (?:the |updated )?(?:configuration|settings)\b|寫入配置|写入配置/i.test(source) &&
      !/\b(?:never|do not|don['’]t) write (?:the |updated )?(?:configuration|settings)\b|(?:不要|不得|禁止)[^。\r\n]{0,18}(?:寫入配置|写入配置)/i.test(source)) {
    const allSettings = /"permissions"\s*:\s*\{\s*"allow"\s*:\s*\[([^\]]{0,1200})\]/g;
    const writesBroadRules = match => {
      if (!/"Edit"/.test(match[1]) || !/"Write"/.test(match[1])) return false;
      const patterns = [...match[1].matchAll(/"Bash\(([^"\r\n]+?)[ \t]+\*\)"/g)];
      return new Set(patterns.map(pattern => pattern[1].trim().replace(/[ \t]+/g, ' '))).size >= 2;
    };
    const options = { raw: true, snykEvidence: 'manifest', accepts: writesBroadRules };
    scanMatches('weakened-safeguard', allSettings,
      'The configuration can persist multiple wildcard shell approvals and unrestricted edits across projects.', options);
    if (!limited) scanMatches('system-modification', allSettings,
      'The workflow writes host agent permission settings that can apply across projects.', options);
  }
  if (!limited && source.includes('require_escalated')) {
    const launch = /\b[\w-]+\.ps1\b[\s\S]{0,205}?\bsandbox_permissions:[ \t]*require_escalated\b/gi;
    const options = { raw: true, snykEvidence: 'escalated-packaged-windows-launcher' };
    scanMatches('dangerous-code-pattern', launch,
      'A bundled Windows launcher requests execution outside the normal sandbox and uses an execution-policy override.', options);
    if (!limited) scanMatches('system-modification', launch,
      'The workflow requests elevated host execution for a bundled Windows launcher.', options);
  }
  if (!limited) scanMatches('dangerous-code-pattern', disablesApprovalAcrossAgents,
    'The workflow disables interactive approval in more than one agent harness.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('agent-role-override', bypassesUserAlias,
    'The skill gives its own agent-launch command priority over an alias specified in the user’s instruction file.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\b(?:AGENTS|CLAUDE)\.md\b/.test(source)) scanMatches('system-modification', writesGlobalAgentInstructions,
    'The instruction helper can persist its changes in global agent files.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\b(?:lido na tela ou no arquivo|read (?:it |the result )?from the (?:screen or file|terminal or file))\b/iu.test(source)) {
    scanMatches('third-party-content', waitsForTerminalOutput,
      'The workflow uses the displayed or captured output of another agent or command.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited && /\bparallel\b/i.test(source) && /\b(?:dispatch|launch(?:es|ing)?)\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', disablesShellSafeguards,
      'The linked dispatch guide turns off approval safeguards for parallel agent workers.', {
        raw: true, snykEvidence: 'parallel-worker-approval',
      });
  }
  if (!limited && /\b(?:speech[- ]to[- ]text|transcrib\w*|transcription|ASR)\b/i.test(source) &&
      /\b(?:upload|send)\b[^.!?;\r\n]{0,72}\b(?:API|service)\b|\bBase64\b[^.!?;\r\n]{0,70}\bAPI\b/i.test(source) &&
      /\bbrowser\b[^.!?;\r\n]{0,40}\b(?:network|cookies?|capture)\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', extractsMediaSession,
      'The workflow extracts browser session credentials for a media stream and sends media to a transcription service.', {
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited && /\bWebSocket\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'external-task-listener' };
    scanMatches('runtime-dependency', externalAgentRegistration,
      'The declared server supplies messages to a locally launched agent.', options);
    if (!limited && /\bbypassPermissions\b/.test(source)) scanMatches('dangerous-code-pattern', externalAgentRegistration,
      'The locally launched listener accepts remote messages with agent approval checks disabled.', options);
  }
  if (!limited) scanMatches('system-modification', disablesApprovalAcrossAgents,
    'The workflow changes the approval policies used to launch agent sessions.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\b(?:auto[- ]select|select(?:s|ed)? automatically)\b[^\r\n]{0,95}\b(?:permission )?option\b/i.test(source) &&
      /\bpermission (?:is )?(?:denied|refused) automatically\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest' };
    scanMatches('dangerous-code-pattern', approvesOuterAndInnerAgent,
      'The launcher auto-accepts permission prompts while enabling automatic permissions in the delegated agent.', options);
    if (!limited) scanMatches('system-modification', approvesOuterAndInnerAgent,
      'The launcher changes the permission policy of the delegated agent session.', options);
  }
  if (!limited && /\bprepaid crypto wallet\b/i.test(source) && /\bSMS verification numbers\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', advertisesAnonymousVerification,
      'The skill advertises unattended acquisition of anonymous verification services.', {
        raw: true, snykEvidence: 'manifest',
      });
    if (!limited) scanMatches('financial-execution', advertisesAnonymousVerification,
      'The workflow can make purchases from a prepaid wallet without an interactive step.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited && /(?:绕过|bypass)[^。！？\r\n]{0,42}(?:WAF|CAPTCHA|验证码|SSL pinning)/iu.test(source) &&
      /\b(?:Frida|SSL pinning|native instrumentation)\b/i.test(source) &&
      !/(?:仅限|只限|only)[^。.!？\r\n]{0,35}(?:授权|authorized)/iu.test(source)) {
    scanMatches('dangerous-code-pattern', describesSessionReplay,
      'The skill combines replay of session information with instructions for circumventing access controls.', {
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited && /^(?:from|import)\s+mitmproxy\b/m.test(source) && /^[ \t]+def[ \t]+request\(/m.test(source)) {
    scanMatches('dangerous-code-pattern', capturedSessionHeader,
      'The linked proxy helper reads session credentials from intercepted requests and stores them in JSON.', {
        raw: true, snykEvidence: 'linked-session-capture', accepts: persistsCapturedHeaders,
      });
  }
  if (!limited && /\brequire\(["'](?:node:)?child_process["']\)/.test(source)) {
    const options = { raw: true, snykEvidence: 'dynamic-package-runner', accepts: loadsInstalledPackage };
    scanMatches('dangerous-code-pattern', dependencyFromArgument,
      'The runner installs a package selected at runtime, then constructs objects from its executable exports.', options);
    if (!limited) scanMatches('runtime-dependency', dependencyFromArgument,
      'The runner resolves an unpinned package supplied as an argument at runtime.', options);
  }
  if (!limited && /\bbrowser[- ]profiles?\b/i.test(source) && /\bCDP\b/.test(source) &&
      /127\.0\.0\.1/.test(source) && /\bAuthorization[ \t]*:[ \t]*Bearer\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest' };
    scanMatches('dangerous-code-pattern', localBrowserWithoutAuth,
      'The local browser-control interface accepts requests without authentication.', options);
    if (!limited) scanMatches('credential-handling', localBrowserWithoutAuth,
      'Authentication is optional on the interface that controls browser profiles.', options);
  }
  if (!limited && /\bBaseHTTPRequestHandler\b/.test(source) && /\bRuntime\.evaluate\b/.test(source) &&
      /127\.0\.0\.1/.test(source) && !/\b(?:Authorization|api_key|require_auth)\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'browser-proxy-script' };
    scanMatches('dangerous-code-pattern', browserProxyHandler,
      'The HTTP proxy forwards requests to a browser scripting interface without authenticating callers.', options);
    if (!limited) scanMatches('credential-handling', browserProxyHandler,
      'The proxy gives unauthenticated callers access to the browser session.', options);
  }
  if (!limited) scanMatches('automatic-skill-update', bypassesUpdateConfirmation,
    'The workflow switches off an update confirmation in noninteractive sessions.', {
      raw: true, snykEvidence: 'linked-document',
    });
  if (!limited && /\b(?:re-read|reread)\s+`?SKILL\.md\b/i.test(source)) {
    const update = /\bnpx[ \t]+skills[ \t]+update[ \t]+[\w-]+[^\r\n`]{0,170}[ \t]+(?:-y|--yes)(?=[ \t\r\n`]|$)/gi;
    const options = { raw: true, snykEvidence: 'manifest', accepts: match => {
      const before = source.slice(Math.max(0, match.index - 270), match.index);
      const after = source.slice(match.index + match[0].length, match.index + 1300);
      return !negated(source, match.index) &&
        !/\b(?:confirm (?:the |this )?update|approval before (?:running|updating)|only after (?:user )?(?:confirmation|approval))\b/i.test(before) &&
        /\b(?:currently executing|currently running|current skill)\b[^\r\n]{0,95}\b(?:rewritten|replaced|overwritten)\b/i.test(after) &&
        /\b(?:re-read|reread)\s+`?SKILL\.md`?\b[\s\S]{0,130}\bcontinue (?:from|with|using) the (?:updated|rewritten|new) instructions\b/i.test(after);
    } };
    scanMatches('weakened-safeguard', update,
      'The update skips confirmation and makes the agent resume from its newly rewritten skill instructions.', options);
    if (!limited) scanMatches('system-modification', update,
      'The update replaces the installed skill instructions and directs the active agent to reload them.', options);
  }
  if (!limited && /\b(?:once per|at the start of (?:each|every)) session\b/i.test(source)) {
    scanMatches('weakened-safeguard', refreshesAllSkills,
      'The session setup checks one skill for an update, then directs the agent to refresh all installed skills before verifying its own copy.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          const before = source.slice(Math.max(0, match.index - 800), match.index);
          const after = source.slice(match.index + match[0].length, match.index + 1000);
          const release = /\bhttps:\/\/api\.github\.com\/repos\/([\w.-]+\/[\w.-]+)\/releases\/latest\b/i.exec(before);
          const reinstall = /\bnpx[ \t]+(?:-y[ \t]+)?skills[ \t]+add[ \t]+([\w.-]+\/[\w.-]+)\b/i.exec(after);
          return release && reinstall && release[1].toLowerCase() === reinstall[1].toLowerCase() &&
            /\b(?:release|published) version is newer\b/i.test(before) &&
            /\b(?:first |then )?(?:refresh|update) (?:all|everything)\b/i.test(before) &&
            /\b(?:verify|re-read|check)\b[\s\S]{0,370}\b(?:own (?:skill|agent)|current agent)\b/i.test(after) &&
            !/\b(?:ask (?:the )?user|(?:explicit|user) (?:approval|confirmation)|only after (?:approval|confirmation)|do not run)\b/i.test(before);
        },
      });
  }
  if (!limited && /\b(?:LLM|agent)\b/i.test(source)) {
    scanMatches('weakened-safeguard', disablesPluginConfirmation,
      'The setup tells the agent to skip human confirmation for plugin installation and transform code execution.', {
        raw: true, snykEvidence: 'linked-document', accepts: match => {
          const before = source.slice(Math.max(0, match.index - 400), match.index);
          const after = source.slice(match.index + match[0].length, match.index + 380);
          return /\brun\b[^.!?]{0,110}\bcommand yourself\b/i.test(before) &&
            /\b(?:interactive prompt|human to confirm)\b[\s\S]{0,130}\bplugin\b[\s\S]{0,85}\btransform[- ]code execution\b/i.test(after) &&
            !/\b(?:only after|require|wait for)\b[^.!?]{0,65}\b(?:user|human) (?:approval|confirmation)\b/i.test(before + after);
        },
      });
  }
  if (!limited && source.includes('--preflight')) {
    const options = { snykEvidence: 'manifest', accepts: match => {
      const after = match.input.slice(match.index + match[0].length, match.index + 460);
      return /\b(?:on|during) (?:every|each) invocation\b/i.test(after) &&
        /\bupdate the skill\b[^.!?;]{0,60}\bruntime\b/i.test(after) &&
        !/\b(?:ask|confirm) (?:with )?(?:the )?user\b|\bonly after (?:user )?(?:confirmation|approval)\b/i.test(after);
    } };
    scanMatches('weakened-safeguard', confirmsEveryPreflightUpdate,
      'The startup preflight checks for replacements and automatically approves updates to the installed skill and runtime.', options);
    if (!limited && /\blauncher action\b[^.!?;\r\n]{0,95}\brequire_escalated\b/i.test(source)) {
      scanMatches('system-modification', confirmsEveryPreflightUpdate,
        'The preflight replaces installed runtime software and the launch workflow requests elevated execution.',
        { ...options, assessment: 'capability' });
    }
  }
  if (!limited) scanMatches('agent-role-override', claimsKoreanRulePriority,
    'The skill asserts that its rules take precedence over the system default.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\bmajor\b[^\r\n]{0,110}\bprompt (?:the )?user individually\b/i.test(source)) {
    scanMatches('weakened-safeguard', autoApprovesMajorUpdates,
      'A dependency allowlist exempts some major-version updates from the usual confirmation.', {
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited && /\b(?:persona|role)\s+auto[- ]?(?:switch|select)\b/i.test(source)) {
    const personaInput = /\b(?:inject|insert|prepend|add|apply)\b[^.!?\r\n]{0,45}\b(?:command output|(?:the|its) output|returned text|generated text)\b[^.!?\r\n]{0,100}\b(?:persona|role)\b[^.!?\r\n]{0,75}\b(?:before (?:any|every|task)|pre.task|at startup|at the start)\b/gi;
    const active = removeMarkdownComments(source);
    const commands = markdownBlocks(active).filter(block => !isDocumentationExample(block))
      .flatMap(block => block.entries.filter(entry => entry.code && !/^[ \t]*[#>]/.test(entry.text)));
    for (const { index, address } of setupProseMatches(active, personaInput)) {
      const recent = commands.filter(entry => entry.start < index && entry.start >= index - 1300);
      const automatic = recent.find(entry => /\b(?:persona|role)\s+auto[- ]?(?:switch|select)\b/i.test(entry.text));
      if (!automatic || !recent.some(entry => entry.start > automatic.start &&
          /\b(?:persona|role)\s+(?:context|export|show|read)\b/i.test(entry.text))) continue;
      const consent = active.slice(Math.max(0, automatic.start - 430), index);
      if (/\b(?:ask|request|obtain|require)\b[^.!?\r\n]{0,85}\b(?:approval|consent|confirmation|user to choose)\b/i.test(consent)) continue;
      add('agent-role-override', index, address.length,
        'The skill automatically chooses a persona and inserts command output as the agent’s persona before the task.',
        'capability', false, 'manifest');
      if (limited) break;
    }
  }
  if (!limited) scanMatches('agent-role-override', roleOverride,
    'The matched text can steer the agent away from the instructions that govern it.', {
      snykEvidence: match => {
        const end = match.index + match[0].length;
        const request = match.input.slice(end, end + 125).split(/\r?\n/, 1)[0];
        if (/\band act as (?:an? )?unrestricted (?:AI|assistant|agent)\b[^.!?;]{0,45}\bno limitations\b/i.test(request) &&
            /\.(?:ssh|env)\b/i.test(source) && /\bPOST\b/.test(source)) return 'manifest';
      },
    });
  if (!limited) scanMatches('agent-role-override', falseSystemDirective,
    'The skill presents its own role change as a system directive.', { raw: true, snykEvidence: 'manifest' });
  if (!limited && /\bdelete (?:the|this|its) (?:temporary |update )?branch\b/i.test(source) && /\.claude\/agents\b/i.test(source)) {
    scanMatches('unapproved-file-change', removesAgentBackups,
      'The update removes its temporary branch and forbids preserving a backup of the existing configuration.',
      { snykEvidence: 'manifest' });
  }
  if (!limited && /\bbrowser\b/i.test(source)) scanMatches('undisclosed-evidence-sharing', sharesBrowserEvidence,
    'The configuration enables sharing browser evidence payloads unless changed.',
    { raw: true, snykEvidence: 'linked-evidence-default' });
  if (!limited) scanMatches('concealed-report-sources', concealsPromptSources,
    'The prompt requires withholding which internal instructions or memory were used.', { snykEvidence: 'linked-prompt' });
  if (!limited) scanMatches('concealed-report-verification', concealsVerificationGate,
    'The workflow orders the agent to run verification and keep that activity out of its messages to the user.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const context = source.slice(match.index + match[0].length, match.index + match[0].length + 660);
        return /\b(?:verification run|self[- ]audit|re[- ]render)\b/i.test(context) && /\b(?:the user|user-facing)\b/i.test(context);
      },
    });
  if (!limited && scopeAllowsWorkspaceRemoval.test(source)) {
    scanMatches('overbroad-management-scope', grantsCleanupWriteScope,
      'The workflow requests write permission for cleanup even though the credential can remove resources across the full account or network.', {
        raw: true, snykEvidence: 'manifest', accepts: match =>
          scopeAllowsWorkspaceRemoval.test(source.slice(match.index + match[0].length, match.index + match[0].length + 220)),
      });
  }
  if (!limited && /^(?:login|sign_in)\(\)[ \t]*\{/m.test(source)) {
    const login = /^(?:login|sign_in)\(\)[ \t]*\{[\s\S]{0,9000}?^\}/m.exec(source);
    if (login) scanMatches('undisclosed-account-adoption', claimsLocalResourcesAfterLogin,
      'The bundled login helper automatically claims previously recorded local resources with the new credential.', {
        raw: true, snykEvidence: 'account-login-side-effect', accepts: match => {
          if (match.index < login.index || match.index >= login.index + login[0].length) return false;
          const helper = [...source.matchAll(/^([a-z][\w]*)\(\)[ \t]*\{[\s\S]{0,7000}?^\}/gm)]
            .find(definition => definition[1] === match[1]);
          return helper && /(?:-X|--request)[ \t]+POST\b/.test(helper[0]) && /\/claim(?=["'\s])/.test(helper[0]);
        },
      });
  }
  if (!limited && /\b(?:failed|failing) (?:job|workflow)\b/i.test(source)) {
    scanMatches('third-party-content', readsActionsJobLogs,
      'The investigation reads CI logs that can contain content produced by contributors.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          const context = source.slice(Math.max(0, match.index - 350), match.index);
          return /\b(?:investigate|diagnose|debug) (?:a |the )?(?:failed|failing) (?:job|workflow)\b/i.test(context);
        },
      });
  }
  if (!limited && /\bGitHub Actions\b/i.test(source)) {
    scanMatches('third-party-content', citesCapturedCiLog,
      'The report reads externally influenced CI output and cites it as evidence.', {
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited && /内部检查表|\binternal checklist\b/i.test(source)) {
    const hiddenState = /(?:不展示|不向用户展示|(?:never|do not) (?:show|disclose))[ \t]*`([\w -]{4,60} State)`[^。.!?;\r\n]{0,65}(?:内部检查表|internal checklist)[^。.!?;\r\n]{0,65}(?:用户要求时|除非用户要求|unless (?:the )?user asks)/giu;
    scanMatches('concealed-report-sources', hiddenState,
      'The workflow retains a named task state and withholds it and its checklist until the user asks.', {
        raw: true, snykEvidence: 'manifest', accepts: match =>
          source.split(/\r?\n/).some(line => line.includes('`' + match[1] + '`') &&
            /(?:当前任务|current task)[^。.!?;]{0,45}(?:保留|retain\b|keep\b)|\b(?:retain|keep)\b[^.!?;]{0,95}\bcurrent task\b/i.test(line)),
      });
  }
  if (!limited && hidesMissingMaterial.test(source)) scanMatches('concealed-report-sources', hidesOwnInstructions,
    'The workflow omits gaps in the user’s data and hides the instructions that require that omission.', { snykEvidence: 'manifest' });
  if (!limited) scanMatches('concealed-sign-in-requirement', concealsSignInRequirement,
    'The sign-in workflow keeps the skill’s role in requiring sign-in out of the user-facing explanation.', {
      snykEvidence: 'linked-document', accepts: match => {
        const context = match.input.slice(Math.max(0, match.index - 260), match.index + match[0].length);
        return /\b(?:sign(?:ing)?[ -]in|log(?:ging)?[ -]in|login|authentication)\b/i.test(context) &&
          !/\b(?:sign(?:ing)?[ -]in|login|authentication) (?:is|remains) optional\b/i.test(context);
      },
    });
  if (!limited && /\b(?:generate|create)\b[^.!?;\r\n]{0,40}\b(?:simulated|synthetic) (?:data|results?)\b/i.test(source) &&
      /\b(?:provenance|data sources?)\b[^.!?;\r\n]{0,48}\boutside (?:the )?(?:finished )?report\b/i.test(source)) {
    scanMatches('concealed-report-sources', hidesSimulatedResults,
      'The workflow generates simulated results and directs the agent to withhold their provenance from the report.',
      { snykEvidence: 'manifest' });
  }
  if (!limited && source.includes('--demo')) scanMatches('concealed-report-sources', enablesDemoByDefault,
    'The documented command saves a synthetic figure by default without labeling its data as synthetic.', {
      raw: true, snykEvidence: 'default-demo-report', accepts: exportsUnlabeledDemo,
    });
  if (!limited && source.includes('success') && /\b(?:mock|synthetic|simulated|demo|sample)\b/i.test(source)) {
    scanMatches('concealed-report-sources', assignsMockIngestionData,
      'The data-ingestion helper returns mock values as a successful fetch without labeling their origin.', {
        raw: true, snykEvidence: 'mock-fetch-success', accepts: reportsUnlabeledMockFetch,
      });
  }
  if (!limited) scanMatches('unapproved-file-change', appendsVendorPlugin,
    'The authentication operation also appends a vendor plugin to the user’s configuration.', { snykEvidence: 'manifest' });
  if (!limited && localBrowserFork.test(source) && browserDebugging.test(source) && browserFingerprints.test(source)) {
    scanMatches('weakened-safeguard', browserAntiDetection,
      'The workflow uses a local browser fork designed to circumvent site detection.', { snykEvidence: 'manifest' });
  }
  if (!limited && /\b(?:click|pointer|press)\b/i.test(source)) {
    scanMatches('weakened-safeguard', describesBrowserAutomationDecoy,
      'The bundled adapter takes actions in a signed-in browser while avoiding controls designed to detect automation.',
      { raw: true, snykEvidence: 'signed-in-adapter' });
  }
  if (!limited && supplyChainAttackTerms.filter(term => term.test(source)).length >= 2) {
    scanMatches('offensive-supply-chain-guidance', offensiveSupplyChain,
      'The skill presents multiple software supply-chain attack techniques as its intended workflow.',
      { raw: true, accepts: match => match.index < 1500, snykEvidence: 'manifest' });
  }
  if (!limited && /\bargs\s*:\s*\[/.test(source)) scanMatches('weakened-safeguard', unsandboxedBrowser,
    'The browser test configuration disables the Chromium sandbox.', { raw: true, snykEvidence: 'extension-test-script' });
  if (!limited && /\bPuppeteer config\b[^\r\n]{0,55}\bsafer sandbox args\b/i.test(source)) {
    scanMatches('weakened-safeguard', unsandboxedBrowser,
      'The document-rendering fallback disables Chromium sandbox protections.', {
        raw: true, snykEvidence: 'document-renderer-sandbox', accepts: match => {
          const before = match.input.slice(Math.max(0, match.index - 200), match.index);
          return /['"]executablePath['"]\s*:\s*\w+[\s,]*['"]args['"]\s*:\s*\[[\s\r\n]*$/.test(before);
        },
      });
  }
  if (!limited && /\bheadless\b/i.test(source) && /\binstall apt (?:deps|dependencies|packages)\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'linked-document', accepts: match => {
      const begin = match.input.lastIndexOf('\n', match.index - 1) + 1;
      const stop = match.input.indexOf('\n', match.index);
      const line = match.input.slice(begin, stop < 0 ? undefined : stop);
      return /\bheadless\b/i.test(line) && /\binstall apt (?:deps|dependencies|packages)\b/i.test(line) &&
        !/\b(?:do not deploy|never use|insecure example)\b/i.test(line);
    } };
    scanMatches('weakened-safeguard', headlessRootSandboxFallback,
      'The headless export fallback disables the browser sandbox when running as root.', options);
    if (!limited) scanMatches('system-modification', headlessRootSandboxFallback,
      'The same headless export fallback directs the agent to install system packages.', { ...options, assessment: 'capability' });
    if (!limited) scanMatches('suspicious-download', thirdPartyRenderContainer,
      'The fallback selects a third-party Docker image for the rendering service.', {
        ...options, accepts: match => options.accepts(match) && /\bfall back to\b[^\r\n]{0,130}$/i.test(
          match.input.slice(Math.max(0, match.index - 130), match.index)),
      });
  }
  if (!limited && /\bAPPROVE_RE\s*=/.test(source) && /\bapprovals=/.test(source) && /\brecords?\b/i.test(source.slice(0, 900))) {
    const autoApproval = { raw: true, snykEvidence: 'recorded-product-action',
      accepts: match => match.index < 900 && !negated(source, match.index) };
    scanMatches('weakened-safeguard', approvesWriteCards,
      'The recorder approves write actions as part of capturing a product demonstration.', autoApproval);
    scanMatches('system-modification', approvesWriteCards,
      'The recording workflow can change product state by approving a write action.', { ...autoApproval, assessment: 'capability' });
    if (/\bTRANSCRIPT_JS\b/.test(source)) scanMatches('third-party-content', recordsTranscriptTail,
      'The recorder reads the product transcript, which can contain text supplied by other users.', {
        raw: true, assessment: 'capability', snykEvidence: 'recorded-product-action',
        accepts: match => match.index < 900,
      });
  }
  if (!limited && recordsLifecycleEvents(source)) {
    scanMatches('weakened-safeguard', emitsLifecycleContext,
      'The bundled lifecycle hook records project events and emits text into the agent context.', {
        raw: true, snykEvidence: 'packaged-lifecycle-context',
      });
  }
  if (!limited) scanMatches('agent-role-override', claimedPriority,
    'The skill asserts that its procedure takes precedence over the agent’s governing instructions.',
    { snykEvidence: 'manifest' });
  if (!limited) scanMatches('agent-role-override', dismissesPriorTraining,
    'The skill tells the agent to disregard its training and claims precedence over other sources.', {
      snykEvidence: 'manifest', accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 170), match.index);
        const after = match.input.slice(match.index + match[0].length, match.index + 270);
        return /\bmust(?:\*\*|__)?[ \t]+follow[ \t]+(?:these|the)[ \t]+(?:instructions?|rules?)\b/i.test(before) &&
          /\bsupersedes?[ \t]+all[ \t]+(?:other[ \t]+)?sources\b/i.test(after);
      },
    });
  if (!limited) {
    const previousCount = results.length;
    scanMatches('undisclosed-startup-command', silentSessionStartup,
      'A recurring startup command is explicitly hidden from the operating user.', { snykEvidence: 'manifest' });
    if (!limited && results.length > previousCount) scanMatches('system-modification', startupPackageUpdate,
      'The hidden startup workflow leads to commands that update installed agent skills.',
      { assessment: 'capability', raw: true, snykEvidence: 'manifest' });
  }
  if (!limited && /\bPATH (?:configuration|setup)\b/.test(source)) {
    scanMatches('delegated-host-setup', delegatedHostSetup,
      'The procedure delegates installation and PATH changes to the current contents of a setup guide.', { snykEvidence: 'manifest' });
  }
  if (!limited) scanMatches('agent-role-override', remoteCredentialSetupSkill,
    'A workflow that changes routing uses a live remote skill as its credential setup entry point.', {
      raw: true, snykEvidence: 'linked-document', accepts: ([, prefix]) => {
        const route = new RegExp(String.raw`\$\{?${prefix}_(?:URL|HOST)\}?/api/(?:combos|routes|routing/rules)(?=[/\s"']|$)`, 'i');
        return source.split(/\r?\n/).some(line => /\bcurl[ \t]+[^\r\n]{0,68}\b(?:POST|PUT|PATCH)\b/i.test(line) && route.test(line));
      },
    });
  if (!limited) scanMatches('undisclosed-authorship', concealAuthorship,
    'The skill directs the agent to conceal its involvement from commit messages and pull request descriptions.', { snykEvidence: 'manifest' });
  if (!limited && playerAnalytics.test(source) && persistentPlayerIdentity.test(source) && !informsPlayer.test(source)) {
    scanMatches('undisclosed-local-analytics', savesAnalytics,
      'The implementation saves player analytics and gives no notice or consent step.', { raw: true, snykEvidence: 'manifest' });
  }
  if (!limited && disablesDaemon.test(source)) scanMatches('unverified-host-tool', latestHostTool,
    'The setup gets a tool that can disable service processes from a mutable release.', { snykEvidence: 'linked-document' });
  if (!limited && !disclosesTemplateStub.test(source)) scanMatches('undisclosed-template-stub', stubbedArtifact,
    'The template returns a fixed artifact URL and a hard-coded cost.', { raw: true, snykEvidence: 'advertised-template' });
  if (!limited) scanMatches('automatic-package-patch', inPlacePackageEdit,
    'The script patches an installed package file in place.', { raw: true, snykEvidence: 'installed-module-hook' });
  if (!limited && copiesItsOwnScript.test(source) && /\.unref\s*\(\s*\)/.test(source)) {
    scanMatches('background-self-update', detachedUpdater,
      'The updater duplicates its script and lets a detached child run without captured output.',
      { raw: true, snykEvidence: 'documented-updater' });
  }
  if (!limited) scanMatches('terminates-profile-owner', profileOwnerTermination,
    'The script terminates the existing profile holder before logging in.', { raw: true, snykEvidence: 'invoked-script' });
  if (!limited && copiesUserSkill.test(source)) {
    const previousCount = results.length;
    scanMatches('default-host-hook', installsStopHook,
      'The installer adds a persistent host hook alongside the user-level skill.', { raw: true, snykEvidence: 'linked-document' });
    if (!limited && results.length > previousCount) scanMatches('runtime-dependency', unpinnedSkillPackage,
      'The installer obtains skill material from an unpinned repository.', { raw: true, snykEvidence: 'linked-document' });
  }
  if (!limited) scanMatches('automatic-telemetry', backgroundLocalNotice,
    'The workflow sends a local notification from a detached command without showing its output.',
    { raw: true, snykEvidence: 'manifest' });
  if (!limited && callerTelemetry.test(source)) scanMatches('automatic-telemetry', leavesUsageTagOut,
    'The workflow reports that an agent initiated the operation and keeps that detail out of the user-facing plan.',
    { snykEvidence: 'manifest' });
  if (!limited && /\b(?:[a-z][a-z0-9_]*_)?API_KEY\b/i.test(source) &&
      !/\bself\.headers\.get\(\s*['"](?:Authorization|X-Proxy-Key)['"]\s*\)/i.test(source)) {
    const publicHost = /\bhttp\.server\.HTTPServer\b/.test(source) ? implicitPublicHost : explicitPublicHost;
    scanMatches('public-local-proxy', publicHost,
      'The proxy’s listening address allows connections beyond the local machine.', { raw: true, snykEvidence: 'linked-local-proxy' });
  }
  if (!limited && /\bextra recommendations?\b/i.test(source)) scanMatches('directed-product-endorsement', directsEndorsement,
    'The skill prescribes an endorsement in its extra recommendation section.', { snykEvidence: 'manifest' });
  if (!limited && /\bpaid plan removes the badge\b/i.test(source) && /\bshow user_message\b[^\r\n]{0,40}\bverbatim\b/i.test(source)) {
    scanMatches('directed-product-endorsement', directsPaidBadgePitch,
      'The publishing workflow tells the agent to pass on a paid upgrade link to remove its badge.', {
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('directed-product-endorsement', fixedPromotionalFooter,
    'The skill mandates a promotional footer with an external contact or community link.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const footer = source.slice(match.index, match.index + 580);
        return /(?:关注公众号|添加微信|加入[^\r\n]{0,60}(?:群|社群))/u.test(footer) && /https?:\/\//i.test(footer);
      },
    });
  if (!limited && source.includes('开头')) scanMatches('directed-product-endorsement', fixedPromotionalGreeting,
    'The skill requires a publisher contact message in the first reply of each conversation.',
    { raw: true, snykEvidence: 'manifest', accepts: match => {
      const template = source.slice(match.index + match[0].length, match.index + match[0].length + 340);
      return /^[:：\s]*```(?:text|markdown)?[ \t]*\r?\n[^\r\n]{0,180}(?:微信|wx)[ \t]*[:：+加][ \t]*[\w-]+/i.test(template);
    } });
  if (!limited && /\blive (?:setup|onboarding)\b/i.test(source)) scanMatches('directed-product-endorsement', trackedPaidProductPitch,
    'The bundled README appends a tracked pitch for paid setup with the publisher.',
    { raw: true, snykEvidence: 'readme-paid-product-pitch', accepts: match =>
      /\bLicense\s*:/i.test(source.slice(Math.max(0, match.index - 1300), match.index)),
    });
  if (!limited && /mailgoogle\.com/i.test(source)) scanMatches('agent-role-override', mismatchedMailSignIn,
    'The sign-in instructions direct the user to a mail domain that differs from the named provider.',
    { raw: true, snykEvidence: 'linked-document' });
  if (!limited && /\bdo not (?:silently )?fall back to another browser tool\b/i.test(source)) {
    scanMatches('agent-role-override', assertsBrowserDefault,
      'The skill treats past installation as permission to choose its browser without asking.',
      { raw: true, snykEvidence: 'manifest' });
  }
  if (!limited && /\byour agent['’]s MCP settings\b/i.test(source) && /\bloopback address\b/i.test(source)) {
    scanMatches('system-modification', addsStreamableHttpServer,
      'The connection setup adds a local server to the agent’s integration settings.',
      { raw: true, assessment: 'capability', snykEvidence: 'manifest' });
  }
  if (!limited && source.includes('pane.snapshot')) scanMatches('weakened-safeguard', dismissesTrustWithKeystrokes,
    'The terminal workflow dismisses trust prompts automatically and archives pane output.', {
      raw: true, snykEvidence: 'manifest', accepts: match =>
        /\bpane\.snapshot\b[^\r\n]{0,115}\bsaves?\b/i.test(source.slice(match.index, match.index + 440)),
    });
  if (!limited && /\bno automated redaction\b/i.test(source)) scanMatches('third-party-content', readsPaneDisplay,
    'The workflow reads text and output that other programs display in the terminal pane.',
    { raw: true, assessment: 'capability', snykEvidence: 'manifest' });
  if (!limited && /\bAI[- ]authored plan\b/i.test(source) && source.includes('--snapshot-file')) {
    scanMatches('third-party-content', taskSnapshotTextFields,
      'The agent-authored plan uses a snapshot with task notes and comments written by workspace users.',
      { raw: true, assessment: 'capability', snykEvidence: 'automation-task-snapshot' });
  }
  if (!limited && /\bCanva\b/i.test(source)) scanMatches('unconfirmed-hosted-asset', createsHostedDesignWithoutAsking,
    'The workflow creates and commits a temporary hosted design before informing the user.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const before = source.slice(Math.max(0, match.index - 450), match.index);
        const after = source.slice(match.index, match.index + 430);
        return /\bcommit\b/.test(before) && /\bexport-design\b/.test(after);
      },
    });
  if (!limited && /\bpermission dialog is open\b/i.test(source)) scanMatches('weakened-safeguard', wakesBeforeDialogResolves,
    'The default wake can submit terminal input while a permission prompt is awaiting a response.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\bcross-host (?:payloads|messages)\b/i.test(source) && /\bmessage body is authoritative\b/i.test(source)) {
    scanMatches('third-party-content', drainsPeerMessageBodies,
      'The wake directs the agent to act on message bodies that can come from other hosts.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('automatic-pr-registration', existingPrRegistration,
    'The workflow registers the URL of an existing pull request with the host without a separate request to register it.',
    { snykEvidence: 'manifest' });
  if (!limited && requiresUncachedSkill.test(source) && /https?:\/\//.test(source)) {
    scanMatches('agent-role-override', alwaysFetchSkill,
      'The workflow requires the latest remote skill instructions on every session, without a reviewed local copy.',
      { snykEvidence: 'manifest' });
  }
  if (!limited && /\bWebFetch\b/i.test(source)) {
    const reviewRules = /\b(?:fetch|retrieve)\s+(?:the\s+)?(?:fresh|latest)\s+(?:guidelines|rules)\s+before\s+(?:each|every)\s+(?:review|audit)\b/gi;
    const options = {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const procedure = source.slice(match.index, match.index + 420);
        const endpoint = /https:\/\/[\w.-]+\/api\/(?:[\w.-]+\/)*(?:guidelines|rules)\?[^\s<>`]+/i.exec(procedure)?.[0];
        return endpoint && !/(?:\b[0-9a-f]{40}\b|[?&](?:ref|version|sha)=)/i.test(endpoint) &&
          !negated(source, match.index) &&
          /\bWebFetch\b[^\r\n]{0,100}\b(?:retrieve|fetch|load)\b[^\r\n]{0,45}\b(?:guidelines|rules)\b/i.test(procedure) &&
          !/\b(?:pinned|signed|verify (?:the )?(?:signature|digest)|reference only|only with user approval)\b/i.test(procedure);
      },
    };
    scanMatches('agent-role-override', reviewRules,
      'Each review refreshes the rules it follows from a mutable external endpoint.', options);
    if (!limited) scanMatches('runtime-dependency', reviewRules,
      'The runtime review rules depend on the response from an unversioned API endpoint.', options);
  }
  if (!limited) scanMatches('agent-role-override', fallbackRawScript,
    'The workflow falls back to executing an unpinned remote script when local copies are missing.',
    { raw: true, snykEvidence: 'manifest' });
  if (!limited) scanMatches('runtime-dependency', fallbackRawScript,
    'The fallback downloads an executable from a mutable Git branch.', { raw: true, snykEvidence: 'manifest' });
  if (!limited) {
    const options = { raw: true, snykEvidence: 'manifest', accepts: match =>
      !/\b(?:checksum|sha-?256|signature)\b/i.test(match[0]), };
    scanMatches('suspicious-download', standaloneHelperFallback,
      'When a bundled shell script is missing, the skill runs a remote copy without verifying its integrity.', options);
    if (!limited) scanMatches('runtime-dependency', standaloneHelperFallback,
      'The fallback uses a shell script retrieved at execution time.', options);
  }
  if (!limited && /\bdownload (?:the )?public pull script,?\s+then run it\b/i.test(source)) {
    scanMatches('agent-role-override', loadsLatestGuide,
      'The workflow runs a downloaded script to determine which instructions the agent follows.', { snykEvidence: 'manifest' });
    scanMatches('runtime-dependency', loadsLatestGuide,
      'A remotely fetched guide determines the runtime workflow.', { snykEvidence: 'manifest' });
  }
  if (!limited && /\bgit clone\b/i.test(source)) {
    scanMatches('agent-role-override', clonedGuideAuthority,
      'The workflow lets a document from the cloned repository govern agent behavior.', { raw: true, snykEvidence: 'manifest' });
    scanMatches('runtime-dependency', clonedGuideAuthority,
      'An external repository provides the workflow’s authoritative instructions.', { raw: true, snykEvidence: 'manifest' });
    scanMatches('third-party-content', clonedGuideAuthority,
      'The workflow reads instructions from a potentially third-party checkout.', {
        assessment: 'capability', raw: true, snykEvidence: 'manifest',
      });
    scanMatches('system-modification', changesUserAgentSettings,
      'The setup changes a persistent user-level agent setting.', {
        assessment: 'capability', raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('forced-escalation', requireOutsideSandbox,
    'The workflow requires broader permissions when its operation is blocked by the sandbox.',
    { snykEvidence: 'manifest', accepts: match => !asksForApproval.test(nearMatch(match)) });
  if (!limited) scanMatches('forced-escalation', retryEscalation,
    'The workflow retries a sandbox denial with elevated permissions.', {
      snykEvidence: 'manifest', accepts: match => !asksForApproval.test(nearMatch(match)),
    });
  if (!limited) scanMatches('forced-escalation', escalatesLibraryNetworkCalls,
    'The network commands request broader permissions and the workflow says that they do not ask the operator.', {
      snykEvidence: 'manifest', accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 120), match.index);
        const after = match.input.slice(match.index + match[0].length, match.index + 130);
        return /\bcommands? need the network\b/i.test(before) && /\b(?:do not|don't|never) ask\b/i.test(after) &&
          !asksForApproval.test(after);
      },
    });
  if (!limited && /\blaunchd agent\b/i.test(source) && /\bsystemd user service\b/i.test(source)) {
    scanMatches('system-modification', listensAfterHostRestart,
      'The background listener registers a per-user service that resumes after a restart.', {
        snykEvidence: 'manifest', assessment: 'capability',
      });
  }
  if (!limited) scanMatches('third-party-content', acceptsExternalMessagesForRuns,
    'The listener can start an agent run from a message sent by an enabled contact.', {
      snykEvidence: 'manifest', assessment: 'capability', accepts: match => {
        const after = match.input.slice(match.index + match[0].length, match.index + 245);
        return /\bcontacts?\b/i.test(after) && /\b(?:turns? on|enables?)\b/i.test(after);
      },
    });
  if (!limited && movingRemoteMarkdown.test(source)) {
    const reruns = { snykEvidence: 'linked-document', accepts: match =>
      !/\b(?:após|depois de|mediante|com) (?:a )?(?:aprovação|autorização|confirmação)\b/iu.test(nearMatch(match)) };
    scanMatches('forced-escalation', retriesRemoteReadWithEscalationPt,
      'The workflow tells the agent to retry a blocked network read with broader permissions.', reruns);
    if (results.some(result => result.id === 'forced-escalation') &&
        /\bnão (?:usar|utilizar) fallback local\b/iu.test(source)) {
      scanMatches('dangerous-code-pattern', retriesRemoteReadWithEscalationPt,
        'The workflow requires elevated retrieval of mutable remote guidance and forbids using a local copy.', reruns);
    }
    const options = { snykEvidence: 'linked-document', assessment: 'capability' };
    scanMatches('third-party-content', requiresRemoteGuidancePt,
      'The instructions require reading remotely maintained text into the agent’s context.', options);
    scanMatches('runtime-dependency', requiresRemoteGuidancePt,
      'The workflow uses guidance from an unpinned remote branch.', options);
  }
  if (!limited && [...source.matchAll(removesPnpmReleaseDelay)].length >= 2) {
    scanMatches('weakened-safeguard', removesPnpmReleaseDelay,
      'The install workflow repeatedly disables the package release-age requirement.', { raw: true, snykEvidence: 'manifest' });
  }
  if (!limited && source.includes('-terms')) {
    scanMatches('unapproved-license-acceptance',
      /\x60[\w./-]+[ \t]+[^\r\n\x60]{0,90}\b(?:submit|publish|register)\b[^\r\n\x60]{0,125}[ \t]--accept-(?:submission|developer|publisher|marketplace)-terms(?=[ \t\x60])[^\r\n\x60]*\x60/gi,
      'The workflow supplies a consent flag for publication or submission terms without asking the user to accept them.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          const before = source.slice(Math.max(0, match.index - 165), match.index);
          const context = before.slice(before.lastIndexOf('\n') + 1);
          return !/\b(?:only after|after (?:the )?user|ask (?:the )?user|user must|explicit (?:user )?(?:approval|permission|confirmation|consent)|do not)\b/i.test(context);
        },
      });
  }
  if (!limited && /\b(?:firmware|NAS|network appliance)\b/i.test(source)) {
    const options = { snykEvidence: 'linked-document' };
    scanMatches('unapproved-license-acceptance', acceptsUpdateTerms,
      'The firmware update flow accepts warnings and license terms without asking the user to approve the terms.', {
        ...options, accepts: match => {
          const context = match.input.slice(Math.max(0, match.index - 240), match.index + match[0].length + 160);
          return ![...context.matchAll(firmwareTermApproval)].some(confirm => !negated(context, confirm.index));
        },
      });
    scanMatches('system-modification', acceptsUpdateTerms,
      'The instructions document a confirmed firmware installation on a remote device.', { ...options, assessment: 'capability' });
  }
  if (!limited) scanMatches('third-party-content', searchContainerRegistry,
    'The management workflow exposes results from a container registry search.', {
      raw: true, snykEvidence: 'linked-document', assessment: 'capability',
    });
  if (!limited && /\bmultipart\/form-data\b/i.test(source)) {
    scanMatches('suspicious-download',
      /^[ \t]*[-*][ \t]+Base URL:[ \t]+\x60?https:\/\/(?:[\w-]+\.)*free-?(?:supabase|firebase)\.shop(?=[\x60\/ \t\r\n]|$)/gim,
      'The skill configures file uploads to a commercial hostname that resembles a backend provider.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          const before = source.slice(Math.max(0, match.index - 120), match.index);
          const settings = source.slice(match.index + match[0].length, match.index + match[0].length + 420)
            .split(/\r?\n[ \t]*\r?\n/, 1)[0];
          return /\bupload API\b[^\r\n]*\r?\n$/i.test(before) &&
            /\bEndpoint:[ \t]+\x60?\/[^\r\n]*\bupload\b/i.test(settings) &&
            /\bMethod:[ \t]+\x60?POST\b/i.test(settings) && /\bmultipart\/form-data\b/i.test(settings);
        },
      });
  }
  if (!limited) scanMatches('suspicious-download', bypassesQuarantineAfterReleaseDownload,
    'The setup downloads an executable release archive and removes its quarantine metadata.', {
      raw: true, snykEvidence: 'linked-document',
      accepts: match => !/\b(?:verify|checksum|signature|sha256)\b|校验|验签/iu.test(match[0]),
    });
  if (!limited) scanMatches('suspicious-download', mirroredJarDownload,
    'The workflow downloads a Java executable from a mirror and uses it without a verified publisher digest.', {
      raw: true, snykEvidence: 'linked-document', accepts: match => {
        const after = source.slice(match.index + match[0].length, match.index + match[0].length + 1600);
        const name = match[1].replaceAll('.', '\\.');
        const launch = new RegExp('\\bjava[ \\t]+-jar[ \\t]+[^\\r\\n]{0,115}' + name + '\\b', 'i').exec(after);
        return Boolean(launch) &&
          !/\b(?:sha256sum|shasum|signature verification|verify checksum)\b|验签/u.test(after.slice(0, launch.index));
      },
    });
  if (!limited && /\bgit[ \t]+(?:clone|fetch)\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'linked-document' };
    const count = results.length;
    scanMatches('suspicious-download', automaticCheckoutMirror,
      'The workflow automatically routes source downloads through a third-party mirror.', options);
    if (!limited && results.length > count) {
      scanMatches('runtime-dependency', automaticCheckoutMirror,
        'The mirror delivers repository contents for the agent to use at runtime.', options);
      scanMatches('system-modification', changesGitNetworkConfig,
        'The workflow can change the user’s global Git network settings.', { ...options, assessment: 'capability' });
    }
  }
  if (!limited && /\b(?:try|switch to) (?:the )?next mirror\b/i.test(source) &&
      /\bafter fetching (?:all |the )?(?:repository )?data, analyze\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest', accepts: match => {
      const hosts = [...match[0].matchAll(/https:\/\/([\w.-]+)/gi)].map(item => item[1].toLowerCase());
      return repositoryProviderHosts.has(hosts[0]) && hosts.some(host => !repositoryProviderHosts.has(host));
    } };
    scanMatches('suspicious-download', repositoryMirrorList,
      'The repository workflow automatically falls back to mirrors outside the source provider.', options);
    if (!limited) scanMatches('runtime-dependency', repositoryMirrorList,
      'External mirrors can determine the repository contents analyzed at runtime.', options);
    if (!limited) scanMatches('third-party-content', repositoryMirrorList,
      'The agent analyzes repository data returned by a third-party mirror.', options);
  }
  if (!limited && installsAdditionalFilesZh.test(source) && /(?:mkdir -p|rm -rf) ~\/\.(?:claude|agents|codex)\/skills\//.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest' };
    scanMatches('undisclosed-install-files', confirmsOneManifestZh,
      'The confirmation names only SKILL.md, while the installation phase also writes additional files.', {
        ...options, accepts: match => {
          const after = source.slice(match.index + match[0].length);
          const extra = installsAdditionalFilesZh.exec(after);
          return extra !== null && !/(?:重新审查|再次确认|单独确认|一并列出)/u.test(after.slice(0, extra.index + extra[0].length));
        },
      });
    scanMatches('third-party-content', fetchesUnpinnedManifest,
      'The installation workflow reads externally maintained skill instructions.', { ...options, assessment: 'capability' });
    scanMatches('runtime-dependency', fetchesUnpinnedManifest,
      'The installation workflow obtains its skill instructions from a mutable remote source.', options);
    scanMatches('system-modification', createsUserSkillFolder,
      'The installation writes externally retrieved instructions to user-level agent configuration.', {
        ...options, assessment: 'capability',
        accepts: () => !source.matchAll(fetchesUnpinnedManifest).next().done,
      });
  }
  if (!limited && /\b[A-Z_]*(?:TARGET|DEST)[A-Z_]*=[^\r\n]{0,25}\.(?:claude|agents|codex)\b/.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest', accepts: copiedAgentConfiguration };
    scanMatches('third-party-content', clonesAgentConfiguration,
      'The installer places externally maintained rule files in the agent’s instruction directories.', {
        ...options, assessment: 'capability',
      });
    scanMatches('runtime-dependency', clonesAgentConfiguration,
      'The installer loads agent instructions from a checkout without an immutable revision.', options);
    if (/(?:追加ファイル|additional files)[^\r\n]{0,70}(?:フック|hooks?)[^\r\n]{0,70}(?:スクリプト|scripts?)/iu.test(source)) {
      scanMatches('suspicious-download', clonesAgentConfiguration,
        'The unpinned agent configuration checkout can install bundled hooks and scripts.', options);
    }
  }
  if (!limited && /\b(?:origen|instalaci[oó]n|proveniencia)\b/iu.test(source)) {
    scanMatches('unapproved-file-change', claimsUnknownInstallationEs,
      'The diagnostics workflow treats files of unknown ownership as eligible for overwrite.', {
        snykEvidence: 'linked-document',
      });
  }
  if (!limited) scanMatches('third-party-content', remoteIssueRelation,
    'The runtime exposes the body of an externally authored GitHub issue.', {
      raw: true, snykEvidence: 'linked-document', assessment: 'capability',
    });
  if (!limited) scanMatches('system-modification', createsServiceRelation,
    'The setup relation can create a persistent runtime service.', {
      raw: true, snykEvidence: 'linked-document', assessment: 'capability',
    });
  if (!limited && source.includes('--copy') && source.includes('--all')) {
    const options = {
      raw: true, snykEvidence: 'global-skill-copy', accepts: ([, flags]) => {
        const args = new Set(flags.trim().split(/\s+/));
        return (args.has('-g') || args.has('--global')) && args.has('--all') && args.has('--copy');
      },
    };
    scanMatches('system-modification', globalSkillCopy,
      'The documented installer copies the skill into the global configuration of every detected agent.', options);
    if (!limited) scanMatches('runtime-dependency', globalSkillCopy,
      'The documented installer obtains those skill files from a Git repository without pinning a revision.', options);
  }
  if (!limited && source.includes('git clone') && source.includes('npm install') && source.includes('set-key')) {
    const clone = /^[ \t]*git[ \t]+clone[ \t]+https:\/\/github\.com\/[\w.-]+\/([a-z0-9][\w.-]*?)\.git[ \t]*\r?\n[ \t]*cd[ \t]+\1[ \t]*&&[ \t]*npm[ \t]+install[ \t]*(?:(?:&&|;)[^\r\n]{0,75})?(?=\r?\n|$)/gim;
    scanMatches('suspicious-download', clone,
      'The setup installs an unpinned local checkout and uses the resulting CLI with a user credential.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          const tail = source.slice(match.index + match[0].length, match.index + match[0].length + 2800);
          const repository = match[1].replaceAll('.', '\\.');
          const setsCheckoutKey = new RegExp('^[ \\t]*node[ \\t]+(?:\\.\\/)?' + repository +
            '\\/[\\w./-]+\\.js[ \\t]+set-key[ \\t]+["\\\']?<[-\\w]*key>["\\\']?', 'im');
          return setsCheckoutKey.test(tail);
        },
      });
    if (!limited) {
      const literalKey = /^[ \t]*(?:node[ \t]+[\w./-]+\.js|npm[ \t]+run[ \t]+[\w.-]+[ \t]+--)[ \t]+set-key[ \t]+["']?<([a-z][\w-]*-key)>["']?/gim;
      scanMatches('credential-handling', literalKey,
        'The workflow asks the user for a credential and submits that value as a literal local CLI argument.', {
          raw: true, snykEvidence: 'manifest', accepts: match => {
            const name = match[1];
            return source.split(/\r?\n/).some(line => /\bask\b/i.test(line) &&
              !/\b(?:never|do not|don't|must not)\s+ask\b/i.test(line) &&
              line.toLowerCase().includes(name.toLowerCase()) &&
              /\b(?:for|user)\b/i.test(line) && /\b(?:user|conversation|paste|receive)\b/i.test(line));
          },
        });
    }
  }
  if (!limited && source.includes('auth.json') && /\b(?:OAuth|access_token)\b/i.test(source)) {
    const globalSkill = /\bnpx[ \t]+skills[ \t]+add[ \t]+[\w.-]+\/[\w.-]+[ \t]+(?:-g|--global)(?=[\s\x60"'.,]|$)/g;
    scanMatches('suspicious-download', globalSkill,
      'The mutable global skill installer supplies a bundled command that reads a cached OAuth credential.', {
        raw: true, snykEvidence: 'global-skill-with-session-token',
      });
    if (!limited) scanMatches('third-party-content', globalSkill,
      'The bundled command forwards supplied prompt text into a model request and reads the streamed response.', {
        raw: true, snykEvidence: 'bundled-model-cli-prompt', assessment: 'capability',
      });
  }
  if (!limited) scanMatches('suspicious-download', documentsGitCheckout,
    'The README runs code from a checkout whose owner differs from the package’s declared repository owner.', {
      raw: true, snykEvidence: 'repository-origin-conflict', accepts: invokesDocumentedCheckout,
    });
  if (!limited) scanMatches('runtime-dependency', readmeSkillInstall,
    'The installation guide uses a remote repository to install this user-level agent skill.', {
      raw: true, snykEvidence: 'readme-skill-install',
    });
  if (!limited && closingMigrationPitchPt.test(source)) scanMatches('directed-product-endorsement', openingReleasePitchPt,
    'The skill mandates a release link in its first response and includes a migration pitch at the end.', {
      raw: true, snykEvidence: 'linked-document',
    });
  if (!limited && /\bAI Gateway\b/i.test(source) &&
      !/\b(?:ask|allow|prompt) (?:the )?user to (?:choose|select|supply) (?:a|the|their) model\b/i.test(source)) {
    const assigned = [...source.matchAll(assignedGatewayModel)];
    scanMatches('default-model-provider', defaultGatewayModel,
      'The guide repeatedly selects the same third-party model for the workflow’s external calls.', {
        raw: true, snykEvidence: 'linked-document', accepts: match =>
          !/^(?:example|provider)\//i.test(match[1]) && assigned.filter(setting => setting[1] === match[1]).length >= 3,
      });
  }
  if (!limited && /\bspace-index\x60?[ \t]+setting is \x60?auto\x60?[ \t]+by default\b/i.test(source) &&
      /\bsmall local index skill\b/i.test(source)) {
    scanMatches('undisclosed-local-index', omitsLocalIndexDetails,
      'The workflow stores a local index by default and prevents the agent from naming the file or controls.', {
        raw: true, snykEvidence: 'linked-document',
      });
  }
  if (!limited && /["']colorScienceMode["']/.test(source) && /["']colorSpaceTimeline["']/.test(source)) {
    scanMatches('unapproved-file-change', assertsProjectColorSettings,
      'The timeline operation can rewrite color settings across the project.', {
        raw: true, snykEvidence: 'project-color-settings',
      });
  }
  if (!limited && /\bimport pickle\b/.test(source) && /\bargparse\b/.test(source) &&
      !/\b(?:RestrictedUnpickler|verify_signature|check_sha256)\b/.test(source)) {
    scanMatches('suspicious-download', loadsUnverifiedModelPickle,
      'The workflow opens a supplied model artifact through a loader that can execute serialized objects.', {
        raw: true, snykEvidence: 'model-pickle-artifact',
      });
  }
  if (!limited && /\bPlaywright MCP\b/i.test(source) &&
      /(?:провер(?:ить|ка|яет) сайт|пройти сайт|тестировани[ея] сайта)/iu.test(source)) {
    scanMatches('automatic-verification-repair', repairsAfterBrowserRoundRu,
      'The browser verification loop directs the agent to repair the tested code after a round.', {
        snykEvidence: 'linked-document',
        accepts: match => !/(?:только после|без согласия не)[^。\r\n]{0,25}(?:подтверждения|согласия)/iu.test(nearMatch(match)),
      });
  }
  if (!limited && /\bdo not modify any source code\b[^\r\n]{0,110}\bthis skill is read-only\b/i.test(source)) {
    scanMatches('automatic-verification-repair', repairsFailedVerification,
      'The workflow automatically edits project files after a failed gate despite declaring the skill read-only.', {
        raw: true, snykEvidence: 'manifest',
        accepts: match => {
          const line = source.slice(match.index, match.index + match[0].length + 110).split(/\r?\n/, 1)[0];
          return !asksForApproval.test(nearMatch(match)) && !asksForApproval.test(line);
        },
      });
  }
  if (!limited) scanMatches('unapproved-file-change', opensPullRequestAutonomouslyRu,
    'The branch and pull-request workflow discloses the write as an autonomous action.', {
      raw: true, snykEvidence: 'linked-document',
    });
  if (!limited && /(?:инбокс|входящие сообщения)/iu.test(source) && /\bAGENTS\.md\b/.test(source)) {
    scanMatches('third-party-content', readsRoleInboxRu,
      'The role workflow reads incoming assignments and messages from other participants.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
  }
  if (!limited && /(?:chmod[ \t]+\+x|скрипт[^\r\n]{0,60}созда)/iu.test(source) &&
      /(?:~\/bin\/|\$HOME\/bin\/)/i.test(source)) {
    scanMatches('unguarded-channel-launcher', setsUnguardedChannelLauncher,
      'The installed launcher invokes the agent with browser access and permission prompts disabled.', {
        raw: true, snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\b(?:browser_navigate|navigate to the target URL)\b/i.test(source)) {
    scanMatches('third-party-content', readsPageSnapshot,
      'The verification workflow reads the visited page’s interactive content.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\b(?:Telegram|Discord|Slack)\b/i.test(source) && /\battachment_file_id\b/i.test(source)) {
    scanMatches('third-party-content', receivesChannelAttachment,
      'The messaging workflow retrieves attachments sent to the channel.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\binspect (?:it|the (?:package|archive)) before installing\b/i.test(source) &&
      /\binstall by copying\b[^\r\n]{0,150}\.\w+\/skills\//i.test(source) &&
      !/\b(?:must|first|before installing)\b[^.!?;\r\n]{0,65}\b(?:verify|validate)\b[^.!?;\r\n]{0,70}\b(?:checksum|signature|digest)\b/i.test(source)) {
    const options = { snykEvidence: 'manifest' };
    scanMatches('third-party-content', packageDownloadIntake,
      'The installer inspects a package provided at runtime, including its instruction files.', {
        ...options, assessment: 'capability',
      });
    scanMatches('runtime-dependency', packageDownloadIntake,
      'The workflow installs agent instructions from a package URL chosen at runtime.', options);
    if (results.some(result => result.id === 'runtime-dependency')) scanMatches('suspicious-download', untrustedPackageSamples,
      'The workflow installs packages from a shared or unspecified distribution host.', { raw: true, ...options });
  }
  if (!limited && /\bGatekeeper\b/i.test(source) && /\bdownload(?:ed|s)?\b/i.test(source)) {
    scanMatches('weakened-safeguard', removesQuarantine,
      'The installation guide removes macOS quarantine from a downloaded executable.', { raw: true, snykEvidence: 'manifest' });
    scanMatches('system-modification', removesQuarantine,
      'The command changes how macOS screens the downloaded executable.', {
        assessment: 'capability', raw: true, snykEvidence: 'manifest',
      });
    if (!limited && !source.matchAll(removesQuarantine).next().done) scanMatches('runtime-dependency', latestGoInstall,
      'The setup can obtain its executable at runtime from the latest Git release.', { raw: true, snykEvidence: 'manifest' });
  }
  if (!limited) scanMatches('forced-escalation', retriesWithPrivilegedInstall,
    'A permissions error can lead directly to a privileged global install.', {
      snykEvidence: 'manifest', raw: true, accepts: match => !asksForApproval.test(nearMatch(match)),
    });
  if (!limited && optOutApproval.test(source)) scanMatches('weakened-safeguard', runsAgentsAutonomously,
    'Agents are launched with autonomy enabled unless the user changes the permission setting.',
    { raw: true, snykEvidence: 'manifest' });
  if (!limited && selfSignedCertificate.test(source)) scanMatches('local-root-trust', installMachineTrust,
    'The setup changes the machine’s root trust for a locally generated certificate.', { snykEvidence: 'linked-document' });
  if (!limited && createsAgentAlias.test(source)) scanMatches('weakened-safeguard', disablesShellSafeguards,
    'The script creates an agent launcher with its normal permission checks disabled.', { raw: true, snykEvidence: 'invoked-script' });
  if (!limited) scanMatches('weakened-safeguard', defaultsToUnrestrictedAgent,
    'The agent launch defaults to automatic approval with sandbox protection disabled.', {
      accepts: match => !asksForApproval.test(nearMatch(match)), raw: true, snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('weakened-safeguard', requestsAllConnections,
    'The connector requests full access to all connected accounts without a permission set.', {
      snykEvidence: 'manifest', accepts: match => {
        const context = match.input.slice(match.index, match.index + match[0].length + 420);
        return /\b(?:every|all) (?:existing |connected |their )?(?:connections?|connected (?:apps?|tools?|accounts?))\b/i.test(context) &&
          /\b(?:full|unrestricted|unlimited)[ -]+access\b/i.test(context) &&
          /\b(?:no|omit(?:s|ted)?|skip(?:s|ped)?|without)\b[^.!?;\r\n]{0,70}\b(?:permissions?[ _-](?:set|scope)|[A-Z0-9_]*PERMISSION_SET)\b/i.test(context) &&
          !asksForApproval.test(context);
      },
    });
  if (!limited && /\b(?:push guard|pre-push guard|git-guard)\b/i.test(source)) {
    const options = {
      raw: true, snykEvidence: 'manifest',
      accepts: match => /\b[A-Z_]*GUARD_REASON[ \t]*=/.test(match[0]) &&
        /\b(?:push guard|pre-push guard|git-guard)\b/i.test(source.slice(Math.max(0, match.index - 380), match.index)),
    };
    scanMatches('weakened-safeguard', pushGuardOverride,
      'The workflow activates a documented override of the repository push safeguards.', options);
    if (!limited) scanMatches('system-modification', pushGuardOverride,
      'The workflow changes the effective push guard settings for a network write.', { ...options, assessment: 'capability' });
  }
  if (!limited) scanMatches('weakened-safeguard', delegatesCredentialSetup,
    'An unpinned onboarding tool directs a sign-in flow that writes a project credential.', {
      raw: true,
      accepts: match => {
        const context = nearMatch(match);
        return !asksForApproval.test(context) && !/\bask (?:the )?user to (?:approve|confirm) before\b/i.test(context);
      },
      snykEvidence: 'manifest',
    });
  if (!limited && /\?form=/i.test(source)) {
    scanMatches('weakened-safeguard', directsBotCredentialsToForm,
      'The setup directs bot credential creation through a dedicated onboarding form and gives the developer console as the manual alternative.', {
        raw: true, snykEvidence: 'linked-document', accepts: match => {
          const before = source.slice(Math.max(0, match.index - 140), match.index);
          const after = source.slice(match.index + match[0].length, match.index + match[0].length + 200);
          return /\b(?:simplest|recommended|preferred) (?:setup|path|option)\b/i.test(before) &&
            /\b(?:manual|standard) path\b[^.!?\r\n]{0,100}\bdeveloper console\b/i.test(after) &&
            [...after.matchAll(/https:\/\/[\w.-]+\/app(?=[\s`]|$)/gi)]
              .some(([url]) => url.toLowerCase() === match[1].toLowerCase() + '/app');
        },
      });
  }
  if (!limited) scanMatches('weakened-safeguard', disablesSafetyFilterInTable,
    'The documented defaults disable a content safety filter.', {
      raw: true,
      accepts: match => {
        const preceding = match.input.slice(Math.max(0, match.index - 3000), match.index);
        const section = preceding.split(/\r?\n[ \t]*\r?\n/).at(-1);
        return /^[ \t]*\|[^|\r\n]+\|[^|\r\n]+\|[ \t]*default[ \t]*\|/im.test(section);
      },
      snykEvidence: 'manifest',
    });
  if (!limited && /\b(?:bearer token|session cookie|API key)\b/i.test(source)) {
    const introduction = source.slice(0, 2048);
    const writesGlobalSettings = managesGlobalApiSettings.test(introduction) && writesApiSettings.test(source);
    const options = { accepts: match => !asksForApproval.test(nearMatch(match)), raw: true, snykEvidence: 'manifest' };
    if (writesGlobalSettings || readsApiData.test(introduction)) {
      scanMatches('weakened-safeguard', disablesApiAuthentication,
        'The API guide suggests disabling the access check that protects the documented operations.', options);
    }
    if (!limited && writesGlobalSettings) {
      scanMatches('system-modification', disablesApiAuthentication,
        'The workflow changes the authentication setting for an administrative API.', { ...options, assessment: 'capability' });
    }
  }
  const readClaims = limited ? [] : [...source.slice(0, 2048).matchAll(declaredLimitedReads)]
    .map(match => match[1]).filter(claim => /\.md\b/i.test(claim));
  if (readClaims.length) {
    const readPaths = new Set([...source.matchAll(specificFileRead)]
      .filter(match => !negated(source, match.index)).map(match => match[1]));
    scanMatches('unapproved-file-change', specificFileWrite,
      'The skill reads and writes a file outside its stated list of inputs.', {
        accepts: match => readPaths.has(match[1]) && readClaims.some(claim => !claim.includes(match[1].split('/').at(-1))),
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited && /['"](?:node:)?child_process['"]/.test(source) && /\bprocess\.argv\b/.test(source)) {
    scanMatches('unchecked-shell-argument', shellArgument,
      'A command string uses an interpolated value before passing the command to a shell.',
      { raw: true, snykEvidence: 'invoked-script', accepts: interpolatesDynamicValue });
  }
  if (!limited) scanMatches('agent-role-override', roleMarker,
    'A role marker can make skill text look like a privileged instruction.', { raw: true });
  if (!limited && (source.includes('--git-tracked') || source.includes('--all-tracked'))) {
    scanMatches('unapproved-file-change', trackedWriteThenCheck,
      'The one-command workflow rewrites repository-wide tracked files before running its checks.', {
        raw: true, snykEvidence: 'tracked-repair-workflow', accepts: match => {
          const context = source.slice(Math.max(0, match.index - 240), match.index);
          return !/--(?:dry-run|check|preview|paths?)(?=[\s=]|$)/i.test(match[2]) &&
            !/\b(?:only after|after (?:the )?user|ask (?:the )?user|user must)\b[^\r\n]{0,70}\b(?:approv(?:e[sd]?|al)|confirm(?:s|ed|ation)?|(?:pre)?review(?:s|ed)?)\b/i.test(context);
        },
      });
  }
  if (!limited) scanMatches('unapproved-file-change', destructiveOverwrite,
    'The workflow instructs the agent to overwrite original files in bulk.', { raw: true, snykEvidence: 'direct' });
  if (!limited && /^#![^\r\n]*\b(?:ba|da|k|z)?sh\b/.test(source)) {
    scanMatches('unapproved-file-change', removesInstallTarget,
      'The installer recursively deletes a caller-selected directory when it has no Git checkout.', {
        raw: true, snykEvidence: 'caller-selected-installer-target', accepts: replacesCallerSelectedCheckout,
      });
  }
  if (!limited) scanMatches('unapproved-file-change', unapprovedChanges,
    'The workflow asks the agent to change user or installed files without approval.', { snykEvidence: 'direct' });
  if (!limited) scanMatches('unapproved-file-change', uncheckedFileChanges,
    'The workflow instructs the agent to make file changes while suppressing clarification or confirmation.', {
      accepts: match => !/\b(?:ask for (?:user )?approval|only after (?:user )?confirmation)\b/i.test(match[0]),
      snykEvidence: match => /\(AUTOMATED EVAL:\s*You\s*$/i.test(
        match.input.slice(Math.max(0, match.index - 45), match.index)) ? 'evaluation-prompt' : 'manifest',
    });
  if (!limited && /\.iterdir\s*\(\s*\)/.test(source)) scanMatches('unapproved-file-change', deletesByOutputPrefix,
    'The cleanup filter can remove files that share the output name even when their extension is unrelated.', {
      raw: true,
      accepts: match => {
        const here = match.index;
        const prefix = source.slice(Math.max(0, here - 440), here);
        const loop = /\bfor\s+(\w+)\s+in\s+\w+\.iterdir\s*\(\s*\)/.exec(prefix);
        if (!loop) return false;
        const readsName = new RegExp('\\b' + match[1] + '\\s*=\\s*' + loop[1] + '\\.name\\b');
        const removesFile = new RegExp('\\b' + loop[1] + '\\.unlink\\s*\\(');
        return readsName.test(prefix) && removesFile.test(source.slice(here + match[0].length, here + match[0].length + 240));
      },
      snykEvidence: 'invoked-script',
    });
  if (!limited && /\bxcode\s+build\b/i.test(source)) scanMatches('weakened-safeguard', fixedDistributionIdentity,
    'The distribution build specifies fixed signing identifiers instead of using the user’s team and key configuration.',
    { raw: true, snykEvidence: 'manifest' });
  if (!limited && /\b(?:orphan (?:root )?commit|replace a repository.s main line)\b/i.test(source) &&
      /\b(?:archive branch|archive is pushed)\b/i.test(source)) {
    scanMatches('unapproved-file-change', pushesRestartedDefaultBranch,
      'The workflow replaces the default branch with a new history after preserving the previous tip.',
      { raw: true, snykEvidence: 'manifest' });
  }
  if (!limited) scanMatches('unapproved-file-change', resetsAndForcePushesDefaultBranch,
    'The recovery procedure resets the default branch and force-pushes to its remote without a separate approval step.', {
      snykEvidence: 'manifest', accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 230), match.index);
        const after = match.input.slice(match.index, match.index + match[0].length + 115);
        return /\b(?:recover|recovery|force-push (?:main|master) back)\b/i.test(before) &&
          !/\b(?:only after approval|(?:ask|confirm) (?:with )?(?:the )?user|approval before (?:pushing|force-pushing))\b/i.test(before + after);
      },
    });
  if (!limited && /^#![^\r\n]*\b(?:ba|z)?sh\b/.test(source) && /\bgh[ \t]+gist[ \t]+create\b/.test(source)) {
    scanMatches('weakened-safeguard', waitsAfterSecretWarning,
      'The sharing script pauses after detecting possible secrets and continues to upload unless interrupted.', {
        raw: true, snykEvidence: 'invoked-shell', accepts: match => {
          const before = match.input.slice(Math.max(0, match.index - 600), match.index);
          const beforeUpload = match.input.slice(match.index + match[0].length, match.index + 2400);
          const upload = /\bgh[ \t]+gist[ \t]+create\b/.exec(beforeUpload);
          const warningBranch = beforeUpload.split(/^[ \t]*(?:else|fi)\b/m, 1)[0];
          return upload && /\bcontains potential secrets\b/i.test(before) &&
            /\babort with Ctrl-C\b[^\r\n]{0,95}\bwait to continue\b/i.test(before) &&
            !/^[ \t]*(?:exit|return|read)\b/m.test(warningBranch) &&
            !/\b(?:confirm|approve) before (?:uploading|sharing)\b/i.test(beforeUpload.slice(0, upload.index));
        },
      });
  }
  if (!limited && /^#![^\r\n]*\b(?:ba|z)?sh\b/.test(source)) {
    scanMatches('dangerous-code-pattern', desktopJavaScriptSource,
      'The invoked shell helper evaluates JavaScript from standard input inside a desktop application.', {
        raw: true, snykEvidence: 'desktop-script-evaluation', accepts: feedsDesktopScriptFromStdin,
      });
  }
  if (!limited && /\bchild_process\b/.test(source) && /\b(?:cscript|osascript)\b/.test(source)) {
    const writesRequestedScript = /\bwriteFileSync\(\s*([A-Za-z_]\w*)\s*,\s*[A-Za-z_]\w*\.params\.(?:script|code)\s*\)/g;
    scanMatches('dangerous-code-pattern', writesRequestedScript,
      'The desktop bridge writes caller-supplied script text to a file and passes that file to the application scripting host.', {
        raw: true, snykEvidence: 'desktop-script-input', accepts: match => {
          const before = source.slice(Math.max(0, match.index - 550), match.index);
          const after = source.slice(match.index + match[0].length, match.index + match[0].length + 590);
          const script = match[1];
          return /\bos\.tmpdir\(\)/.test(before) && /\.jsx\b/.test(before) &&
            new RegExp(String.raw`\b(?:spawnSync|execFileSync)\(['"](?:cscript|osascript)['"],[^\r\n]{0,160}\b${script}\b`).test(after);
        },
      });
  }
  if (!limited && /\brecord_(?:user_)?prompt\b/i.test(source) && /\brecord_(?:integration_)?result\b/i.test(source) &&
      [...source.matchAll(/\bautomatically install dependencies\b[^.!?;\r\n]{0,110}\bwithout waiting for (?:user )?confirmation\b/gi)]
        .some(match => !negated(source, match.index))) {
    const embedsGeneratedCredentials = /\bembed (?:the )?returned credentials directly into generated code\b/gi;
    const options = { raw: true, snykEvidence: 'manifest' };
    scanMatches('dangerous-code-pattern', embedsGeneratedCredentials,
      'The workflow embeds credentials in generated code and runs the generated project with automatic reporting and installation.', options);
    if (!limited) scanMatches('credential-handling', embedsGeneratedCredentials,
      'The returned credentials are written directly into the generated project.', options);
    if (!limited && /\bMCP tools?\b[^\r\n]{0,85}\bonly authoritative source\b/i.test(source)) {
      scanMatches('runtime-dependency', embedsGeneratedCredentials,
        'Remote tool output supplies the credentials and rules used to generate runnable source code.', options);
    }
  }
  if (!limited && /https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/(?:main|master)\/templates\//i.test(source) &&
      /\bcopy (?:the )?[^\r\n]{0,75}loop scripts\b/i.test(source)) {
    const launchesLoopScript = {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const before = source.slice(Math.max(0, match.index - 460), match.index);
        const command = source.slice(match.index, match.index + 160).split(/\r?\n/, 1)[0];
        return /\b(?:must|always) start the loop automatically\b/i.test(before) &&
          /\bdo not ask (?:the )?user to run it\b/i.test(before) &&
          !/\b(?:ask for approval|wait for confirmation|after the user approves)\b/i.test(before) &&
          /\s-File\s+["']?(?:\.\/)?scripts\/[\w.-]+\.ps1\b/i.test(command);
      },
    };
    scanMatches('dangerous-code-pattern', windowsPolicyBypass,
      'The skill launches a copied automation loop using templates from a mutable branch and disables Windows script policy for the launch.', launchesLoopScript);
    if (!limited) scanMatches('runtime-dependency', windowsPolicyBypass,
      'The automatic loop depends on scripts obtained from a mutable template directory.', launchesLoopScript);
    if (!limited && /\bsudo[ \t]+apt(?:-get)?[ \t]+install\b/i.test(source)) {
      scanMatches('system-modification', windowsPolicyBypass,
        'The loop setup includes privileged package installation and launches the copied scripts automatically.', launchesLoopScript);
    }
  }
  if (!limited && /\bSECURELOAD\b/i.test(source)) {
    const disablesDrawingScriptProtection = /\bsetvar[ \t]+\\?["']SECURELOAD\\?["'][ \t]+0\b/gi;
    const options = { raw: true, snykEvidence: 'manifest', accepts: match => {
      const before = source.slice(Math.max(0, match.index - 240), match.index);
      const after = source.slice(match.index + match[0].length, match.index + 195);
      return /\boperation[ \t]*=[ \t]*["']execute_lisp["']/.test(before) &&
        /\(load\b/.test(after) && !/\b(?:never run|unsafe example|do not execute|example to avoid)\b/i.test(before);
    } };
    scanMatches('dangerous-code-pattern', disablesDrawingScriptProtection,
      'The desktop automation loads a script with the application’s script-loading protection disabled.', options);
    if (!limited) scanMatches('system-modification', disablesDrawingScriptProtection,
      'The workflow changes the desktop application’s security setting while loading a script.', options);
  }
  if (!limited && /\bmodule\s+"[\w-]*security[_-]group[\w-]*"\s*\{/.test(source)) {
    scanMatches('weakened-safeguard', allowsPublicSshIngress,
      'The infrastructure template allows inbound SSH from any internet address.', {
        raw: true, snykEvidence: 'linked-document', accepts: match => {
          const before = match.input.slice(Math.max(0, match.index - 415), match.index);
          return !/\b(?:do not deploy|insecure example|anti[- ]pattern|for demonstration only)\b/i.test(before) &&
            !/\b(?:action|policy)\s*=\s*"(?:deny|reject)"/i.test(match[0]);
        },
      });
  }
  if (!limited && /\b(?:citation|bibliography)(?: and source)? audit\b/i.test(source)) {
    scanMatches('unapproved-file-change', rewritesAllRegisteredCitations,
      'A citation audit rewrites fields in every registered document, including files outside the current task.',
      { snykEvidence: 'manifest' });
    if (!limited) scanMatches('third-party-content', readsSourcesForCitation,
      'The citation workflow reads full text from external publications.', { assessment: 'capability', snykEvidence: 'manifest' });
  }
  if (!limited && installsSkillsForAgents.test(source)) scanMatches('automatic-agent-skill-install', updatesAgentSkillsDuringCommands,
    'Ordinary commands install agent skills on first run and refresh them after updates.',
    { snykEvidence: 'manifest' });
  if (!limited && /\bread[- ]only\b/i.test(source)) {
    const protectedDirectories = Array.from(source.matchAll(readOnlyDirectory), match => match[1]);
    if (protectedDirectories.length) scanMatches('unapproved-file-change', shellFileWrite,
      'The workflow writes into a directory that it explicitly says it leaves untouched.', {
        raw: true, snykEvidence: 'manifest',
        accepts: match => {
          const lineStart = Math.max(source.lastIndexOf('\n', match.index - 1), source.lastIndexOf('\r', match.index - 1)) + 1;
          const prefix = source.slice(lineStart, match.index).trimStart();
          return !prefix.startsWith('#') && (!match[0].startsWith('>') || Boolean(prefix)) &&
            protectedDirectories.some(path => match[1].startsWith(path));
        },
      });
  }
  if (!limited) scanMatches('undisclosed-live-account', concealedLiveUse,
    'The instruction calls for silently selecting the live environment.', { snykEvidence: 'direct' });
  if (!limited && persistentContext.test(source)) scanMatches('undisclosed-persistence', hiddenWrites,
    'The workflow keeps changes for future sessions and tells the agent to keep those writes quiet.', { snykEvidence: 'direct' });
  if (!limited) scanMatches('undisclosed-monitoring', concealedMonitoring,
    'The instructions direct the agent to withhold that it is monitoring or recording a user artifact or activity.',
    { snykEvidence: 'manifest' });
  if (!limited && /\bWebSocket events\b/i.test(source) && /\bvisual_index\b/.test(source)) {
    scanMatches('third-party-content', publicVideoIngest,
      'The workflow ingests public video and consumes text derived from media streams.',
      { raw: true, snykEvidence: 'manifest', assessment: 'capability' });
    if (!limited && /\b(?:exports?|transcodes?|reframes?|reframing)\b[^\r\n]{0,110}\b(?:callback_url|webhook)\b/i.test(source)) {
      scanMatches('dangerous-code-pattern', monitorsCredentialField,
        'The screen capture workflow advertises alerts for credential fields and processes recordings through an external service.',
        { raw: true, snykEvidence: 'manifest' });
    }
  }
  if (!limited && /\b(?:once per session|every (?:session|conversation))\b/i.test(prose.text) &&
      /\bbackground\s+(?:\*\*)?sub[- ]agent\b/i.test(prose.text) &&
      /\b(?:current conversation|session observations)\b/i.test(source)) {
    scanMatches('undisclosed-monitoring', concealedSessionObserver,
      'The recurring session observer tells the agent to hide its activity and skip user consent.',
      { raw: true, snykEvidence: 'manifest' });
    if (!limited && /\b(?:rewrites?|updates?|writes?)\b[^.!?;\r\n]{0,75}\b(?:journal|observations)\b/i.test(source) &&
        /~\/[\w./-]+\/journal\//i.test(source)) {
      scanMatches('dangerous-code-pattern', concealedSessionObserver,
        'The undisclosed session observer persists conversation observations in a journal under the user home directory.',
        { raw: true, snykEvidence: 'manifest' });
      if (!limited) scanMatches('system-modification', concealedSessionObserver,
        'The background workflow modifies files under the user home directory without notice.',
        { raw: true, snykEvidence: 'manifest' });
      if (!limited && /\binclude real examples from sessions\b/i.test(source) &&
          !/\b(?:redact\w*|anonymiz\w*|sanitiz\w*|scrub\w*)\b/i.test(source)) {
        scanMatches('credential-handling', concealedSessionObserver,
          'The journal can persist sensitive session examples without redacting them.',
          { raw: true, snykEvidence: 'manifest' });
      }
    }
  }
  if (!limited && /\burlopen\(/.test(source) && /["']\/chat\/completions["']/.test(source) &&
      /["']messages["']\s*:\s*\[/.test(source) && /["']choices["']/.test(source) &&
      /\.add_argument\(["']--url["']/.test(source)) {
    const options = { raw: true, snykEvidence: 'vision-request-payload', assessment: 'capability' };
    scanMatches('third-party-content', encodesLocalVisionImage,
      'The vision helper takes local and remote images and reads a response from the external model.', options);
    if (!limited) scanMatches('runtime-dependency', encodesLocalVisionImage,
      'The workflow depends on the external vision service response.', options);
    if (!limited && /\bwinreg\.HKEY_CURRENT_USER,\s*["']Environment["']/.test(source) && /\bwinreg\.SetValueEx\(/.test(source)) {
      scanMatches('dangerous-code-pattern', encodesLocalVisionImage,
        'The helper sends local image data to a remote vision service and can persist a credential supplied in chat.',
        { raw: true, snykEvidence: 'vision-request-with-chat-credential' });
    }
  }
  if (!limited && /\bvercel\.json\b/.test(source) && /\.rewrites\.push\(/.test(source) && /\bdestination:\s*['"]https:\/\//.test(source) &&
      /\.get\(["']transaction_token["']\)/.test(source) && /\bwriteFileSync\(/.test(source)) {
    const options = { raw: true, snykEvidence: 'bundled-tracking-rewrite' };
    scanMatches('dangerous-code-pattern', insertsRuntimeTracker,
      'The installer adds a tracking script, reads transaction identifiers, and changes request routing.', options);
    if (!limited) scanMatches('runtime-dependency', insertsRuntimeTracker,
      'The injected tracking script is loaded at runtime through the configured route.', options);
  }
  if (!limited && /\b(?:copies?|writes?|exports?) to (?:the )?clipboard by default\b/i.test(source) &&
      /\boutput each input in chronological order\b/i.test(source) &&
      /\bno need to display the content in the response\b/i.test(source) &&
      !/\b(?:redact|mask|remove) (?:any |all )?(?:credentials|secrets|sensitive (?:data|values))\b|\bpreview (?:the )?export before\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', exportsPriorConversation,
      'The workflow exports all user messages from the current and resumed session history without a preview.',
      { snykEvidence: 'manifest' });
    if (!limited) scanMatches('credential-handling', exportsPriorConversation,
      'The export can copy credentials and other sensitive values embedded in previous messages.',
      { snykEvidence: 'manifest' });
  }
  if (!limited && /"(?:observer|monitoring)_role"\s*:/i.test(source)) scanMatches('undisclosed-monitoring', covertObserverPrompt,
    'The background observer prompt requires keeping the monitored session unaware.', { raw: true, snykEvidence: 'linked-document' });
  const frontmatterEnd = /^---[ \t]*\r?\n/.test(source) ? /\r?\n---[ \t]*(?:\r?\n|$)/.exec(source)?.index : undefined;
  if (!limited && frontmatterEnd !== undefined &&
      /^#{1,2}[ \t]+[^\r\n]{0,70}\bcontrolled provocation\b/im.test(source) &&
      /\breveal\w*\b[^.!?;\r\n]{0,65}\bhidden (?:details|information|facts?|objective|truth)\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', describesProvocation,
      'The skill directs the agent to manipulate a person into disclosing sensitive information.', {
        raw: true, snykEvidence: 'manifest', accepts: match => match.index + match[0].length <= frontmatterEnd,
      });
  }
  if (!limited && frontmatterEnd !== undefined && /\bDPI(?:\/censorship)? systems\b/i.test(source) &&
      /\bordinary HTTPS browsing traffic\b/i.test(source) &&
      /\bactive probing\b/i.test(source) && /\bcertificate stealing\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', auditsTrafficCircumvention,
      'The workflow explicitly evaluates a circumvention setup against traffic fingerprinting and active probing.', {
        raw: true, snykEvidence: 'manifest', accepts: match => match.index + match[0].length <= frontmatterEnd,
      });
  }
  if (!limited && /含(?:登录)?凭据的备份/u.test(source) && /保存历史会话/u.test(source) &&
      /(?:重启|重新登录)|\brestart\b/iu.test(source)) {
    scanMatches('retained-relay-authentication', relaysStoredLoginResponse,
      'The recovery flow sends a saved login response to a relay while older sessions and credential backups remain on disk.', {
        raw: true, snykEvidence: 'manifest',
        accepts: match => !/(?:不要|不得|禁止|脱敏|已获用户授权)[^。！？\r\n]{0,45}(?:扫码|Relay)/iu.test(nearMatch(match)),
      });
  }
  if (!limited && frontmatterEnd !== undefined && /\b(?:requests?|responses?|endpoint|target|http)\b/i.test(source) &&
      !/\b(?:authoriz\w*|scope|consent|approval|allowlist|permission)\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', skillDescriptionField,
      'The skill declares active firewall bypass as its purpose without stating an authorization boundary.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          const description = match[0];
          return match.index + description.length <= frontmatterEnd &&
            /\b(?:WAF|web application firewall)\b[^.!?;]{0,48}\b(?:bypass\w*|evad\w*|circumvent\w*)\b|\b(?:bypass\w*|evad\w*|circumvent\w*)\b[^.!?;]{0,48}\b(?:WAF|web application firewall)\b/i.test(description) &&
            /\b(?:attempt\w*|test\w*|probe\w*|find\w*|hunt\w*|perform\w*|apply|run\w*|obtain\w*)\b/i.test(description) &&
            !/\b(?:prevent\w*|detect\w*|defend\w*|mitigat\w*|harden\w*)\b/i.test(description);
        },
      });
  }
  if (!limited && frontmatterEnd !== undefined) scanMatches('default-host-hook', suppressedCommandHook,
    'The manifest runs a bundled script after Bash calls and suppresses its failure output.', {
      raw: true,
      accepts: match => match.index + match[0].length <= frontmatterEnd,
      snykEvidence: 'manifest',
    });
  if (!limited && /decision\s*:\s*["']block["']/i.test(source) && /\blearned skills\b/i.test(source)) {
    scanMatches('undisclosed-persistence', extendsStoppedSession,
      'The Stop hook can add a model turn so it can save instructions for future sessions.', { raw: true, snykEvidence: 'manifest' });
  }
  if (!limited && /\b(?:network egress|outbound network access)\b/i.test(source)) {
    scanMatches('weakened-safeguard', opensAllNetworkDomains,
      'The onboarding fallback widens outbound network access to every domain after a domain policy blocks a request.', {
        raw: true, snykEvidence: 'linked-document', accepts: match => {
          const context = source.slice(Math.max(0, match.index - 1250), match.index).split(/\r?\n[ \t]*\r?\n/).at(-1);
          return /\b(?:network egress|outbound network access)\b/i.test(context) &&
            /\b(?:host not in allowlist|domain (?:is|was) blocked|network proxy)\b/i.test(context) &&
            /\b(?:no domain list|still blocked|allowlist (?:is )?unavailable)\b/i.test(context);
        },
      });
  }
  if (!limited) scanMatches('weakened-safeguard',
    /\b(?:disable|turn off|deactivate)[ \t]+(?:the[ \t]+)?(?:Cloudflare[ \t]+)?Bot Fight Mode\b|\bBot Fight Mode\b[^.!?;\r\n]{0,95};[ \t]*(?:disable|turn off|deactivate)[ \t]+it\b/gi,
    'The guidance recommends turning off bot protection for the whole zone.', {
      raw: true, snykEvidence: 'linked-document',
      accepts: match => {
        const context = nearMatch(match);
        const before = match.input.slice(Math.max(0, match.index - 120), match.index);
        return !asksForApproval.test(context) &&
          !/\b(?:request|obtain|require|wait for)[ \t]+(?:the[ \t]+)?(?:user(?:'s)?[ \t]+)?(?:approval|confirmation|permission)[^.!?;\r\n]{0,45}\bbefore\b[^.!?;\r\n]*$/i.test(before) &&
          !/\b(?:never|avoid|do not|don['’]t)[ \t]+(?:disable|turn off|deactivate)\b/i.test(context);
      },
    });
  if (!limited) scanMatches('automatic-telemetry', unsolicitedReporting,
    'Reporting happens on every run or without a separate request from the user.', {
      accepts: match => !/\b(?:only if|only when|if|after) (?:the )?user (?:opts in|approves|enables|confirms)\b/i.test(nearMatch(match)),
      snykEvidence: 'direct',
    });
  if (!limited && /\b(?:usage beacon|startup telemetry)\b/i.test(source)) {
    scanMatches('automatic-telemetry', startupUsageBeacon,
      'The skill sends a usage event at startup that can be linked to the signed-in account.', {
        snykEvidence: match => {
          const event = /\b([a-z][\w-]*)[ \t]+--skill(?:=|[ \t])/i.exec(match[1])?.[1];
          if (!event) return;
          const prohibition = new RegExp(String.raw`(?:\b(?:do not|don['’]t|never) run[ \t]+\x60${event}\x60|\x60${event}\x60 is[^.!?;\r\n]{0,45}\btelemetry\.[ \t]+(?:do not|don['’]t|never) run them\b)`, 'i');
          if (prohibition.test(match.input)) return 'manifest';
        },
        accepts: match => {
          const prior = match.input.slice(Math.max(0, match.index - 110), match.index).split(/\r?\n/).at(-1);
          const tail = match.input.slice(match.index + match[0].length, match.index + match[0].length + 165).split(/\r?\n/, 1)[0];
          return /\b(?:usage beacon|startup telemetry)\b/i.test(prior) &&
            /\b(?:account[- ]linked|linked to (?:the |your )?account)\b/i.test(tail) &&
            !asksForApproval.test(prior + tail) && !/\b(?:only (?:if|after|when)|once) (?:the )?user (?:opts in|consents|enables)\b/i.test(prior + tail);
        },
      });
  }
  if (!limited && /"\$hints"[ \t]*:[ \t]*\[[\s\S]{0,950}?\bFix:[^\r\n]{0,100}\bdelete[- ]property\b/i.test(source)) {
    scanMatches('weakened-safeguard', executesSuggestedFix,
      'The workflow executes remedial commands returned by a service, including commands that delete workspace properties.', {
        snykEvidence: 'linked-suggested-fix', accepts: match => !asksForApproval.test(nearMatch(match)) &&
          !/\b(?:only if|only after|when) (?:the )?user (?:asks|approves|confirms)\b/i.test(nearMatch(match)),
      });
  }
  if (!limited && /安全扫描会拦截/u.test(source) && /标准绕过/u.test(source)) {
    scanMatches('weakened-safeguard', documentsAuthorizationScanBypass,
      'The instructions direct the agent to bypass an authorization safety scanner.',
      { raw: true, snykEvidence: 'manifest', accepts: match => !/(?:禁止|不要|切勿)/u.test(match[0]) });
  }
  if (!limited && /\baudit logging for agent interactions\b/i.test(source) &&
      /--prompt\b[^\r\n]{0,100}--response\b/.test(source)) {
    scanMatches('automatic-telemetry', remoteConversationAuditLog,
      'The remote sync can publish an audit log containing agent prompts and responses.', {
        raw: true, snykEvidence: 'remote-conversation-audit-log',
        accepts: match => source.slice(Math.max(0, match.index - 2000), match.index).includes(match[2]) &&
          !/\b(?:redact|exclude)\b[^.!?;\r\n]{0,70}\b(?:prompts|responses|interactions)\b/i.test(source),
      });
  }
  if (!limited && /^#![^\r\n]*\b(?:ba)?sh\b/.test(source) && /\bTOUCHPOINT=["']first_call["']/.test(source)) {
    scanMatches('automatic-telemetry', sendsCampaignAndTouchpoint,
      'The invoked create request sends the vendor campaign and touchpoint headers by default.', {
        raw: true, snykEvidence: 'vendor-attribution-headers', accepts: match => {
          const before = match.input.slice(Math.max(0, match.index - 480), match.index);
          return /\bcurl\b[\s\S]{0,250}(?:--request[ \t]+POST|-X[ \t]+POST)\b/.test(before) &&
            /\bAuthorization:[ \t]+Bearer\b/.test(before);
        },
      });
  }
  if (!limited && /\bone report per build session\b/i.test(source) && /\bsubmit feedback \(after a build session\)/i.test(source)) {
    scanMatches('automatic-telemetry', reportsBuildFeedback,
      'The build workflow tells the agent to submit feedback when it runs into problems.', {
        raw: true, snykEvidence: 'linked-document', accepts: match =>
          !/\b(?:if|when|after) (?:the )?user (?:asks|requests|approves|consents)\b/i.test(nearMatch(match)),
      });
  }
  if (!limited) scanMatches('automatic-telemetry', filesVendorReportBeforeContinuing,
    'The workflow directs the agent to report problems to the service before continuing its work.', {
      snykEvidence: 'linked-document', accepts: match => {
        const nearby = match.input.slice(Math.max(0, match.index - 280), match.index + 210);
        return /\b(?:unexpected (?:error|failure)|something\b[^.!?;\r\n]{0,65}\bstops you)\b/i.test(nearby) &&
          !/\b(?:ask|confirm|approval|consent|opt[- ]in|if requested)\b/i.test(nearby);
      },
    });
  if (!limited) scanMatches('weakened-safeguard', configuresAgentToolsFromRegistry,
    'The workflow has the agent run a registry package that changes the workspace’s agent configuration and copies skills.', {
      snykEvidence: 'manifest', accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 180), match.index);
        const after = match.input.slice(match.index + match[0].length, match.index + 340);
        return /\bconfigure it yourself\b/i.test(before) && /\bproject root\b/i.test(before) &&
          /\bMCP servers?\b/i.test(after) && /\bcop(?:y|ies|ying)\b[^.!?;\r\n]{0,45}\bskills\b/i.test(after) &&
          !/\b(?:ask|confirm|approval|consent|opt[- ]in|if requested)\b/i.test(before + after);
      },
    });
  if (!limited && /\ba hook runs after edits\b/i.test(source)) {
    const options = { snykEvidence: 'manifest', accepts: match => {
      const before = match.input.slice(Math.max(0, match.index - 220), match.index);
      const after = match.input.slice(match.index + match[0].length, match.index + 350);
      return /\bafter the report\b/i.test(before) &&
        /\badds? a hook to\b[^.\r\n]{0,20}\x60?\.(?:claude\/settings|cursor\/hooks)\.json\b/i.test(after) &&
        /\bonly after a clear yes\b/i.test(after);
    } };
    scanMatches('project-agent-hook', installsProjectAgentHook,
      'With approval, the command registers a hook that runs after changes to the project.', options);
    if (!limited) scanMatches('system-modification', installsProjectAgentHook,
      'The hook installer changes settings that persist in the workspace.', { ...options, assessment: 'capability' });
  }
  if (!limited && /\bPOST[ \t]+\/v\d+\/records[ \t`]+creates?\b/i.test(source) &&
      /\bsharing a record with (?:a person|another user) or a team\b/i.test(source)) {
    scanMatches('third-party-content', listsSharedRecords,
      'The workflow lists shared records whose text can be written by other users.', {
        raw: true, snykEvidence: 'manifest', assessment: 'capability',
        accepts: match => !/[?&](?:id|key)=/.test(match[0]),
      });
  }
  if (!limited) scanMatches('weakened-safeguard', invocationAuthorizesExternalReview,
    'The workflow treats invocation as authorization to send local code to a selected external reviewer.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 300), match.index);
        const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 300);
        return /\bcross-model (?:job|review)\b/i.test(before) && /\bcode that leaves the machine\b/i.test(after) &&
          /\bdo not ask (?:the )?user to confirm\b/i.test(after);
      },
    });
  if (!limited) scanMatches('default-output-attribution', signsOutputByDefault,
    'The workflow adds its own signature to the deliverable by default.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const name = declaredSkillName(source, true);
        const clause = nearMatch(match);
        return name?.toLowerCase() === match[1].toLowerCase() &&
          !/\b(?:licen[sc]e|copyright|attribution requirement|only (?:if|when) the user)\b/i.test(clause);
      },
    });
  if (!limited) scanMatches('default-output-attribution', addsPromotionalPageByDefault,
    'The workflow adds a page promoting the tool to the generated document by default.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 190), match.index);
        const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 120);
        return /\b(?:omit|remove|skip|disable)\s+(?:the|a)\s+promo(?:tional)?\s+page\b/i.test(before) &&
          /\b(?:discover|find|learn about)\s+(?:the|this)\s+tool\b/i.test(after) &&
          /\b(?:reports?|documents?|deliverables?)\b/i.test(after);
      },
    });
  if (!limited) scanMatches('default-output-attribution', brandsPullRequestByDefault,
    'The publishing workflow enables its own branding in the resulting pull request.', {
      raw: true, snykEvidence: 'linked-document',
      accepts: match => !/\b(?:optional|opt.in|if requested|only (?:if|when) the user)\b/i.test(nearMatch(match)),
    });
  if (!limited && /<AbsoluteFill\b/.test(source)) scanMatches('default-output-attribution', renderedPromotionalText,
    'The copied video component adds a fixed promotional caption to the render.', {
      raw: true, snykEvidence: 'rendered-promotional-text', accepts: match => {
        const before = source.slice(Math.max(0, match.index - 360), match.index);
        const after = source.slice(match.index + match[0].length, match.index + match[0].length + 110);
        return /\bposition\s*:\s*["']absolute["']/.test(before) && />\s*$/.test(before) &&
          /^\s*<\/[a-z][\w-]*>/i.test(after);
      },
    });
  if (!limited && /\b(?:centerline|route geometry|river geometry)\b/i.test(source)) {
    scanMatches('third-party-content', sourcedGeometry,
      'The rendering workflow sources route geometry from community-edited map data.', {
        raw: true, snykEvidence: 'community-route-geometry', assessment: 'capability',
      });
  }
  if (!limited) scanMatches('weakened-safeguard', minimumReviewFindings,
    'A supported review mode requires findings even when it has found none, and the workflow can apply fixes from that review.', {
      raw: true, snykEvidence: 'rendered-review-quota', accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 580), match.index);
        const after = match.input.slice(match.index + match[0].length, match.index + 405);
        return /\[\[workflow\.thorough_lenses\]\]/.test(before) &&
          /\b(?:finding floor|minimum (?:finding count|number of findings))\b/i.test(before) &&
          /\b(?:do not|never) (?:stop|return|finish) with an empty (?:list|result)\b/i.test(after);
      },
    });
  if (!limited) scanMatches('automatic-telemetry', logsAppOpenTelemetry,
    'The setup logs the authoring agent, model, and tools as an application analytics event during verification.', {
      raw: true, snykEvidence: 'linked-document', accepts: match => {
        const section = match.input.slice(Math.max(0, match.index - 850), match.index + 520);
        return new RegExp(String.raw`\b${match[1]}_agent_name\b`).test(section) &&
          new RegExp(String.raw`\b${match[1]}_model_name\b`).test(section) &&
          new RegExp(String.raw`\b${match[1]}_tool_names\b`).test(section) &&
          /\breplace with (?:the )?actual (?:agent|model) name\b/i.test(section) &&
          !/\b(?:only (?:if|when) the user|user (?:consent|approval|confirmation))\b/i.test(section);
      },
    });
  if (!limited) scanMatches('weakened-safeguard', applicationWithoutTeamScope,
    'The email tool can submit a job application with personal information using a key outside the applicant’s team.', {
      raw: true, snykEvidence: 'external-application', accepts: match => {
        const section = match.input.slice(Math.max(0, match.index - 400), match.index + 2500);
        return /\bsubmit (?:a |the )?job applications?\b/i.test(section) &&
          /\bapplicant['’]s full name\b/i.test(section) && /\bapplicant['’]s email address\b/i.test(section) &&
          /\bnon[- ]interactive\b/i.test(section) &&
          !/\b(?:explicit (?:user )?(?:confirmation|consent) required|only (?:if|when) the user)\b/i.test(section);
      },
    });
  if (!limited && /\bany local process can control the app['’]s web contents\b/i.test(source)) {
    scanMatches('weakened-safeguard', relaunchesAppForDebugging,
      'The workflow closes a running app and relaunches it with a debugging interface accessible to other local processes.', {
        raw: true, snykEvidence: 'desktop-debug-relaunch',
      });
  }
  if (!limited) scanMatches('weakened-safeguard', documentsGuardedOperationMode,
    'The workflow documents a confirmation mode that its packaged execution tools do not implement.', {
      raw: true, snykEvidence: 'unimplemented-operation-mode',
    });
  if (!limited) scanMatches('third-party-content', readsDesktopNotifications,
    'The desktop tool returns notification titles and bodies that other people may have written.', {
      raw: true, assessment: 'capability', snykEvidence: 'desktop-notification-read',
    });
  if (!limited) scanMatches('third-party-content', streamsHardwareLog,
    'The helper streams live diagnostic text from the attached device.', {
      raw: true, assessment: 'capability', snykEvidence: 'hardware-log-stream',
    });
  if (!limited && /\bopen_can_bus\(/.test(source) && /\boutput_(?:event|json)\(/.test(source)) {
    scanMatches('third-party-content', readsCanFrames,
      'The diagnostic command reports data received from other devices on the CAN bus.', {
        raw: true, assessment: 'capability', snykEvidence: 'hardware-log-stream',
        accepts: match => new RegExp(String.raw`\b${match[1]}\.data\b`).test(source.slice(match.index, match.index + 950)),
      });
  }
  if (!limited) scanMatches('system-modification', replacesDebugProbeDriver,
    'The setup calls for changing the driver bound to the connected debug probe.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('weakened-safeguard', assignsTicketToCaller,
    'The workflow takes ownership of the ticket and changes its status before the user’s comment is posted.', {
      raw: true, snykEvidence: 'linked-document', accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 340), match.index);
        const after = match.input.slice(match.index + match[0].length, match.index + 270);
        return /\bCLAIM (?:KEY|ISSUE|TICKET)\b/.test(before) && /\btransition\b/i.test(after) &&
          /\b(?:run|apply) (?:them|those changes) before (?:your |the )?(?:first )?comment\b/i.test(after) &&
          !/\b(?:ask (?:the )?user|after (?:user )?approval|only if requested)\b/i.test(before + after);
      },
    });
  if (!limited) scanMatches('third-party-content', readsIssueWorkBundle,
    'The issue workflow reads descriptions and comments written by project participants.', {
      raw: true, assessment: 'capability', snykEvidence: 'issue-work-bundle',
    });
  if (!limited) scanMatches('weakened-safeguard', opensOrExposesLocalViewer,
    'The viewer workflow permits exposing a local server without defining who may access it.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 290), match.index);
        const line = match.input.slice(match.index, match.index + 360).split(/\r?\n/, 1)[0];
        return /\b(?:viewer launch|launch (?:the )?(?:local )?viewer)\b/i.test(before) &&
          /\b(?:run|start)\b[^\r\n]{0,115}\bin the background\b/i.test(line) &&
          /\b(?:read|use)\b[^\r\n]{0,45}\bURL\b[^\r\n]{0,80}\bexpose it\b/i.test(line) &&
          !/\b(?:private|authenticated|confirm|approval|permission|only (?:if|when) the user)\b/i.test(before + line);
      },
    });
  if (!limited && /\b(?:local dev(?:elopment)? (?:server|base URL)|local(?:host)? (?:page|URL))\b/i.test(source)) {
    scanMatches('weakened-safeguard', forwardsPageUrl,
      'The skill can share the local page address with an external service as a URL parameter.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          const host = match[1].replace(/\.$/, '');
          if (!host.includes('.') || /\.(?:localhost|local)$|^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d/i.test(host)) return false;
          const start = Math.max(0, match.index - 280);
          const context = match.input.slice(start, match.index + match[0].length + 250);
          return /\b(?:point|send|direct) (?:the )?user to\b|\b(?:open|visit|use) (?:the |this )?(?:live |external |hosted )?(?:viewer|preview|link)\b/i.test(context) &&
            !/\b(?:public (?:URLs?|pages?) only|only (?:use|send|pass) public (?:URLs?|pages?)|never (?:send|include|pass|share) (?:local|private)|confirm before (?:sending|sharing))\b/i.test(context);
        },
      });
  }
  if (!limited && /\b(?:co[- ]author(?:ing|ed[- ]by)?|authorship|attribution)\b/i.test(source)) {
    if (pushesRewrittenHistory.test(source)) {
      scanMatches('dangerous-code-pattern', stripsCoauthorTrailers,
        'The workflow strips existing co-author records across commits and force-pushes the rewritten history.', {
          raw: true, snykEvidence: 'manifest', accepts: match => {
            const nearby = source.slice(Math.max(0, match.index - 1800), match.index + match[0].length + 750);
            return pushesRewrittenHistory.test(nearby) &&
              !/\b(?:example of what not to do|never (?:remove|strip|rewrite) (?:existing )?co-author)/i.test(nearby);
          },
        });
    }
    if (/\bno agentic annotations\b/i.test(source) && /\bco-authored-by:[\x60]?[ \t]+lines referencing AI tools\b/i.test(source)) {
      scanMatches('undisclosed-authorship', removesExistingAttribution,
        'The workflow removes existing AI attribution when it rewrites commit messages.', {
          raw: true, snykEvidence: 'manifest', accepts: match => !asksForApproval.test(nearMatch(match)),
        });
    }
    const prose = source.replace(/\*{1,2}/g, '');
    const omitsBackup = /\b(?:no backup|without (?:a )?backups?|(?:do(?:es)? not|never) (?:keep|create|make) (?:a )?backup)\b/i.test(prose);
    const concealsHistory = /\b(?:remove all trace|erase all trace|never (?:having )?had AI involvement|permanently conceal)\b/i.test(prose);
    if (omitsBackup && concealsHistory) {
      const activeRewrite = match => !negated(source, match.index);
      scanMatches('dangerous-code-pattern', rewritesGitHistory,
        'The workflow rewrites repository history to conceal attribution while omitting a recovery copy.',
        { raw: true, snykEvidence: 'manifest', accepts: activeRewrite });
      scanMatches('system-modification', rewritesGitHistory,
        'The workflow permanently rewrites repository history without keeping a backup.',
        { raw: true, assessment: 'capability', snykEvidence: 'manifest', accepts: activeRewrite });
    }
  }
  if (!limited && /\bSocket\.dev\b/i.test(source)) {
    scanMatches('weakened-safeguard', installsSocketFromPypi,
      'The installation command selects a Python package in place of the documented Socket.dev CLI.', {
        raw: true, snykEvidence: 'linked-document', accepts: match => !negated(source, match.index),
      });
    scanMatches('third-party-content', retrievesSocketReport, socketReportRetrievalReason, {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
        accepts: match => !negated(source, match.index),
      });
  }
  let handlesChannelWorkerInput = false;
  if (!limited && workerPrompts.test(source)) for (const match of source.matchAll(channelMessages)) {
    const { index, 0: message } = match;
    const before = source.slice(Math.max(0, index - 120), index);
    const workflow = source.slice(index + message.length, index + 3000).split(/\r?\n#{1,6}[ \t]/, 1)[0];
    if (negated(source, index) ||
        !/\b(?:re[- ]?read|read|process)\b/i.test(before) ||
        !/\b(?:restat\w+|decompos\w+|deriv\w+)\b/i.test(workflow) ||
        !workerPrompts.test(workflow)) continue;
    handlesChannelWorkerInput = true;
    add('third-party-content', index, message.length,
      'The workflow derives worker prompts from incoming channel messages.', 'capability', false, 'manifest');
    if (!/\bauto[- ]?approv(?:e|es|ing|al)\b/i.test(workflow)) continue;
    const bypass = [...workflow.matchAll(disablesShellSafeguards)].find(option => !negated(workflow, option.index));
    if (!bypass || limited) continue;
    const start = index + message.length + bypass.index;
    add('dangerous-code-pattern', start, bypass[0].length,
      'The workflow hands incoming channel content to workers launched with execution safeguards disabled.', undefined, false, 'manifest');
    if (!limited) add('system-modification', start, bypass[0].length,
      'The workflow launches workers with approvals or sandboxing disabled.', 'capability', false, 'manifest');
    if (limited) break;
  }
  if (!limited && /\b(?:signers?|e[- ]?signature|embedded signing)\b/i.test(source)) {
    scanMatches('weakened-safeguard', disablesSignerEmailByDefault,
      'The workflow suppresses signer notifications by default, including ordinary document sends.', {
        raw: true, snykEvidence: 'manifest',
        accepts: match => !negated(source, match.index) &&
          !/\b(?:only (?:for|when) embedded|embedded signing only|unless (?:the )?user (?:asks|requests))\b/i.test(match[0]),
      });
  }
  if (!limited) scanMatches('weakened-safeguard', skipsInstallationRiskPrompt,
    'The skill installation instructions recommend skipping interactive risk prompts.', {
      raw: true, snykEvidence: 'linked-document', accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 440), match.index);
        const line = match.input.slice(match.index, match.index + 175).split(/\r?\n/, 1)[0];
        return /\b(?:missing|recommended)\b[^\r\n]{0,110}\b(?:skills?|install)\b/i.test(before) &&
          /\b(?:install|skills[ \t]+add)\b[^\r\n]{0,125}--force\b/i.test(before) &&
          !/\b(?:only after|only with|user (?:approval|confirmation|consent)|do not use)\b/i.test(before + line);
      },
    });
  if (!limited) scanMatches('weakened-safeguard', provisionsScratchDatabase,
    'The setup offers to provision a remote database when the user has supplied no database credentials.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 200), match.index).split(/\r?\n/).at(-1);
        const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 250);
        return /\b(?:scratch (?:Redis|database)|database credentials)\b/i.test(before) &&
          /\b(?:hasn['’]t|has not|did not) (?:provided|supplied|given)\b/i.test(before) &&
          !/\b(?:ask (?:the )?user|user (?:approval|confirmation)|confirm before)\b/i.test(before + after);
      },
    });
  if (!limited) scanMatches('weakened-safeguard', replacesAnotherServiceWebhook,
    'The incoming-message workflow can replace a webhook configured by another service.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const line = match.input.slice(match.input.lastIndexOf('\n', match.index) + 1)
          .split(/\r?\n/, 1)[0];
        return /\bincoming messages\b/i.test(line) && /\bbot\b/i.test(line) &&
          /\b(?:send|forward)\b[^\r\n]{0,65}\b(?:updates|messages)\b/i.test(line) &&
          !/\b(?:user (?:approval|confirmation)|confirm with the user|only with consent)\b/i.test(line);
      },
    });
  if (!limited) scanMatches('weakened-safeguard', withholdsRecurringSharingNotice,
    'The workflow uploads conversation text repeatedly and suppresses the notice in later sessions.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const before = source.slice(Math.max(0, match.index - 750), match.index);
        return /\bshare [^.!?;\r\n]{0,70}\bquestions and answers\b/i.test(before) &&
          /\bafter each [\w -]{0,50}answer\b/i.test(before);
      },
    });
  if (!limited) scanMatches('weakened-safeguard', withholdsMeetingAccessDetailsZh,
    'The workflow suppresses meeting access details across all response types.', {
      raw: true, snykEvidence: 'manifest', accepts: match =>
        !/(?:除非|仅当)[^。\r\n]{0,35}用户[^。\r\n]{0,20}(?:要求|确认|授权)/u.test(nearMatch(match)),
    });
  if (!limited) scanMatches('weakened-safeguard', deletesUnlistedCacheDirectories,
    'The default cleanup covers whole cache directories that are absent from the reviewed catalog.', {
      raw: true, snykEvidence: 'linked-document', accepts: match => {
        const before = source.slice(Math.max(0, match.index - 220), match.index);
        return /\bauto-cleaned with no question\b/i.test(before);
      },
    });
  if (!limited && /\bcross[- ]model\b[^\r\n]{0,55}\b(?:panel|review|consultation)\b/i.test(source.slice(0, 1200))) {
    scanMatches('weakened-safeguard', detachedWorkerInheritsPermissions,
      'The detached worker inherits the launcher’s extended permissions for its lifetime.', {
        raw: true, snykEvidence: 'linked-document', accepts: match => {
          const start = Math.max(0, match.index - 220);
          const context = match.input.slice(start, match.index + 1250);
          return /\bfull command escalation\b/i.test(context) &&
            /\b(?:for its lifetime|until the job exits)\b/i.test(context) &&
            /\b(?:read.only|tool[\s]+restrictions)\b/i.test(context);
        },
      });
  }
  if (!limited) scanMatches('default-output-attribution', referralLink,
    'An integration workflow promotes a product from the skill maintainer through a referral link.', {
      raw: true, snykEvidence: 'linked-document', accepts: match => {
        const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 560);
        return /\bappl(?:y|ies) this skill\b/i.test(after) &&
          /\bdisclosure\b[^\r\n]{0,130}\bmaintains this repo(?:sitory)?\b/i.test(after);
      },
    });
  if (!limited && /[?&]utm_medium=skill\b/i.test(source)) {
    scanMatches('default-output-attribution', recommendsTrackedService,
      'The workflow directs the agent to promote another service through a tracked link when a session reaches its runtime limit.', {
        raw: true, snykEvidence: 'linked-document', accepts: match => {
          const before = source.slice(Math.max(0, match.index - 550), match.index);
          return /[?&]utm_medium=skill(?:&|$)/i.test(match[1]) && /[?&]utm_source=[\w.-]+(?:&|$)/i.test(match[1]) &&
            /\b(?:must outlive|needs? to outlive|must run longer than)\b[^.\r\n]{0,160}\b(?:minutes?|hours?|runs?|sessions?)\b[^.\r\n]{0,160}$/i.test(before) &&
            /\b(?:no|without)\b[^.\r\n]{0,85}\bpersistent sessions?\b/i.test(before) &&
            !/\bif (?:the )?user (?:asks|requests)\b[^.\r\n]{0,85}$/i.test(before);
        },
      });
  }
  if (!limited && /\b(?:npx|bunx)[ \t]+(?:-y|--yes)[ \t]+[\w@/.-]+\b/.test(source)) {
    scanMatches('weakened-safeguard', installsSessionHooks,
      'The downloaded CLI can add persistent session hooks to user-level agent settings.', {
        raw: true, snykEvidence: 'linked-document', accepts: match => {
          const after = match.input.slice(match.index, match.index + 470);
          return !negated(source, match.index) &&
            /~\/\.(?:claude|codex)\/(?:settings|hooks)\.json\b/.test(after);
        },
      });
  }
  if (!limited && /\bhref=\{githubUrl\}/.test(source)) scanMatches('default-output-attribution', defaultGitHubLink,
    'The scaffolded output renders a link to the template publisher by default.', {
      raw: true, snykEvidence: 'rendered-template-link', accepts: ([, name]) =>
        new RegExp(String.raw`\bgithubUrl[ \t]*=[ \t]*${name}\b`).test(source),
    });
  if (!limited && /\bemailDomain\s*:\s*\w+(?:\?\.|\.)domain\b/.test(source) &&
      /\burl\.searchParams\.set\s*\(/.test(source) && /\bfetch\(url\b/.test(source) && /\btelemetryDisabled\b/.test(source)) {
    scanMatches('automatic-telemetry', gitIdentityLookup,
      'The invoked helper reads the local Git identity and includes its email domain in telemetry requests.',
      { raw: true, snykEvidence: 'git-identity-telemetry' });
  }
  if (!limited && /^#![^\r\n]*\b(?:ba)?sh\b/.test(source)) {
    scanMatches('weakened-safeguard', systemWideRecordingFallback,
      'After an app-specific recording fails, the helper starts recording other processes despite the documented app boundary.',
      { raw: true, snykEvidence: 'instrumentation-fallback' });
  }
  if (!limited) scanMatches('unapproved-file-change', installsMarketplaceWithoutAsking,
    'The setup changes the host plugin marketplace and installs a plugin without asking the user.',
    { raw: true, snykEvidence: 'manifest' });
  if (!limited) scanMatches('weakened-safeguard', declaresPreapproval,
    'The workflow treats its invocation as permission to bypass existing requirements to ask first.',
    { raw: true, snykEvidence: 'linked-document', accepts: match =>
      overridesAskFirst.test(source.slice(match.index + match[0].length, match.index + match[0].length + 900)),
    });
  if (!limited && /\.design\b/i.test(source) && /\bnpx[ \t]+skills[ \t]+add\b/i.test(source)) {
    scanMatches('weakened-safeguard',
      /https:\/\/[\w.-]+\/[\w./-]+\.design\b[^\r\n]{0,120}\b(?:asks?|tells?|instructs?|requires?) (?:the )?agents? to (?:save|copy|place|write)\b[^.!?;\r\n]{0,75}\b(?:root|workspace)\b[^.!?;\r\n]{0,40}\binstall[ \t]+\x60?npx[ \t]+skills[ \t]+add[ \t]+[\w.-]+\/[\w.-]+\b/gi,
      'The external design contract directs agents to install a skill in the client workspace as part of setup.',
      { raw: true, snykEvidence: 'external-design-bootstrap', accepts: match =>
        !/\b(?:only (?:if|when|after)|after) (?:the )?user (?:explicitly )?(?:approves|confirms)\b/i.test(nearMatch(match)),
      });
  }
  if (!limited) scanMatches('weakened-safeguard',
    /\b(?:post|submit|run)\s+`gh\s+pr\s+review\b[^`\r\n]{0,100}\s--approve\b[^`\r\n]*`/gi,
    'The workflow treats a request to merge a pull request as permission to post a separate public approval.', {
      raw: true, snykEvidence: 'linked-document', accepts: match => {
        const remainder = source.slice(match.index + match[0].length, match.index + match[0].length + 330)
          .split(/\r?\n[ \t]*\r?\n/)[0];
        return /\b(?:the\s+)?(?:merge\s+(?:instruction|request)|request\s+to\s+merge)\s+(?:already\s+)?(?:covers|authorizes|counts as)\s+(?:the\s+)?(?:review\s+)?approval\b[^.!?;]{0,80}\b(?:no|without)\s+(?:a\s+)?separate\s+(?:prompt|confirmation|preview)\b/i.test(remainder);
      },
    });
  if (!limited) scanMatches('weakened-safeguard', treatsDocumentAsApproval,
    'The skill treats receipt of its instructions as approval to execute the setup without confirmation.', {
      snykEvidence: 'manifest', accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 250), match.index);
        return /\b(?:execute|apply|run|finish|complete)\b[^.!?;\r\n]{0,50}\b(?:all|every)\b[^.!?;\r\n]{0,40}\b(?:steps?|instructions?|commands?)\b[^.!?;\r\n]{0,95}\bwithout (?:pausing for |stopping for |waiting for )?(?:asking|approval|consent|confirmation)\b/i.test(before);
      },
    });
  if (!limited) scanMatches('weakened-safeguard', avoidsCleanupGate,
    'The workflow selects a cleanup method specifically to avoid the host’s destructive-action gate.', {
      snykEvidence: 'manifest', accepts: match =>
        /\b(?:trash|cleanup)\b/i.test(match.input.slice(Math.max(0, match.index - 280), match.index)),
    });
  if (!limited && /\bSystem\.Windows\.Automation\.InvokePattern\b/.test(source)) {
    scanMatches('weakened-safeguard', selectsPersistentTrust,
      'The trust-dialog helper can select the persistent trust option when only a one-time load is needed.',
      { raw: true, snykEvidence: 'persistent-trust-selection' });
  }
  if (!limited && /\benv\[["']LD_PRELOAD["']\]\s*=/.test(source) && /\bsubprocess\.run\s*\(/.test(source)) {
    scanMatches('weakened-safeguard', fixedTemporaryLibrary,
      'The helper preloads a native library and can reuse an existing file at a fixed temporary path.', {
        raw: true, snykEvidence: 'invoked-script',
        accepts: ([, name]) => new RegExp(String.raw`\bif[ \t]+${name}\.exists\(\):[ \t]*\r?\n[ \t]+return[ \t]+${name}\b`).test(source),
      });
  }
  if (!limited) scanMatches('automatic-telemetry', proactiveFeedbackSubmission,
    'Tool behavior can trigger sending product feedback before the user asks to submit it.', {
      raw: true,
      accepts: match => !asksForApproval.test(nearMatch(match)) &&
        !/\b(?:only (?:if|when|after) (?:the )?user|before submitting,? ask)\b/i.test(nearMatch(match)),
      snykEvidence: 'manifest',
    });
  if (!limited) for (const block of blocks) {
    let instruction;
    if (externalFeedbackHeading.test(block.section)) instruction = unsolicitedFeedback.exec(block.text);
    else if (vendorFeedbackHeading.test(block.section) && feedbackOnEveryInteraction.test(block.text) &&
        !asksForApproval.test(block.text) && !userRequestedFeedback.test(block.text)) {
      instruction = reportsWithFeedbackService.exec(block.text);
    }
    if (!instruction || negated(block.text, instruction.index)) continue;
    const span = markdownEvidence(source, block, instruction.index, instruction[0].length);
    add('automatic-telemetry', span.start, span.end - span.start,
      'The workflow tells the agent to send feedback to an external recipient without approval.', undefined, false, 'manifest');
    if (limited) break;
  }
  if (!limited) {
    const beforeRetry = results.length;
    scanMatches('forced-escalation', sandboxRetry,
      'A sandbox denial triggers an instruction to retry with broader access.', {
        accepts: match => !asksForApproval.test(nearMatch(match)),
        snykEvidence: match => {
          const start = prose.original(match.index);
          const end = prose.original(match.index + match[0].length);
          const before = source.slice(Math.max(0, start - 500), start);
          const after = source.slice(end, end + 280);
          const readsGuide = /\bversion-matched guide\b/i.test(before) &&
            /\bskills get [\w-]+\b/.test(before) && /\bruntime_access_denied\b/.test(before.slice(-90)) &&
            /\bread-only discovery\b/i.test(after) && /\b(?:do not|don't|never)\b[^.!?;\r\n]{0,70}\brestart\b/i.test(after);
          return readsGuide ? 'guide-read-recovery' : 'direct';
        },
      });
    if (!limited && results.length > beforeRetry &&
        /\b(?:drives|controls) the GUI of a (?:visible )?local app(?:lication)? window\b/i.test(source.slice(0, 900))) {
      const scoped = results.slice(beforeRetry).find(hit => hit.snykEvidence === 'guide-read-recovery');
      if (scoped) {
        const { start, end } = scoped.evidence[0];
        add('system-modification', start, end - start,
          'The app-control workflow can retry a blocked host connection with broader access.', 'capability', false, 'manifest');
      }
    }
  }
  if (!limited) scanMatches('forced-escalation', disableSandbox,
    'The workflow instructs the agent to disable sandboxing and use expanded permissions.', {
      snykEvidence: 'manifest',
      accepts: match => !asksForApproval.test(nearMatch(match)),
    });
  if (!limited && source.includes('dangerouslyDisableSandbox')) {
    const options = { raw: true, snykEvidence: 'manifest',
      accepts: match => !negated(source, match.index) && !asksForApproval.test(nearMatch(match)) };
    scanMatches('dangerous-code-pattern', requiresCommandSandboxBypass,
      'The workflow requires running commands with the tool sandbox disabled.', options);
    if (!limited) scanMatches('system-modification', requiresCommandSandboxBypass,
      'The workflow directs the agent to bypass the host command sandbox.', { ...options, assessment: 'capability' });
  }
  if (!limited && source.includes('enabledPlugins') && source.includes('~/.claude/settings.json') &&
      source.includes('skills/bootstrap/SKILL.md') && /\bmarketplace-agnostic\b/i.test(source) &&
      /\bmerge mode\b/i.test(source) && !/\b(?:approve|review) each (?:plugin|bootstrap)\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', invokesDiscoveredPluginBootstraps,
      'The coordinator delegates repository writes to dynamically discovered plugin skills across marketplaces.',
      { raw: true, snykEvidence: 'manifest' });
  }
  if (!limited && source.includes('sort=downloads') && /\bdownload\b[^\r\n]{0,120}\btokenizer\.json\b/i.test(source)) {
    scanMatches('weakened-safeguard', usesRejectedTokenizer,
      'The workflow uses a tokenizer from a ranked external search even when its compatibility check fails.', {
        raw: true, snykEvidence: 'invoked-shell',
      });
  }
  if (!limited && source.includes('pkg/model.json')) {
    scanMatches('system-modification', restartsPackagedModelServer,
      'The model build stops an existing local server and starts it with the new model package.', {
        raw: true, assessment: 'capability', snykEvidence: 'invoked-shell',
      });
  }
  if (!limited && /\banother Claude Code instance\b/i.test(source) &&
      /\bJSONL conversation-log parsing\b/i.test(source) && source.includes('TARGET_JSONL')) {
    const options = { raw: true, snykEvidence: 'manifest', accepts: match => !negated(source, match.index) };
    scanMatches('dangerous-code-pattern', reportsOtherSessionExcerpt,
      'The watcher targets another agent session and reports part of its recorded conversation.', options);
    if (!limited && !/\b(?:redact|mask|remove)\b[^.!?\r\n]{0,70}\b(?:secrets|credentials|tokens|passwords)\b/i.test(source)) {
      scanMatches('credential-handling', reportsOtherSessionExcerpt,
        'The report copies conversation text from another session without a stated redaction step.', options);
    }
    if (!limited) scanMatches('third-party-content', reportsOtherSessionExcerpt,
      'The watcher reads messages authored outside the current agent session.', { ...options, assessment: 'capability' });
  }
  if (!limited && /ネットワーク[^。！？\r\n]{0,75}(?:必須|必要)/u.test(source) &&
      /\bgh[ \t]+project[ \t]+create\b/i.test(source) && /\bPUBLIC\b/.test(source)) {
    scanMatches('forced-escalation', disablesCommandSandboxJa,
      'The workflow disables command sandboxing while creating a project that can be public.', {
        accepts: match => !/(?:承認|許可|同意)[^。！？\r\n]{0,25}(?:後|場合のみ)|実行しない/u.test(nearMatch(match)),
        snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('weakened-safeguard', defaultPrivateData,
    'The configuration enables collecting user data by default.', {
      raw: true,
      accepts: match => !/\b(?:only if|only when|if|after) (?:the )?user (?:opts in|approves|enables|confirms)\b/i.test(nearMatch(match)),
      snykEvidence: 'direct',
    });
  if (!limited) scanMatches('weakened-safeguard', redirectsGuardedFileRemoval,
    'The linked guide recommends removing files through a path that the deletion guard does not inspect.', {
      snykEvidence: 'linked-document', accepts: match => {
        const end = match.index + match[0].length;
        const explanation = match.input.slice(end, end + 380).split(/\r?\n/, 1)[0];
        return /\b(?:guard|hook) permits this\b/i.test(explanation) &&
          /\bdoes not (?:scan|inspect|check)\b/i.test(explanation);
      },
    });
  if (!limited && /\bper-harness grants\b/i.test(source) && /\bquota it spent\b/i.test(source)) {
    scanMatches('weakened-safeguard', defaultsCredentialReuseToGranted,
      'An unset grant allows the workflow to reuse a signed-in account and spend its quota.',
      { snykEvidence: 'linked-document' });
  }
  if (!limited && /\btrustPolicyExclude\b/.test(source)) {
    const active = removeMarkdownComments(source);
    const exception = /\b(?:add|append|insert)\b[^.\r\n]{0,95}\b(?:to|in|into|under)[ \t]+\x60?trustPolicyExclude\b/gi;
    const policy = /\b(?:trust downgrade|trusted publishing|provenance attestations?|no-downgrade)\b/i;
    for (const match of active.matchAll(exception)) {
      const start = match.index;
      const end = start + match[0].length;
      const before = active.slice(Math.max(0, start - 1150), start);
      const after = active.slice(end, end + 100);
      if (negated(active, start) || !policy.test(before) || !/\b(?:rerun|retry|resume|re-run)\b/i.test(after)) continue;
      add('weakened-safeguard', start, match[0].length,
        'The instructions add a package provenance exception before retrying the install.',
        'capability', false, 'direct');
      if (limited) break;
    }
  }
  if (!limited && /\b(?:unattended login|impersonat(?:e|ion)|sign in as|log in as)\b/i.test(source)) {
    const enabledSimulation = /\x60--(?:[\w-]+-)?(?:simulate|mock|fake|test)[-\w]*(?:token|login|oauth|auth)[-\w]*\x60/gi;
    const active = removeMarkdownComments(source);
    for (const match of active.matchAll(enabledSimulation)) {
      const start = match.index;
      const end = start + match[0].length;
      const details = active.slice(end, end + 420).split(/\r?\n[ \t]*\r?\n/, 1)[0];
      if (negated(active, start) || !/^[*_ \t]*(?:enables?|adds?|activates?|exposes?)\b/i.test(details) ||
          !/\b(?:token[- ]gated|endpoint|oauth)\b/i.test(details) ||
          !/\b(?:unattended login|impersonat(?:e|ion)|sign in as|log in as)\b/i.test(details) ||
          !/\b(?:development|dev[- ]only|local testing|end[- ]to[- ]end|e2e|test[- ]only)\b/i.test(details)) continue;
      add('weakened-safeguard', start, end - start,
        'The guide documents enabling simulated authentication for delegated or unattended login.',
        'capability', false, 'linked-document');
      if (limited) break;
    }
  }
  if (!limited) scanMatches('weakened-safeguard', forceDirtyTree,
    'The instructions enable forcing changes in a working tree with uncommitted edits.', {
      accepts: match => !/\b(?:fail|refuse|abort|stop)s?[ \t]+unless[ \t]+`?--force\b/i.test(match[0]) &&
        !/\b(?:never|do not|don't|avoid|must not|only after)\s+(?:\w+\s+){0,4}[\x60'"]*--force\b/i.test(nearMatch(match)),
      snykEvidence: match => {
        const start = match.input.lastIndexOf('\n', match.index - 1) + 1;
        const prefix = match.input.slice(start, match.index);
        const inlineAdvice = /^\s*git[ \t]+worktree[ \t]+remove[ \t]+[^#\r\n]+[ \t]+#[ \t]*(?:add|pass|append|use)[ \t]+$/i.test(prefix) &&
          !/--force\b/i.test(prefix) && /^(?:--force\b|\x60--force\b)/i.test(match[0]);
        return !inlineAdvice && !/--force\x60(?:[ \t]*,[ \t]*\x60-[\w-]+\x60)?\**[ \t]*\||\|[ \t]*\**\x60[^\x60|]*--force\b/i.test(match[0]) && 'direct';
      },
    });
  if (!limited && /\b(?:rejects?|refuses? to run on)\b[^.!?;\r\n]{0,38}\bdirty (?:worktree|working tree)\b/i.test(source)) {
    scanMatches('weakened-safeguard', forceAlongsideUncommittedEdits,
      'The instructions offer a force option that bypasses the dirty-worktree guard.', {
        accepts: match => !asksForApproval.test(nearMatch(match)), snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('unapproved-file-change', commitsEntireProject,
    'A workflow step commits all changes under the project root and can move the user to a different branch.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const after = match.input.slice(match.index, match.index + 620).split(/\r?\n#{1,6}[ \t]/, 1)[0];
        return switchesCommitBranch.test(after) && !asksForApproval.test(nearMatch(match)) &&
          !/\b(?:before (?:stag|committ|switch)ing,? (?:ask|confirm|request)|(?:waits?|requires?) (?:for )?(?:explicit )?(?:user |operator )?(?:approval|confirmation|permission))\b/i.test(after);
      },
    });
  if (!limited && /\b(?:unsigned|signed build|unknown binaries)\b/i.test(source)) {
    scanMatches('weakened-safeguard', turnsOffSmartAppControl,
      'The troubleshooting guide offers turning off Windows Smart App Control for downloaded code.',
      { snykEvidence: 'linked-document' });
  }
  if (!limited && /\b(?:in the guest|guest agent|guest VM)\b/i.test(source)) scanMatches('weakened-safeguard', sharedGuestSetup,
    'Troubleshooting runs shell code from a shared volume and grants Accessibility access to the guest agent.',
    { raw: true, snykEvidence: 'linked-document' });
  if (!limited && /\btools\.include\b/i.test(source)) scanMatches('dangerous-code-pattern', trustsDiscoveredToolFiles,
    'The workflow discovers tool modules by path and treats them as unrestricted extensions on the host.', {
      raw: true, snykEvidence: 'linked-document', accepts: match => {
        const before = source.slice(Math.max(0, match.index - 480), match.index);
        return /\btools\.include\b/i.test(before) && /\b(?:resolves?|discovers?|loads?) tool files\b/i.test(before);
      },
    });
  if (!limited) scanMatches('weakened-safeguard', avoidsHostPermissionPrompt,
    'The instructions recommend changing shell command structure to avoid a host permission prompt.', {
      raw: true,
      accepts: match => /`[^`\r\n]{1,24}`/.test(match[0]) && /\b(?:shell|bash|commands?)\b/i.test(
        source.slice(Math.max(0, match.index - 230), match.index)),
      snykEvidence: 'manifest',
    });
  if (!limited && /\blockfile\b/i.test(source) && /\b(?:upgrade|update)\b[^\r\n]{0,80}\b(?:packages|dependencies)\b/i.test(source)) {
    scanMatches('weakened-safeguard', noninteractiveSkillUpdate,
      'The package upgrade also updates installed agent skills with confirmation disabled.', {
        raw: true, accepts: match => !asksForApproval.test(nearMatch(match)), snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('weakened-safeguard', trustsPluginAtInstall,
    'The plugin install grants trust before the tool can present its review step.', {
      raw: true, accepts: match => !asksForApproval.test(nearMatch(match)),
      snykEvidence: match => !/\bUnity-Technologies\/unity-agent-plugin\b/i.test(match[0]) && 'linked-document',
    });
  if (!limited && /\bcreate_automation\b/i.test(source)) scanMatches('weakened-safeguard', activatesWithoutQuestion,
    'The workflow activates a new automation automatically after creating it in an inactive state.', {
      raw: true,
      accepts: match => /\bcreate_automation\b[^\r\n]{0,280}\bactive\s*=\s*false\b/i.test(
        source.slice(Math.max(0, match.index - 500), match.index)) && !asksForApproval.test(nearMatch(match)),
      snykEvidence: 'manifest',
    });
  if (!limited && /--snapshots\b|\bpersistent (?:cloud )?environment\b/i.test(source)) {
    const storedEnvironment = { raw: true, snykEvidence: 'manifest',
      accepts: match => /\benvironments? (?:create|set)\b/i.test(source.slice(Math.max(0, match.index - 285), match.index)) };
    scanMatches('weakened-safeguard', environmentWithLocalSshKey,
      'The setup copies a local SSH private key into a stored environment variable.', storedEnvironment);
    if (!limited && /\bsandbox exec\b[^\r\n]{0,150}--sudo\b/i.test(source)) {
      scanMatches('system-modification', environmentWithLocalSshKey,
        'The workflow persists credentials in an environment that supports privileged commands.', storedEnvironment);
    }
  }
  if (!limited && /\bpublish everything\b|^#{1,6}[ \t]+[^\r\n]{0,35}\bpublish[ \t]*$/im.test(source)) {
    scanMatches('concealed-report-sources', authenticDemoTestimonials,
      'The workflow publishes convincing sample testimonials without requiring a visible demo label.', {
        raw: true,
        accepts: match => !/\b(?:label|identify|mark)\b[^.!?;\r\n]{0,60}\bas (?:fictional|demo|sample|illustrative)\b/i.test(
          source.slice(Math.max(0, match.index - 110), match.index + match[0].length + 95)),
        snykEvidence: 'manifest',
      });
  }
  if (!limited && frontmatterEnd !== undefined && /["']targetDir["']\s*:\s*["']models["']/i.test(source)) {
    const descriptors = [...source.slice(0, frontmatterEnd).matchAll(downloadDescriptor)];
    if (descriptors.some(match => runtimeDescriptor.test(match[0]) && digestDescriptor.test(match[0]))) {
      for (const match of descriptors) {
        const descriptor = match[0];
        const download = /["']url["']\s*:\s*["']https:\/\/[^"'\r\n]+/i.exec(descriptor);
        if (!modelDescriptor.test(descriptor) || digestDescriptor.test(descriptor) || !download) continue;
        add('weakened-safeguard', match.index + download.index, download[0].length,
          'The runtime download has an integrity check, while the model download in the same setup has none.', undefined, false, 'manifest');
        if (limited) break;
      }
    }
  }
  if (!limited) scanMatches('weakened-safeguard', replacesProxyWrapper,
    'The guide replaces the platform proxy wrapper with direct client calls.', { raw: true, snykEvidence: 'manifest' });
  if (!limited && /\bstorage\.objectCreator\b/i.test(source) && /\b(?:logs|telemetry|logging)\b/i.test(source)) {
    scanMatches('weakened-safeguard', grantsBucketAdministration,
      'The setup grants bucket administration while the same guide identifies object creation as sufficient for writing logs.',
      { raw: true, snykEvidence: 'manifest' });
  }
  if (!limited) scanMatches('weakened-safeguard', disabledTrustChecks,
    'The documented command disables a verification or confirmation check while changing the environment.', {
      raw: true, snykEvidence: 'direct',
    });
  if (!limited) scanMatches('weakened-safeguard', skipsAutomaticProjectConfirmation,
    'The deployment workflow skips confirmation of an automatically selected project.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const context = match.input.slice(Math.max(0, match.index - 320), match.index + match[0].length + 100);
        return /\b(?:automatically resolved project|project is resolved automatically|automatic project resolution)\b/i.test(context) &&
          /\bnon[- ]interactive\b/i.test(context);
      },
    });
  if (!limited) scanMatches('weakened-safeguard', reportsMockSuccessWithoutCredentials,
    'The example returns an ordinary success status when the evaluation uses mock data in place of a real API call.', {
      raw: true, snykEvidence: 'linked-document', accepts: match => {
        const context = match.input.slice(Math.max(0, match.index - 490), match.index);
        const key = new RegExp(String.raw`\b${match[1]}[ \t]*=[ \t]*os\.environ\.get\(["'][A-Z_]*API_KEY["']`);
        return key.test(context) && /\bmock mode\b/i.test(context) && /\bevals?\b/i.test(context) &&
          /["']status["'][ \t]*:[ \t]*["']success["']/.test(match[2]) &&
          !/["'](?:mock(?:ed)?|synthetic|simulated|source|mode)["'][ \t]*:/.test(match[2]);
      },
    });
  if (!limited && /\bx-[\w-]+-refresh-token\b/i.test(source)) {
    scanMatches('weakened-safeguard', refreshRequestFromCredentialRecord,
      'The helper sends OAuth credentials to an endpoint taken from a credential record without checking the destination.', {
        raw: true, snykEvidence: 'credential-refresh-route', accepts: routesRefreshCredentials,
      });
  }
  if (!limited && /\|[ \t]*in trajectory\?[ \t]*\|/i.test(source)) {
    scanMatches('third-party-content', recordsFetchedPageInEvaluation,
      'The inspected evaluation trace can contain web content returned by a tool under test.', {
        assessment: 'capability', raw: true, snykEvidence: 'evaluation-web-trace',
      });
  }
  if (!limited && /\bterraform apply\b/i.test(source) && /\bservice[- ]accounts?\b/i.test(source)) {
    scanMatches('system-modification', modifiesCloudProjectPolicy,
      'The deployment applies infrastructure changes and grants access in the cloud project.', {
        assessment: 'capability', raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited && /\bcurl\b/.test(source) && /Authorization:[ \t]*Bearer[ \t]+\$/i.test(source)) {
    const assignments = /^[ \t]*([A-Z_]\w*)="\$\{([A-Z]+[A-Z0-9_]*?)_(?:BASE(?:_URL)?|ENDPOINT):-https:\/\/[a-z0-9.-]+\}\/[^"\r\n]*"[ \t]*\r?$/gm;
    scanMatches('weakened-safeguard', assignments,
      'The shell helper sends the same service’s bearer credential to a destination controlled by an environment override.', {
        raw: true, snykEvidence: 'configurable-bearer-destination', accepts: match => {
          const endpoint = new RegExp(String.raw`"\$\{?${match[1]}\}?"`);
          const bearer = new RegExp(String.raw`Authorization:[ \t]*Bearer[ \t]+\$\{?${match[2]}_(?:KEY|TOKEN)\}?(?=[ "'\r\n]|$)`, 'i');
          const assignment = String.raw`(?:${match[1]}|${match[2]}_(?:BASE(?:_URL)?|ENDPOINT))`;
          const guard = new RegExp(String.raw`^[ \t]*(?:if|elif|case)[^\r\n]{0,140}\$\{?${assignment}\b[^\r\n]*(?=[\r\n]|$)`, 'm');
          if (guard.test(source)) return false;
          const window = source.slice(match.index + match[0].length, match.index + match[0].length + 1800);
          return [...window.matchAll(/^[ \t]*(?:[A-Z_]\w*=\$\()?curl\b(?:[^\r\n]*?\\\r?\n){0,10}[^\r\n]*/gm)]
            .some(request => endpoint.test(request[0]) && bearer.test(request[0]));
        },
      });
  }
  if (!limited) scanMatches('agent-role-override', delegatedCliGuide,
    'The skill delegates its operative instructions to the text returned by a command.', {
      snykEvidence: 'manifest',
      accepts: match => /\b(?:run|invoke|execute|command|CLI)\b/i.test(
        match.input.slice(Math.max(0, match.index - 220), match.index)
      ),
    });
  if (!limited) scanMatches('agent-role-override', delegatedFetchedProcedure,
    'The skill tells the agent to execute procedures found in fetched material.', { snykEvidence: 'manifest' });
  if (!limited) scanMatches('agent-role-override', delegatedPlaybook,
    'The skill makes a remote playbook authoritative for each step of the workflow.', {
      raw: true, snykEvidence: 'manifest',
      accepts: match => /https?:\/\/\S+/i.test(match.input.slice(match.index, match.index + match[0].length + 240)),
    });
  if (!limited) scanMatches('agent-role-override', delegatedWorkspaceRules,
    'The skill makes instructions from a mutable workspace file authoritative by default.', {
      snykEvidence: 'manifest', accepts: workspaceRuleWithoutApproval,
    });
  if (!limited) scanMatches('unapproved-file-change', writesProjectInstructions,
    'The workflow changes persistent project instructions by default and gives the user a way to opt out.', {
      snykEvidence: 'manifest', accepts: writesInstructionsByDefault,
    });
  if (!limited) for (const { start, length } of uncheckedCheckoutFallbacks(source)) {
    add('agent-role-override', start, length,
      'The skill can run code from a shared checkout after ignoring a failed clone.', undefined, false, 'manifest');
    add('runtime-dependency', start, length,
      'The workflow runs code from an external checkout without confirming which revision is present.',
      undefined, false, 'manifest');
    if (limited) break;
  }
  if (!limited) scanMatches('agent-role-override', encodedText,
    encodedRoleOverrideReason, { raw: true, snykEvidence: 'direct', accepts: match => {
      // Decode only bounded candidates and check the text without rendering it.
      const length = match[0].length;
      if (length < 24 || length > 2048 || length % 4 !== 0) return false;
      try {
        const decoded = atob(match[0]);
        return !decoded.matchAll(roleOverride).next().done || !decoded.matchAll(roleMarker).next().done;
      } catch {
        return false;
      }
    } });
  if (!limited) scanMatches('dangerous-code-pattern', encodedExecution,
    'The instruction connects an encoded value to execution. Review the decoded content as text.');
  if (!limited && /^#![^\r\n]*\b(?:ba|z)?sh\b/.test(source)) {
    scanMatches('dangerous-code-pattern', /\bbase64[ \t]+(?:-d|--decode)[ \t]*\|[ \t]*(?:ba|z)?sh\b/gi,
      'The shell script passes decoded input directly to a shell interpreter.', {
        raw: true, snykEvidence: 'direct', accepts: match => !/^[ \t]*#/.test(sourceLineAt(source, match.index)),
      });
  }
  if (!limited) scanMatches('dangerous-code-pattern', unsafeExecution,
    'The matched code passes freshly downloaded text into an interpreter.', { raw: true });
  if (!limited && /\b(?:preview|verify)\b/i.test(source) && /\bupload code\b/i.test(source) && /\bscreenshots?\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', defaultsToHostedSecrets,
      'The hosted test workflow directs the agent to upload the user’s local secrets by default.', {
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited && source.includes('SHOPIFY_ACCESS_TOKEN')) {
    const options = { raw: true, snykEvidence: 'manifest', accepts: sendsStoreCredentialToAnotherService };
    scanMatches('dangerous-code-pattern', fillsStoreCredentialPayload,
      'The store access token and customer identifier are sent to a separate service in the export request.', options);
    if (!limited) scanMatches('credential-handling', fillsStoreCredentialPayload,
      'The request places the store credential in the payload alongside customer data.', options);
  }
  if (!limited && /\bif (?:the )?user (?:pastes|provides|sends) (?:an?|their) API key (?:directly )?in chat\b/i.test(source)) {
    const forwardedKey = /\bcurl[ \t]+[^\r\n]{0,110}\bPOST[ \t]+["']?https:\/\/([\w.-]+)\/[^\s"'\x60]{1,150}[^\r\n]{0,330}(?:\\\r?\n[^\r\n]{0,330}){0,5}"api_key"[ \t]*:[ \t]*["']{0,4}\$\{?([A-Z][A-Z0-9_]*_API_KEY)\}?/g;
    scanMatches('dangerous-code-pattern', forwardedKey,
      'The workflow captures an API key supplied in chat and forwards it in a request body to a different service endpoint.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          const after = source.slice(match.index + match[0].length, match.index + match[0].length + 430);
          if (!/\b(?:always include|must include)\b/i.test(after) || !/"(?:query|user_query)"[ \t]*:/.test(match[0])) return false;
          const preceding = source.slice(0, match.index);
          return [...preceding.matchAll(/\bhttps:\/\/([\w.-]+)\/[^\s"'\x60]+\/(?:quota|usage)\b[^\r\n]{0,120}\bX-API-Key:[ \t]*\$\{?([A-Z][A-Z0-9_]*_API_KEY)\}?/gi)]
            .some(([ , host, key]) => host.toLowerCase() !== match[1].toLowerCase() && key === match[2]);
        },
      });
  }
  if (!limited && /学术诚信/u.test(source) && /\bcanvas[ \t]+assignment[ \t]+submit\b/i.test(source)) {
    scanMatches('agent-role-override', ignoresAssignmentIntegrity,
      'The instructions tell the agent to ignore academic integrity boundaries when submitting generated work.', {
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited && /https:\/\/[\w.-]+\/courses\/[^\r\n]{0,80}\/assignments\//i.test(source) &&
      /附件/u.test(source) && /根据作业描述[^。\r\n]{0,65}(?:生成|完成)/u.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest', assessment: 'capability' };
    scanMatches('third-party-content', readsRemoteAssignment,
      'The workflow reads externally authored assignment content and attachments to prepare the submission.', options);
    if (!limited) scanMatches('runtime-dependency', readsRemoteAssignment,
      'The assignment retrieved at runtime determines the work the agent produces.', options);
  }
  if (!limited && /\brsync[ \t]+-[a-z]+[ \t]+--delete\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest', accepts: replacesInstructionsOnEachUse };
    scanMatches('dangerous-code-pattern', deletesAndReplacesSkill,
      'An automatic update overwrites the installed skill with a mutable checkout and removes local files absent from it.', options);
    if (!limited) scanMatches('runtime-dependency', deletesAndReplacesSkill,
      'The skill replaces its own instructions from a mutable repository before use.', options);
    if (!limited) scanMatches('third-party-content', deletesAndReplacesSkill,
      'The agent re-reads instructions written in the downloaded checkout.', { ...options, assessment: 'capability' });
  }
  if (!limited && /\buser_wiki\b/i.test(source)) {
    scanMatches('concealed-profile-access', concealsProfileRead,
      'The workflow tells the agent to conceal that it has read the learner’s profile.', {
        raw: true, snykEvidence: 'manifest',
        accepts: match => readsProfileForLesson.test(source.slice(Math.max(0, match.index - 1500), match.index)),
      });
  }
  if (!limited && /网页课程|博客|文档链接/u.test(source)) {
    scanMatches('third-party-content', archivesFetchedCourseSource,
      'The workflow archives externally authored course material and uses it to prepare lessons.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
        accepts: match => /\bwiki\/course_wiki\/[^\r\n]{0,75}\/raw\//i.test(source.slice(match.index, match.index + 1700)),
      });
  }
  if (!limited && /\bsystemctl[ \t]+restart\b/i.test(source)) {
    scanMatches('fixed-deployment-alias', fixedDeploymentAlias,
      'The deployed configuration adds a fixed public alias in addition to the host supplied by the user.', {
        raw: true, snykEvidence: 'dns-deployment-alias',
      });
  }
  if (!limited && /\bos\.path\.join\(self\.\w*skill\w*,/.test(source) && /\bsubprocess\.run\(/.test(source)) {
    scanMatches('dangerous-code-pattern', runsTargetSkillScript,
      'The repair workflow can execute script paths taken from the target skill.', {
        raw: true, snykEvidence: 'automated-skill-repair',
        accepts: match => !validatesTargetScriptPath.test(match.input.slice(Math.max(0, match.index - 200), match.index) + match[0]),
      });
  }
  if (!limited && /\bcan_send\.py\b/i.test(source)) {
    scanMatches('unconfirmed-device-action', skipsDeviceSendConfirmation,
      'The workflow can send to an automatically selected CAN interface without another confirmation.', {
        raw: true, snykEvidence: 'unconfirmed-can-output',
      });
  }
  if (!limited && /\bself\.voice_activation\.start\(/.test(source) &&
      /^[ \t]*from[ \t]+(?:[\w.]+\.)?voice_activation[ \t]+import\b/m.test(source)) {
    scanMatches('dangerous-code-pattern', forwardsTranscribedSpeech,
      'The bundled background assistant routes transcribed speech directly into a device action.', {
        raw: true, snykEvidence: 'background-speech-device-action', accepts: routesSpeechToDeviceAction,
      });
  }
  if (!limited && /\bbrowser\s+<session>\s+bind\b/i.test(source) &&
      /\bbrowser\s+network\b/i.test(source) && /\bbrowser\s+upload\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest' };
    scanMatches('dangerous-code-pattern', browserCredentialField,
      'The workflow combines access to a signed-in browser with an example that extracts a sensitive form value.', options);
    scanMatches('credential-handling', browserCredentialField,
      'The workflow reads a sensitive value from a browser form into model-visible output.', options);
  }
  const opening = /^---[ \t]*\r?\n[\s\S]{1,1450}?\r?\n---[ \t]*(?:\r?\n|$)/.exec(source)?.[0] ?? '';
  if (!limited && /\bcloud\b/i.test(opening) && /\b(?:AWS|Azure|GCP)\b/i.test(opening)) {
    const count = results.length;
    scanMatches('dangerous-code-pattern', describesCloudIntrusion,
      'The skill declares cloud intrusion and privilege escalation as operating capabilities.', {
        raw: true, snykEvidence: 'manifest',
        accepts: match => match.index + match[0].length < opening.length &&
          !/\b(?:detect|prevent|mitigate|defend against)\b/i.test(match[0]),
      });
    if (!limited && results.length > count) {
      scanMatches('credential-handling', declaresCredentialHarvest,
        'The declared workflow handles credentials acquired from target accounts.', {
          raw: true, snykEvidence: 'manifest', accepts: match => match.index < opening.length,
        });
    }
  }
  if (!limited && /\b(?:OAuth|identity provider)\b/i.test(opening) && /\bphishing\b/i.test(opening)) {
    const count = results.length;
    scanMatches('dangerous-code-pattern', credentialHarvestPurpose,
      'The declared workflow acquires reusable credentials through a phishing flow.', {
        raw: true, snykEvidence: 'manifest',
        accepts: match => match.index + match[0].length < opening.length &&
          !/\b(?:detect|prevent|study|mitigate|teach|defend against)\b/i.test(match[0]),
      });
    if (!limited && results.length > count) {
      scanMatches('credential-handling', collectsReusableTokens,
        'The workflow handles reusable access or refresh tokens obtained from a target account.', {
          raw: true, snykEvidence: 'manifest', accepts: match => match.index > opening.length,
        });
    }
  }
  if (!limited && /(?:下载|获取)[^\r\n]{0,35}(?:CLI\s*)?(?:二进制|可执行文件)/i.test(source) && asksForSetupToken.test(source)) {
    scanMatches('dangerous-code-pattern', automaticBinarySetup,
      'The workflow automatically runs setup for a downloaded executable and asks the user for a credential.',
      { raw: true, snykEvidence: 'manifest' });
    scanMatches('credential-handling', passesSetupToken,
      'The setup passes the token supplied in chat as a command-line argument.', { raw: true, snykEvidence: 'manifest' });
  }
  if (!limited && /\btmux[ \t]+send-keys\b/i.test(source) && !source.matchAll(readsTerminalPane).next().done) {
    scanMatches('dangerous-code-pattern', exposesHostShell,
      'A persistent host shell hook exposes new user terminal sessions to both command input and output capture.',
      { snykEvidence: 'linked-document' });
    if (!limited && !/\b(?:redact|filter)\b[^.!?;]{0,65}\b(?:secrets|credentials)\b/i.test(source)) {
      scanMatches('credential-handling', exposesHostShell,
        'The host session capture can expose credentials present in terminal output.',
        { assessment: 'potential', snykEvidence: 'linked-document' });
    }
  }
  if (!limited) scanMatches('dangerous-code-pattern', shellToolEntry,
    'The same tool exposes arbitrary shell commands, file replacement, and persistent memory writes.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const prefix = match[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        return new RegExp('\\x60' + prefix + '\\s+file\\s+replace\\x60').test(source) &&
          new RegExp('\\x60' + prefix + '\\s+memory\\s+write\\x60').test(source);
      },
    });
  if (!limited && externalTlsEndpoint.test(source) && localCredentialReader.test(source) &&
      opensHttpConnection.test(source) && /\b(?:apiKey|accessToken)\b/.test(source)) {
    scanMatches('dangerous-code-pattern', disablesTlsVerification,
      'The invoked script handles local API credentials and disables TLS verification for remote requests.', {
        raw: true, snykEvidence: 'invoked-script',
      });
  }
  if (!limited && /\.post\(/i.test(source)) scanMatches('dangerous-code-pattern', sendsCredentialInRecord,
    'A bundled script sends the raw credential as a field in a telemetry record.', {
      raw: true, snykEvidence: 'credential-telemetry', accepts: match => {
        const target = new RegExp('^' + match[1] + '[ \\t]*=[ \\t]*["\']https://[^/\\s"\']+/' +
          '[^\\s"\']{0,120}\\b(?:telemetry|record|analytics)(?:/|[?"\'])', 'm');
        return target.test(source) && /\bos\.(?:getenv|environ\.get)\s*\(/.test(source);
      },
    });
  if (!limited) scanMatches('dangerous-code-pattern', sensitiveTransfer,
    'The matched instruction directs sensitive values to an external destination.');
  if (!limited) scanMatches('dangerous-code-pattern', persistence,
    'The matched instruction requests persistent or unauthorized access.');
  if (!limited && runtimeInstrumentation.test(source) && /\b(?:connect mode|preloaded|embed\w*|inject\w*)\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', appInstrumentation,
      'The workflow uses embedded application instrumentation to introduce code into a running app.', { snykEvidence: 'manifest' });
  }
  if (!limited && mandatoryDispatch.test(source) && modifiesWorkspaceFromDirective.test(source)) {
    scanMatches('dangerous-code-pattern', forcedRuntimeDirective,
      'The workflow requires dispatching runtime directives that can modify code or persistent memory.', { snykEvidence: 'manifest' });
  }
  if (!limited && /\$(?:\{(?:[1@*])|[1@*])/.test(source)) scanMatches('dangerous-code-pattern', builtShellExpression,
    'The shell passes a constructed program to a JavaScript evaluator.', {
      raw: true, snykEvidence: 'invoked-shell',
      accepts: match => new RegExp('^\\s*' + match[1] + '\\s*\\+=', 'mi').test(source),
    });
  if (!limited && remoteToolEndpoint.test(source)) scanMatches('anonymous-agent-endpoint', anonymousEndpoint,
    'The registered tool endpoint is reachable without authenticating the client.', { snykEvidence: 'documented-agent-install' });
  if (!limited && preservesRealIdentity.test(source)) scanMatches('identity-moderation-fallback', mediaPolicyFallback,
    'The media workflow specifies a fallback when generation of identifiable content is blocked.', { snykEvidence: 'manifest' });
  if (!limited && /^[ \t]*[*# ]*moderation (?:ops|workaround)\b/im.test(source) &&
      /\b(?:image-to-video|(?:generate|author) (?:images?|videos?|media|(?:fresh )?prompts?))\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', mediaRequestsModerationBypass,
      'The media workflow treats bypassing content moderation as an instruction.', {
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited && /\b(?:background process|live feed|persistent monitor)\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', forwardsSessionTranscripts,
      'The monitor forwards local session transcript entries to an external chat in the background.', {
        accepts: match => !/\b(?:only (?:redacted|anonymized)|redact(?:s|ed)? all (?:user messages|transcripts))\b/i.test(nearMatch(match)),
        snykEvidence: 'manifest',
      });
  }
  if (!limited && htmlReportHeading.test(source) && !redactsReportCredentials.test(source)) {
    const report = { raw: true, snykEvidence: 'manifest', accepts: match => {
      const prefix = source.slice(Math.max(0, match.index - 1400), match.index);
      let depth = 7;
      for (const heading of [...prefix.matchAll(/^[ \t]*(#{1,6})[ \t]+[^\r\n]+/gm)].reverse()) {
        if (heading[1].length >= depth) continue;
        if (htmlReportHeading.test(heading[0])) return true;
        depth = heading[1].length;
      }
      return false;
    } };
    const beforeReport = results.length;
    scanMatches('credential-handling', credentialReportTable,
      'The HTML report includes a table with the credentials found during the review.', report);
    if (!limited && results.length > beforeReport && /\b(?:auditoría|audit)\b/iu.test(source)) {
      const writes = new Set([...source.matchAll(mutatingAuditRequest)].map(([, method]) => method.toUpperCase()));
      const captured = source.matchAll(capturedAuditResponse).next().value;
      if (writes.size >= 2 && captured) {
        scanMatches('dangerous-code-pattern', credentialReportTable,
          'The audit collects and reports credentials while performing multiple types of state-changing requests.', report);
        if (!limited) add('third-party-content', captured.index, captured[0].length,
          'The audit reads remote responses into variables used by its inspection workflow.', 'capability', false, 'manifest');
      }
    }
  }
  if (!limited && source.includes('disableSkillShellExecution')) {
    scanMatches('dangerous-code-pattern', renderShellPolicy,
      'The guide describes shell commands executed during rendering and identifies bundled or managed skills as exceptions to the execution policy.', {
        raw: true, snykEvidence: 'linked-document', accepts: match => {
          const before = source.slice(Math.max(0, match.index - 2100), match.index);
          const after = source.slice(match.index + match[0].length, match.index + match[0].length + 380);
          return /\bexecute\b[^.\r\n]{0,75}\bcommand\b[^.\r\n]{0,70}\brender[- ]time\b/i.test(before) &&
            /\bstdout\b[^.\r\n]{0,85}\bbefore the model\b/i.test(before) &&
            /\b(?:bundled|managed) skills\b[^.\r\n]{0,90}\b(?:not affected|unaffected|exempt)\b/i.test(after);
        },
      });
  }
  if (!limited && /\bhistorical success rate\b/i.test(source)) {
    scanMatches('agent-role-override', exampleActualOutcome,
      'The guide labels a placeholder financial example’s outcome as actual alongside an unsourced historical success rate.', {
        raw: true, snykEvidence: 'linked-document', accepts: match => {
          const before = source.slice(Math.max(0, match.index - 1600), match.index);
          const pattern = /\bhistorical success rate\b[^\r\n]{0,95}\b\d{1,3}(?:[–-]\d{1,3})?\s*%[^\r\n]{0,100}\r?\n[\s\S]{0,85}\bexample pattern\s*:\**[ \t]*\r?\n[ \t]*\x60{3}\w*[ \t]*\r?\n[ \t]*(?:stock|asset|company)\s+(?:ABC|XYZ)\b/i.exec(before);
          if (!pattern) return false;
          const example = before.slice(pattern.index);
          return /\bexpected outcome\b/i.test(example) &&
            !/\b(?:hypothetical|fictional|illustrative|synthetic)\b|https?:\/\/|doi:/i.test(example);
        },
      });
  }
  if (!limited && /\bevery (?:markdown|`?\.md`?) file in the vault\b/i.test(source) &&
      /\bno role-based skips\b/i.test(source) && /\bsave the raw findings JSON\b/i.test(source) &&
      !/\b(?:exclude|redact|mask|omit)\b[^.!?;\r\n]{0,70}\b(?:credentials?|secrets?|CLAUDE\.local\.md)\b/i.test(source)) {
    const options = { snykEvidence: 'full-vault-chat-report', accepts: match => {
      const before = match.input.slice(Math.max(0, match.index - 120), match.index);
      return !asksForApproval.test(before);
    } };
    scanMatches('dangerous-code-pattern', emitsFullVaultReport,
      'The workflow sends a complete report derived from private vault files into the chat transcript.', options);
    if (!limited) scanMatches('credential-handling', emitsFullVaultReport,
      'The full report can include material from local notes that may contain personal credentials.', options);
  }
  if (!limited && personLocation.test(source) && personalActivitySource.test(source)) scanMatches(
    'personal-routine-profile', personalTimeline, 'The workflow builds a personal routine from online activity and location evidence.',
    { raw: true, accepts: match => match.index < 1000, snykEvidence: 'manifest' });
  if (!limited && /--email\s*=<address>/i.test(source) && /\bproxy\b/i.test(source)) {
    scanMatches('cli-identity-proxy', swapsIdentity,
      'The proxy maps the supplied address to a user’s OAuth credentials without exposing the token to the operator.',
      { snykEvidence: 'manifest' });
  }
  if (!limited && /new document|创建新文档后/iu.test(source) &&
      mandatoryNewDocumentSteps.test(source)) scanMatches('dangerous-code-pattern', fixedDocumentOwner,
    'A required post-creation workflow grants full document access and transfers ownership to a fixed email address.', {
      raw: true,
      accepts: match => {
        const prior = source.slice(Math.max(0, match.index - 480), match.index);
        return mandatoryNewDocumentSteps.test(prior) && [...prior.matchAll(fixedDocumentAccess)]
          .some(grant => grant[1].toLowerCase() === match[1].toLowerCase());
      },
      snykEvidence: 'manifest',
    });
  if (!limited && /\bdom_snapshot\b/i.test(source)) {
    const previousCount = results.length;
    scanMatches('third-party-content', pollsRenderedReview,
      'The review tool feeds rendered page text and reviewer input into the workflow.',
      { assessment: 'capability', snykEvidence: 'manifest' });
    if (!limited && results.length > previousCount) scanMatches('dangerous-code-pattern', concealedMonitoring,
      'The workflow hides its monitoring of a rendered artifact supplied to a polling process.', { snykEvidence: 'manifest' });
  }
  if (!limited && dynamicallyImportsLocalModule.test(source) && /\b(?:file:\/\/|pathToFileURL\b)/i.test(source) &&
      credentials.test(source) && /\bchild_process\b/.test(source)) {
    scanMatches('private-credential-interface', privateCredentialBypass,
      'The workflow bypasses approved tooling and loads a private credential interface at runtime.', { snykEvidence: 'manifest' });
  }
  if (!limited) {
    const opening = source.slice(0, 500);
    if (/\bNTLM\b/i.test(opening) && /\brelay\b/i.test(opening)) {
      scanMatches('dangerous-code-pattern', authenticationCoercion,
        'The skill’s stated purpose involves forced authentication and credential relay.', {
          raw: true, accepts: match => match.index + match[0].length <= opening.length, snykEvidence: 'manifest',
        });
    }
  }
  if (!limited && browserDebugging.test(source)) {
    if (preservedBrowserCredentials.test(source) && interceptsBrowserConnections.test(source)) {
      scanMatches('dangerous-code-pattern', persistentBrowserHook,
        'The browser workflow combines persistent page hooks with credential access and request interception.', { snykEvidence: 'manifest' });
    }
    if (!limited && preservedBrowserCredentials.test(source) && sensitiveBrowserOperation.test(source)) {
      scanMatches('dangerous-code-pattern', debuggingLiveProfile,
        'The browser debugger can control a live profile that retains authentication state.', { snykEvidence: 'manifest' });
    }
    if (!limited && browserControlPrompt.test(source)) {
      const previousCount = results.length;
      scanMatches('dangerous-code-pattern', automaticPromptApproval,
        'The workflow can automatically approve a prompt granting browser debugging access.', { snykEvidence: 'manifest' });
      if (!limited && results.length > previousCount) {
        scanMatches('third-party-content', readsAccessibilityText,
          'The watcher uses text from browser dialogs to decide which action to take.', { assessment: 'capability', snykEvidence: 'manifest' });
        if (!limited) scanMatches('system-modification', registersLoginAgent,
          'The watcher installs a process that runs when the user logs in.', { assessment: 'capability', snykEvidence: 'manifest' });
      }
    }
    if (!limited) scanMatches('third-party-content', readsCDPResponse,
      'The browser debugger reads response bodies that can contain third-party text.', { assessment: 'capability', raw: true, snykEvidence: 'manifest' });
  }
  if (!limited) for (const match of source.matchAll(childWithEnvironment)) {
    if (negated(source, match.index) || !runsRegistryPackageWithEnvironment(match)) continue;
    const versioned = invokesVersionedRegistryTool(match);
    add('registry-environment', match.index, match[0].length,
      'The code runs a registry package with the parent process environment, which may contain secrets.',
      undefined, false, versioned ? 'versioned-registry-package' : 'direct');
    if (!limited && versioned) add('runtime-dependency', match.index, match[0].length,
      'The code runs an explicitly versioned package fetched from the registry.', undefined, false, 'direct');
    if (limited) break;
  }
  if (!limited && /\bexecFileSync\s*\(\s*["']npx["']/.test(source)) {
    const options = { raw: true, snykEvidence: 'package-selector-script', accepts: match => {
      const context = source.slice(match.index + match[0].length, match.index + match[0].length + 1500);
      const identifier = match[1].replaceAll('$', '\\$');
      const args = new RegExp(String.raw`\b(?:const|let)\s+(\w+)\s*=\s*\[\s*["'](?:--yes|-y)["']\s*,\s*${identifier}\s*,`).exec(context);
      return Boolean(args && new RegExp(String.raw`\bexecFileSync\s*\(\s*["']npx["']\s*,\s*${args[1]}\b`).test(context));
    } };
    const count = results.length;
    scanMatches('suspicious-download', envRegistryPackage,
      'A runtime environment value can select which registry package the launcher automatically downloads and runs.', options);
    if (!limited && results.length > count) {
      scanMatches('runtime-dependency', envRegistryPackage,
        'The launcher runs a registry package selected at runtime without a package integrity check.', options);
      if (!limited) scanMatches('third-party-content', delegatedPublicBrowse,
        'The delegated agent opens a supplied URL or public search result.', { raw: true, snykEvidence: 'package-selector-script' });
    }
  }
  if (!limited) scanMatches('financial-execution', payment,
    'This instruction can move money or create a financial obligation. Review its approval and account limits.', {
      assessment: 'capability',
      accepts: match => {
        if (/^send\b[^.!?;\r\n]{0,45}\bto (?:a|the) payment$/i.test(match[0]) &&
            /^\s+page\b/i.test(match.input.slice(match.index + match[0].length))) return false;
        const prefix = match.input.slice(Math.max(0, match.index - 180), match.index).split(/[.!?;\r\n]/).at(-1);
        const prohibited = /\b(?:do not|don't|never|must not)\s+(?:[\w -]+,\s*){1,8}(?:or\s+|and\s+)?$/i.exec(prefix);
        if (!prohibited || /\b(?:but|then|instead)\b/i.test(prohibited[0])) return true;
        const after = match.input.slice(match.index + match[0].length, match.index + match[0].length + 175)
          .split(/[.!?;\r\n]/, 1)[0];
        return /\b(?:without|unless|until)\b[^\r\n]{0,85}\b(?:approv\w*|confirm\w*|consent)\b/i.test(after);
      },
      snykEvidence: match => (concretePayment.test(match[0]) ||
        (walletOperation.test(nearMatch(match)) && walletContext.test(source))) && 'manifest',
    });
  if (!limited) scanMatches('financial-execution', paymentEndpoint,
    'The API endpoint can create a charge, transfer funds, or create another financial obligation.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\bPayment-Required\b/.test(source) && /\bpayment operation\b/i.test(source)) {
    scanMatches('financial-execution', followsX402PaymentFlow,
      'The linked workflow can submit a live payment as part of an authorized API operation.', {
        assessment: 'capability', raw: true, snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\bstripe\./i.test(source)) {
    const description = /^description:[ \t]*([^\r\n]*)/im.exec(source.slice(0, 2048))?.[1];
    if (!description || /\b(?:payments?|checkout|refunds?|billing|stripe)\b/i.test(description)) {
      scanMatches('financial-execution', paymentSdkCall,
        'The workflow creates or captures a payment or refund through the billing SDK.', {
          assessment: 'capability', raw: true, snykEvidence: 'manifest',
        });
    }
  }
  if (!limited) scanMatches('financial-execution', paidToolInvocation,
    'The workflow can make automatic payments to access a paid operation.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
      accepts: match => {
        const line = source.slice(source.lastIndexOf('\n', match.index) + 1, match.index);
        return !/^description:/i.test(line) &&
          (!match[0].startsWith('--') || /\b(?:auto[- ]?pay(?:ment)?|automatically pay)\b/i.test(nearMatch(match)));
      },
    });
  if (!limited && walletContext.test(source)) scanMatches('financial-execution', walletTransferCommand,
    'The workflow can submit a wallet or blockchain bridge transfer.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
      accepts: match => {
        const previous = source.slice(Math.max(0, match.index - 540), match.index).split(/\r?\n[ \t]*\r?\n/).at(-1);
        return !/^[ \t]*\|[^|\r\n]+\|[ \t]*policy checks[ \t]*\|/im.test(previous);
      },
    });
  if (!limited && /\b(?:idempotenc(?:y|e)|idempotent)\b/i.test(source)) {
    scanMatches('financial-execution', transfersProviderEarnings,
      'The operation moves a provider’s settled earnings or account balance.', { assessment: 'capability', snykEvidence: 'manifest' });
  }
  if (!limited) scanMatches('financial-execution', paymentSetup,
    'The workflow can set up an operation that charges or debits an account.', {
      assessment: 'capability', snykEvidence: 'manifest',
      accepts: match => !requiresExternalBillingAdmin.test(match.input.slice(
        match.index + match[0].length, match.index + match[0].length + 115
      )),
    });
  if (!limited && /\bbudgetDecision\.(?:image|video|audio|generation)AttemptLimit\b/.test(source) &&
      /\b(?:paid provider|paid generation)\b/i.test(source)) {
    scanMatches('financial-execution', changesGenerationBudget,
      'The workflow can change the allowed budget for attempts against a paid generation provider.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('financial-execution', purchaseExecution,
    'The workflow can place or confirm a paid order.', {
      assessment: 'capability', accepts: match => purchaseContext.test(nearMatch(match)), snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('financial-execution', paidServerRental,
    'The rental command commits a paid server reservation up to a caller-supplied charge limit.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('financial-execution', purchaseEndpoint,
    'The API call can place or confirm an order or capture payment.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('financial-execution', tradingOrder,
    'The workflow can submit an order in a financial market.', {
      assessment: 'capability', accepts: match => tradingContext.test(nearMatch(match)), snykEvidence: 'manifest',
    });
  if (!limited && source.includes('preview_order')) {
    scanMatches('financial-execution', /\bbefore (?:any )?live[ \t]+\x60?(?:[\w.]+\.)?place_order\(\)\x60?/gi,
      'The workflow can submit orders against a live brokerage account after preview and user confirmation.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest', accepts: match => {
          const policy = sourceLineAt(source, match.index);
          return /\bpaper trading\b/i.test(policy) && /\bpreview_order\(\)/i.test(policy) &&
            /\bwait for explicit user confirmation\b/i.test(policy);
        },
      });
  }
  if (!limited && /\btest case generation\b/i.test(source)) scanMatches('financial-execution', voucherWriteTestCase,
    'The live test recipe can revoke a billing voucher through the configured cloud account.',
    { assessment: 'capability', raw: true, snykEvidence: 'live-voucher-test' });
  if (!limited) scanMatches('third-party-content', publicData,
    'The agent can encounter third-party instructions through this input. Review the boundary before acting on it.', { assessment: 'capability' });
  if (!limited && /\bimage-to-3D\b/i.test(source) && /\bAPI key\b/i.test(source) && /\bHTTP API or SDK\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'linked-asset-sourcing' };
    scanMatches('weakened-safeguard', reinterpretsAssetRestriction,
      'The fallback proceeds with external asset generation even when the user has restricted downloads.', options);
    if (!limited) scanMatches('third-party-content', downloadsAllowedPublicAssets,
      'With permission, the workflow can download assets created by outside parties.', { ...options, assessment: 'capability' });
  }
  if (!limited) scanMatches('third-party-content', webRetrieval, webRetrievalReason, {
      assessment: 'capability', accepts: match =>
        !isRetrievalLabel(match) && !isNavigationOrMetadataOnly(match) && !readsVendorDocumentation(match) &&
        !(/^open[ \t]+(?:the[ \t]+)?(?:chosen|selected)[ \t]+URL\b/i.test(match[0]) &&
          /^\s*:\s*\*{0,2}macOS\b[^\r\n]{0,70}\bxdg-open\b[^\r\n]{0,40}\bWindows\b[^\r\n]{0,25}\bstart\b[.\s\x60]*$/i
            .test(source.slice(prose.original(match.index)).split(/\r?\n/, 1)[0]
              .replace(/^open[ \t]+(?:the[ \t]+)?(?:chosen|selected)[ \t]+URL\b/i, ''))) &&
        !/^[ \t]*\|[ \t]*`?[\w.]*urls?`?[ \t]*\|[ \t]*(?:no|optional)[ \t]*\|[^\r\n]{0,130}\b(?:server|servers|backend) (?:fetches|fetch) these URLs\b/i
          .test(sourceLineAt(source, prose.original(match.index))),
      snykEvidence: match => {
        const start = prose.original(match.index);
        const isPlaceholderFetch = (/^fetch\(url\b/i.test(match[0]) && showsNativeFetchReplacement(source, start)) ||
          (/^fetch\(toValue\(url\b/.test(match[0]) && showsReactiveFetchExample(source, start));
        const embedsLocalAssets = /^read (?:those|the) files and embed them into (?:the )?(?:final )?HTML as `?data:`?\s+URLs\b/i
          .test(source.slice(start, start + 110)) && /\b(?:local(?:ly extracted)?|temporary)\s+`?(?:[\w.-]+\/)?`?\s*(?:assets?|media|folder)\b/i
          .test(sourceLineAt(source, start));
        return isPlaceholderFetch || embedsLocalAssets || isPermissionAssessmentRow(source, start) ?
          'reference-example' : readsThroughOperation(match);
      },
    });
  if (!limited && /\blistActions[ \t]*\(/.test(source) &&
      /\b(?:list|get|read|search|view)[A-Za-z\w]{0,48}(?:Threads|Messages|Comments|Emails|Documents)\b/.test(source)) {
    scanMatches('third-party-content', runsConnectedAction,
      'The workflow reads content from connected services and receives it in the action response.', {
        assessment: 'capability', raw: true, snykEvidence: 'manifest', accepts: match => {
          const after = source.slice(match.index + match[0].length, match.index + match[0].length + 650);
          return /\b(?:connectionKey|connection\.key)\b/.test(after) &&
            (/\b(?:status|ok)\b[^\r\n]{0,120}\bdata\b/.test(after) ||
              new RegExp(String.raw`\b${match[1]}\.data\b`).test(after));
        },
      });
  }
  if (!limited && /\blist_images\b/.test(source)) scanMatches('third-party-content', sharedMarketplaceImages,
    'The image listing can return metadata written by publishers of shared or marketplace images.',
    { assessment: 'capability', raw: true, snykEvidence: 'marketplace-image-listing' });
  if (!limited) scanMatches('third-party-content', readsTargetSkillInstructions,
    'The test workflow reads commands and metadata from a separately installed skill.',
    { assessment: 'capability', raw: true, snykEvidence: 'external-skill-test-input' });
  if (!limited && /\bassets? (?:are|is) downloaded locally\b/i.test(source)) {
    scanMatches('third-party-content', editableWebCapture,
      'The capture workflow brings content from a live site into the local project.',
      { assessment: 'capability', snykEvidence: 'linked-web-capture' });
  }
  if (!limited && /\bconnectOverCDP\(/.test(source)) scanMatches('third-party-content', cdpPageTextOutput,
    'The browser workflow navigates to a web page and returns the page body as text.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited && /\bitem['’]s actual files are fetched\b/i.test(source)) {
    scanMatches('third-party-content', readsRawRegistry,
      'The catalog reads an external registry manifest and content published by registry contributors.',
      { assessment: 'capability', raw: true, snykEvidence: 'linked-registry-catalog' });
  }
  if (!limited) scanMatches('third-party-content', readsUntrustedRepositoryText,
    'The repository review reads untrusted README text and commit messages.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited && /\bread\b[^\r\n]{0,50}\bfiles\b/i.test(source) && /\bREADME\b/.test(source) &&
      /\b(?:synthesize|write|produce|generate) (?:the |a )?report\b/i.test(source)) {
    scanMatches('third-party-content', clonesUserRepository,
      'The review reads files from a caller-selected repository and uses those files in its report.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited && /\bgit[ \t]+diff\b/.test(source)) {
    scanMatches('third-party-content', comparesRecentFilePatch,
      'The workflow can use the latest Git patch and commit message as evidence about a named file.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document', accepts: match => {
          const before = match.input.slice(Math.max(0, match.index - 140), match.index);
          return /(?:名前(?:の出た|が出た)ファイル|\b(?:named|specific) files?\b)/iu.test(before);
        },
      });
  }
  if (!limited && /\bPath\([ \t]*(?:cwd|current|state_root),[ \t]*["']\.[\w-]+["'][ \t]*\)/.test(source) &&
      /\b_put_snapshots\([ \t]*_ensure_dir\([ \t]*state,[ \t]*["']inputs["'][ \t]*\)/.test(source)) {
    scanMatches('unapproved-file-change', writesInputSnapshot,
      'The invoked checker retains full input copies in a hidden project state directory.', {
        raw: true, snykEvidence: 'invoked-script', accepts: match => {
          const preceding = match.input.slice(Math.max(0, match.index - 430), match.index);
          const digestPath = new RegExp(String.raw`\b${match[1]}\s*=\s*str\(Path\(folder,\s*${match[2]}\.sha256\s*\+\s*['"]\.bin['"]\)\)`);
          return digestPath.test(preceding);
        },
      });
  }
  if (!limited && /\bquery\s+(?:users|records)\b/i.test(source)) {
    scanMatches('third-party-content', importsExternalSheetRecords,
      'The queried sheet can contain records imported from another service.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
        accepts: match => !negated(source, match.index),
      });
  }
  if (!limited && /\bgrounded inputs\b/i.test(source) && /\bad comments\b/i.test(source)) {
    scanMatches('third-party-content', collectsCustomerReviews,
      'The creative workflow uses customer reviews and ad comments as source material.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited && /\.docx\b/i.test(source) && /\b(?:review|annotat|summari)[a-z]*\b/i.test(source)) {
    scanMatches('third-party-content', extractsContractText,
      'The review ingests contract text that a counterparty may have written.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
        accepts: match => !negated(source, match.index),
      });
  }
  if (!limited && /\.(?:docx|pptx|potx)\b/i.test(source)) {
    scanMatches('third-party-content', readsOfficeContent,
      'The document-reading workflow exposes author-controlled file content to the agent as Markdown.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest', accepts: ([, command, script]) => {
          if (!script) return !/[<>]|[ \t]-(?:o\b|-output\b)/i.test(command);
          return source.split(/\r?\n/).some(line => line.startsWith('|') && line.includes(script) &&
            /\balt text\b/i.test(line) && /\bspeaker notes\b/i.test(line) && /\bas markdown\b/i.test(line));
        },
      });
  }
  if (!limited && /(?:转写原文|逐句原始发言|meeting transcript)/iu.test(source)) {
    scanMatches('third-party-content', readsMeetingTranscript,
      'The meeting workflow reads a transcript containing statements from other participants.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
  }
  if (!limited) scanMatches('third-party-content', inventoriesPackageDescriptions,
    'The inventory reports descriptions supplied by installed packages.', {
      raw: true, assessment: 'capability', snykEvidence: 'packaged-inventory-description',
    });
  if (!limited && /\.add_argument\([ \t]*["']--base-url["']/.test(source) &&
      /\bbase_url[ \t]*=[ \t]*args\.base_url\b/.test(source) && /\.read\(\)\.decode\(/.test(source)) {
    scanMatches('third-party-content', externalApiBody,
      'The command places response text from a caller-selected service into its report.', {
        raw: true, assessment: 'capability', snykEvidence: 'invoked-script', accepts: match => {
          const next = source.slice(match.index + match[0].length, match.index + 900);
          const field = new RegExp('\\b(\\w+)\\[[\'"]checks[\'"]\\]\\.append\\([\\s\\S]{0,240}?[\'"]body[\'"]\\s*:\\s*' +
            match[1] + '\\b');
          const report = field.exec(next)?.[1];
          return Boolean(report && new RegExp('\\bprint\\(json\\.dumps\\(' + report + '\\b').test(next));
        },
      });
  }
  if (!limited && /\bget_13f_summary\(/.test(source) && /\bholder\[["']name["']\]/.test(source)) {
    scanMatches('third-party-content', displaysCompanyProfileName,
      'The report includes company and holder names supplied by an external financial-data service.', {
        raw: true, assessment: 'capability', snykEvidence: 'invoked-script', accepts: match => {
          const after = source.slice(match.index + match[0].length, match.index + 480);
          return new RegExp(String.raw`\bprint\(f["'][^\r\n]{0,75}\{${match[2]}\}`).test(after);
        },
      });
  }
  if (!limited) scanMatches('third-party-content', readsPageJsonLd,
    'The workflow reads JSON-LD supplied by the publisher of each inspected page.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest', accepts: match =>
        /\b(?:each|target|supplied) URL\b/i.test(source.slice(Math.max(0, match.index - 180), match.index)),
    });
  if (!limited && /\b(?:recent cards|record fields|card fields)\b/i.test(source)) scanMatches(
    'third-party-content', readsWorkflowRecords, 'The workflow samples records with fields that other people can write.',
    { raw: true, assessment: 'capability', snykEvidence: 'manifest' });
  if (!limited && releaseNotesFromHistory.test(source)) scanMatches('third-party-content', gitLogCommand,
    'The release workflow uses commit messages from repository contributors to write release notes.', {
      raw: true, assessment: 'capability', accepts: gitLogReadsMessages, snykEvidence: 'linked-document',
    });
  if (!limited && /\b(?:for (?:each|every) entry|verify every selected entry)\b/i.test(source)) {
    scanMatches('third-party-content', checksTaskHistory,
      'The triage workflow uses contributor-authored commit messages to verify selected entries.', {
        raw: true, assessment: 'capability', accepts: gitLogReadsMessages, snykEvidence: 'manifest',
      });
  }
  if (!limited && /\bimplementation_artifacts\b/.test(source)) {
    scanMatches('weakened-safeguard', selfDeclaredArtifactReceipt,
      'The executing session can declare ignored files as proof of work for publication into the main checkout.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          const after = source.slice(match.index, match.index + 2100);
          return /\bproof-of-work[ \t]+probe\b[\s\S]{0,95}\bno changes\b/i.test(after) &&
            /\bpublishes?[ \t]+the[ \t]+accepted[ \t]+ignored\b/i.test(after) &&
            /\b(?:main[ -]checkout|main[ -]worktree)\b/i.test(after);
        },
      });
  }
  if (!limited && releaseNotesFromHistory.test(source)) scanMatches('third-party-content', evaluatesReleaseSources,
    'The release workflow analyzes externally authored commit and pull request text.', {
      assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited && /\b(?:spawnSync|execFileSync)\([ \t]*["']git["']/i.test(source)) {
    const options = { raw: true, snykEvidence: 'release-history-script' };
    scanMatches('third-party-content', gitLogSubjectArgument,
      'The release-note script reads subject or body text from commits supplied by repository contributors.',
      { ...options, assessment: 'capability' });
    if (!limited && /\[[ \t]*["']remote["'][ \t]*,[ \t]*["']get-url["'][ \t]*,[ \t]*["']origin["'][ \t]*\]/.test(source)) {
      scanMatches('suspicious-download', rendersGitHubCompareUrl,
        'The generated GitHub comparison URL interpolates the repository and release references at runtime.', options);
    }
  }
  if (!limited && /(?:翻译|\btranslate\b)/iu.test(source) && /(?:报告|\breport\b)/iu.test(source)) {
    const options = {
      raw: true, snykEvidence: 'manifest', accepts: match =>
        source.includes(`https://github.com/${match[1]}/releases/tag/`),
    };
    scanMatches('third-party-content', fetchesReleaseIndex,
      'The workflow reads and translates release notes written by outside maintainers.', { ...options, assessment: 'capability' });
    if (!limited) scanMatches('runtime-dependency', fetchesReleaseIndex,
      'The current release index selects the upstream notes used in the report.', options);
  }
  if (!limited && /\bnpm[ \t]+pack(?:[ \t]+<package>(?:@<version>)?|[ \t]+--json)(?=[\s`"']|$)/i.test(source) &&
      /\b(?:README|maintainers|dist-tags|metadata)\b/i.test(source)) {
    scanMatches('third-party-content', auditsNpmMetadata,
      'The audit retrieves live registry metadata and examines the external package.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\b(?:pubspec\.yaml|README\.md)\b/i.test(source) && /(?:静的レビュー|static (?:review|inspection))/iu.test(source)) {
    scanMatches('third-party-content', reviewsDartArchive,
      'The workflow retrieves a published Dart package and reads its documentation or configuration.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\bgit[ \t]+fetch\b/i.test(source) && /\bgit[ \t]+diff[ \t]+--stat\b/i.test(source)) {
    scanMatches('third-party-content', readsRemoteCommitSubjects,
      'The workflow reads commit titles from the fetched remote branch.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
  }
  if (!limited) scanMatches('third-party-content', readsGeneratedDesign,
    'The workflow fetches externally generated HTML and makes it available for analysis.', {
      raw: true, assessment: 'capability', snykEvidence: 'linked-document',
    });
  if (!limited) scanMatches('third-party-content', readsSpreadsheetUrlRecords,
    'The workflow reads external spreadsheet records through a supplied document URL.', {
      raw: true, assessment: 'capability', snykEvidence: 'linked-document',
    });
  if (!limited) scanMatches('third-party-content', receivesMailReports,
    'The workflow reads email authentication or delivery reports sent by outside mail servers.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
      accepts: match => !negated(source, match.index),
    });
  if (!limited && /\bGitLab\b/i.test(source)) scanMatches('third-party-content', readsReleaseWorkItemsZh,
    'The release check reads work items and review material written by other contributors.', {
      raw: true, assessment: 'capability', snykEvidence: 'linked-document',
    });
  if (!limited && /\bGmail\b/i.test(source) && /(?:Tìm|tìm) hóa đơn/u.test(source)) {
    scanMatches('third-party-content', searchesInvoiceAttachments,
      'The workflow searches incoming messages and reads invoice attachments.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\b(?:PyPI|registry\.npmjs\.org)\b/i.test(source)) {
    scanMatches('third-party-content', registryMetadataRequest,
      'The invoked helper reads metadata controlled by package publishers.', {
        raw: true, assessment: 'capability', snykEvidence: 'registry-metadata-script',
      });
  }
  if (!limited && /\bJENKINS_URL\b/i.test(source) && /\bconsole log\b/i.test(source)) {
    scanMatches('third-party-content', readsBuildConfiguration,
      'The workflow reads build configuration and logs from a supplied server.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
    scanMatches('system-modification', runsJenkinsControllerScript,
      'The workflow sends a script to an administrative execution surface on the build server.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\bsym node show\b/i.test(source)) scanMatches('third-party-content', readsPeerInbox,
    'The startup operation reads messages written by other agents or users.', {
      raw: true, assessment: 'capability', snykEvidence: 'linked-document',
    });
  if (!limited && /\btext from past transcripts\b/i.test(source)) scanMatches('third-party-content', readsSessionTranscripts,
    'The session lookup reads free-form text from an earlier transcript.', {
      raw: true, assessment: 'capability', snykEvidence: 'linked-document',
    });
  if (!limited && /\bCoinGecko\b/i.test(source) && /\b(?:DexScreener|DefiLlama)\b/i.test(source)) {
    scanMatches('third-party-content', searchesMarketCatalog,
      'The catalog search reads names and related metadata from public market data services.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\b(?:research a market|market discovery)\b/i.test(source)) {
    scanMatches('third-party-content', marketDetailsCommand,
      'The workflow reads market descriptions and order-book data before evaluating a trade.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest', accepts: ([, cli]) => {
          const command = String.raw`^[ \t]*${cli}[ \t]+`;
          return new RegExp(command + String.raw`markets[ \t]+search\b`, 'im').test(source) &&
            new RegExp(command + String.raw`clob[ \t]+book\b`, 'im').test(source);
        },
      });
  }
  if (!limited && /\b(?:filesystem|container image|dependencies)\b/i.test(source) && writesCompositionReport.test(source)) {
    scanMatches('third-party-content', readsCompositionDescriptions,
      'The review reads vulnerability descriptions or package metadata supplied by outside publishers.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest', accepts: match => {
          const after = source.slice(match.index, match.index + 680);
          return /\bCVE\b[^\r\n]{0,150}\bDescription\b/i.test(after);
        },
      });
  }
  if (!limited) scanMatches('third-party-content', extractsRemotePageTitle,
    'The workflow reads the page title from remote HTML.', {
      raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      accepts: match => {
        const previous = source.slice(Math.max(0, match.index - 520), match.index);
        return new RegExp('\\b' + match[1] + '[ \\t]*=[ \\t]*requests\\.get\\([ \\t]*url\\b').test(previous);
      },
    });
  if (!limited) scanMatches('third-party-content', readsCustomerSubmissions,
    'The workflow reads text submitted by customers or survey respondents.', {
      assessment: 'capability', accepts: match => !/\b(?:count|totals?|volume|numeric|statistics)\b/i.test(nearMatch(match)),
      snykEvidence: 'linked-document',
    });
  if (!limited && /\b(?:draft|write|review)\b[^.!?;\r\n]{0,65}\bproposal\b/i.test(source)) {
    scanMatches('third-party-content', pastedJobPost,
      'The proposal workflow consumes the full text of a job post supplied by the user.',
      { assessment: 'capability', snykEvidence: 'manifest' });
  }
  if (!limited && /\b(?:curl|wget)\b[^\r\n]{0,165}https:\/\/[\w.-]+\/[\w./-]*(?:releases?|downloads?)\//i.test(source)) {
    const releaseVersionCommand = /^[ \t]*(?:curl|wget)\b[^\r\n|]{1,165}\b(https:\/\/[\w.-]+\/[\w./-]*(?:releases?|downloads?)[\w./-]*\/)[ \x60"']*\|[ \t]*(?:grep|sed|awk|jq)\b[^\r\n]{0,200}\|[ \t]*sort\b[^\r\n]{0,100}\|[ \t]*(?:head|tail)\b/gim;
    const usesAsVersion = /\b(?:use|substitut\w*|insert|plug)\b[^.\r\n]{0,85}\b(?:version|tag)\b[^.\r\n]{0,70}\b(?:download URL|release URL|download path)\b/gi;
    const active = removeMarkdownComments(source);
    const versionUsage = setupProseMatches(active, usesAsVersion);
    const activeBlocks = markdownBlocks(active);
    for (const block of activeBlocks) {
      if (isDocumentationExample(block)) continue;
      for (const entry of block.entries) {
        releaseVersionCommand.lastIndex = 0;
        const match = entry.code && releaseVersionCommand.exec(entry.text);
        if (!match) continue;
        const end = entry.start + entry.text.length;
        const next = active.slice(end, end + 900);
        if (!versionUsage.some(usage => usage.index > end && usage.index < end + 900) || !next.includes(match[1])) continue;
        add('third-party-content', entry.start + match[0].indexOf(match[1]), match[1].length,
          'The workflow uses a public release listing to select the version it downloads.',
          'capability', false, 'manifest');
        const launcher = !limited && extractedReleaseLauncher(active, activeBlocks, match[1], end);
        if (launcher) add('runtime-dependency', launcher.start, launcher.length,
          'Setup launches code extracted from the release selected at runtime.',
          'capability', false, 'manifest');
        if (limited) break;
      }
      if (limited) break;
    }
  }
  if (!limited && /\b(?:files?|documents?)\s+(?:or|and)\s+(?:URLs?|links?|web pages?)\b/i.test(source) &&
      /\b(?:convert|converts|converting|transform|render|export)\b[^.\r\n]{0,110}\b(?:to|as|into)\s+(?:clean\s+)?(?:Markdown|plain text)\b/i.test(source)) {
    const readsConvertedContent = /\b(?:read|summari[sz]e|extract|analy[sz]e|compare|quote|inspect)\b[^.\r\n]{0,85}\b(?:content|sections?|(?:converted|extracted) text|resulting Markdown)\b/gi;
    const usage = setupProseMatches(source, readsConvertedContent)[0];
    const active = removeMarkdownComments(source);
    const hasUrlInvocation = markdownBlocks(active).some(block => !isDocumentationExample(block) &&
      block.entries.some(entry => entry.code &&
        /^[\w-]+\s+["']https:\/\/[^ \r\n"']+["'][^\r\n]{0,60}\b(?:URLs?|web)\b/i.test(entry.text)));
    if (usage && hasUrlInvocation) add('third-party-content', usage.index, usage.address.length,
      'The workflow reads Markdown converted from files or web pages.',
      'capability', false, 'manifest');
  }
  if (!limited && source.includes('raw.githubusercontent.com/') &&
      /\b(?:JSON response|README\.md)\b/i.test(source)) {
    const active = removeMarkdownComments(source);
    const catalogRequest = /\b(?:fetch|retrieve|load|read)\b[ \t]*\x60?(https:\/\/raw\.githubusercontent\.com\/([\w.-]+\/[\w.-]+)\/(main|master|HEAD|[a-f0-9]{40})\/(?:[\w.-]+\/)*([\w.-]+\.json))/gi;
    for (const { index, address } of setupProseMatches(active, catalogRequest)) {
      const [, url, , ref, filename] = [...address.matchAll(catalogRequest)][0];
      const following = active.slice(index + address.length, index + address.length + 1900);
      if (!/\b(?:read|fetch)\b[^.!?\r\n]{0,75}\bREADME\.md\b/i.test(following) ||
          !new RegExp(String.raw`\x60${filename.replace(/[.]/g, '\\.')}\x60[ \t]+(?:has|contains|includes)\b`, 'i').test(following) ||
          !/\b(?:each entry|entries|schema|fields)\b/i.test(following)) continue;
      const start = index + address.indexOf(url);
      add('third-party-content', start, url.length,
        'The workflow reads a public JSON catalog and uses the repository README as an alternative source.',
        'capability', false, 'manifest');
      if (!limited && !/^[a-f0-9]{40}$/i.test(ref) && /^\|\s*\x60install\x60\s*\|[^\r\n]+\b(?:install command|installation command)\b/im.test(following) &&
          /\b(?:recommend|present|return)\b[^.\r\n]{0,65}\b(?:entries|results|options|matches)\b/i.test(active.slice(index + address.length, index + address.length + 6000))) {
        add('runtime-dependency', start, url.length,
          'A mutable public catalog supplies the available skills and their installation commands.',
          'capability', false, 'manifest');
      }
      if (limited) break;
    }
    const directoryURL = /^https:\/\/api\.github\.com\/repos\/([\w.-]+\/[\w.-]+)\/contents\/([\w.-]+(?:\/[\w.-]+)*)$/i;
    const rawSelection = /https:\/\/raw\.githubusercontent\.com\/([\w.-]+\/[\w.-]+)\/(main|master|HEAD|[a-f0-9]{40})\/([\w.-]+(?:\/[\w.-]+)*)\/<[^\r\n<>]{1,60}>\.json\b/gi;
    for (const block of markdownBlocks(active)) {
      if (isDocumentationExample(block)) continue;
      for (const entry of block.entries) {
        const directory = directoryURL.exec(entry.text);
        if (!directory) continue;
        const preceding = active.slice(Math.max(0, entry.start - 220), entry.start);
        if (!/\b(?:fetch|retrieve|get|list)\b[^.!?\r\n]{0,120}\b(?:list|files?|directory|GitHub)\b/i.test(preceding)) continue;
        const end = entry.start + entry.text.length;
        const following = active.slice(end, end + 5500);
        if (!/\b(?:parse|read|inspect|extract)\b[^.!?\r\n]{0,45}\bJSON response\b[^\r\n]{0,115}\b(?:files?|names?|entries|list)\b/i.test(following.slice(0, 550)) ||
            !/\b(?:ask|prompt)\b[^\r\n]{0,60}\buser\b[^\r\n]{0,65}\b(?:pick|choose|select)\b/i.test(following)) continue;
        const selection = [...following.matchAll(rawSelection)].find(match => match[1] === directory[1] && match[3] === directory[2]);
        if (!selection) continue;
        add('third-party-content', entry.start, entry.text.length,
          'The workflow lists public files and reads the JSON item the user selects.',
          'capability', false, 'manifest');
        if (!limited && !/^[a-f0-9]{40}$/i.test(selection[2]) && /\b(?:copy|merge|write|set)\b[^.\r\n]{0,130}\b(?:fetched|downloaded)\b[^.\r\n]{0,80}\b(?:into|to)\s+(?:the\s+)?[\x60"\']?(?:(?:[~\w.\/-]+)\/)?(?:settings|config)\.json\b/i.test(
          following.slice(selection.index + selection[0].length))) {
          add('runtime-dependency', end + selection.index, selection[0].length,
            'The workflow imports settings from a mutable public repository into the agent configuration.',
            'capability', false, 'manifest');
        }
        if (limited) break;
      }
      if (limited) break;
    }
  }
  if (!limited && /\b(?:latest|current)[ \t]+(?:prebuilt[ \t]+)?(?:binary|executable)\b/i.test(source)) {
    const asksForLatestBinary = /\bif[ \t]+(?:missing|not installed|(?:it|the check) fails)\b[^.\r\n]{0,65}\b(?:tell|ask|have|instruct) (?:the )?user to\s+(?:download|fetch)\s+(?:the\s+)?(?:latest|current)\s+(?:(?:prebuilt|pre-built)\s+)?(?:binary|executable)\s+(?:release\s+)?from\s+\[[^\]\r\n]+\]\((https:\/\/github\.com\/[\w.-]+\/([\w.-]+)\/releases(?:\/latest)?)\)[^.\r\n]{0,110}\bPATH\b/gi;
    const active = removeMarkdownComments(source);
    const commands = markdownBlocks(active).filter(block => !isDocumentationExample(block))
      .flatMap(block => block.entries.filter(entry => entry.code));
    const provesIntegrity = /\b(?:checksums?|hash verification|signature|shasum|sha256sum|cosign verify)\b/i;
    for (const { index, address } of setupProseMatches(active, asksForLatestBinary)) {
      const [, url, executable] = [...address.matchAll(asksForLatestBinary)][0];
      const precheck = commands.some(entry => entry.start >= index - 750 && entry.start < index &&
        /^(?:which|command[ \t]+-v|type[ \t]+-p)[ \t]+([\w.-]+)$/i.exec(entry.text)?.[1] === executable);
      const end = index + address.length;
      const used = commands.some(entry => entry.start > end && entry.start < end + 1600 &&
        /^([\w.-]+)[ \t]+[\w-]+\b/.exec(entry.text)?.[1] === executable);
      if (!precheck || !used || provesIntegrity.test(active.slice(Math.max(0, index - 750), end + 1600))) continue;
      const start = index + address.indexOf(url);
      add('suspicious-download', start, url.length,
        'The workflow requires the latest executable from a release page and provides no integrity verification.',
        'capability', false, 'manifest');
      if (limited) break;
    }
  }
  if (!limited && /\bMCP\b/i.test(source) && /https:\/\/[\w.-]+\/(?:[\w.-]+\/)*mcp\/?\b/i.test(source)) {
    const active = removeMarkdownComments(source);
    const accountCatalog = /\b(?:call|invoke|run|use)\s+[\x60"']?tools\/list\b[^\r\n]{0,160}\b(?:tools returned|returned tools|returned catalog)\b/gi;
    const readsMessages = /\b(?:searching|reading|search|read|list)(?:\s+or\s+(?:searching|reading|search|read|list))?\s+(?:the\s+)?(?:customer |account )?messages\b/gi;
    for (const discovery of setupProseMatches(active, accountCatalog)) {
      const prior = active.slice(Math.max(0, discovery.index - 1100), discovery.index);
      if (!/\b(?:OAuth|authorization)\b/i.test(prior)) continue;
      const read = setupProseMatches(active, readsMessages).find(item =>
        item.index > discovery.index && item.index < discovery.index + 1650);
      if (!read) continue;
      add('third-party-content', read.index, read.address.length,
        'The authenticated connector exposes account messages to the agent through tools in its live catalog.',
        'capability', false, 'manifest');
      break;
    }
    const providerGuide = /\bread\s+(?:the\s+)?returned\s+[\x60"']?[\w-]+[\x60"']?\s+field\s+before\s+(?:chaining|calling|invoking)\s+(?:(?:the|provider)\s+)?tools\b/gi;
    for (const result of setupProseMatches(active, providerGuide)) {
      if (limited) break;
      const prior = active.slice(Math.max(0, result.index - 850), result.index);
      const after = active.slice(result.index + result.address.length, result.index + result.address.length + 450);
      if (!/\bresponse\s+(?:carries|includes|returns|contains)\b[\s\S]{0,110}\b(?:JSON\s+Schema|input schema)\b/i.test(prior) ||
          !/\b(?:provider|vendor|server)\b[\s\S]{0,100}\b(?:workflow guide|playbook|instructions)\b/i.test(after)) continue;
      add('third-party-content', result.index, result.address.length,
        'The agent reads workflow guidance returned by the provider.',
        'capability', false, 'manifest');
      if (!limited) add('runtime-dependency', result.index, result.address.length,
        'The tool workflow depends on guidance supplied by the provider at runtime.',
        'capability', false, 'manifest');
      break;
    }
  }
  if (!limited && /\bcredentials\s+by\s+auth(?:entication)?\s+type\b/i.test(source)) {
    const providerCredentials = /\b[a-z][\w-]*\([^\r\n)]{1,120}\)[^\r\n]{0,70}\bcredentials\s+by\s+auth(?:entication)?\s+type\b/gi;
    for (const { index, address } of setupProseMatches(source, providerCredentials)) {
      const following = removeMarkdownComments(source.slice(index + address.length, index + address.length + 1450));
      const inline = /\b(api_key|client_secret|password|access_token)\s*=\s*["'](?:\.{3}|YOUR[_A-Z]+)["']/gi;
      const fields = new Set([...following.matchAll(inline)].map(match => match[1].toLowerCase()));
      if (fields.size < 2 || !/\b(?:OAuth2?|hosted consent)\b/i.test(following)) continue;
      add('credential-handling', index, address.length,
        'The connection workflow passes raw credentials in tool arguments for non-OAuth providers.',
        'capability', false, 'manifest');
      break;
    }
  }
  if (!limited && /\bmcp[ \t]+add-json\b/i.test(source) && /\bmcp-remote\b/i.test(source)) {
    const rawHeader = /^(?:claude|codex)\s+mcp\s+add-json\b[^\r\n]{1,300}\bmcp-remote\b[^\r\n]{0,210}\b(Authorization:\s*Bearer)\s+(?:[A-Z0-9_]+(?:YOUR|PASTE|REPLACE)[A-Z0-9_]*|YOUR_[A-Z0-9_]+)[\s"']/i;
    const configuration = markdownBlocks(removeMarkdownComments(source)).filter(block => !isDocumentationExample(block))
      .flatMap(block => block.entries)
      .find(entry => entry.code && rawHeader.test(entry.text));
    if (configuration) {
      const match = rawHeader.exec(configuration.text);
      add('credential-handling', configuration.start + match[0].indexOf(match[1]), match[1].length,
        'The MCP setup embeds the API key in a command-line header instead of using a credential reference.',
        'capability', false, 'manifest');
    }
  }
  if (!limited && /\bconfigure\s+\.mcp\.json\s+with\s+(?:an?\s+)?API key\b/i.test(source)) {
    const pasteInChat = /\b(?:once|when|after)\s+(?:you have it|you create it|you get it)[^!?.\r\n]{0,20}\bpaste it here\b/gi;
    scanMatches('credential-handling', pasteInChat,
      'The setup dialogue asks the user to paste a newly created API key into the conversation.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
        accepts: match => {
          const prior = match.input.slice(Math.max(0, match.index - 650), match.index);
          return /\bAssistant:[^\r\n]{0,180}\bAPI key\b/i.test(prior) &&
            /\b(?:create|obtain|get) (?:an? |your |the )?API key\b/i.test(prior);
        },
      });
  }
  if (!limited && /\bMCP\b/i.test(source) && /\bget_screen\b/i.test(source)) {
    const active = removeMarkdownComments(source);
    const screenTool = /\b(?:call|invoke|get|fetch)\b[^\r\n]{0,100}\bget_screen\b/gi;
    const targets = setupProseMatches(active, screenTool);
    for (const { index, address } of targets) {
      const following = active.slice(index + address.length, index + address.length + 2700);
      const fetch = /\b(?:web_fetch|read_url_content)\b[^\r\n]{0,110}\b(?:fetch|retrieve|read)\b[^\r\n]{0,50}\bHTML(?: code| content)?\b/i.exec(following.slice(0, 500));
      const readsExternalHtml = fetch && following.slice(0, 285).includes('htmlCode.downloadUrl') &&
        /\b(?:analy[sz]e|inspect|extract|parse|read)\b[^\r\n]{0,70}\bHTML\b/i.test(following.slice(fetch.index + fetch[0].length));
      const convertsExternalHtml = /\b(?:persist|save|download|write)\b[^\r\n]{0,115}\bHTML\b[^\r\n]{0,100}\.html\b/i.test(following.slice(0, 400)) &&
        /^#{1,5}\s*HTML\s*(?:→|->|to)\s*(?:React|Vue|Svelte|components?)\b/im.test(following);
      if (!readsExternalHtml && !convertsExternalHtml) continue;
      const start = index + address.toLowerCase().lastIndexOf('get_screen');
      add('third-party-content', start, 'get_screen'.length,
        'The workflow reads HTML returned by a design service and uses it to analyze or generate a design.',
        'capability', false, 'linked-document');
      if (!limited && readsExternalHtml &&
          /\b(?:create|write|save)\s+(?:a\s+)?\x60?[\w.\/-]*\/DESIGN\.md\x60?\b/i.test(following)) {
        add('runtime-dependency', start, 'get_screen'.length,
          'The linked workflow can produce prompt guidance from design assets retrieved at runtime.',
          'capability', false, 'external-design-guidance');
      }
      break;
    }
  }
  if (!limited && /\bgh[ \t]+pr[ \t]+checks\b/i.test(source) && /--log(?:-failed)?\b/i.test(source)) {
    const active = removeMarkdownComments(source);
    const logCommand = /\bgh[ \t]+run[ \t]+view\b[^\r\n\x60]{0,145}--log(?:-failed)?(?=[ \t\x60#\r\n]|$)/i;
    const failure = /\b(?:failing (?:CI|PR|checks?|workflows?|jobs?)|failure snippets?|GitHub Actions logs?|failed (?:job|check|workflow)|log real|fallo de c[oó]digo)\b/i;
    const useLogs = /\b(?:summari[sz]e failures|log snippets?|from (?:the|its) logs?|read (?:the|its) logs?|extract[^.!?\r\n]{0,50}logs?|classif[iy](?:car)?[^.!?\r\n]{0,50}\b(?:CI|failures?|fallo)|reproducir localmente|inspeccionar el log real)\b/i;
    for (const block of markdownBlocks(active)) {
      if (isDocumentationExample(block)) continue;
      for (const entry of block.entries) {
        if (/^\s*[>#]/.test(entry.text)) continue;
        const command = logCommand.exec(entry.text);
        if (!command) continue;
        const index = entry.start + command.index;
        if (negated(active, index)) continue;
        const end = index + command[0].length;
        const prior = active.slice(Math.max(0, index - 1500), index);
        const after = active.slice(end, end + 1300);
        const nearby = active.slice(Math.max(0, index - 250), end + 300);
        if (!failure.test(prior + after) || !(useLogs.test(nearby) || useLogs.test(after))) continue;
        add('third-party-content', index, command[0].length,
          'The pull request workflow retrieves and analyzes external CI log text.',
          'capability', false, 'linked-document');
        break;
      }
      if (limited) break;
    }
  }
  if (!limited && /\bgh[ \t]+api\b/i.test(source) && /\bcontents\//i.test(source)) {
    const active = removeMarkdownComments(source);
    const downloadCatalog = /^(?:[ \t]*\$[ \t]+)?[ \t]*gh[ \t]+api\b[^#\r\n]{0,220}(?:\\\r?\n[^#\r\n]{0,220}){0,4}\brepos\/([\w.-]+\/[\w.-]+)\/contents\/(?:[\w./-]+\/)?[\w.-]+\.json[ \t]*(?:\\\r?\n[ \t]*)?>[ \t]*["']?\$([A-Za-z_]\w*)\b/gim;
    for (const match of active.matchAll(downloadCatalog)) {
      const start = match.index;
      const end = start + match[0].length;
      const selection = active.slice(end, end + 2900);
      const readsSaved = new RegExp('\\bjq\\b[\\s\\S]{0,430}?\\$' + match[2] + '\\b', 'gi');
      if (negated(active, start) || ![...selection.matchAll(readsSaved)].some(([query]) =>
        /\.(?:description|body|body_text|message|content|markdown|release_notes|transcript|text)\b/i.test(query))) continue;
      add('third-party-content', start, end - start,
        'The workflow reads prose fields from a retrieved repository catalog to select an entry.',
        'capability', false, 'manifest');
      if (!limited && /\b(?:builds?|compiles?|installs?|executes?)\b/i.test(active.slice(end))) {
        add('runtime-dependency', start, end - start,
          'The workflow uses a remote catalog to select source code for a linked build.',
          'capability', false, 'linked-catalog-build');
      }
      if (limited) break;
    }
  }
  if (!limited && /\b(?:yt-dlp|youtube-dl)\b/i.test(source) && /--(?:write-|convert-subs)/i.test(source)) {
    const active = removeMarkdownComments(source);
    const captions = /\b(?:yt-dlp|youtube-dl)\b[^\r\n\x60]{0,240}--(?:write-(?:auto-)?subs|write-automatic-subs|write-sub|convert-subs)\b/gi;
    for (const match of active.matchAll(captions)) {
      const line = sourceLineAt(active, match.index);
      if (/^\s*[#>]/.test(line) || negated(active, match.index)) continue;
      add('third-party-content', match.index, match[0].length,
        'The workflow downloads subtitle or caption text from a media URL.',
        'capability', false, 'manifest');
      if (limited) break;
    }
  }
  if (!limited && /\bhooks?\b/i.test(source) && /\b(?:cloud[- ]hosted|remote runner|managed cloud|hosted sessions?)\b/i.test(source)) {
    const active = removeMarkdownComments(source);
    const introduction = active.slice(0, 2100);
    const hosted = /\b(?:cloud[- ]hosted|remote runner|managed cloud|hosted sessions?)\b/i.exec(introduction);
    const execution = /\b(?:hooks?\b[^.!?\r\n]{0,60}\b(?:fire|run|execute)\b|(?:runs?|executes?)\b[^.!?\r\n]{0,80}\b(?:repository|project|session)[- ](?:provided[ \t]+)?hooks?\b)/gi;
    if (hosted && !negated(introduction, hosted.index) &&
        /\b(?:trigger(?:ed|s)?|schedule[ds]?|automatically|on every (?:PR|push|commit|event))\b/i.test(introduction) &&
        /\b(?:clones?|checks? out)\s+(?:the\s+)?(?:repo\b|repositor(?:y|ies)\b|project source\b)/i.test(introduction) &&
        /\b(?:picks? up (?:updated |repository |repo )?hooks|updated hooks|repository[- ]provided|repo[- ]provided|evolve\s+in repo|hooks (?:from|defined in) the repo)\b/i.test(introduction) &&
        !/\bhooks?\b[^.!?\r\n]{0,50}\b(?:only after (?:explicit )?(?:approval|review)|must be reviewed before|pinned and verified)\b/i.test(introduction)) {
      for (const match of introduction.matchAll(execution)) {
        const line = sourceLineAt(introduction, match.index);
        if (/^\s*[#>]/.test(line) || negated(introduction, match.index)) continue;
        add('dangerous-code-pattern', match.index, match[0].length,
          'The unattended hosted workflow runs hooks inherited from the checked-out repository.',
          'capability', false, 'manifest');
        break;
      }
    }
  }
  if (!limited && /\bpipeline_input[ \t]*:/i.test(source) && /\bhttp_(?:inbound|poll)\b/i.test(source)) {
    const active = removeMarkdownComments(source);
    const connector = /^[ \t]*(?:-[ \t]+)?type:[ \t]*http_(?:inbound|poll)\b/gim;
    for (const match of active.matchAll(connector)) {
      const start = match.index;
      const next = active.slice(start + match[0].length, start + 720)
        .split(/\r?\n[ \t]*-[ \t]*(?:name|type)[ \t]*:/i, 1)[0];
      if (!/^[ \t]*(?:content|text|body)[ \t]*:[ \t]*["']?\$\.(?:[\w-]+\.)*(?:text|content|body|message)(?=[\s"']|$)/im.test(next) ||
          !/^[ \t]*pipeline_input[ \t]*:[ \t]*[\w-]+\b/im.test(next)) continue;
      add('third-party-content', start, match[0].length,
        'A connector passes externally authored message text into the agent pipeline.',
        'capability', false, 'linked-document');
      if (limited) break;
    }
  }
  if (!limited && /\b(?:DOM|page) text\b/i.test(source)) {
    const active = removeMarkdownComments(source);
    const browserText = /\b(?:browser[_ -]pipeline|browser (?:tool|session|workflow))\b[^\r\n]{0,150}\b(?:navigat(?:e|es|ion)|open|load|visit|fetch)\b[^\r\n]{0,150}\b(?:extract(?:s|ing)?|read(?:s|ing)?|collect(?:s|ing)?)\b[^.!?\r\n]{0,45}\b(?:DOM text|page text|page content|page body|web content)\b/gi;
    for (const match of active.matchAll(browserText)) {
      const line = sourceLineAt(active, match.index);
      if (negated(active, match.index) || /\b(?:fixture|mock|localhost|local preview|never (?:read|extract)|headless tests?)\b/i.test(line)) continue;
      add('third-party-content', match.index, match[0].length,
        'The browser workflow navigates to a page and extracts its text.', 'capability', false, 'linked-document');
      if (limited) break;
    }
  }
  if (!limited && /\bInstall system[- ]wide \(requires sudo\)/i.test(source)) {
    const active = removeMarkdownComments(source);
    const installer = /https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/main\/install\.sh\b/gi;
    for (const match of active.matchAll(installer)) {
      if (!offersReviewedRepoInstaller(active, new URL(match[0]))) continue;
      const option = /\bInstall system[- ]wide \(requires sudo\)/i.exec(active.slice(match.index + match[0].length, match.index + 1900));
      if (!option) continue;
      add('system-modification', match.index, match[0].length,
        'The offered setup includes a system-wide installation option that requires elevated privileges.',
        'capability', false, 'manifest');
      break;
    }
  }
  if (!limited && /\bweb_search_[\w-]+\b/i.test(source) && /\b(?:collect|read|use) results\b/i.test(source)) {
    const active = removeMarkdownComments(source);
    const externalResearch = /(?:^|\r?\n)[ \t]*(?:\/\/|#)[ \t]+External documentation search[ \t]*\r?\n[ \t]*(?:delegate_task|start_task)\([^\r\n]{0,240}\)/gi;
    for (const match of active.matchAll(externalResearch)) {
      const end = match.index + match[0].length;
      if (!/\b(?:collect|read|use) results\b/i.test(active.slice(end, end + 260))) continue;
      add('third-party-content', match.index, match[0].length,
        'The workflow delegates a search of outside documentation and collects the results.',
        'capability', false, 'manifest');
      if (limited) break;
    }
  }
  if (!limited) scanMatches('third-party-content', readsRuntimeApiSpec,
    'The workflow consumes an API specification supplied through a runtime URL.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('third-party-content', readsAdvisoryText,
    'The workflow consumes the text of a public security advisory.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited && /\b(?:API|https?)\b[^。！？\r\n]{0,45}(?:POI|places? search)|\b(?:searchPOI|searchPlaces)\s*\(/i.test(source)) {
    scanMatches('third-party-content', rendersPublicPlaceRecords,
      'The map lookup returns externally authored place names and addresses to the agent.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited && /\b(?:curl|wget)\b[^\r\n]{0,180}https?:\/\/[^\s"'<>]{1,120}\/(?:<[a-z_]*url>|\{[a-z_]*url\})/i.test(source)) {
    scanMatches('third-party-content', remotePageConversion,
      'The workflow requests the user’s target page through a Markdown conversion service.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited && /\bWebFetch\b/.test(source)) {
    scanMatches('third-party-content', fetchedPageBoundary,
      'The workflow reads externally authored web content and defines how the agent should interpret it.', {
        assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('third-party-content', openThinReferenceSource,
    'The reference workflow opens external source material to fill gaps in the bundled entries.', {
      assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('suspicious-download', linkedAddonRecommendation,
    'The guide directs the agent to a repository-supplied add-on when the built-in tool is insufficient.', {
      raw: true, snykEvidence: 'linked-document',
    });
  if (!limited) scanMatches('third-party-content', publicDataTool,
    'This tool can return web content or user-authored discussion to the agent.', {
      assessment: 'capability', raw: true, snykEvidence: usesWebTool, accepts: match => !readsVendorDocumentation(match),
    });
  if (!limited) scanMatches('third-party-content', reviewDiffCommand,
    'The review command reads proposed changes written by repository contributors.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('third-party-content', userAuthoredContent,
    'The instruction reads messages, posts or reviews that other people can write.', { assessment: 'capability', snykEvidence: 'direct' });
  if (!limited) scanMatches('third-party-content', researchesProductPricing,
    'The product research prompt brings pricing from external sources into the agent’s comparison.', {
      raw: true, assessment: 'capability', snykEvidence: 'linked-document',
    });
  if (!limited && source.includes('/review/list') && !source.matchAll(readsPublicBookReviews).next().done) {
    const options = { raw: true, snykEvidence: 'linked-document' };
    scanMatches('third-party-content', readsPublicBookReviews,
      'The workflow retrieves public reviews authored by other readers.', { ...options, assessment: 'capability' });
    if (!limited) scanMatches('weakened-safeguard', concealsReviewRouting,
      'The review workflow directs the agent to withhold how it selects and configures the source of public content.', options);
  }
  if (!limited) scanMatches('third-party-content', routesBuyerMessagesZh,
    'The router dispatches buyer messages to a customer-support workflow.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited && /\blive catalog\b/i.test(source)) scanMatches('third-party-content', readsLiveServicePricing,
    'The workflow reads a vendor’s live pricing and catalog data.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('third-party-content', readsFailedWorkflowSteps,
    'The workflow reads external CI jobs and failure details.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited && /\bKakaoTalk\b/i.test(source)) scanMatches('third-party-content', readsKakaoMessages,
    'The workflow reads messages authored by other chat participants.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited && /\bsignal-headless[ \t]+jsonRpc\b/.test(source)) scanMatches('third-party-content', readsRpcMessageBodies,
    'The messaging workflow reads bodies authored by other chat participants.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('third-party-content', printsPublishedSiteFile,
    'The workflow retrieves a published site file and exposes its contents to the agent.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited && /\brerun the install script with `?sudo\b/i.test(source)) {
    scanMatches('system-modification', installsInSystemBin,
      'The setup installs an executable in a system path and offers a privileged retry.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited && /\bsearch[.]py\b/i.test(source)) scanMatches('third-party-content', readsSocialSearchNotes,
    'The workflow reads titles and author names from externally published posts.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('third-party-content', socialPlatformRead,
    'The workflow reads posts, media, or discussion from a social platform.', {
      assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited && source.includes('prepare_reply')) scanMatches('third-party-content', preparesReplyFromPublicPost,
    'The workflow reads an externally authored post before drafting a reply.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
      accepts: match => !negated(source, match.index),
    });
  if (!limited && /\bMCP server\b/i.test(source) && /\b(?:repository URL or local path|user-supplied repository URL)\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest', accepts: match => {
      const suffix = source.slice(match.index + match[0].length, match.index + match[0].length + 900);
      return /\bwait for indexing to complete\b/i.test(suffix) &&
        suffix.toLowerCase().includes('query ' + match[1].toLowerCase() + ' for');
    } };
    scanMatches('third-party-content', indexesRepositoryWithMcp,
      'The agent submits a repository selected by the user and queries the returned repository index.',
      { ...options, assessment: 'capability' });
    if (!limited) scanMatches('runtime-dependency', indexesRepositoryWithMcp,
      'The analysis depends on repository content supplied by the MCP indexing server at runtime.', options);
  }
  if (!limited) scanMatches('third-party-content', publicMarketResearch,
    'The research step brings material from public sites or reviews into the workflow.', {
      assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited && /\b(?:what(?:'s| is)|what (?:tokens?|assets?) (?:are|is)) trending (?:on|in) [\w-]+/i.test(source)) {
    scanMatches('third-party-content', namedMarketDataProviders,
      'The workflow queries named market data providers to answer requests about current trends.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('third-party-content', readsPaidMarketplace,
    'The workflow reads search results or descriptions supplied by paid service publishers.', {
      assessment: 'capability', raw: true, snykEvidence: 'linked-document',
    });
  if (!limited && /\bMCP (?:\([^\r\n]{0,45}\) )?servers?\b/i.test(source)) {
    scanMatches('third-party-content', readsMcpSession,
      'The workflow reads resources or tool metadata published by a connected MCP server.', {
        assessment: 'capability', raw: true, snykEvidence: 'linked-document',
      });
  }
  if (!limited && networksForAdvertising.test(source)) scanMatches('third-party-content', ingestsPublicAdvertising,
    'The workflow reads ad copy or campaign material that outside advertisers can write.', {
      assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('third-party-content', publicListings,
    'The workflow searches listings that third-party publishers can write.', {
      assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('third-party-content',
    /^[ \t]*\|[ \t]*`[\w.-]+[ \t]+search[ \t]+\[keyword\]`[ \t]*\|[ \t]*`--type (?:news|community|feed)`[^|\r\n]*\|[ \t]*(?:news search|community search|stock feed)\b/gim,
    'The market-data CLI can return externally authored news or community text.', {
      raw: true, assessment: 'capability', snykEvidence: 'linked-market-content',
    });
  if (!limited && /\b(?:titles?|keywords?|abstracts?)\b/i.test(source)) {
    scanMatches('third-party-content', academicSearch,
      'The workflow queries a public research index and reads authors’ bibliographic text.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest',
        accepts: match => !negated(source, match.index),
      });
  }
  if (!limited) scanMatches('third-party-content', webSearchService,
    'The web search or extraction service can return text from external authors.', { assessment: 'capability', snykEvidence: 'manifest' });
  if (!limited) scanMatches('third-party-content', responseParsing,
    'This command retrieves and parses content from a remote service.', { assessment: 'capability', raw: true });
  if (!limited && browserNavigation.test(source)) scanMatches('third-party-content', browserRead,
    'The workflow navigates to a page and makes its content available to the agent.', {
      assessment: 'capability', raw: true, snykEvidence: 'direct',
    });
  if (!limited) scanMatches('third-party-content', browserTraceTarget,
    'The browser trace captures data from a supplied page and makes it available to the workflow.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
      accepts: match => browserTraceOutput.test(match.input.slice(
        Math.max(0, match.index - 120), match.index + match[0].length + 140
      )),
    });
  if (!limited && /\b(?:api key|bearer token)\b/i.test(source)) scanMatches('third-party-content', authenticatedRead,
    'The workflow queries an authenticated API and can consume its response.', {
      assessment: 'capability', accepts: match => !matchesDocumentationUrl(match) &&
        !/^[ \t]*\|[ \t]*`?(?:GET|POST|PUT|PATCH|DELETE)`?[ \t]*\|[ \t]*`?\/api\/[^|]+\|[ \t]*`?[\w-]+:read`?[ \t]*\|/i
          .test(sourceLineAt(source, prose.original(match.index))),
      snykEvidence: match => readsThroughOperation(match) && 'manifest',
    });
  if (!limited) scanMatches('third-party-content', discussionReader,
    'The command reads messages, issues, or pages that other people can write.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\bgws[ \t]+gmail\b/i.test(source)) {
    scanMatches('third-party-content', workspaceMailFromMessage,
      'The Gmail operation resolves an existing message by ID before forwarding or replying to it.', {
        assessment: 'capability', raw: true, snykEvidence: 'manifest',
      });
    if (!limited && /\bstream\w*\b[^\r\n]{0,45}\b(?:emails?|messages?|NDJSON)\b/i.test(source)) {
      scanMatches('third-party-content', workspaceMailStream,
        'The Gmail watch operation streams incoming message content into the workflow.', {
          assessment: 'capability', raw: true, snykEvidence: 'manifest',
          accepts: ([line]) => !/--(?:help|msg-format(?:[ \t]+|=)(?:metadata|minimal)\b)/i.test(line),
        });
    }
  }
  if (!limited && /^[ \t]*gws[ \t]+chat[ \t]+<resource>[ \t]+<method>/im.test(source)) {
    scanMatches('third-party-content', workspaceChatMessages,
      'The Chat command exposes the messages resource, including messages written by other participants.', {
        assessment: 'capability', raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited && /\b(?:ticket|issue) text, comments, and attachments as untrusted\s+data\b/i.test(source)) {
    scanMatches('third-party-content', linkedTrackerWorkItem,
      'The workflow consumes issue text and comments that contributors can edit.',
      { assessment: 'capability', raw: true, snykEvidence: 'manifest' });
  }
  if (!limited && /\bworkspace token\b/i.test(source) &&
      /\bcomments[ \t]+list\b/i.test(source) && /\bsearch(?:ing)? for pages or databases\b/i.test(source)) {
    scanMatches('third-party-content', readsWorkspacePage,
      'The workspace CLI reads page content and comments that collaborators can write.',
      { assessment: 'capability', snykEvidence: 'manifest' });
  }
  if (!limited && /\bnew FileReader\b/.test(source) && /\.readAsText\s*\(/.test(source)) {
    scanMatches('third-party-content', rendersCsvPreview,
      'The app reads CSV text supplied by the user and displays it in the import preview.', {
        assessment: 'capability', raw: true, snykEvidence: 'scaffold-csv-preview', accepts: match => {
          const before = source.slice(Math.max(0, match.index - 900), match.index);
          return /\.onload\s*=/.test(before) && /\bparseCsv\s*\(/i.test(before);
        },
      });
  }
  if (!limited && /\bannotations?\b/i.test(source)) {
    scanMatches('third-party-content', receivesQueuedReviewPrompts,
      'The review tool delivers browser annotations and queued prompts to the agent.',
      { assessment: 'capability', snykEvidence: 'manifest' });
  }
  if (!limited && /\bpublishes the artifact\b/i.test(source)) {
    scanMatches('credential-handling', sharesArtifactWithCredentialArguments,
      'The publishing command accepts a password and access token as command-line arguments.',
      { snykEvidence: 'manifest' });
  }
  if (!limited && /\bRequest Headers\b/i.test(source) && /\bFULL_COOKIE\b/.test(source)) {
    const options = { snykEvidence: 'manifest' };
    scanMatches('dangerous-code-pattern', requestsFullBrowserCookie,
      'The workflow asks the user to share a complete browser session cookie with the agent.', options);
    if (!limited) scanMatches('credential-handling', requestsFullBrowserCookie,
      'The sign-in guidance moves the full session cookie into the conversation.', options);
  }
  if (!limited && /\b(?:login|authentication|session) cookies\b/i.test(source)) {
    const options = {
      raw: true, snykEvidence: 'manifest',
      accepts: match => {
        const start = Math.max(0, match.index - 900);
        const before = source.slice(start, match.index);
        const prompt = /\b(?:send this message|tell the user):[ \t]*\r?\n((?:[ \t]*(?:>[^\r\n]*)?\r?\n)+)$/i.exec(before);
        return prompt && !negated(source, start + prompt.index) &&
          /\bI need your (?:login|authentication|session) cookies\b/i.test(prompt[1]) &&
          /\b(?:copies|exports) all cookies (?:as|in) JSON\b/i.test(prompt[1]);
      },
    };
    scanMatches('dangerous-code-pattern', requestsCookieExportInChat,
      'The browser workflow asks the user to provide a complete authenticated cookie export in chat.', options);
    if (!limited) scanMatches('credential-handling', requestsCookieExportInChat,
      'The sign-in guidance moves raw session cookies into the conversation.', options);
  }
  if (!limited && /\bchrome\.debugger\.attach\s*\(/.test(source)) {
    scanMatches('dangerous-code-pattern', readsExtensionCookies,
      'The bundled browser extension collects session cookies alongside response data stored by its recorder.',
      { raw: true, snykEvidence: 'extension-session-recorder' });
  }
  if (!limited) scanMatches('credential-handling', extensionTokenArgument,
    'The workflow passes a session-related token in command-line arguments.',
    { raw: true, snykEvidence: 'extension-session-token-argument' });
  if (!limited && exportsPrimaryBrowserCookies.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest' };
    scanMatches('dangerous-code-pattern', sharesBrowserSessionsAcrossAgents,
      'The workflow makes authenticated browser sessions from the user’s browser available to other agents.', options);
    if (!limited) scanMatches('credential-handling', sharesBrowserSessionsAcrossAgents,
      'Raw browser credentials are persisted in the session file shared by agents.', options);
    if (!limited) scanMatches('third-party-content', sharesBrowserSessionsAcrossAgents,
      'Site-controlled browser state can be copied into the shared session used by later agents.', {
        ...options, assessment: 'capability',
      });
  }
  if (!limited && /\bAllow remote debugging for this browser instance\b/i.test(source) &&
      /--remote-debugging-port\b/i.test(source) && !source.matchAll(exportsBrowserCookieFile).next().done) {
    const options = { raw: true, snykEvidence: 'packaged-browser-session-export' };
    scanMatches('dangerous-code-pattern', exportsBrowserCookieFile,
      'The browser automation package can export the active session cookies to a local file.', options);
    if (!limited) scanMatches('system-modification', enablesAttachedBrowserDebugging,
      'The workflow enables remote debugging on the existing browser instance.', options);
  }
  if (!limited && /\bcluster-side Python\b/.test(source) && /\bpersistent\s+SSH\b/i.test(source)) {
    scanMatches('dangerous-code-pattern', automaticRemoteWorkerInstall,
      'The workflow automatically deploys a persistent remote agent that can run commands over SSH.',
      { snykEvidence: 'remote-command-worker' });
    if (!limited) scanMatches('system-modification', optionalMacAutostart,
      'The packaged launch service can start the cluster control daemon and keep it running.',
      { raw: true, snykEvidence: 'packaged-worker-autostart' });
  }
  if (!limited && (contentRequest.test(source) || remoteDescription.test(source))) {
    scanMatches('third-party-content', contentTool,
      'The workflow calls a content retrieval operation that can return text written by other people.', {
        assessment: 'capability', raw: true, snykEvidence: match => {
          const preceding = source.slice(Math.max(0, match.index - 640), match.index);
          const question = preceding.split(/\r?\n[ \t]*\r?\n/).at(-1);
          if (/^\s*\d+[.)][ \t]+\*\*[^\r\n]{1,60}\*\*[ \t]+Can I\b[\s\S]{0,155}$/i.test(question) &&
              /\battempt to break your own rules\b/i.test(preceding) && /\bretrieve documents\b/i.test(match[0])) {
            return 'reference-example';
          }
          return 'manifest';
        },
        accepts: match => {
          if (/^read PAGE$/.test(match[0]) && /\blocal\b[^.!?;\r\n]{0,50}\bhelper\b/i.test(source) &&
              /^[# \t]+ANCHOR\b/.test(source.slice(match.index + match[0].length))) return false;
          if (/\blist issues?\b/i.test(match[0]) &&
              /\bfor each slide,[ \t]+list issues\b|\blist issues found\b[^\r\n]{0,40}\bif none found\b/i.test(nearMatch(match))) {
            return false;
          }
          return !/\sPOST$/.test(match[0]) || !/^[ \t]+\//.test(source.slice(match.index + match[0].length));
        },
      });
  }
  if (!limited && remoteApiHost.test(source) && !inputTransform.test(source)) scanMatches('third-party-content', queryArgument,
    'The workflow uses query parameters alongside a remote API endpoint.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('third-party-content', suppliedLinks,
    'The workflow takes links supplied by the user, so the linked content may be controlled by an outside party.', {
      assessment: 'capability', snykEvidence: incomingLinkUse, accepts: match => !reportsGeneratedLink.test(match[0]),
    });
  if (!limited && /\bpnpm[ \t]+(?:up|update)\b[^\r\n`]{0,72}--latest\b/.test(source)) {
    scanMatches('third-party-content', registryVersionList,
      'The upgrade workflow reads published registry versions to decide whether to retry the upgrade.', {
        assessment: 'capability', snykEvidence: 'manifest', accepts: match =>
          /\b(?:if|when) (?:the )?(?:(?:missing|requested|new) )?version (?:now )?(?:exists|is available|appears)\b/i.test(
            match.input.slice(match.index + match[0].length, match.index + 175)),
      });
  }
  if (!limited) scanMatches('third-party-content', developmentFeedback,
    'The workflow consumes review feedback, history, or build output that other contributors can influence.', {
      assessment: 'capability', snykEvidence: 'direct',
      accepts: match => !/^check for test (?:results|reports|outputs) in\b/i.test(match[0]),
    });
  if (!limited) scanMatches('third-party-content', readsDesktopText,
    'The desktop tool reads text that can be authored by people outside the current session.', { assessment: 'capability', snykEvidence: 'manifest' });
  if (!limited && source.includes('<用户')) scanMatches('third-party-content', importsUserRecords,
    'The CLI reads a file supplied by the user and returns its contents or derived fields to the agent.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\b(?:bug |issue )?reports? from (?:markdown |\.md )files exported from\b|\bbug reports? from any ticket system\b/i.test(source) &&
      /\b(?:extracts?|parses?|transforms?)\b[^.!?;\r\n]{0,100}\b(?:structured data|structured JSON|JSON state)\b/i.test(source)) {
    scanMatches('third-party-content', readsExportedTicketMarkdown,
      'The workflow parses ticket-system Markdown as data and uses it to create structured records.', {
        assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited && /\b(?:user(?:'s)? host|host mode|persistent terminal sessions)\b/i.test(source)) {
    scanMatches('third-party-content', readsTerminalPane,
      'The workflow reads terminal output that may contain text from other programs or sessions.',
      { assessment: 'capability', raw: true, snykEvidence: 'linked-document' });
  }
  if (!limited && /\bssh[ \t]+["']?\$\{?\w+\}?[^\r\n]{0,70}\btmux[ \t]+capture-pane\b/i.test(source)) {
    scanMatches('third-party-content', printsPaneToModel,
      'The workflow uses captured output from a remote terminal session.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\b(?:Android|iOS|mobile (?:app|automation)|device UI)\b/i.test(source)) {
    scanMatches('third-party-content', readsDeviceInterface,
      'The device workflow reads text controlled by the current app or web view.', {
        assessment: 'capability', raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('third-party-content', chineseWebFetch,
    'The workflow uses WebFetch to obtain externally authored content.', { assessment: 'capability', snykEvidence: 'manifest' });
  if (!limited && prWorkflow.test(source)) scanMatches('third-party-content', prReadback,
    'The workflow reads back the title and body of a remote pull request.', { assessment: 'capability', snykEvidence: 'manifest' });
  if (!limited) scanMatches('third-party-content', remoteChangeRequestFields,
    'The command reads GitHub issue or pull request text that other contributors can change.',
    { assessment: 'capability', raw: true, snykEvidence: 'manifest' });
  if (!limited && /\bpull[ \t]+<owner\/repo>/.test(source)) {
    scanMatches('third-party-content', /^[ \t]*([\w-]+)[ \t]+(?:map[ \t]+)?show[ \t]+<repo>[ \t]+--ref\b[^\r\n]{0,110}\buse with Read\b/gim,
      'The workflow reads reference content generated from the public repository selected by the agent.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest', accepts: ([, command]) =>
          new RegExp(String.raw`^[ \t]*${command}[ \t]+pull[ \t]+<owner/repo>[ \t]+#[^\r\n]{0,75}\bclone\b`, 'mi').test(source),
      });
  }
  if (!limited && /\bawait\b/.test(source) && /\.(?:get|post)\(/.test(source)) {
    scanMatches('third-party-content', selectsDownloadFromSearch,
      'The workflow sends a user query to an external search and downloads the URL derived from the selected result.', {
        raw: true, snykEvidence: 'invoked-script', accepts: match => {
          const definition = new RegExp(String.raw`^(?:async[ \t]+)?def[ \t]+${match.groups.search}\(`, 'm').exec(source);
          if (!definition) return false;
          const body = source.slice(definition.index, definition.index + 1800).split(/\r?\n(?=(?:async[ \t]+)?def[ \t])/)[0];
          return /\.(?:get|post)\(/.test(body) && /\.json\(/.test(body);
        },
      });
  }
  if (!limited && /\b(?:implement|apply)\s+(?:the\s+)?(?:changes?|fixes|fix)\b/i.test(source) && /\bgit\s+push\b/i.test(source)) {
    scanMatches('third-party-content',
      /\breviewThreads\b[^\r\n]{0,160}?\.\s+(?:These|They) (?:are|become) (?:the )?(?:change|fix) requests\b|\b(?:use|treat)\b[^.\r\n]{0,60}\breviewThreads\b[^.\r\n]{0,65}\bas (?:the )?(?:change|fix) requests\b/gi,
      'The workflow uses external pull request review threads to decide which changes to implement and push.',
      { raw: true, snykEvidence: 'linked-document' });
  }
  if (!limited && /\b(?:related|named|target) (?:PRs?|pull requests?)\b/i.test(source) &&
      /\b(?:post(?:s|ing)? comments?|PR descriptions?|pull request descriptions?)\b/i.test(source)) {
    scanMatches('third-party-content', readsReviewDiff,
      'The review workflow reads changes submitted by other contributors.',
      { assessment: 'capability', raw: true, snykEvidence: 'manifest' });
  }
  if (!limited && /\bremote MCP server\b/i.test(source) && /\bCRM records\b/i.test(source)) {
    scanMatches('third-party-content', readsCrmRecords,
      'The workflow queries CRM records through a remote MCP service.',
      { assessment: 'capability', raw: true, snykEvidence: 'manifest' });
  }
  if (!limited && /(?:сайтов и репозиториев|из внешних репозиториев)/iu.test(source)) {
    scanMatches('third-party-content', readsCatalogCandidateRu,
      'The workflow reads original prompt or skill definitions from external catalogs.',
      { assessment: 'capability', raw: true, snykEvidence: 'linked-document' });
  }
  if (!limited) scanMatches('third-party-content', extractsReceiptTextJa,
    'The workflow extracts text from received receipts or invoices.',
    { assessment: 'capability', raw: true, snykEvidence: 'linked-document' });
  if (!limited) scanMatches('third-party-content', renderedContent,
    'The workflow reads text or structured content from a rendered page.', {
      assessment: 'capability', snykEvidence: 'direct',
    });
  if (!limited && calendarContext.test(source)) scanMatches('third-party-content', calendarRead,
    'The operation retrieves event text or invitee details that other calendar users can enter.', {
      assessment: 'capability', raw: true, snykEvidence: 'direct',
    });
  if (!limited) scanMatches('third-party-content', calendarReadCommand,
    'The calendar command returns event text that invitees or organizers can write.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('third-party-content', documentIntake,
    'The workflow processes text from an input document whose author can be outside the current session.', {
      assessment: 'capability', snykEvidence: 'direct',
    });
  if (!limited && mediaTextWorkflow.test(source)) scanMatches('third-party-content', mediaIntake,
    'The workflow converts speech from input media into text that the agent can read.', {
      assessment: 'capability', snykEvidence: 'manifest',
      accepts: match => !/^dub\b[^\r\n]*\bvideos$/i.test(match[0]) && !/\b(?:generated|synthetic|sample|example)\b/i.test(nearMatch(match)),
    });
  if (!limited && usesRemoteTranscriptionInput.test(source) && readsTranscriptionOutput.test(source)) {
    scanMatches('third-party-content', remoteTranscriptionInput,
      'The transcription workflow reads text derived from media supplied by a remote URL.', {
        raw: true, assessment: 'capability', snykEvidence: 'linked-document',
      });
  }
  if (!limited && evaluatesVideoText.test(source)) {
    scanMatches('third-party-content', remoteVideoAnalysis,
      'The workflow reads transcribed speech and on-screen text from a video supplied to a remote analysis tool.', {
        assessment: 'capability', raw: true, snykEvidence: 'manifest',
        accepts: match => !illustrativeStep.test(source.slice(Math.max(0, match.index - 90), match.index)),
      });
  }
  if (!limited && source.includes('running ')) {
    scanMatches('unverified-app-evaluator', runsUnpinnedAppEvaluator,
      'A floating registry package from outside the named platform is used to evaluate code in a running app.', {
        raw: true,
        snykEvidence: match => {
          const argument = source.slice(match.index + match[0].length, match.index + match[0].length + 100);
          const readsBooleanFlag = /^[ \t]+(["'])(?:[A-Za-z_$][\w$]*)\1\x60[ \t]+(?:->|→)[ \t]+\x60(?:true|false)\x60(?=[ \t]*(?:\r?\n|$))/.test(argument);
          return readsBooleanFlag ? 'reference-example' : 'linked-document';
        },
        accepts: match => {
          const [, name, platform] = match;
          const tool = name.toLowerCase();
          const firstParty = platform.toLowerCase();
          return tool !== firstParty && !tool.startsWith('@' + firstParty + '/') &&
            !tool.startsWith(firstParty + '-') && !illustrativeStep.test(nearMatch(match));
        },
      });
  }
  if (!limited && source.includes('@deprecated')) scanMatches('third-party-content', readsDependencyAnnotations,
    'The workflow resolves installed dependency source and reads its annotations to guide the migration.', {
      assessment: 'capability', raw: true, snykEvidence: 'linked-document',
    });
  if (!limited && acceptsPublicMedia.test(source) && createsTimestampedTranscript.test(source)) {
    scanMatches('third-party-content', resolvesPublicTranscript,
      'The workflow resolves a public media URL and brings its transcript into the editing task.', {
        assessment: 'capability', snykEvidence: 'manifest',
      });
  }
  if (!limited && (source.includes('requests.get(') || source.includes('httpx.get('))) scanMatches('third-party-content', consumedHttpResponse,
    'The code makes a remote request and consumes its response body.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\b(?:import|from)\s+(?:requests|httpx|urllib)\b/.test(source)) {
    scanMatches('third-party-content', sessionHttpResponse,
      'The script parses the body of an HTTP read.', {
        assessment: 'capability', raw: true, snykEvidence: 'invoked-script',
        accepts: match => !/\b(?:localhost|127\.0\.0\.1)\b/.test(match[0]),
      });
  }
  if (!limited) scanMatches('third-party-content', readExplicitEndpoint,
    'The workflow reads a response body from a specified network endpoint.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('third-party-content', chineseExternalRead,
    'The instructions read pages, messages, or comments that outside authors can control.', {
      assessment: 'capability', snykEvidence: 'manifest',
      accepts: match => {
        const before = match.input.slice(Math.max(0, match.index - 75), match.index);
        return !/(?:不要|不得|禁止|切勿|不应|避免)[^。！？；\r\n]{0,12}$/.test(before.slice(-16)) &&
          !/\bWebFetch\(\*\)`?[ \t]*[—:-][ \t]*允许[ \t]*$/iu.test(before);
      },
    });
  if (!limited) scanMatches('system-modification', systemChange,
    'This instruction can change host state. Review the permission boundary and the scope of the change.', { assessment: 'capability' });

  if (!limited && /\bKeychain access\b[^\r\n]{0,85}\bdecrypt the cookie\b/i.test(source)) {
    scanMatches('system-modification', persistsExtractedAppCookie,
      'The tool decrypts another app’s session cookie through the host Keychain and persists it in user configuration.', {
        snykEvidence: 'manifest',
        accepts: match => {
          const prior = source.slice(Math.max(0, match.index - 650), match.index);
          return prior.includes(match[1]) && /\bauto-extracted from the\b[^\r\n]{0,45}\bdesktop app\b/i.test(prior);
        },
      });
  }
  if (!limited) scanMatches('system-modification', systemCommand,
    'This command can change host state. Review the permission boundary and the scope of the change.', { assessment: 'capability', raw: true });
  if (!limited && /\bLibrary\/LaunchAgents\b/.test(source) && /<key>StartCalendarInterval<\/key>/.test(source)) {
    scanMatches('system-modification', loadsScheduledLaunchAgent,
      'The invoked script writes a scheduled LaunchAgent and loads it into the user’s session.', {
        assessment: 'capability', raw: true, snykEvidence: 'invoked-shell', accepts: match => {
          const before = match.input.slice(0, match.index);
          return new RegExp(String.raw`\bcat[ \t]+>[ \t]+"?\$\{?${match[1]}\}?"?[ \t]+<<`).test(before);
        },
      });
  }
  if (!limited) scanMatches('system-modification', enablesNewLinuxService,
    'The deployment installs and enables a new system service.', {
      assessment: 'capability', raw: true, snykEvidence: 'linked-document',
    });
  if (!limited && /\bself-hosted \(auto-install\)/i.test(source) && /\bauto-detects AI API keys from your environment\b/i.test(source)) {
    scanMatches('suspicious-download', installsUnpinnedBackgroundService,
      'The fallback installs an unpinned global package and starts its service without an interactive setup.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          const name = match[1].replace(/-app$/i, '');
          const after = match.input.slice(match.index + match[0].length, match.index + 280);
          return new RegExp(String.raw`\b${name}[ \t]+init[ \t]+--non-interactive\b[^\r\n]{0,110}\b${name}[ \t]+start\b`, 'i').test(after);
        },
      });
  }
  if (!limited && /\breal human testers\b/i.test(source) && /\btester records their screen and microphone\b/i.test(source) &&
      /\buse the hosted version at\b[^\r\n]{0,30}https:\/\//i.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest', assessment: 'capability' };
    scanMatches('third-party-content', readsHumanTestReport,
      'The workflow pulls reports based on feedback from external testers.', options);
    if (!limited) scanMatches('runtime-dependency', readsHumanTestReport,
      'The workflow uses the hosted test report to determine subsequent work.', options);
  }
  if (!limited && /\bpython3 --version\s*\|\|\s*python --version\b/.test(source)) {
    scanMatches('system-modification', installsPythonPrerequisite,
      'The prerequisite setup installs Python through the system package manager with elevated privileges.', {
        assessment: 'capability', raw: true, snykEvidence: 'python-tool-prerequisite', accepts: match => {
          const before = match.input.slice(Math.max(0, match.index - 290), match.index);
          return /\bif Python is not installed\b/i.test(before) && /\bUbuntu\/Debian\b/i.test(before);
        },
      });
  }
  if (!limited && source.includes(' host setup') && /\b[\w.-]+ host setup\b/.test(source)) {
    scanMatches('system-modification', startsServiceDuringHostSetup,
      'The host setup installs a release and starts a persistent service.', {
        assessment: 'capability', snykEvidence: 'linked-document', accepts: match => {
          const before = match.input.slice(Math.max(0, match.index - 470), match.index);
          return /\bhost setup\b/i.test(before) && /\bwrites? [`"']?host\.json\b/i.test(before);
        },
      });
  }
  if (!limited && /-ItemProperty/i.test(source)) scanMatches('system-modification', writesWindowsRegistry,
    'A PowerShell helper writes to the current-user or machine registry.', {
      assessment: 'capability', raw: true, snykEvidence: 'registry-script',
    });
  if (!limited && /^[ \t]*def[ \t]+install![ \t]*\r?$/m.test(source) && /\bclass\s+\w+\s*<\s*Step\b/.test(source)) {
    scanMatches('system-modification', elevatedSetupExample,
      'The setup template enables a generated installation step to run a command with elevated permissions.', {
        assessment: 'capability', raw: true, snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\.bat\b/i.test(source)) scanMatches('system-modification', windowsPolicyBypass,
    'The batch launcher runs PowerShell with execution policy bypassed for that process.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\bpowershell\b/i.test(source) && /\.bat\b/i.test(source)) scanMatches('unverified-windows-package', numericPackagePublisher,
    'The README points to a numeric publisher for an executable Windows package.', {
      raw: true, snykEvidence: 'windows-package-publisher',
    });
  if (!limited && hostServiceContext.test(source)) scanMatches('system-modification', serviceLifecycleCommand,
    'The tool can install or remove a service on the host.', { assessment: 'capability', snykEvidence: 'manifest' });
  if (!limited) scanMatches('system-modification', disablesLaunchdByMovingPlist,
    'The cleanup disables automatic service startup by renaming its launchd property list.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited && /--systemd/i.test(source)) scanMatches('system-modification', setupSystemService,
    'The setup creates or starts an operating-system service on the host.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest', accepts: match => {
        const after = source.slice(match.index + match[0].length, match.index + match[0].length + 220);
        return !negated(source, match.index) &&
          /--systemd\b[^\r\n]{0,125}\b(?:creates?|installs?|registers?|starts?)\b[^\r\n]{0,65}\b(?:systemd[ \t]+)?service\b/i.test(after);
      },
    });
  if (!limited && /\bsudo[ \t]+-n[ \t]+true\b/.test(source)) scanMatches('system-modification', privilegedCacheRemoval,
    'The cleanup removes system-managed package or journal data with elevated permissions.', {
      raw: true, assessment: 'capability', snykEvidence: 'documented-cache-cleanup',
      accepts: match => {
        const before = source.slice(source.lastIndexOf('\n', match.index) + 1, match.index);
        return !negated(source, match.index) &&
          (!before.trim() || /^\s*add_cand\b[^\r\n]{0,170}\bsystem[ \t]+cmd\b/.test(before));
      },
    });
  if (!limited) scanMatches('system-modification', mutatesMacKeychain,
    'The command changes a macOS keychain or its access settings.', { assessment: 'capability', raw: true, snykEvidence: 'manifest' });
  if (!limited) scanMatches('system-modification', mutatesMacSystemTrust,
    'The privileged command adds a certificate to the macOS system trust store.', {
      assessment: 'capability', raw: true, snykEvidence: 'linked-document',
    });
  if (!limited && /\/etc\//i.test(source)) scanMatches('system-modification', systemConfigWrite,
    'The workflow writes system-managed configuration files.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('system-modification', tracewayHostInstaller,
    'The host installs the official telemetry collector as a persistent system service.', {
      assessment: 'capability', raw: true, snykEvidence: 'manifest',
      accepts: match => documentsPublishedTool('traceway-otel-agent', source, match.index) &&
        /\b(?:systemd|launchd|Windows service)\b/i.test(source.slice(Math.max(0, match.index - 475), match.index + 850)),
    });
  if (!limited) scanMatches('runtime-dependency', executeClonedCode,
    'The workflow obtains a Git checkout from an external source and then installs or executes code from it.', {
      accepts: match => !/(?:\r\n|\r|\n)[ \t]*(?:[\x60~]{3}|#)|\b(?:checkout|switch)[ \t]+(?:--detach[ \t]+)?[a-f0-9]{40}\b/i.test(match[0]),
      raw: true, snykEvidence: clonedDependencyEvidence,
    });
  if (!limited) scanMatches('runtime-dependency', buildsClonedApp,
    'The setup runs the development build from a mutable remote checkout.', {
      raw: true, snykEvidence: 'linked-document',
      accepts: match => !negated(source, match.index),
    });
  if (!limited && source.includes('cloudflared')) {
    const tunnels = [...source.matchAll(publicLoopbackTunnel)];
    const options = {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const end = match.index + match[0].length;
        const following = source.slice(end, end + 1200);
        const setup = following.split(/\r?\n[ \t]*[`~]{3}/, 1)[0];
        if (!/^[ \t]*python(?:3)?[ \t]+-m[ \t]+pip[ \t]+install[ \t]+-r[ \t]+[^\r\n]{1,140}$/im.test(setup) ||
            !/^[ \t]*python(?:3)?[ \t]+(?:[\w.-]+\/)*[\w.-]+\.py\b/im.test(setup) ||
            /\bgit[ \t]+(?:checkout|switch|verify-commit|verify-tag)\b/i.test(setup)) return false;
        return tunnels.some(tunnel => tunnel.index > end &&
          new RegExp(String.raw`\b(?:127\.0\.0\.1|localhost):` + tunnel[1] + String.raw`\b`, 'i')
            .test(following.slice(0, Math.min(following.length, tunnel.index - end))));
      },
    };
    scanMatches('suspicious-download', checkoutForLocalPythonService,
      'The setup starts code from a mutable checkout and exposes the resulting local service through a public tunnel.', options);
    if (!limited) scanMatches('runtime-dependency', checkoutForLocalPythonService,
      'The public service runs code obtained from a mutable repository at setup time.', options);
  }
  if (!limited && /\bnpx[ \t]+skills[ \t]+add\b/.test(source)) {
    scanMatches('runtime-dependency', installsSkillFromMutableSource,
      'The installation guide fetches a mutable skill that bundles lifecycle code.', {
        raw: true, snykEvidence: 'readme-lifecycle-install',
      });
  }
  if (!limited && delegatesNativeHostSetup.test(source)) {
    const setups = new Set([...source.matchAll(runsNativeHostSetup)]
      .filter(match => !negated(source, match.index)).map(([, namespace]) => namespace.toLowerCase()));
    scanMatches('runtime-dependency', runsNativeHostSetup,
      'The native host setup runs an unpinned package from a registry.', { raw: true, snykEvidence: 'manifest' });
    if (!limited) scanMatches('suspicious-download', repairsSkillFromMutableSource,
      'The repair workflow installs a mutable skill checkout alongside an unpinned native host setup.', {
        raw: true, snykEvidence: 'manifest', accepts: ([, repository]) => setups.has(repository.toLowerCase()),
      });
  }
  if (!limited) scanMatches('suspicious-download', clonesAgentSkill,
    'The setup clones a mutable repository into the agent’s skill directory and runs its helper.', {
      raw: true, snykEvidence: 'readme-agent-skill-checkout', accepts: match => {
        const before = source.slice(Math.max(0, match.index - 235), match.index);
        const after = source.slice(match.index + match[0].length, match.index + match[0].length + 480);
        return /\bJoin-Path[ \t]+\$env:CODEX_HOME[ \t]+["']skills["']|\.codex\\skills\b/.test(before) &&
          /\bpython[ \t]+-m[ \t]+pip[ \t]+install[ \t]+-r[ \t]+requirements\.txt\b/i.test(after) &&
          /\bpython[ \t]+scripts\\[\w.-]+\.py\b/i.test(after) &&
          !/\bgit[ \t]+checkout\b[^\r\n]{0,60}\b[a-f0-9]{40}\b/i.test(after);
      },
    });
  if (!limited && /\bRun `bootstrap\.js`/i.test(source)) {
    scanMatches('suspicious-download', clonesWorkspaceBootstrap,
      'The setup clones an unpinned repository into an agent skill directory and runs its bundled installer.', {
        raw: true, snykEvidence: 'cloned-workspace-bootstrap', accepts: match => {
          const after = source.slice(match.index + match[0].length, match.index + match[0].length + 950);
          return /\bRun `bootstrap\.js`/i.test(after) && !/\bgit[ \t]+(?:checkout|switch)\b[^\r\n]{0,65}\b[a-f0-9]{40}\b/i.test(after);
        },
      });
  }
  if (!limited && source.includes('--agent')) {
    const bootstrap = { raw: true, snykEvidence: 'cloned-python-agent-bootstrap',
      accepts: match => !negated(source, match.index) };
    scanMatches('suspicious-download', clonesPythonAgentBootstrap,
      'The installation runs an agent bootstrap script immediately after cloning a mutable repository.', bootstrap);
    scanMatches('runtime-dependency', clonesPythonAgentBootstrap,
      'Installation depends on executable Python from a mutable repository checkout.', bootstrap);
  }
  if (!limited && pythonScaffoldCommand.test(source) && !source.matchAll(globalSkillInstaller).next().done) {
    scanMatches('suspicious-download', clonesWorkspaceBootstrap,
      'The installation guide uses a mutable Git checkout that supplies an executable workspace scaffold.', {
        raw: true, snykEvidence: 'readme-python-scaffold', accepts: match => {
          const repository = /github\.com\/([\w.-]+\/[\w.-]+)\.git\b/i.exec(match[0])?.[1];
          const after = source.slice(match.index + match[0].length, match.index + match[0].length + 1600);
          return repository && [...source.matchAll(globalSkillInstaller)].some(([, name]) => name === repository) &&
            !/\bgit[ \t]+(?:checkout|switch)\b[^\r\n]{0,65}\b[a-f0-9]{40}\b/i.test(after);
        },
      });
  }
  if (!limited) {
    const bootstrap = { raw: true, snykEvidence: 'readme-skill-bootstrap',
      accepts: match => !negated(source, match.index) };
    scanMatches('suspicious-download', remoteSkillBootstrap,
      'The installation guide pipes a mutable remote skill bootstrap into a shell.', bootstrap);
    scanMatches('runtime-dependency', remoteSkillBootstrap,
      'The bootstrap downloads the skill and its executable helper from a mutable branch.', bootstrap);
    scanMatches('runtime-dependency', targetsSkillInRemoteBootstrap,
      'The installer passes this skill’s name to a script loaded from a mutable branch.', {
        raw: true, snykEvidence: 'targeted-skill-bootstrap',
      });
  }
  if (!limited && source.includes('git clone') && source.includes('ln -s')) {
    scanMatches('runtime-dependency', clonesAndLinksSkill,
      'The install links an unpinned Git checkout into the agent’s active skills directory.',
      { raw: true, snykEvidence: 'readme-linked-mutable-skill' });
  }
  if (!limited && /\bgh[ \t]+attestation[ \t]+verify\b/i.test(source) && /\/releases\//i.test(source)) {
    const active = removeMarkdownComments(source);
    const download = /^[ \t]*(?:\$[ \t]+)?(?:curl|wget)\b[^\r\n]{0,150}https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/releases\/(?:latest\/download|download\/[\w.-]+)\/([\w.-]+)(?=[\s\x60"']|$)/gim;
    for (const match of active.matchAll(download)) {
      const asset = match[1];
      if (/\.(?:sha256|sig|asc|md|sh|ps1)$/i.test(asset)) continue;
      const end = match.index + match[0].length;
      const following = active.slice(end, end + 2050);
      const name = asset.replaceAll('.', '\\.');
      const run = new RegExp('^[ \\t]*(?:\\$[ \\t]+)?(?:sudo[ \\t]+)?\\./' + name + '(?=[\\s\\x60]|$)', 'im').exec(following);
      const attestation = new RegExp('\\bgh[ \\t]+attestation[ \\t]+verify[ \\t]+["\']?(?:\\./)?' + name + '(?=[\\s\\x60"\']|$)', 'i');
      const verify = attestation.exec(following);
      const preceding = active.slice(Math.max(0, match.index - 350), match.index);
      if (!run || !verify || verify.index <= run.index || attestation.test(preceding) ||
          /\b(?:verify|check|validate)\b[^.\r\n]{0,70}\b(?:attestation|signature)\b[^.\r\n]{0,55}\b(?:before (?:running|executing)|first)\b/i.test(preceding)) continue;
      const intervening = following.slice(0, run.index);
      if (!intervening.includes(asset + '.sha256') || !/\b(?:sha256sum[ \t]+(?:-c|--check)|shasum[ \t]+-a[ \t]+256[ \t]+-c)\b/.test(intervening)) continue;
      add('suspicious-download', match.index, match[0].length,
        'The example executes the release binary before verifying its provenance attestation.',
        'capability', false, 'release-provenance-order');
      if (limited) break;
    }
  }
  if (!limited) scanMatches('suspicious-download', executablePlaceholderCheckout,
    'The workflow makes a shell script executable after cloning from a placeholder repository owner.', {
      accepts: match => !/^[ \t]*(?:git[ \t]+(?:checkout|switch|verify-commit)|(?:sha256sum|shasum|gpg)\b)/im.test(match[0]),
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('unverified-wrapper-setup', installsClonedWrapper,
    'The README installs a command wrapper from a mutable agent skill checkout.', {
      raw: true, snykEvidence: 'installed-cloned-wrapper',
      accepts: match => !/\r?\n[ \t]*[\x60~]{3}|\b(?:checkout|switch)[ \t]+(?:--detach[ \t]+)?[a-f0-9]{40}\b/i.test(match[0]),
    });
  if (!limited) for (const match of source.matchAll(numericPagesCheckout)) {
    if (negated(source, match.index)) continue;
    const { index, 0: checkout } = match;
    add('suspicious-download', index, checkout.length,
      'The Git checkout uses a numeric GitHub Pages hostname instead of a repository URL.', undefined, false, 'manifest');
    add('runtime-dependency', index, checkout.length,
      'The checkout depends on a mutable source with no visible repository provenance.', undefined, false, 'manifest');
    const next = source.slice(index + checkout.length, index + checkout.length + 235)
      .split(/\r?\n[ \t]*[\x60~]{3}/, 1)[0];
    const directory = deceptiveCheckoutDirectory.exec(next);
    if (directory && runsCheckoutInstaller.test(next.slice(directory.index + directory[0].length))) {
      add('opaque-tool-installation', index, checkout.length,
        'The workflow runs an installer from an obscured checkout named for an exploitation tool.',
        undefined, false, 'manifest');
      if (!limited && /-dupe\b/i.test(directory[0]) && /\bgame\b/i.test(source) && /\binventor(?:y|ies)\b/i.test(source)) {
        add('dangerous-code-pattern', index, checkout.length,
          'An automated installer for a game inventory workflow comes from an obscured checkout named for item duplication.',
          undefined, false, 'manifest');
      }
    }
    if (limited) break;
  }
  if (!limited) scanMatches('runtime-dependency', remoteCodeInstall,
    'The package manager installs executable code from a Git location.', {
      accepts: match => (!match[1] || handlesChannelWorkerInput) && !/@[a-f0-9]{40}(?:[?#]|$)/i.test(match[0]),
      raw: true, snykEvidence: 'direct',
    });
  if (!limited && source.includes('jscodeshift')) {
    const linkedCodemod = { raw: true, snykEvidence: 'linked-document' };
    scanMatches('suspicious-download', usesMutableRemoteCodemod,
      'The codemod loads executable transformation code from a mutable remote branch.', linkedCodemod);
    if (!limited) scanMatches('runtime-dependency', usesMutableRemoteCodemod,
      'The transformation code can change independently of the skill.', linkedCodemod);
  }
  if (!limited) scanMatches('suspicious-download', plainHttpPackageIndex,
    'The package install example retrieves code over an unencrypted HTTP connection.', {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const host = match[1];
        return /\.[a-z]{2,}$/i.test(host) && !/\.(?:local|localhost|test|invalid)$/i.test(host);
      },
    });
  if (!limited) scanMatches('suspicious-download', exampleRuntimeScript,
    'The example identifies a remote JavaScript payload as input to a runtime evaluator.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\bimage:[ \t]*['"][\w./-]+:latest['"]/i.test(source) &&
      /\b(?:cmd|command):[ \t]*['"]docker['"][ \t]*,[ \t]*args\b/.test(source) &&
      /\[[ \t]*['"]run['"][ \t]*,[ \t]*['"]--rm['"]/.test(source)) {
    scanMatches('runtime-dependency', pullsSelectedContainer,
      'The helper pulls and launches an executable container from a mutable registry tag.', {
        raw: true, snykEvidence: 'documented-container-runner',
      });
  }
  if (!limited) scanMatches('runtime-dependency', remoteModule,
    'The code imports an executable module directly from an external URL.', { raw: true, snykEvidence: importedAtRuntime });
  if (!limited) scanMatches('runtime-dependency', registryModule,
    'The code loads a module identified by an external repository path.', { raw: true, snykEvidence: 'direct' });
  if (!limited) scanMatches('runtime-dependency', hostedPackageCommand,
    'The package runner executes code resolved from an external GitHub repository.', {
      raw: true, snykEvidence: 'direct',
      accepts: match => !/^[a-f\d]{40}$/i.test(match[1] ?? ''),
    });
  if (!limited && paidApiPurpose.test(source.slice(0, 2048))) {
    scanMatches('runtime-dependency', registryPaidCall,
      'The paid API workflow runs a registry package as part of making or testing payments.', {
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited && buildsNewWorktree.test(source)) scanMatches('runtime-dependency', updatesRemoteWorktree,
    'The workflow builds from a Git worktree created at a branch that can change between runs.', {
      raw: true, snykEvidence: 'manifest',
      accepts: match => buildsNewWorktree.test(source.slice(match.index + match[0].length, match.index + match[0].length + 2600)),
    });
  if (!limited && /\bmcp[ \t]+(?:add|register)\b/i.test(source)) {
    const packages = new Set([...source.matchAll(mcpPackageCommand)].map(match => match[1].toLowerCase()));
    scanMatches('runtime-dependency', mcpPackageCommand,
      'The MCP setup launches a registry package whose version can change between runs.', {
        raw: true,
        accepts: match => {
          if (/^v?\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?$/.test(match[2] ?? '')) return false;
          const before = source.slice(Math.max(0, match.index - 460), match.index);
          if (/(?:configuration examples|examples? \(only when|package reference \(for version comparisons)/i.test(before)) return false;
          return packages.size > 1 || /\b(?:install|register|add|configure) (?:each|required|the required)\b|^[ \t]*(?:install(?:ation)?|설치):[ \t]*$/im.test(before);
        },
        snykEvidence: 'linked-document',
      });
  }
  if (!limited) scanMatches('runtime-dependency', runtimeSchema,
    'A remotely retrieved schema determines the API operations available during the run.', { snykEvidence: 'direct' });
  if (!limited && apiSpecCodegen.test(source)) scanMatches('runtime-dependency', readsRuntimeApiSpec,
    'The runtime API specification determines the client code the workflow generates.', {
      raw: true, assessment: 'capability', snykEvidence: 'manifest',
    });
  if (!limited) scanMatches('runtime-dependency', companionSkillInstall,
    'The workflow requires installing another skill from an external source before continuing.', {
      raw: true, snykEvidence: 'manifest',
      accepts: match => !illustrativeStep.test(nearMatch(match)),
    });
  if (!limited && source.includes('/api/skills/')) {
    const options = { raw: true, snykEvidence: 'manifest', accepts: usesUnverifiedMarketplaceDownload };
    scanMatches('suspicious-download', marketplaceSkillDownloadLink,
      'The workflow selects skill downloads through a remote marketplace without an integrity check.', options);
    if (!limited) scanMatches('runtime-dependency', marketplaceSkillDownloadLink,
      'The remote marketplace determines which skill package the workflow receives.', options);
  }
  if (!limited && /\bgo[ \t]+run\b/i.test(source) && /(?:Go CLI|Go command[- ]line tool)/i.test(source.slice(0, 1600))) {
    const run = [...source.matchAll(runsRemoteGoTool)];
    if (run.some(match => /\blint$/i.test(match[0])) && run.some(match => /\bbuild$/i.test(match[0]))) {
      scanMatches('runtime-dependency', runsRemoteGoTool,
        'The workflow executes the remote Go module as part of checking and building the requested output.', {
          assessment: 'capability', raw: true, snykEvidence: 'linked-document',
        });
    }
  }
  if (!limited && /https:\/\/[\w.-]+\/(?:[\w./-]+\/)?llms\.txt\b/i.test(source)) {
    scanMatches('third-party-content', readsVersionedDocIndex,
      'The workflow reads a remote documentation index and uses the sources it selects for the installed version.', {
        raw: true, assessment: 'capability', snykEvidence: 'manifest', accepts: match => {
          const end = match.index + match[0].length;
          const follow = source.slice(end, end + 400);
          return /\bpass result paths to[ \t]+\x60get_doc\x60[ \t]+unchanged\b/i.test(follow) &&
            /https:\/\/[\w.-]+\/llms\.txt\b/i.test(follow);
        },
      });
    scanMatches('runtime-dependency', fetchesRemoteDocsForAnswer,
      'The workflow fetches mutable remote documentation and uses its text to answer the user.', {
        snykEvidence: 'manifest',
      });
    for (const match of source.matchAll(gatewaySetupGuide)) {
      if (limited) break;
      const before = source.slice(Math.max(0, match.index - 510), match.index).split(/^#{1,6}\s+/m).at(-1);
      const afterStart = match.index + match[0].length;
      const after = source.slice(afterStart, afterStart + 270).split(/^#{1,6}\s+/m)[0];
      if (!liveGatewayConnection.test(before) || !Array.from(before.matchAll(trackedGatewayLink)).some(
        endpoint => endpoint[1].toLowerCase() === match[1].toLowerCase())) continue;
      add('runtime-dependency', match.index, match[0].length,
        'A live account setup directs the agent to a mutable guide on the gateway host.', 'capability', false, 'manifest');
      const signIn = gatewaySignIn.exec(after);
      if (signIn && !gatewayUserApproval.test(before + after) && !negated(after, signIn.index)) {
        add('promotional-account-connection', afterStart + signIn.index, signIn[0].length,
          'A tracked gateway link directs the agent to sign in to live accounts without a confirmation step.',
          undefined, false, 'manifest');
      }
    }
  }
  if (!limited && /https:\/\/[^\s`"']+\/(?:docx|docs?|wiki)\//i.test(source) &&
      /(?:用户提供的(?:链接|文档)|文档链接|user[- ](?:provided|supplied) (?:document )?URL)/iu.test(source)) {
    scanMatches('third-party-content', opensSuppliedExternalDocument,
      'The workflow brings the supplied document’s text into the agent’s context.', {
        assessment: 'capability', raw: true, snykEvidence: 'linked-document',
      });
    scanMatches('runtime-dependency', opensSuppliedExternalDocument,
      'The user-provided document is fetched at runtime and determines the content the workflow generates.', {
        raw: true, snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\beach result has[ \t]+`?install_ref\b/i.test(source)) {
    scanMatches('runtime-dependency', installsFromSearchResult,
      'The workflow installs agent instructions from a source selected from public search results.', {
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('runtime-dependency', remoteCompanionSkillUse,
    'The workflow loads an unpinned companion skill before performing the task.', {
      raw: true, snykEvidence: 'linked-document', accepts: match =>
        /使用前必须加载技能|\bmust load (?:the |this )?skill before use\b/iu.test(
          source.slice(Math.max(0, match.index - 160), match.index)),
    });
  if (!limited) scanMatches('runtime-dependency', latestInstallerCommand,
    'The documented setup executes the newest published version of a registry package.', {
      raw: true, snykEvidence: 'linked-document', accepts: match => {
        const before = source.slice(Math.max(0, match.index - 160), match.index);
        const after = source.slice(match.index + match[0].length, match.index + match[0].length + 270);
        return /\bInstalaci[oó]n MCP\b|\bMCP (?:installation|setup)\b/iu.test(before) ||
          /\b(?:quickstart|installation)\b/i.test(before) && /\bthe installer prompts\b/i.test(after);
      },
    });
  if (!limited) scanMatches('runtime-dependency', isolatedToolInstaller,
    'The setup runs an unpinned package from the registry to install its dependencies.', {
      raw: true, snykEvidence: 'linked-document', accepts: match =>
        source.split(/\r?\n/).some(line => line.trim() === `pipx run ${match[1]} install`),
    });
  if (!limited && /\blocal MCP server\b/i.test(source) && /\bserver starts automatically\b/i.test(source)) {
    scanMatches('suspicious-download', downloadsReleaseBinary,
      'The setup obtains an unverified release binary for the MCP server.', {
        raw: true, snykEvidence: 'manifest', accepts: match => !mentionsReleaseIntegrity.test(nearMatch(match)),
      });
  }
  if (!limited && preparesWindowsExecutable.test(source) && publishesReleaseFromTag.test(source) &&
      /\bgh[ \t]+release[ \t]+(?:list|view)\b/i.test(source) && !mentionsReleaseIntegrity.test(source)) {
    scanMatches('suspicious-download', publishesToReleaseRepository,
      'The workflow publishes a Windows executable through a release tag without a documented integrity check.', {
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('runtime-dependency', gitToolSetup,
    'The setup executes a tool from an external Git tag.', {
      raw: true, snykEvidence: 'linked-document',
    });
  if (!limited) scanMatches('suspicious-download', unpinnedGitTool,
    'The workflow runs its ordinary commands from a Git repository without pinning a revision.', {
      raw: true, snykEvidence: 'manifest', accepts: runsOrdinaryCommandsFromGit,
    });
  if (!limited) scanMatches('runtime-dependency', unpinnedGitTool,
    'The workflow loads the command implementation from a mutable Git source at runtime.', {
      raw: true, snykEvidence: 'manifest', accepts: runsOrdinaryCommandsFromGit,
    });
  if (!limited) for (const block of source.matchAll(requirementsBlock)) {
    if (/^\s*--require-hashes\b/m.test(block[1])) continue;
    const match = block[1].matchAll(releaseWheel).next().value;
    if (!match) continue;
    const start = block.indices[1][0] + match.index;
    add('suspicious-download', start, match[0].length,
      'The dependency recipe installs a wheel from a GitHub release without a recorded hash.',
      undefined, false, 'requirements-recipe');
    if (!limited) add('runtime-dependency', start, match[0].length,
      'The dependency recipe uses the release tag to select the wheel at installation time.',
      undefined, false, 'requirements-recipe');
    if (limited) break;
  }
  if (!limited && installsSkillArchive.test(source)) {
    scanMatches('suspicious-download', downloadsSkillRelease,
      'The package README installs an unverified release archive into the agent’s skill directory.', {
        raw: true, snykEvidence: 'agent-skill-release-archive', accepts: match => {
          const end = match.index + match[0].length;
          const steps = source.slice(end, end + 640);
          return savesSkillArchive.exec(steps)?.[1] === match[1] && installsSkillArchive.exec(steps)?.[1] === match[1] &&
            !mentionsReleaseIntegrity.test(source.slice(Math.max(0, match.index - 240), end + 640));
        },
      });
  }
  if (!limited) scanMatches('suspicious-download', importsMutableSkillZip,
    'The installation guide imports the latest release ZIP into the agent’s skills settings without an integrity check.', {
      raw: true, snykEvidence: 'agent-skill-release-archive',
      accepts: match => !mentionsReleaseIntegrity.test(match.input.slice(Math.max(0, match.index - 160), match.index + match[0].length)),
    });
  if (!limited && /\bimport\b[^;]{0,300}\bfrom[ \t]+['"]remotion['"]/.test(source)) {
    scanMatches('suspicious-download', renderedInstallExample,
      'The catalogued animation displays a command to install software from a mutable checkout.', {
        raw: true, snykEvidence: 'rendered-install-recipe', accepts: match =>
          new RegExp(String.raw`>[^<>{}\r\n]{0,65}\{[ \t]*${match.groups.binding}[ \t]*\}[^<>{}\r\n]{0,30}</`).test(source),
      });
  }
  if (!limited && /\b(?:playwright|puppeteer|selenium)\b/i.test(source)) {
    const beforeDownloadChecks = results.length;
    scanMatches('suspicious-download',
      /\b(?:bypass(?:es|ing)?|circumvent(?:s|ing)?)\s+(?:the\s+)?(?:Cloudflare|anti-bot (?:protection|checks?))\b[^.!?;\r\n]{0,45}\b(?:downloads?|downloading)\b|\b(?:downloads?|downloading)\b[^.!?;\r\n]{0,45}\b(?:bypass(?:es|ing)?|circumvent(?:s|ing)?)\s+(?:the\s+)?(?:Cloudflare|anti-bot (?:protection|checks?))\b|绕(?:过)?[ \t]*Cloudflare\b[ \t]*下载|下载[^。！？\r\n]{0,45}绕(?:过)?[ \t]*Cloudflare\b/gi,
      'The workflow retrieves files from an external source by bypassing its download protection.', {
        raw: true, snykEvidence: 'linked-document', accepts: match => {
          const context = nearMatch(match);
          return !/\b(?:mock|local test server|our own|authorized test)\b/i.test(context) &&
            !/(?:不要|禁止|不得)[^，。！？\r\n]{0,35}绕(?:过)?[ \t]*Cloudflare/i.test(context);
        },
      });
    if (!limited && results.length > beforeDownloadChecks) {
      scanMatches('system-modification', /\bpip3?[ \t]+install\b[^\r\n;|&]{0,180}[ \t]--break-system-packages\b/gi,
        'The download setup disables the Python installer’s protection for system-managed packages.',
        { raw: true, snykEvidence: 'linked-document' });
    }
  }
  if (!limited && source.includes('HF_ENDPOINT')) {
    const mirror = /\bHF_ENDPOINT[ \t]*=[ \t]*["']?(https:\/\/[a-z0-9.-]+)(?=[/"'\x60 \t\r\n]|$)/gi;
    scanMatches('suspicious-download', mirror,
      'The workflow configures an alternate model-download host before loading a model without a verified digest.', {
        raw: true, snykEvidence: 'download-model-from-alternate-host', accepts: match => {
          const host = match[1].slice('https://'.length).toLowerCase();
          const context = source.slice(Math.max(0, match.index - 200), match.index + match[0].length + 140);
          return host.includes('.') && !/^(?:huggingface\.co|hf\.co|localhost)$/i.test(host) &&
            !/^(?:127\.|0\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)|(?:^|\.)example\.(?:org|com|net)$|\.(?:example|invalid|local|localhost|test)$/i.test(host) &&
            /\b(?:hugging face|model download)\b/i.test(context) && /\b(?:mirror|download fails?)\b/i.test(context);
        },
      });
  }
  if (!limited) scanMatches('runtime-dependency', pinnedRegistryInitializer,
    'The setup invokes an external registry package to initialize the project.', {
      raw: true, snykEvidence: 'linked-document',
    });
  if (!limited && /\bcpanel[ \t]+deploy:wp\b/i.test(source)) scanMatches('runtime-dependency', downloadsLatestWordPress,
    'The deployment downloads the current WordPress package from a mutable URL.', {
      raw: true, snykEvidence: 'manifest',
    });
  if (!limited && /\binstall\b[^\r\n]{0,75}\btarball\b/i.test(source) &&
      /\bcurl\b[^\r\n]{0,150}\$\{?tarball_url\}?/i.test(source) && !signatureTool.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest' };
    scanMatches('suspicious-download', fetchesMirroredManifest,
      'An unsigned manifest from a primary source or mirror selects the downloadable installer.', options);
    if (!limited) scanMatches('runtime-dependency', fetchesMirroredManifest,
      'The installation depends on the tarball selected by a remote manifest.', options);
  }
  if (!limited && /^#![^\r\n]*\b(?:ba)?sh\b/.test(source) && /\bbrowser (?:bridge|extension)\b/i.test(source) &&
      /https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/releases\b/i.test(source) && /\bunzip\b/i.test(source) &&
      !signatureTool.test(source)) {
    const options = { raw: true, snykEvidence: 'invoked-shell' };
    scanMatches('suspicious-download', fetchesBrowserExtensionZip,
      'The setup obtains an unverified browser extension archive from the latest release.', options);
    if (!limited) scanMatches('runtime-dependency', fetchesBrowserExtensionZip,
      'The setup uses the browser extension archive chosen from the current remote release.', options);
  }
  if (!limited) scanMatches('runtime-dependency', latestGoModule,
    'The workflow installs the current version of a module from an external repository.', {
      raw: true,
      snykEvidence: match => !(/\bgithub\.com\/pengelbrecht\/agentviewer@latest\b/i.test(match[0]) &&
        docsOfferAgentViewerInstallOptions(source)) && 'manifest',
    });
  if (!limited && /\bprimary instructions for this skill\b/i.test(source)) {
    const name = declaredSkillName(source);
    const options = {
      raw: true, snykEvidence: 'registry-instruction-loader', accepts: match => {
        const preceding = source.slice(Math.max(0, match.index - 240), match.index);
        return match[2] === name && /\b(?:follow|use) (?:its|the) (?:printed )?output as (?:the )?primary instructions\b/i.test(preceding);
      },
    };
    scanMatches('runtime-dependency', mutableRegistryInstructions,
      'Output from the registry package supplies this skill’s primary instructions.', options);
  }
  if (!limited && /\bread and follow\b[^.!?;\r\n]{0,100}\$\{[A-Z_]*PLUGIN_ROOT\}\/SKILL\.md\b/i.test(source)) {
    const options = { raw: true, snykEvidence: 'manifest' };
    scanMatches('suspicious-download', bootstrapsReleasedPluginCli,
      'The wrapper delegates installation of a released executable to its plugin without an approval step.', options);
    if (!limited) scanMatches('runtime-dependency', bootstrapsReleasedPluginCli,
      'The workflow relies on a release installer defined outside the wrapper’s instructions.', options);
  }
  if (!limited && checksPackageRegistry.test(source)) {
    scanMatches('third-party-content', consultsExternalSource,
      'The workflow consults package registry content and reads externally maintained documentation or source code.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          const preceding = source.slice(Math.max(0, match.index - 4500), match.index);
          const heading = [...preceding.matchAll(/^#{1,6}\s/gm)].at(-1)?.index ?? 0;
          return checksPackageRegistry.test(preceding.slice(heading));
        },
      });
  }
  if (!limited) for (const block of blocks) {
    const prev = block.group[block.index - 1]?.text ?? '';
    if (illustrativeStep.test(prev) || !requiredStep.test(prev + ' ' + block.text)) continue;
    for (const match of block.text.matchAll(requiredRegistryCommand)) {
      if (negated(block.text, match.index)) continue;
      const command = block.text.slice(match.index).split(/\r?\n/, 1)[0];
      if (/\s--dry-run(?=[\s`]|$)/i.test(command) && /\bpreviews? (?:one|the|this) request\b/i.test(prev)) continue;
      const span = markdownEvidence(source, block, match.index, match[0].length);
      const entry = block.entries[0];
      const indent = entry.start - entry.rowStart;
      const parent = block.group.slice(Math.max(0, block.index - 10), block.index).findLast(item => {
        const first = item.entries[0];
        return first.start - first.rowStart < indent && /^[-*+]\s/.test(first.text);
      });
      const approval = asksBeforePluginInstall.exec(parent?.text ?? '');
      const guarded = /\sinstall$/i.test(match[0]) && approval && !negated(parent.text, approval.index);
      add('runtime-dependency', span.start, span.end - span.start, guarded
        ? 'The skill requires approval before running this non-interactive registry installer.'
        : 'A required step runs a registry package with installation confirmation disabled.',
      guarded ? 'guarded' : undefined, false, guarded ? 'approval-gated' : 'manifest');
      if (limited) break;
    }
    if (limited) break;
  }
  if (!limited) scanMatches('runtime-dependency', shellFromVariableUrl,
    'The workflow passes a download from a variable source directly to an interpreter.', {
      raw: true, snykEvidence: match => !(/\bINSTALL_SCRIPT_URL="\$\{ERDA_CLI_INSTALL_SCRIPT_URL:-https:\/\/erda-release\.oss-cn-hangzhou\.aliyuncs\.com\/cli\/scripts\/install\.sh\}"/.test(source) &&
        /\bcommand -v erda-cli\b/.test(source) && /\$\{INSTALL_SCRIPT_URL\}/.test(match[0])) && 'direct',
    });
  if (!limited && /\bExpand-Archive\b|\b(?:spawn|spawnSync|execFileSync)\([ \t]*["']tar["']/.test(source) &&
      /\b(?:cpSync|copyFileSync)\([^\r\n]{0,150}["'][\w.-]+\.exe["']/.test(source) && !mentionsReleaseIntegrity.test(source)) {
    const options = { raw: true, snykEvidence: 'invoked-script', accepts: match =>
      new RegExp(String.raw`\bfetch\(\s*${match[1]}\s*\)`).test(source) };
    scanMatches('suspicious-download', executableZipSource,
      'The setup fetches an unverified archive and installs the Windows executables it contains.', options);
    if (!limited) scanMatches('runtime-dependency', executableZipSource,
      'The runtime setup installs executables from a remote archive.', options);
  }
  if (!limited && /['"](?:node:)?child_process['"]/.test(source) && /\b(?:scripts\/)?install[\w.-]*\.[cm]?js\b/.test(source)) {
    scanMatches('remote-checkout-installer', clonesWithNode,
      'The installer starts Node inside a source checkout without pinning the Git revision.', {
        raw: true, accepts: installsFromMutableCheckout, snykEvidence: 'invoked-script',
      });
  }
  if (!limited && /\brun the installer\b/i.test(source)) scanMatches('suspicious-download', clonesUnlockedPackage,
    'The installer comes from a repository advertising unlocked premium software.', { raw: true, snykEvidence: 'linked-document' });
  if (!limited && /\bplan-delete\b/.test(source) && /\bdelete\b[^\r\n]{0,100}--trash\b/.test(source)) {
    scanMatches('suspicious-download', numericCleanupPublisher,
      'The skill installs a separate cleanup backend with deletion access without pinning the package version.', {
        raw: true,
        accepts: match => {
          const backend = match[1].replace(/\.+$/, '').replace(/\.git$/, '').replaceAll('.', '\\.');
          return new RegExp('\\bnpm\\s+(?:install|i)\\s+-g\\s+' + backend + '(?=[ \\t\\r\\n`"\']|$)').test(source);
        },
        snykEvidence: 'linked-document',
      });
  }
  if (!limited && /\btarfile\.open\s*\(/.test(source) && /https:\/\/[^\s"']+\.tar(?:\.[a-z0-9]+)?\b/i.test(source) &&
      /\b(?:urlopen|urlretrieve)\s*\(/.test(source)) {
    scanMatches('unfiltered-archive-download', tarExtraction,
      'The download helper extracts a remote tar archive without declaring an extraction filter.', {
        raw: true,
        accepts: match => {
          const context = source.slice(Math.max(0, match.index - 400), match.index);
          const opened = new RegExp('\\btarfile\\.open\\s*\\([^\\r\\n]{0,120}\\)\\s+as\\s+' + match[1] + '\\b');
          const protectiveFilter = /\bfilter\s*=\s*(?!(?:None|["']fully_trusted["'])\b)(?:["'](?:data|tar)["']|[\w.]+)/.test(match[0]);
          return opened.test(context) && !protectiveFilter &&
            !/\b(?:extraction_filter|is_relative_to|data_filter|verify_checksum)\b/.test(context);
        },
        snykEvidence: 'invoked-script',
      });
  }
  if (!limited) for (const match of source.matchAll(sendsClonedInstaller)) {
    if (negated(source, match.index) || /\b(?:checkout|switch)\s+[a-f0-9]{40}\b/i.test(match[0])) continue;
    add('suspicious-download', match.index, match[0].length,
      'The terminal workflow sends a download and install sequence from a mutable Git checkout.', undefined, false, 'manifest');
    add('runtime-dependency', match.index, match[0].length,
      'The installer comes from a repository that can change between runs.', undefined, false, 'manifest');
    add('system-modification', match.index, match[0].length,
      'The unverified installer runs with the target terminal’s host permissions.', 'capability', false, 'manifest');
    if (limited) break;
  }
  if (!limited) scanMatches('runtime-dependency', remotePowerShellBootstrap,
    'The PowerShell pipeline downloads code and immediately evaluates it.', {
      raw: true, snykEvidence: match => {
        const url = /https:\/\/[^\s'"`|]+/.exec(match[0]);
        if (url) {
          try {
            const type = publishedDownloadType(new URL(url[0]));
            if (type === 'installer' && documentsOptionalUvSetup(source, match.index + url.index)) return;
            if (publishedBootstrapTypes.has(type) && documentsPublishedTool(type, source, match.index + url.index)) return;
          } catch {
            // A malformed URL provides no publisher evidence.
          }
        }
        return 'linked-document';
      },
    });
  if (!limited && /\b(?:unavailable|not (?:found|installed))\b[^.!?]{0,55}\binstall the latest\b/i.test(source)) {
    scanMatches('weakened-safeguard', shellReleaseBootstrap,
      'The fallback installation directly evaluates installers from the same mutable release on both platforms.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          const product = match[1].split('/')[1];
          const declared = declaredSkillName(source);
          if (declared !== product && !declared?.startsWith(product + '-')) return false;
          const windowsInstaller = `https://github.com/${match[1]}/releases/latest/download/${match[2]}.ps1`;
          return [...source.matchAll(remotePowerShellBootstrap)].some(command =>
            command[0].includes(windowsInstaller + ' ') && !negated(source, command.index));
        },
      });
  }
  if (!limited && /\b(?:tarball|project archive)\b/i.test(source) && /\bcurl\b/.test(source)) {
    const uploads = [...source.matchAll(archiveUpload)];
    if (uploads.length) scanMatches('unauthenticated-deploy-proxy', deployProxyEndpoint,
      'The deploy helper sends the project archive to an application endpoint without authentication.', {
        raw: true,
        accepts: match => {
          const endpoint = new RegExp('\\$\\{?' + match[1] + '(?![\\w-])');
          return uploads.some(upload => {
            const command = source.slice(upload.index, upload.index + 360).split(/\r?\n/, 1)[0];
            return endpoint.test(command) && !/\bAuthorization\s*:|\s(?:-u|--user|--oauth2-bearer|--netrc)\b/i.test(command);
          });
        },
        snykEvidence: 'deploy-helper',
      });
  }
  if (!limited && /\bupload skill\b/i.test(source)) scanMatches('runtime-dependency', releasedSkillArchive,
    'The setup installs skill instructions obtained from a mutable release URL.', { raw: true, snykEvidence: 'linked-document' });
  if (!limited && source.includes('raw.githubusercontent.com')) {
    const options = {
      raw: true, snykEvidence: 'remote-host-installer', accepts: match => {
        const line = sourceLineAt(source, match.index);
        return mutableWindowsInstallerPath.test(match[0]) && windowsInstallerPolicy.test(line) &&
          !/^\s*#/.test(line) && !/\b(?:verify|check)\b[^\r\n]{0,80}\b(?:digest|signature|checksum)\b/i.test(line);
      },
    };
    scanMatches('suspicious-download', remotePowerShellBootstrap,
      'The documented installer immediately evaluates PowerShell from a mutable branch.', options);
    scanMatches('runtime-dependency', remotePowerShellBootstrap,
      'The installer uses remotely maintained PowerShell code at runtime.', options);
    scanMatches('system-modification', remotePowerShellBootstrap,
      'The remote installation recipe bypasses host script policy for its process.', { ...options, assessment: 'capability' });
  }
  if (!limited) scanMatches('suspicious-download', remotePowerShellBootstrap,
    'The PowerShell installer runs code from a publisher that differs from the nearby source checkout.', {
      raw: true, accepts: conflictingPowerShellPublisher, snykEvidence: 'linked-document',
    });
  if (!limited) scanMatches('system-modification', remotePowerShellBootstrap,
    'The unverified installer runs with the current host PowerShell permissions and can modify host state.', {
      assessment: 'capability', raw: true, accepts: conflictingPowerShellPublisher, snykEvidence: 'linked-document',
    });
  if (!limited && userAgentConfiguration.test(source) && /\bsettings\.json\b/i.test(source) &&
      /\bhooks\b/i.test(source) && /\b(?:copy|cp)\b/i.test(source) &&
      !/\bgit\s+(?:checkout|switch)\s+(?:--detach\s+)?[a-f0-9]{40}\b/i.test(source)) {
    scanMatches('suspicious-download', downloadsUserConfiguration,
      'The setup copies hooks and settings from a mutable repository into user-level agent configuration.',
      { raw: true, snykEvidence: 'manifest' });
  }
  if (!limited && /\bHttpClient\b/.test(source) && nativeArtifactUsesMD5.test(source) &&
      !/\bsha(?:256|384|512)\.convert\b/i.test(source)) {
    scanMatches('weak-native-download', releaseOrigin,
      'The native binary is fetched from a release and verified only with an MD5 digest.', { raw: true, snykEvidence: 'manifest' });
  }
  if (!limited && downloadsToFile.test(source) && executableRelease.test(source)) {
    if (proceedsWithoutReleaseIntegrity.test(source) ||
        (overrideableReleaseOrigin.test(source) && !mentionsReleaseIntegrity.test(source))) {
      scanMatches('suspicious-download', releaseOrigin,
        'The installer can download and enable a release executable without an integrity check.',
        { raw: true, snykEvidence: 'release-installer-source' });
    }
    if (!limited) scanMatches('runtime-dependency', releaseOrigin,
      'The script obtains an executable release during the workflow.',
      { raw: true, snykEvidence: 'release-installer-source' });
    if (!limited && !signatureTool.test(source) && !source.matchAll(releaseOrigin).next().done) {
      scanMatches('suspicious-download', checksumsFromRelease,
        'The installer downloads an unsigned checksum from the same origin as the executable release.', {
          raw: true, snykEvidence: 'release-installer-source',
          accepts: match => new RegExp('\\bcurl\\b[^\\r\\n]{0,145}\\$\\{?' + match[1] + '\\}?/\\$').test(source),
        });
    }
  }
  if (!limited && /\b(?:extract|unpack)\b[^\r\n]{0,130}\bSKILL\.md\b/i.test(source)) {
    const releaseManifest = /https:\/\/([\w.-]+)\/(?:[\w.-]+\/)*release\.json(?=[)\s`]|$)/gi;
    scanMatches('suspicious-download', releaseManifest,
      'The website supplies both the installable skill archive and the checksum used to verify it.', {
        raw: true, snykEvidence: 'site-skill-archive', accepts: match => {
          const procedure = source.slice(match.index, match.index + 700);
          return /\bZIP URL\b[^\r\n]{0,55}\bSHA-?256\b/i.test(procedure) &&
            /\b(?:check|compare|verify) (?:the )?checksum\b/i.test(procedure) &&
            !/\b(?:verify (?:the )?signature|signed manifest|trusted key|independent digest)\b/i.test(procedure) &&
            [...source.matchAll(/https:\/\/([\w.-]+)\/(?:[\w.-]+\/)*install\.txt(?=[)\s`]|$)/gi)]
              .some(guide => guide[1].toLowerCase() === match[1].toLowerCase() &&
                /\b(?:package|archive|ZIP) URL and checksum\b/i.test(source.slice(guide.index, guide.index + 190)));
        },
      });
  }
  if (!limited && /\blatest GitHub Release\b/i.test(source)) {
    const options = {
      raw: true, snykEvidence: 'manifest', accepts: match => {
        const steps = source.slice(match.index + match[0].length, match.index + match[0].length + 560);
        return /\bverify (?:the )?(?:checksum|signature) (?:when possible|if (?:available|possible))\b/i.test(steps) &&
          /\b(?:extract|unpack) (?:the )?(?:binary|executable)\b/i.test(steps) && /\bPATH\b/.test(steps);
      },
    };
    scanMatches('suspicious-download', downloadsLatestReleaseBinary,
      'The installation proceeds with a mutable release binary when verification is unavailable.', options);
    if (!limited) scanMatches('runtime-dependency', downloadsLatestReleaseBinary,
      'The workflow installs the remote binary before resuming the requested task.', options);
  }
  if (!limited && source.includes('raw.githubusercontent.com/')) scanMatches('runtime-dependency', configuredShellInstaller,
    'The shell helper executes an installer fetched at runtime with a configured destination.',
    { raw: true, snykEvidence: 'configured-shell-installer' });
  if (!limited && source.includes('.pages.dev/install.sh')) scanMatches('suspicious-download', hostedCiInstaller,
    'The linked CI setup executes an installer directly from a mutable hosting endpoint.', {
      raw: true, snykEvidence: 'ci-example-installer', accepts: match =>
        /^#{2,5}[^\r\n]{0,50}\bwire CI\b/im.test(source.slice(Math.max(0, match.index - 900), match.index)),
    });
  if (!limited) scanMatches('runtime-dependency', downloadsRelativePython,
    'The workflow downloads a Python script into the project and runs it.', {
      raw: true, snykEvidence: 'manifest', accepts: match => !mentionsReleaseIntegrity.test(match[0]),
    });
  if (!limited) {
    const unpinnedSql = match => !/\/[a-f\d]{40}\//i.test(match[1]);
    scanMatches('suspicious-download', downloadsAndRunsSql,
      'The workflow downloads mutable SQL and executes the downloaded file against a database.',
      { raw: true, snykEvidence: 'linked-document', accepts: unpinnedSql });
    scanMatches('runtime-dependency', downloadsAndRunsSql,
      'The database workflow depends on executable SQL that can change at its source.',
      { raw: true, snykEvidence: 'linked-document', accepts: unpinnedSql });
  }
  if (!limited && source.includes('compose.y')) scanMatches('suspicious-download', startsDownloadedCompose,
    'The instructions start containers using a Compose configuration fetched from a mutable repository branch.',
    { raw: true, snykEvidence: 'direct' });
  if (!limited && !source.matchAll(readsEnvForServiceReport).next().done &&
      [...source.matchAll(downloadsRelativePython)].some(match => !mentionsReleaseIntegrity.test(match[0]))) {
    scanMatches('dangerous-code-pattern', downloadsRelativePython,
      'A downloaded script is run in a workflow that reads the project environment file.', {
        raw: true, snykEvidence: 'manifest', accepts: match => !mentionsReleaseIntegrity.test(match[0]),
      });
    if (!limited) scanMatches('credential-handling', readsEnvForServiceReport,
      'The workflow reads the environment file to populate a user-facing services table.', {
        raw: true, snykEvidence: 'manifest',
      });
  }
  if (!limited) scanMatches('runtime-dependency', executeTempDownload,
    'The workflow downloads a file and passes the same file to an interpreter.', {
      raw: true,
      accepts: match => !/\b(?:verify|check)\b[^.!?;\r\n]{0,45}\b(?:signature|checksum|sha-?256|digest)\b/i.test(match[0]),
      snykEvidence: 'manifest',
    });
  if (!limited && /\bcopies component source code into your project\b/i.test(source)) {
    const options = {
      raw: true, snykEvidence: 'manifest',
      accepts: match => !/^https:\/\/ui\.shadcn\.com\//i.test(match[1]) &&
        source.includes(match[1] + '/{name}.json'),
    };
    scanMatches('suspicious-download', registrySourceInstall,
      'The component installer directly downloads source code from a custom package registry.', options);
    if (!limited) scanMatches('runtime-dependency', registrySourceInstall,
      'The project depends on an unpinned registry response for the components it installs.', options);
    if (!limited) scanMatches('third-party-content', registrySourceInstall,
      'The installer adds externally authored component source code to the project.', { ...options, assessment: 'capability' });
  }
  if (!limited) scanMatches('suspicious-download', companionMarketplaceInstall,
    'A required companion is obtained through a mutable plugin marketplace repository.', {
      raw: true,
      snykEvidence: 'companion-marketplace-install',
      accepts: match => match[1].toLowerCase() === match[2].toLowerCase() &&
        requiredCompanionContext.test(source.slice(Math.max(0, match.index - 345), match.index)),
    });
  if (!limited && source.includes('subprocess') && source.includes('args.dialogue')) scanMatches(
    'third-party-content',
    /^[ \t]*([\w]+)[ \t]*=[ \t]*\[[^\]]{0,700}?["']--prompt["'][ \t]*,[ \t]*([\w]+)/gm,
    'The invoked script forwards user-supplied prompt and dialogue fields into a companion model prompt.', {
      raw: true,
      assessment: 'capability',
      snykEvidence: 'model-prompt-forward',
      accepts: match => buildsForwardedModelPrompt(source, match),
    });
  if (!limited) scanMatches('runtime-dependency', linkedComponentRegistryInstall,
    'The referenced installation guide adds code from the community component registry.', {
      raw: true,
      snykEvidence: 'linked-component-registry',
      accepts: match => {
        const host = match[1].toLowerCase();
        if (host === 'ui.shadcn.com') return false;
        const before = source.slice(Math.max(0, match.index - 700), match.index);
        return before.split(/\r?\n/).some(line => /\b(?:registry|third.party|extended components)\b/i.test(line) &&
          line.toLowerCase().includes(host));
      },
    });
  if (!limited) scanMatches('suspicious-download', registryRouteInstall,
    'The component installer fetches source from a third-party registry route.', {
      raw: true, snykEvidence: 'component-registry-route', accepts: match => {
        const host = match[1].toLowerCase();
        const before = source.slice(Math.max(0, match.index - 350), match.index);
        return host !== 'ui.shadcn.com' && !negated(source, match.index) &&
          [...before.matchAll(/\bregistry\b[^\r\n]{0,70}https:\/\/([\w.-]+)[/)]/gi)]
            .some(registry => registry[1].toLowerCase() === host);
      },
    });
  if (!limited) scanMatches('suspicious-download', prerequisiteSkillRepository,
    'The required companion skill is distributed from a mutable third-party repository.', {
      raw: true, snykEvidence: 'required-skill-checkout', accepts: match => {
        const before = source.slice(Math.max(0, match.index - 850), match.index);
        const section = before.match(/^#{1,6}[ \t]+[^\r\n]+/gm)?.at(-1);
        return Boolean(section && /\b(?:prerequisites|required dependencies)\b/i.test(section));
      },
    });
  if (!limited && /\bgit[ \t]+clone\b/i.test(source)) {
    scanMatches('suspicious-download', copiesClonedSkill,
      'The installation copies a skill from a mutable checkout with undeclared provenance into the user’s agent skill directory.', {
        raw: true, snykEvidence: 'manifest', accepts: match => {
          if (match.groups.skill !== declaredSkillName(source) || mentionsReleaseIntegrity.test(nearMatch(match))) return false;
          const metadata = /^---[ \t]*\r?\n([\s\S]{0,2000}?)\r?\n---[ \t]*\r?$/m.exec(source.slice(0, 2100))?.[1] ?? '';
          const author = /^[ \t]*author:[ \t]*["']?([\w. -]+?)["']?[ \t]*\r?$/im.exec(metadata)?.[1];
          const normalize = value => value.toLowerCase().replace(/[^a-z0-9]/g, '');
          return !author || normalize(author) !== normalize(match.groups.owner);
        },
      });
  }
  if (!limited && /\b(?:sourced (?:facts|report)|web research)\b/i.test(source)) {
    scanMatches('third-party-content', skillToolInvocation,
      'A research skill supplies third-party material that this workflow distills into a downstream report.', {
        assessment: 'capability', raw: true, snykEvidence: 'manifest', accepts: match => {
          if (!/\bresearch\b/i.test(match[1]) || negated(source, match.index)) return false;
          const after = source.slice(match.index + match[0].length, match.index + 1700);
          return [...after.matchAll(/^\s*(?:\d+\.[ \t]+)?when[ \t]+([\w-]+)[ \t]+returns?,[ \t]+(?:distill|summarize|extract)[ \t]+its[ \t]+report[ \t]+into\b/gim)]
            .some(result => result[1] === match[1]);
        },
      });
  }
  if (!limited && /\bssl\._create_default_https_context[ \t]*=[ \t]*ssl\._create_unverified_context\b/.test(source)) {
    const options = {
      raw: true, snykEvidence: 'unverified-python-bootstrap',
      accepts: match => {
        const context = new RegExp(String.raw`^[ \t]*${match[2]}[ \t]*=[ \t]*ssl\._create_unverified_context\(\)`, 'm');
        return context.test(source.slice(Math.max(0, match.index - 1100), match.index)) &&
          !/\b(?:hashlib|sha256|verify_signature|verify_checksum)\b/i.test(match[0]);
      },
    };
    scanMatches('weakened-safeguard', runsPythonFromUnverifiedDownload,
      'The installer disables TLS verification and executes the downloaded Python file.', options);
    if (!limited) scanMatches('runtime-dependency', runsPythonFromUnverifiedDownload,
      'A Python bootstrap downloaded without certificate validation supplies executable code at runtime.', options);
  }
  if (!limited && /\bsubprocess\.run\(\[[ \t]*sys\.executable,[ \t]*\w+[ \t]*\]/.test(source)) {
    scanMatches('weakened-safeguard', remoteBootstrapMetadata,
      'The automatic installer gets the bootstrap location and digest from mutable remote metadata.', {
        raw: true, snykEvidence: 'self-updating-remote-bootstrap',
        accepts: match => {
          const after = source.slice(match.index + match[0].length, match.index + match[0].length + 1300);
          return executesBootstrapFromMetadata(match[1], after);
        },
      });
  }

  const pinnedDownloads = limited ? new Set() : lockedDownloads(source);
  const generatedMarkdown = limited || !source.includes('<<') ? [] : generatedMarkdownRanges(source);
  if (!limited && /^jobs:[ \t]*\r?$/m.test(source)) {
    const action = source.matchAll(mutableWorkflowAction).next().value;
    if (action) add('runtime-dependency', action.index, action[0].length,
      'The workflow executes an action from a remote repository without an immutable commit pin.', undefined, false, 'linked-workflow');
    if (!limited && installsWorkflowTemplate.test(source)) scanMatches('runtime-dependency', clonesConfiguredWorkflowTool,
      'The installable workflow executes a helper from a configured, mutable Git branch.', {
        raw: true, snykEvidence: 'configured-workflow-runtime', accepts: executesConfiguredWorkflowTool,
      });
    if (!limited) scanMatches('suspicious-download', clonesWorkflowTool,
      'The workflow executes a program from a mutable GitHub checkout.', {
        raw: true, snykEvidence: 'linked-workflow', accepts: match => {
          const following = followingWorkflowSteps(match);
          return [...following.matchAll(executesWorkflowTool)].some(invocation =>
            invocation[1].startsWith(match[1] + '/') &&
            !verifiesWorkflowCheckout.test(following.slice(0, invocation.index)));
        },
      });
    if (!limited && /\buses:[^\r\n]{0,100}\btag-action@/i.test(source) && /\.outputs\.changelog\s*\}\}/i.test(source)) {
      scanMatches('third-party-content', workflowChangelog,
        'The release notes can include changelog text written by repository contributors.', {
          raw: true, assessment: 'capability', snykEvidence: 'linked-workflow',
          accepts: match => generatedMarkdown.some(([begin, end]) => match.index >= begin && match.index < end),
        });
    }
  }
  if (!limited && /\bsudo\s+mv\b[^\r\n]{0,85}\/usr\/local\/bin\b/i.test(source)) {
    scanMatches('system-modification', removesQuarantine,
      'The setup removes quarantine before moving the executable into a system path.', {
        raw: true,
        accepts: match => /\bsudo\s+mv\b[^\r\n]{0,85}\/usr\/local\/bin\b/i.test(
          source.slice(match.index + match[0].length, match.index + match[0].length + 150)),
        snykEvidence: 'manifest',
      });
  }
  const shellScript = /^#![^\r\n]*\b(?:ba|da|k|z)?sh\b/.test(source);
  if (!limited && shellScript && packagedSkillFixture) {
    const fixture = { raw: true, snykEvidence: 'direct' };
    scanMatches('suspicious-download', executesRemoteFixtureResponse,
      'An executable skill fixture pipes a remote response to a shell.', fixture);
    if (!limited) scanMatches('runtime-dependency', executesRemoteFixtureResponse,
      'An executable skill fixture depends on a remote response at runtime.', fixture);
  }
  if (!limited && /^#{1,6}[ \t]+Source of Truth[ \t]*$/im.test(source) &&
      /\bcached\s+summary, not the authority\b/i.test(source) && /\bfollow the live page\b/i.test(source)) {
    scanMatches('runtime-dependency', followsLiveSetupPage,
      'The workflow follows live setup documentation when it differs from the bundled instructions.',
      { raw: true, snykEvidence: 'manifest' });
  }
  if (!limited) for (const match of prose.text.matchAll(urlPattern)) {
    const urlText = match[0].replace(/[.,;:\]}]+$/, '');
    if (pinnedDownloads.has(urlText)) continue;
    let url;
    try {
      url = new URL(urlText.replace(documentedPort, '$1'));
    } catch {
      continue;
    }
    if (url.hostname.includes('*')) continue;
    const start = match.index;
    const originalStart = prose.original(start);
    const originalEnd = prose.original(start + urlText.length);
    if (shellScript && /\.(?:html?|md)(?:\\[nr])*$/i.test(urlText)) {
      const prefix = source.slice(source.lastIndexOf('\n', originalStart - 1) + 1, originalStart);
      const suffix = source.slice(originalEnd).split(/\r?\n/, 1)[0];
      const quote = /^[ \t]*(?:printf|echo)[ \t]+(["'])[ \t]*$/.exec(prefix)?.[1];
      if (quote && suffix[0] === quote && /^[ \t]*(?:#.*)?$/.test(suffix.slice(1))) continue;
    }
    const authority = urlText.split(/[/?#]/)[2];
    if (/%[a-f0-9]{2}/i.test(authority) && /^[\w-]+(?:\.[\w-]+)+$/.test(url.username.replace(/%[a-f0-9]{2}/gi, 'x')) &&
        urlIncludesCredentialPair.test(source)) {
      const originalStart = prose.original(start);
      const length = prose.original(start + urlText.length) - originalStart;
      secrets.set(originalStart, length);
      add('suspicious-download', originalStart, length,
        'The URL authority combines encoded text with a username that resembles a host.',
        undefined, true, 'obscured-url-example');
      if (limited) break;
      continue;
    }
    const before = prose.text.slice(Math.max(0, start - 170), start).split(/\r\n|\r|\n/).at(-1);
    const after = prose.text.slice(start + urlText.length, start + urlText.length + 165).split(/\r\n|\r|\n/, 1)[0];
    if (url.hostname === 'nodejs.org' && url.pathname === '/' && !url.search &&
        /\bInstall Node [\d.+]+ from[ \t]*$/i.test(before) &&
        /^ so npx can run\b[^\r\n]{0,80}\bthen re-run this launcher\b/i.test(after)) continue;
    if (url.href === 'https://cli.github.com/' && /\bInstall gh[ \t]+\($/i.test(before) &&
        /^\)[ \t]+and run[ \t]+`?gh auth login\b/i.test(after)) continue;
    if (/\b(?:login|log-in|configure)\b[^\x60;|\r\n]{0,125}--(?:api-url|base-url|endpoint)(?:=|[ \t]+)["']?$/i.test(before)) continue;
    if (url.pathname.split('/').includes('...') && /(?:^|\s)\.\.\.\s*["']?\s*$/.test(after)) continue;
    if (url.hostname === 'github.com' && /^\/[\w.-]+\/[\w.-]+\/?$/.test(url.pathname) &&
        /\b(?:print|console\.(?:error|warn))\s*\(["'][^"\r\n]{0,100}\b(?:not found|missing)[^"\r\n]{0,35}\bInstall:[ \t]*$/i.test(before)) continue;
    if (/^https:\/\/github\.com\/\{(?:owner|org)\}\/\{(?:repo|repository)\}\/releases\//i.test(urlText)) continue;
    if (/^example\.(?:com|org|net)$/.test(url.hostname) && /\b(?:Request|Example)\b[\x60* \t]*:/i.test(before)) continue;
    if (/^example\.(?:com|org|net)$/.test(url.hostname) && !url.username &&
        /\.apk$/i.test(url.pathname) && /\binstall-app[ \t]*$/i.test(before) &&
        /\binstall-app[ \t]+\.\/[\w.-]+\.apk[ \t]*\r?\n[^\r\n]*$/i.test(
          source.slice(Math.max(0, originalStart - 240), originalStart))) continue;
    const actions = [...before.matchAll(new RegExp(downloadAction.source, 'gi'))];
    const action = actions.at(-1);
    if (!action || /[.!?;]\s/.test(before.slice(action.index + action[0].length)) ||
        negated(prose.text, start - before.length + action.index)) continue;
    const originalLength = originalEnd - originalStart;
    const scriptComment = shellScript && /^\s*#/.test(source.slice(source.lastIndexOf('\n', originalStart) + 1, originalStart));
    const obscured = shortener.test(url.hostname) || downloadHost.test(url.hostname) || url.username !== '' ||
      /^\[|^\d+\.\d+\.\d+\.\d+$/.test(url.hostname);
    const executableArtifact = artifact.test(url.pathname) ||
      /^(?:install|execute|launch|run)$/i.test(action[0]) && /\b(?:helper|script|binary|executable)\b/i.test(before);
    const verified = /\b(?:verify|check|pin)\b[^.!?;\r\n]{0,65}\b(?:signature|checksum|sha-?256|digest|commit hash)\b/i.test(before + ' ' + after) ||
      verifiesDownloadedPowerShellArchive(source, originalStart, originalEnd);
    const pipeToShell = /^[ \t]*['"\x60]?[ \t]*\|[ \t]*(?:bash|sh|zsh|pwsh)\b/i.test(source.slice(originalEnd, originalEnd + 40));
    const rootInstaller = url.pathname === '/' &&
      /\binstall(?:er|ation)?[ \t]*:[ \t]*[`]*[ \t]*(?:curl|wget)\b[^|;&`\r\n]{0,65}$/i.test(before);
    const remoteBootstrap = pipeToShell && (rootInstaller || /\/(?:install|bootstrap)(?:\.sh)?$/i.test(url.pathname));
    const instructsUserToInstall = /\b(?:if not|if (?:it|the check) fails)\b[^.!?;\r\n]{0,24}\b(?:ask|tell|instruct) (?:the )?user to install\b[^.:;!?\r\n]{1,75}:[ \t]*[`]*[ \t]*(?:curl|wget)\b[^|;&`\r\n]{0,65}$/i.test(before);
    const refersToManualSetup = instructsUserToInstall || (remoteBootstrap &&
      /\bcommand not found\b[^\r\n]{0,120}\bpoint (?:the user )?to[ \t]*\r?\n/i.test(source.slice(Math.max(0, originalStart - 190), originalStart)) &&
      /\bstop there\b/i.test(source.slice(originalEnd, originalEnd + 145)));
    const documentsInstallerVerification = remoteBootstrap && !obscured && url.protocol === 'https:' &&
      documentsConditionalInstallerVerification(source, originalStart);
    const documentsInstallerConsent = !obscured && url.protocol === 'https:' &&
      documentsConsentForVendorCli(source, url, originalStart);
    const releaseInstaller = url.hostname === 'github.com' && /\/releases\/(?:latest\/download|download\/[^/]+)\/[^/]+$/i.test(url.pathname) &&
      /^(?:curl|wget|install|download)$/i.test(action[0]);
    const declaredCliRelease = (releaseInstaller || /^invoke-webrequest$/i.test(action[0])) &&
      url.protocol === 'https:' && !obscured && installsDeclaredCliRelease(source, url);
    const publishedType = publishedDownloadType(url);
    const optionalUvSetup = publishedType === 'installer' && documentsOptionalUvSetup(source, originalStart);
    const gatedPublishedSetup = publishedType?.endsWith('-cli') && !obscured && url.protocol === 'https:' &&
      url.hostname === 'raw.githubusercontent.com' && /\/install\.(?:sh|ps1)$/i.test(url.pathname) &&
      installerFollowsPermissionGate(source, originalStart);
    const stagedPowerShell = url.protocol === 'https:' && !obscured &&
      stagesPublisherPowerShellInstaller(source, url, originalStart, originalEnd);
    const publishedTool = documentsPublishedTool(publishedType, source, originalStart) &&
      !(remoteBootstrap && url.hostname === 'raw.githubusercontent.com' &&
        /\/(?:main|master)\/install\.sh$/i.test(url.pathname) && bootstrapsDeploymentCli(source, originalStart));
    const documentationLink = url.hostname === 'github.com' && /^\/[\w.-]+\/[\w.-]+\/blob\/[\w./-]+\/INSTALL\.md$/i.test(url.pathname) &&
      /\brequires the `?[\w.-]+`? binary on `?PATH`?\.[ \t]+Install it with\s+\[the installation guide\]\($/i.test(
        source.slice(Math.max(0, originalStart - 180), originalStart));
    const printedDependencyGuide = shellScript && url.protocol === 'https:' && !obscured &&
      !artifact.test(url.pathname) && printsManualDependencyGuide(source, originalStart, originalEnd);
    const printedPrerequisiteHelp = shellScript && !obscured && printsLiteralPrerequisiteHelp(source, originalStart);
    const usesExistingMcpConnection = url.protocol === 'https:' && !obscured && /^\/mcp\/?$/.test(url.pathname) &&
      /\b(?:the )?user (?:has (?:already )?run|previously ran)[ \t]+\x60claude[ \t]+mcp[ \t]+add[ \t]+--transport[ \t]+http[ \t]+[\w.-]+[ \t]+$/i.test(before) &&
      /^\x60,?[ \t]+(?:then[ \t]+)?(?:fall back|switch)[ \t]+to\b/i.test(after);
    const sourceMetadata = !shellScript && !obscured && !pipeToShell && /^download$/i.test(action[0]) &&
      sourceArchiveMetadata(source, url, originalStart, originalEnd);
    if (sourceMetadata) add('third-party-content', sourceMetadata.start, sourceMetadata.length,
      'The workflow reads external repository metadata to select a source archive.',
      undefined, false, 'direct');
    const documentedDownload = printedPrerequisiteHelp || (!obscured && documentsPublishedPackageAlternative(source, url, originalStart, originalEnd)) ||
      optionalUvSetup || offersReviewedRepoInstaller(source, url) || sourceMetadata || documentationLink || linksPublishedCliDocsInTable(url, source, originalStart, originalEnd) ||
      documentsManualPinnedWhisperRelease(url, source, originalStart) || documentsInstallerVerification || documentsInstallerConsent ||
      gatedPublishedSetup || stagedPowerShell || declaredCliRelease ||
      (!obscured && presentsUserRunInstaller(source, url, originalStart, originalEnd)) ||
      (remoteBootstrap && !obscured && url.protocol === 'https:' && documentsEquivalentCliInstalls(source, url, originalStart, originalEnd)) ||
      (releaseInstaller && url.protocol === 'https:' && downloadsFontArchiveAsData(source, url, originalStart, originalEnd)) ||
      (publishedType === 'installer' && documentsUvInstallation(source, originalStart)) ||
      (publishedType === 'model' && /^(?:curl|wget|download|fetch|retrieve)$/i.test(action[0]) && !pipeToShell) ||
      (publishedType === 'workspace-cli-release' && /\b(?:Google Workspace CLI|gws\.exe|gws --version)\b/i.test(source)) ||
      publishedTool;
    if (obscured || (executableArtifact && (url.protocol !== 'https:' || !verified)) || (!verified && (remoteBootstrap || releaseInstaller))) {
      const isGeneratedText = generatedMarkdown.some(([begin, end]) => originalStart >= begin && originalStart < end);
      add('suspicious-download', originalStart, originalLength,
        obscured ? 'The destination obscures provenance or uses an intermediary download host.' :
          unverifiedDownloadReason,
        undefined, false, !documentedDownload && !isGeneratedText && !printedDependencyGuide && !usesExistingMcpConnection &&
          !scriptComment && !refersToManualSetup && (!obscured || remoteBootstrap) &&
          (executableArtifact || remoteBootstrap || releaseInstaller) && 'direct');
    }
    if (publishedType === 'model' && documentedDownload && !verified) add('runtime-dependency', originalStart, originalLength,
      'The workflow downloads model data during execution.', undefined, false, 'invoked-script');
    if (['workspace-cli-release', 'duckdb-cli-release', 'plantuml-jar-release'].includes(publishedType) &&
        documentedDownload && !verified) add('runtime-dependency', originalStart, originalLength,
      'The setup obtains the CLI from a published release at runtime.', undefined, false, 'linked-document');
    if (publishedType === 'nsyte-install' && url.hostname === 'nsyte.run' && documentedDownload && !verified) {
      add('runtime-dependency', originalStart, originalLength,
        'The setup obtains the installer from an external source at runtime.', undefined, false, 'linked-document');
    }
    const runtime = stagedPowerShell || declaredCliRelease || runtimeUse.test(before + ' ' + after) ||
      (executableArtifact && /^(?:install|execute|launch|run|load)$/i.test(action[0])) ||
      pipeToShell;
    if (runtime && !verified) add('runtime-dependency', originalStart, originalLength,
      mutableRuntimeSourceReason,
      undefined, false, (stagedPowerShell || declaredCliRelease || pipeToShell || runtimeInstructions.test(before + ' ' + after)) &&
        !(publishedBootstrapTypes.has(publishedType) && publishedTool) &&
        !(pipeToShell && installsInSampleImage(source, originalStart)) &&
        !printedPrerequisiteHelp && !optionalUvSetup && !refersToManualSetup && !gatedPublishedSetup && !printsDownloadCommandToMarkdown(source, originalStart) && 'direct');
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
