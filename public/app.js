import { decodeShare, maxPackageBytes, maxPackageFiles, maxHighlightedSourceBytes, maxPathLength, maxSkillBytes, packageSizeLabel } from './shared.js';
import { publicSkillInput, publicSkillPath, skillOverviewPath, snykPreviewPath } from './skill-route.js';

const $ = id => document.getElementById(id);
const editor = $('sp-editor');
const mirror = document.querySelector('.sp-mirror');
const lines = $('sp-lines');
const results = $('sp-finding-list');
const file = $('sp-file');
const folder = $('sp-folder');
const uploadGroup = $('sp-upload-group');
const uploadToggle = $('sp-upload-toggle');
const uploadOptions = $('sp-upload-options');
const sourceFile = $('sp-source-file');
const publicForm = $('sp-public-form');
const publicUrl = $('sp-public-url');
const publicSubmit = $('sp-public-submit');
const publicStatus = $('sp-public-status');
const scanDialog = $('sp-scan-dialog');
const publicResult = $('sp-public-result');
const report = $('sp-full-report');
const sourceToggle = $('sp-source-toggle');
const workspace = $('sp-workspace');
const githubDialog = $('sp-github-dialog');
const githubUrl = $('sp-github-url');
const githubSubmit = $('sp-github-submit');
const githubRef = $('sp-github-ref');
const githubBranches = $('sp-github-branches');
const githubStatus = $('sp-github-status');
const githubSource = $('sp-github-source');
const githubRefRow = $('sp-github-ref-row');
const publicExamples = [
  'github/awesome-copilot/skills/github-issues',
  'vercel-labs/agent-browser/skills/agent-browser',
  'designed-by-ai/skills/skills/design-mobile-apps',
  'mattpocock/skills/skills/triage',
  'google/agents-cli/skills/google-agents-cli-adk-code',
  'google/agents-cli/skills/google-agents-cli-deploy',
  'obra/superpowers/skills/brainstorming',
  'microsoft/azure-skills/skills/microsoft-foundry',
  'microsoft/azure-skills/skills/azure-compute',
  'larksuite/cli/skills/lark-doc',
];
const example = 'github.com/' + publicExamples[Math.floor(Math.random() * publicExamples.length)];
publicUrl.placeholder = example;
githubUrl.placeholder = example;

const encoder = new TextEncoder();
let findings = [];
let selected = -1;
let revision = 0;
let importRevision = 0;
let scanTimer;
let scanRequest;
let githubRequest;
let githubReady = false;
let githubDefaultRef;
let githubSkillName;
let routeRequest;
let currentRoute = '';
let importedPath;
let localMode = false;
let routeLoading = false;
let routeLoadError = '';
let packageFiles;
let activePath;

const assessments = {
  potential: 'Potential issue',
  guarded: 'Guarded',
  requires_provenance: 'Check provenance',
  capability: 'Capability',
  transparency_signal: 'Reporting signal',
};
const panels = {
  gen: 'Gen Agent Trust Hub',
  socket: 'Socket',
  snyk: 'Snyk',
};

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = value;
  return node;
}

function message(node, text) {
  node.textContent = text;
  node.hidden = !text;
}

function syncScroll() {
  mirror.scrollTop = editor.scrollTop;
  mirror.scrollLeft = editor.scrollLeft;
}

function paintSource(source, plain = false) {
  plain ||= encoder.encode(source).byteLength > maxHighlightedSourceBytes;
  editor.classList.toggle('sp-plain', plain);
  if (plain) {
    lines.replaceChildren();
    return;
  }
  const fragment = document.createDocumentFragment();
  const byLine = new Map();
  for (const [index, finding] of findings.entries()) {
    if (finding.path !== activePath) continue;
    for (const span of finding.evidence) {
      for (let number = span.line; number <= span.endLine; number++) {
        const spans = byLine.get(number) ?? [];
        spans.push({ span, level: finding.severity, active: index === selected });
        byLine.set(number, spans);
      }
    }
  }

  let offset = 0;
  for (const [index, text] of source.split('\n').entries()) {
    const number = index + 1;
    const row = element('div', text ? 'sp-line' : 'sp-line empty');
    row.dataset.line = number;
    const end = offset + text.length;
    const spans = byLine.get(number);
    if (!spans) {
      row.textContent = text;
      fragment.append(row);
      offset = end + 1;
      continue;
    }
    const local = spans.filter(({ span }) => span.start < end && span.end > offset);
    const boundaries = new Set([offset, end]);
    for (const { span } of local) {
      boundaries.add(Math.max(offset, span.start));
      boundaries.add(Math.min(end, span.end));
    }
    const cuts = [...boundaries].sort((a, b) => a - b);
    for (let i = 0; i + 1 < cuts.length; i++) {
      const start = cuts[i];
      const finish = cuts[i + 1];
      const covering = local.filter(({ span }) => span.start <= start && span.end >= finish);
      const hit = covering.find(item => item.active) ?? covering.find(item => item.level === 'high') ?? covering[0];
      const value = source.slice(start, finish);
      if (!hit) {
        row.append(document.createTextNode(value));
        continue;
      }
      const mark = element('mark', hit.active ? 'is-selected' : '', value);
      mark.dataset.level = hit.level;
      mark.dataset.start = start;
      if (hit.active) row.classList.add('is-selected');
      row.append(mark);
    }
    fragment.append(row);
    offset = end + 1;
  }
  lines.replaceChildren(fragment);
  syncScroll();
}

function lineLabel(span) {
  return span.line === span.endLine ? 'Line ' + span.line : 'Lines ' + span.line + '–' + span.endLine;
}

function revealSpan(span) {
  if (!span) return;
  if (editor.classList.contains('sp-plain')) {
    editor.focus({ preventScroll: true });
    editor.setSelectionRange(span.start, span.end);
    editor.scrollIntoView({ block: 'nearest' });
    return;
  }
  const row = lines.children[span.line - 1];
  const match = row?.querySelector('mark[data-start="' + span.start + '"]') ?? row;
  if (!match) return;
  const delta = match.getBoundingClientRect().top - mirror.getBoundingClientRect().top;
  if (delta < 12 || delta > editor.clientHeight - 36) {
    editor.scrollTop += delta - editor.clientHeight / 3;
    syncScroll();
  }
  const rect = match.getBoundingClientRect();
  if (rect.top < 0 || rect.top > window.innerHeight - 36) {
    editor.scrollIntoView({ block: 'nearest' });
  }
}

function findingDetail(finding, id) {
  const detail = element('div', 'sp-detail');
  detail.id = id;
  detail.hidden = true;
  for (const [spanIndex, span] of finding.evidence.entries()) {
    const heading = element('div', 'sp-evidence-head');
    heading.append(element('p', '', spanIndex === 0 ? 'Matched text · ' + lineLabel(span) : 'Context · ' + lineLabel(span)));
    const jump = element('button', 'sp-tool', 'Jump to source');
    jump.type = 'button';
    jump.addEventListener('click', () => {
      if (finding.path) showFile(finding.path);
      editor.focus({ preventScroll: true });
      editor.setSelectionRange(span.start, span.end);
      syncScroll();
      revealSpan(span);
    });
    heading.append(jump);
    detail.append(heading, element('code', 'sp-excerpt', span.text));
  }

  const rule = element('p');
  rule.append(element('strong', '', 'Rule · ' + finding.id), document.createElement('br'), finding.rule);
  const why = element('p');
  why.append(element('strong', '', assessments[finding.assessment] || 'CheckSkill evidence'), document.createElement('br'), finding.reason);
  const references = element('div', 'sp-links');
  references.append(element('p', '', 'Related scanner checks'));
  for (const reference of finding.references) {
    const item = element('p');
    const anchor = element('a', '', reference.name);
    anchor.href = reference.url;
    anchor.target = '_blank';
    anchor.rel = 'noopener noreferrer';
    item.append(anchor, ' · ', element('code', '', reference.code));
    references.append(item);
  }
  detail.append(rule, why);
  if (finding.references.length) detail.append(references);
  return detail;
}

function findingEntry(finding, index, panel) {
  const entry = element('article', 'sp-hit');
  const button = element('button', 'sp-hit-toggle');
  const id = `sp-detail-${panel}-${index}`;
  button.type = 'button';
  button.dataset.index = index;
  button.setAttribute('aria-expanded', 'false');
  button.setAttribute('aria-controls', id);
  const meta = element('span', 'sp-hit-meta');
  if (finding.path) meta.append(element('span', 'sp-result-path', finding.path));
  if (finding.evidence[0]) meta.append(element('span', '', lineLabel(finding.evidence[0])));
  button.append(element('span', 'sp-hit-name', finding.title));
  if (meta.childElementCount) button.append(meta);
  entry.append(button, findingDetail(finding, id));
  return entry;
}

function panelStatus(panel, label, tone = 'neutral') {
  const badge = panel.querySelector('.sp-scan-status');
  badge.textContent = label;
  badge.dataset.tone = tone;
}

function appendEvidence(body, label, entries) {
  if (!entries.length) return;
  body.append(element('h3', 'sp-audit-evidence', label), ...entries);
}

function showSnyk(panel, forecast, entries, extra, scanned) {
  const body = panel.querySelector('.sp-scanner-body');
  if (!forecast) {
    panelStatus(panel, scanned ? 'Forecast unavailable' : 'Awaiting results');
    appendEvidence(body, 'Related CheckSkill evidence', entries);
    appendEvidence(body, 'Local evidence without a scanner match', extra);
    return '';
  }
  const { issues = [], possible = [], unmapped = [], limited } = forecast;
  const incomplete = limited || unmapped.length > 0;
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const risk = severities.find(level => issues.some(issue => issue.severity === level));
  const label = risk || (incomplete ? 'Incomplete' : possible.length ? 'Review suggested' : 'No issues predicted');
  panelStatus(panel, label, risk === 'CRITICAL' || risk === 'HIGH' ? 'high' :
    issues.length || incomplete || possible.length ? 'caution' : 'clear');
  if (issues.length) {
    const list = element('ul', 'sp-audit-issues');
    for (const issue of [...issues].sort((a, b) => severities.indexOf(a.severity) - severities.indexOf(b.severity))) {
      const row = element('li', 'sp-audit-issue');
      const meta = element('div', 'sp-audit-meta');
      const severity = element('span', 'sp-scan-status', issue.severity);
      severity.dataset.tone = ['CRITICAL', 'HIGH'].includes(issue.severity) ? 'high' : 'caution';
      meta.append(element('code', '', issue.code), severity);
      row.append(meta, element('p', '', issue.message));
      list.append(row);
    }
    body.append(list);
  } else {
    body.append(element('p', 'sp-empty', incomplete ? 'The available checks did not predict an issue.' : 'No Snyk issues predicted.'));
  }
  if (possible.length) body.append(element('p', 'sp-audit-note', 'Possible matches · ' + possible.join(', ')));
  if (limited) body.append(element('p', 'sp-audit-note', 'The scan reached its finding limit.'));
  if (unmapped.length) body.append(element('p', 'sp-audit-note', 'Unmapped checks · ' + unmapped.join(', ')));
  appendEvidence(body, 'Related CheckSkill evidence', entries);
  appendEvidence(body, 'Local evidence without a scanner match', extra);
  return label;
}

function issueReason(code) {
  const matches = findings.filter(finding => finding.reason && finding.references.some(reference =>
    reference.name === 'Snyk' && reference.code.match(/^[A-Z]\d{3}\b/)?.[0] === code));
  return (matches.find(finding => finding.snykEvidence === 'direct') ?? matches[0])?.reason;
}

function renderPublicReport(forecast) {
  const container = $('sp-report-findings');
  const { issues = [], possible = [], unmapped = [], limited } = forecast ?? {};
  $('sp-report-count').textContent = forecast ? `${issues.length} predicted ${issues.length === 1 ? 'issue' : 'issues'}` : 'Forecast unavailable';
  container.replaceChildren();
  if (forecast && !issues.length) container.append(element('p', '', 'No Snyk issues predicted.'));
  for (const issue of issues) {
    const card = element('article', 'sp-report-issue');
    const labels = element('div', 'sp-audit-meta');
    const severity = element('span', 'sp-scan-status', issue.severity);
    severity.dataset.tone = ['CRITICAL', 'HIGH'].includes(issue.severity) ? 'high' : 'caution';
    labels.append(element('code', '', issue.code), severity);
    card.append(labels, element('h3', '', issue.message));
    const reason = issueReason(issue.code);
    if (reason) {
      const analysis = element('ul', 'sp-report-analysis');
      analysis.append(element('li', '', reason));
      card.append(analysis);
    }
    container.append(card);
  }
  if (possible.length) container.append(element('p', '', 'Possible matches · ' + possible.join(', ')));
  if (unmapped.length) container.append(element('p', '', 'Unmapped checks · ' + unmapped.join(', ')));
  if (limited) container.append(element('p', '', 'The scan reached its finding limit.'));
}

function showFindings({ status, scanned = false, limited = false, forecast } = {}) {
  const grouped = { gen: [], socket: [], snyk: [], extra: [] };
  for (const [index, finding] of findings.entries()) {
    const keys = Object.keys(panels).filter(key => finding.references.some(ref => ref.name === panels[key]));
    for (const key of keys.length ? keys : ['extra']) grouped[key].push(findingEntry(finding, index, key));
  }
  for (const key of Object.keys(panels)) $('sp-' + key).querySelector('.sp-scanner-body').replaceChildren();
  for (const key of ['gen', 'socket']) {
    const panel = $('sp-' + key);
    const entries = grouped[key];
    panelStatus(panel, entries.length ? `${entries.length} local ${entries.length === 1 ? 'signal' : 'signals'}` :
      key === 'socket' ? 'No forecast' : scanned ? 'No local signals' : 'Local evidence');
    const explanation = key === 'socket' ? 'CheckSkill does not yet predict Socket’s verdict.' :
      entries.length ? 'CheckSkill signals related to Gen checks.' : scanned ? 'CheckSkill found no signals mapped to Gen checks.' : 'Gen-related signals appear here after a scan.';
    panel.querySelector('.sp-scanner-body').append(element('p', 'sp-audit-note', explanation), ...entries);
  }
  const snykStatus = showSnyk($('sp-snyk'), forecast, grouped.snyk, grouped.extra, scanned);
  message($('sp-scan-note'), status ?? (limited ? 'The scan reached its finding limit.' : ''));
  const announcement = status ?? (snykStatus ? 'Snyk forecast · ' + snykStatus : 'Scan complete');
  if ($('sp-status').textContent !== announcement) message($('sp-status'), announcement);
}

async function api(route, source, controller) {
  const markdown = typeof source === 'string';
  const response = await fetch('/api/' + route, {
    method: 'POST',
    cache: 'no-store',
    headers: { 'Content-Type': markdown ? 'text/markdown; charset=utf-8' : 'application/json' },
    body: markdown ? source : JSON.stringify(source),
    signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'The request failed.');
  return data;
}

function queueScan() {
  const current = ++revision;
  clearTimeout(scanTimer);
  scanRequest?.abort();
  findings = [];
  selected = -1;
  const source = editor.value;
  const entries = packageFiles && [...packageFiles].map(([path, content]) => ({ path, content }));
  const size = entries ? entries.reduce((total, { content }) => total + encoder.encode(content).byteLength, 0) :
    encoder.encode(source).byteLength;
  const oversized = size > (entries ? maxPackageBytes : maxSkillBytes);
  paintSource(source, oversized);
  updateLineCount();
  if (oversized) {
    showFindings({ status: entries ? `Folder text can be at most ${packageSizeLabel} in total.` : `The skill can be at most ${packageSizeLabel}.` });
    return;
  }
  if (!entries && !source.trim()) {
    showFindings();
    return;
  }
  showFindings({ status: 'Checking your skill…' });
  scanTimer = setTimeout(async () => {
    const controller = new AbortController();
    scanRequest = controller;
    try {
      const data = await api('scan', entries ? { files: entries } : source, controller);
      if (current !== revision) return;
      findings = data.findings;
      paintSource(editor.value);
      showFindings({ scanned: true, limited: data.limited, forecast: data.snykForecast });
    } catch {
      if (current === revision) showFindings({ status: 'Could not check your skill. Edit the text to try again.' });
    }
  }, 220);
}

function updateLineCount() {
  const count = editor.value ? editor.value.split('\n').length : 0;
  $('sp-line-count').textContent = count + (count === 1 ? ' line' : ' lines');
}

function setEditor(source) {
  editor.value = source;
  editor.scrollTop = 0;
  editor.scrollLeft = 0;
}

function showFile(path) {
  if (path === activePath) return;
  activePath = path;
  sourceFile.value = path;
  $('sp-editor-label').textContent = path;
  setEditor(packageFiles.get(path));
  updateLineCount();
  paintSource(editor.value);
}

function replaceSource(source) {
  packageFiles = undefined;
  activePath = undefined;
  $('sp-editor-label').textContent = 'SKILL.md';
  $('sp-folder-files').hidden = true;
  message($('sp-folder-status'), '');
  setEditor(source);
  queueScan();
}

function navigateTo(path) {
  currentRoute = path;
  if (path !== location.pathname + location.search || location.hash.startsWith('#skill=')) {
    history.pushState(null, '', path);
  }
}

function detachPublicSkill() {
  routeRequest?.abort();
  publicStatus.textContent = '';
  importedPath = undefined;
  if (publicSkillInput(location.pathname, location.search) || location.hash.startsWith('#skill=')) {
    navigateTo('/');
    message($('sp-folder-status'), '');
    setInputMode(true);
  }
}

function showPackage(files, note) {
  packageFiles = files;
  activePath = undefined;
  findings = [];
  selected = -1;
  const paths = [...files.keys()].sort();
  sourceFile.replaceChildren(...paths.map(path => {
    const option = element('option', '', path);
    option.value = path;
    return option;
  }));
  $('sp-folder-files').hidden = false;
  showFile(files.has('SKILL.md') ? 'SKILL.md' : paths[0]);
  message($('sp-folder-status'), note);
  message($('sp-file-status'), '');
}

editor.addEventListener('scroll', syncScroll);
editor.addEventListener('input', () => {
  importRevision++;
  detachPublicSkill();
  message($('sp-file-status'), '');
  if (packageFiles) packageFiles.set(activePath, editor.value);
  queueScan();
});
sourceFile.addEventListener('change', () => showFile(sourceFile.value));
function selectFinding(event) {
  const button = event.target.closest('button[data-index]');
  if (!button) return;
  const index = Number(button.dataset.index);
  const previous = event.currentTarget.querySelector('button[aria-expanded="true"]');
  if (previous) {
    previous.setAttribute('aria-expanded', 'false');
    $(previous.getAttribute('aria-controls')).hidden = true;
  }
  selected = previous === button ? -1 : index;
  if (selected !== -1) {
    button.setAttribute('aria-expanded', 'true');
    $(button.getAttribute('aria-controls')).hidden = false;
  }
  const finding = findings[selected];
  if (finding?.path) showFile(finding.path);
  paintSource(editor.value);
  revealSpan(finding?.evidence[0]);
}

results.addEventListener('click', selectFinding);

function toggleUploadOptions(open) {
  uploadOptions.hidden = !open;
  uploadToggle.setAttribute('aria-expanded', String(open));
}

uploadToggle.addEventListener('click', () => toggleUploadOptions(uploadOptions.hidden));
uploadGroup.addEventListener('keydown', event => {
  if (event.key !== 'Escape' || uploadOptions.hidden) return;
  toggleUploadOptions(false);
  uploadToggle.focus();
});
uploadGroup.addEventListener('focusout', event => {
  if (!uploadGroup.contains(event.relatedTarget)) toggleUploadOptions(false);
});
document.addEventListener('pointerdown', event => {
  if (!uploadGroup.contains(event.target)) toggleUploadOptions(false);
});
for (const [id, input] of [['sp-upload', file], ['sp-file-button', file], ['sp-folder-button', folder]]) {
  $(id).addEventListener('click', () => {
    toggleUploadOptions(false);
    if (id !== 'sp-upload') uploadToggle.focus();
    input.click();
  });
}
file.addEventListener('change', async () => {
  const [upload] = file.files;
  file.value = '';
  if (!upload) return;
  const current = ++importRevision;
  try {
    if (upload.size > maxSkillBytes) throw new Error(`Choose a Markdown file up to ${packageSizeLabel}.`);
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    const source = decoder.decode(await upload.arrayBuffer());
    if (current !== importRevision) return;
    detachPublicSkill();
    message($('sp-file-status'), '');
    replaceSource(source);
  } catch (error) {
    if (current === importRevision) message($('sp-file-status'),
      upload.size > maxSkillBytes ? error.message : 'Could not read that file as UTF-8 Markdown.');
  }
});

folder.addEventListener('change', async () => {
  const uploads = [...folder.files];
  folder.value = '';
  if (!uploads.length) return;
  const current = ++importRevision;
  let skipped = 0;
  let total = 0;
  const files = new Map();
  try {
    for (const upload of uploads) {
      if (current !== importRevision) return;
      const path = upload.webkitRelativePath.split('/').slice(1).join('/');
      if (!path || path.split('/').some(part => part === '.git')) {
        skipped++;
        continue;
      }
      if (/^(?:image|audio|video)\//.test(upload.type) || /\.(?:zip|rar|7z|gz|tar|pdf|png|jpe?g|webp|icns|exe|dll|so|dylib|wasm)$/i.test(path)) {
        skipped++;
        continue;
      }
      if (path.length > maxPathLength || /[\\\p{Cc}\p{Cf}]/u.test(path)) throw new Error('A file path is too long or contains an unsupported character.');
      if (upload.size > maxPackageBytes - total) throw new Error(`Folder text can be at most ${packageSizeLabel} in total.`);
      const bytes = await upload.arrayBuffer();
      let content;
      try {
        content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
      } catch {
        skipped++;
        continue;
      }
      if (files.size === maxPackageFiles) throw new Error(`Folders can contain up to ${maxPackageFiles} text files.`);
      total += upload.size;
      files.set(path, content.replace(/\r\n?/g, '\n'));
    }
    if (current !== importRevision) return;
    if (!files.size) throw new Error('The folder has no readable UTF-8 files.');
    detachPublicSkill();
    const note = (skipped ? skipped + (skipped === 1 ? ' file skipped. ' : ' files skipped. ') : '') +
      'Scanned the uploaded text files.';
    showPackage(files, note);
    queueScan();
  } catch (error) {
    if (current === importRevision) message($('sp-file-status'), error.message || 'Could not read the folder.');
  }
});

function resetGitHubPicker() {
  githubRequest?.abort();
  githubReady = false;
  githubDefaultRef = undefined;
  githubSkillName = undefined;
  githubRef.value = '';
  githubRefRow.hidden = true;
  githubBranches.replaceChildren();
  message(githubSource, '');
  message(githubStatus, '');
  githubSubmit.textContent = 'Choose revision';
  githubSubmit.disabled = false;
}

publicForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (publicSubmit.disabled) return;
  const githubUrl = publicUrl.value.trim();
  if (!githubUrl) {
    publicUrl.focus();
    return;
  }
  routeRequest?.abort();
  const controller = new AbortController();
  routeRequest = controller;
  const current = ++importRevision;
  publicSubmit.disabled = true;
  publicStatus.removeAttribute('data-error');
  publicStatus.textContent = '';
  let completed = false;
  try {
    scanDialog.showModal();
    const data = await api('scan', { githubUrl }, controller);
    if (controller.signal.aborted || current !== importRevision) return;
    navigateTo(publicSkillPath(data.source));
    showImportedSkill(data);
    completed = true;
  } catch (error) {
    if (controller.signal.aborted || current !== importRevision) return;
    publicStatus.setAttribute('data-error', '');
    publicStatus.textContent = error.name === 'Error' ? error.message : 'Could not load the skill. Try again.';
  } finally {
    publicSubmit.disabled = false;
    if (scanDialog.open) scanDialog.close();
    if (completed) $('sp-snyk-link').focus();
    else if (current === importRevision && !publicForm.hidden) publicUrl.focus();
  }
});

function cancelPublicScan(event) {
  event.preventDefault();
  routeRequest?.abort();
}

$('sp-scan-cancel').addEventListener('click', cancelPublicScan);
scanDialog.addEventListener('cancel', cancelPublicScan);

$('sp-github-button').addEventListener('click', () => {
  if (publicSubmit.disabled) routeRequest?.abort();
  resetGitHubPicker();
  githubUrl.value = publicUrl.value.trim();
  githubDialog.showModal();
  if (githubUrl.value) $('sp-github-form').requestSubmit();
});
$('sp-github-cancel').addEventListener('click', () => githubDialog.close());
githubDialog.addEventListener('close', resetGitHubPicker);
githubUrl.addEventListener('input', resetGitHubPicker);
$('sp-github-form').addEventListener('submit', async event => {
  event.preventDefault();
  githubRequest?.abort();
  const controller = new AbortController();
  githubRequest = controller;
  githubSubmit.disabled = true;
  const githubUrlValue = githubUrl.value.trim();
  try {
    if (!githubReady) {
      message(githubStatus, 'Loading revisions…');
      const { project, skill, defaultRef, branches } = await api('refs', { githubUrl: githubUrlValue }, controller);
      if (controller.signal.aborted || !githubDialog.open) return;
      githubBranches.replaceChildren(...branches.map(branch => {
        const option = document.createElement('option');
        option.value = branch;
        return option;
      }));
      githubRef.value = defaultRef;
      githubSkillName = skill;
      githubDefaultRef = /github\.com\/[^/]+\/[^/]+\/pull\//i.test(githubUrlValue) ? undefined
        : /(?:github\.com\/[^/]+\/[^/]+\/(?:tree|blob)\/|raw\.githubusercontent\.com\/)/i.test(githubUrlValue)
        ? (await api('refs', { githubUrl: `https://github.com/${project}` }, controller).catch(() => null))?.defaultRef
        : defaultRef;
      if (controller.signal.aborted || !githubDialog.open) return;
      githubRef.placeholder = defaultRef ? 'Type a branch, tag, or commit' : 'Use the revision in the URL';
      githubRefRow.hidden = false;
      githubReady = true;
      message(githubSource, skill ? `${project} · ${skill}` : project);
      message(githubStatus, '');
      githubSubmit.textContent = 'Import and scan';
      githubSubmit.disabled = false;
      githubRef.focus();
      githubRef.select();
      return;
    }
    message(githubStatus, 'Importing and scanning…');
    const data = await api('scan', { githubUrl: githubUrlValue, ref: githubRef.value.trim() || undefined }, controller);
    if (controller.signal.aborted || !githubDialog.open) return;
    routeRequest?.abort();
    navigateTo(publicSkillPath(data.source, githubDefaultRef, githubSkillName));
    showImportedSkill(data);
    publicUrl.value = githubUrlValue;
    publicStatus.textContent = '';
    githubDialog.close();
    $('sp-snyk-link').focus();
  } catch (error) {
    if (!controller.signal.aborted && githubDialog.open) {
      message(githubStatus, error.name === 'Error' ? error.message : 'Could not load the skill. Try again.');
      githubSubmit.disabled = false;
    }
  }
});

function showImportedSkill(data) {
  importRevision++;
  revision++;
  clearTimeout(scanTimer);
  scanRequest?.abort();
  const { project, folder, ref, commit, skipped } = data.source;
  const scope = folder ? `${project}/${folder}` : project;
  const files = new Map(data.files.map(file => [file.path, file.content]));
  const skippedNote = skipped ? ` · ${skipped} skipped` : '';
  showPackage(files, `${scope} · ${ref} · ${commit.slice(0, 8)} · ${files.size} ${files.size === 1 ? 'file' : 'files'}${skippedNote}`);
  findings = data.findings;
  paintSource(editor.value);
  showFindings({ scanned: true, limited: data.limited, forecast: data.snykForecast });
  renderPublicReport(data.snykForecast);
  const base = skillOverviewPath(currentRoute);
  importedPath = base;
  const slug = base.split('?')[0].split('/').at(-1);
  const title = data.source.gistFile ?? (folder.split('/').at(-1) || slug);
  const manifest = files.get('SKILL.md') ?? '';
  const frontmatter = manifest.match(/^\uFEFF?---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/)?.[1] ?? '';
  const heading = manifest.match(/^#\s+([^\n]+)$/m)?.[1]?.trim();
  const description = frontmatter.match(/^description:\s*([^\r\n]+)$/m)?.[1]?.trim().replace(/^(['"])(.*)\1$/, '$2');
  $('sp-result-project').textContent = project;
  $('sp-result-title').textContent = heading || title;
  $('sp-result-revision').textContent = `${ref === 'HEAD' ? 'Default branch' : ref} · ${commit.slice(0, 8)}`;
  $('sp-result-description-section').hidden = !description || /^[|>][+-]?$/.test(description);
  $('sp-result-description').textContent = description ?? '';
  $('sp-result-files').textContent = `${files.size} ${files.size === 1 ? 'file' : 'files'} scanned${skippedNote}`;
  const repository = `https://github.com/${project}`;
  const folderPath = folder.split('/').map(part => encodeURIComponent(part)
    .replace(/[!'()*]/g, char => '%' + char.charCodeAt(0).toString(16).toUpperCase())).join('/');
  const treeUrl = `${repository}/tree/${commit}${folderPath ? '/' + folderPath : ''}`;
  const published = !data.source.gist && /^[\w.-]+$/.test(slug) ? `https://www.skills.sh/${project}/${slug}` : '';
  $('sp-result-source').href = data.source.gist ? `https://gist.github.com/${project}/${commit}` : treeUrl;
  $('sp-result-install').hidden = Boolean(data.source.gist);
  $('sp-install-command').textContent = `npx skills add ${treeUrl}`;
  $('sp-copy-command').textContent = 'Copy command';
  $('sp-published-listing').hidden = !published;
  $('sp-published-snyk').hidden = !published;
  if (published) {
    $('sp-published-listing').href = published;
    $('sp-published-snyk').href = published + '/security/snyk';
  }
  $('sp-snyk-link').href = snykPreviewPath(base);
  $('sp-snyk-summary').textContent = $('sp-snyk').querySelector('.sp-scan-status').textContent;
  sourceToggle.open = false;
  showPage();
}

function showPage() {
  const path = location.pathname.replace(/\/$/, '');
  const about = path === '/about';
  const terminal = path === '/terminal';
  const agentSkill = path === '/agent-skill';
  const guide = terminal || agentSkill;
  const loaded = Boolean(importedPath && importedPath === skillOverviewPath(currentRoute));
  const showReport = loaded && currentRoute !== importedPath;
  const routePendingOrFailed = routeLoading || Boolean(routeLoadError);
  $('sp-route-state').hidden = !routePendingOrFailed;
  $('sp-route-title').textContent = routeLoadError ? 'Couldn’t load this skill' : 'Loading skill forecast…';
  $('sp-route-spinner').hidden = !routeLoading;
  $('sp-route-actions').hidden = !routeLoadError;
  message($('sp-route-error'), routeLoadError);
  $('sp-intro').hidden = about || guide || loaded || routePendingOrFailed;
  document.documentElement.classList.remove('sp-route-start');
  $('sp-method').hidden = !about;
  $('sp-guides').hidden = !guide;
  $('terminal').hidden = !terminal;
  $('agent-skill').hidden = !agentSkill;
  publicResult.hidden = !loaded;
  report.hidden = !showReport;
  $('sp-result-overview').hidden = showReport;
  sourceToggle.hidden = !loaded || showReport;
  workspace.hidden = about || guide || showReport || routePendingOrFailed || (loaded ? !sourceToggle.open : !localMode);
  const back = $('sp-result-back');
  back.href = showReport ? importedPath : '/';
  back.textContent = showReport ? '← Skill overview' : '← New scan';
  document.title = loaded ? `${$('sp-result-title').textContent}${showReport ? ' · Snyk forecast' : ''} · CheckSkill`
    : about ? 'How it works · CheckSkill'
      : terminal ? 'Terminal · CheckSkill'
        : agentSkill ? 'Agent skill · CheckSkill' : 'CheckSkill · Preflight for agent skills';
}

function setInputMode(local) {
  localMode = local;
  if (local) {
    routeRequest?.abort();
    publicStatus.textContent = '';
  }
  $('sp-public-mode').setAttribute('aria-pressed', String(!local));
  $('sp-local-mode').setAttribute('aria-pressed', String(local));
  publicForm.hidden = local;
  showPage();
}

$('sp-public-mode').addEventListener('click', () => {
  setInputMode(false);
  publicUrl.focus();
});
$('sp-local-mode').addEventListener('click', () => {
  setInputMode(true);
  editor.focus();
});
$('sp-route-retry').addEventListener('click', () => location.reload());
sourceToggle.addEventListener('toggle', showPage);
for (const id of ['sp-result-back', 'sp-snyk-link']) {
  $(id).addEventListener('click', event => {
    const link = event.currentTarget;
    if (link.pathname === '/' || event.button || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    navigateTo(link.pathname + link.search);
    showPage();
    (report.hidden ? $('sp-snyk-link') : $('sp-result-back')).focus();
  });
}
$('sp-copy-command').addEventListener('click', async event => {
  const button = event.currentTarget;
  const command = $('sp-install-command');
  try {
    await navigator.clipboard.writeText(command.textContent);
    button.textContent = 'Copied';
  } catch {
    getSelection().selectAllChildren(command);
    button.textContent = 'Command selected';
  }
});

async function restorePublicSkill() {
  const path = location.pathname + location.search;
  if (path === currentRoute) return;
  currentRoute = path;
  const input = publicSkillInput(location.pathname, location.search);
  routeLoadError = '';
  if (importedPath === skillOverviewPath(path)) {
    routeLoading = false;
    showPage();
    return;
  }
  importedPath = undefined;
  routeLoading = Boolean(input);
  showPage();
  routeRequest?.abort();
  if (githubDialog.open) {
    githubRequest?.abort();
    githubDialog.close();
  }
  const current = ++importRevision;
  message($('sp-file-status'), '');
  replaceSource('');
  if (!input) return;
  const controller = new AbortController();
  routeRequest = controller;
  setInputMode(false);
  publicUrl.value = input.githubUrl;
  publicStatus.removeAttribute('data-error');
  publicStatus.textContent = '';
  try {
    const data = await api('scan', input, controller);
    if (current === importRevision && !controller.signal.aborted) {
      routeLoading = false;
      showImportedSkill(data);
    }
  } catch (error) {
    if (current !== importRevision || controller.signal.aborted) return;
    routeLoading = false;
    routeLoadError = error.message || 'Could not load the public skill.';
    showPage();
  }
}

async function restoreShare() {
  const fragment = location.hash;
  if (!fragment.startsWith('#skill=') || publicSkillInput(location.pathname, location.search)) return;
  setInputMode(true);
  const current = ++importRevision;
  try {
    const source = await decodeShare(fragment);
    if (current !== importRevision) return;
    message($('sp-file-status'), '');
    replaceSource(source);
  } catch {
    if (current === importRevision) message($('sp-file-status'), 'Could not open this share link. It may be incomplete or too large.');
  }
}
window.addEventListener('popstate', restorePublicSkill);
window.addEventListener('hashchange', restoreShare);
restorePublicSkill();
restoreShare();
