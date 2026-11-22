import readline from 'node:readline';
import { maxPackageBytes, maxPackageFiles, maxPathLength, maxSkillBytes } from '../public/shared.js';
import { isBinaryAsset, scan, scanPackage } from '../src/rules.js';
import { isDefiniteSnykFinding, snykReportFromFindings } from '../src/snyk-report.js';
import { connectorArchiveFindings, invokedCheckoutFindings, templateResourceGateFindings, isPackagedSkillFixture, missingManifest, reachableNodeScripts, scopeSnykFindings, windowsExecutableFinding } from '../src/snyk-rules.js';

const extendedOnly = process.argv.includes('--extended-only');
const channelOnly = process.argv.includes('--rule-channels');
const manifestOnly = process.argv.includes('--manifest-only');
const linkedOnly = process.argv.includes('--linked-only');
const reportOnly = extendedOnly || channelOnly || manifestOnly || linkedOnly || process.argv.includes('--report-only');
const fileLimit = extendedOnly ? 512 : maxPackageFiles;
const byteLimit = extendedOnly ? maxPackageBytes + 1024 * 1024 : manifestOnly ? maxSkillBytes : maxPackageBytes;
const fileBytesLimit = 1024 * 1024;

function scanExtended(files) {
  const manifest = files.find(file => file.path === 'SKILL.md');
  const body = manifest?.content ?? '';
  const nodeScripts = reachableNodeScripts(files, body);
  const findings = manifest ? [] : [missingManifest()];
  let limited = false;
  for (const file of files) {
    const { path, content } = file;
    const executableFinding = windowsExecutableFinding(file, files);
    if (executableFinding) {
      findings.push(executableFinding);
      continue;
    }
    if (isBinaryAsset(file)) continue;
    const result = scan(content, undefined, isPackagedSkillFixture(path, files));
    findings.push(...scopeSnykFindings(result.findings, path, body, nodeScripts, files));
    limited ||= result.limited;
  }

  if (!limited && manifest) {
    const readme = files.find(file => file.path === 'README.md');
    findings.push(...connectorArchiveFindings(body, readme?.content), ...invokedCheckoutFindings(body, files), ...templateResourceGateFindings(body, files));
  }
  return { findings, limited };
}

function forecastReport(result, files) {
  const report = snykReportFromFindings(result);
  if (!channelOnly) return report;
  const manifest = files.find(file => file.path === 'SKILL.md')?.content ?? '';
  const channels = new Set();
  for (const finding of result.findings) {
    const { path, id, reason } = finding;
    const origin = !path || path === 'SKILL.md' ? 'manifest' :
      path.includes('/') && manifest.includes(path) ? 'linked' :
      /\.(?:md|mdx|rst|txt)$/i.test(path) ? 'other text' : 'other file';
    const direct = isDefiniteSnykFinding(finding);
    for (const ref of finding.references) {
      const code = ref.name === 'Snyk' && /^([A-Z]\d{3})\b/.exec(ref.code)?.[1];
      if (code) channels.add(JSON.stringify([code, id, reason, origin, direct]));
    }
  }
  return { ...report, channels: [...channels].map(value => JSON.parse(value)) };
}

function extract(files) {
  if (!Array.isArray(files) || !files.length) return { unavailable: 'inputs_missing' };
  if (manifestOnly || linkedOnly) {
    const manifest = files.find(file => file?.path === 'SKILL.md' && typeof file.contents === 'string');
    if (!manifest) return { unavailable: 'manifest_missing' };
    files = manifestOnly ? [manifest] : files.filter(file =>
      file === manifest || typeof file?.path === 'string' && manifest.contents.includes(file.path));
  }
  if (files.length > fileLimit) return { unavailable: 'file_limit' };
  const seen = new Set();
  let bytes = 0;
  const normalized = [];
  for (const file of files) {
    if (typeof file?.path !== 'string' || typeof file?.contents !== 'string') return { unavailable: 'invalid_input' };
    const path = file.path.toWellFormed();
    const content = file.contents.toWellFormed();
    if (path.length > maxPathLength || /[\\\p{Cc}\p{Cf}]/u.test(path) ||
        path.split('/').some(part => !part || part === '.' || part === '..') || seen.has(path)) {
      return { unavailable: 'invalid_path' };
    }
    seen.add(path);
    const size = Buffer.byteLength(content);
    if (extendedOnly && size > fileBytesLimit) return { unavailable: 'single_file_byte_limit' };
    bytes += size;
    if (bytes > byteLimit) return { unavailable: 'byte_limit' };
    normalized.push({ path, content });
  }
  if (extendedOnly) {
    if (bytes <= maxPackageBytes && files.length <= maxPackageFiles) return { unavailable: 'already_supported' };
    return forecastReport(scanExtended(normalized), normalized);
  }
  const signals = {
    [`bytes_bucket=${Math.floor(Math.log2(1 + bytes))}`]: 1,
    [`files_bucket=${Math.floor(Math.log2(normalized.length))}`]: 1,
  };
  for (const { path } of normalized) {
    const extension = /\.([a-z0-9]{1,12})$/i.exec(path)?.[1]?.toLowerCase();
    if (extension) signals[`extension=${extension}`] = 1;
  }
  const current = manifestOnly ? scan(normalized[0].content) : scanPackage(normalized);
  if (reportOnly) return forecastReport(current, normalized);
  if (current.limited) signals['rules_truncated'] = 1;
  const baselineCodes = new Set();
  for (const finding of current.findings) {
    const key = `rule=${finding.id}/${finding.assessment}/${finding.severity}`;
    signals[key] = Math.min((signals[key] ?? 0) + 1, 5);
    for (const ref of finding.references) {
      const code = ref.name === 'Snyk' && /^([A-Z]\d{3})\b/.exec(ref.code)?.[1];
      if (code) baselineCodes.add(code);
    }
  }
  normalized.sort((left, right) => left.path.localeCompare(right.path, 'en'));
  return {
    text: normalized.map(({ path, content }) => `${path}\n${content}`).join('\n\n'),
    signals,
    baselineCodes: [...baselineCodes].sort(),
  };
}

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of input) {
  const { skill, files } = JSON.parse(line);
  const output = JSON.stringify({ skill, ...extract(files) });
  if (!process.stdout.write(output + '\n')) await new Promise(resolve => process.stdout.once('drain', resolve));
}
