import { maxPackageBytes, maxPackageFiles, maxPathLength, maxSkillBytes, packageSizeLabel } from '../public/shared.js';
import { publicSkillInput } from '../public/skill-route.js';
import { scan, scanPackage } from './rules.js';
import { snykReportFromFindings } from './snyk-report.js';
import { importGitHubSkill, listGitHubRefs } from './github.js';
import { RequestError } from './request-error.js';
import { createJsonTextCompactor } from './json-text.js';
import { recordScan } from './scan-analytics.js';

const maxScanRequest = (maxPackageBytes + maxPackageFiles * maxPathLength) * 6 + 4096;
const maxRefsRequest = 16 * 1024;
const encoder = new TextEncoder();

const headers = {
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Robots-Tag': 'noindex',
};

async function readInput(request, refsOnly) {
  const type = (request.headers.get('Content-Type') || '').split(';', 1)[0].trim().toLowerCase();
  const json = type === 'application/json';
  if (refsOnly && !json) throw new RequestError(415, 'Send JSON with a githubUrl string.');
  if (!json && !['text/plain', 'text/markdown', 'application/octet-stream'].includes(type)) {
    throw new RequestError(415, 'Send text/plain or JSON with a skill string.');
  }
  const limit = refsOnly ? maxRefsRequest : json ? maxScanRequest : maxSkillBytes;
  const sizeError = json ? 'The JSON request exceeds the size limit.' : `The skill can be at most ${packageSizeLabel}.`;
  if (Number(request.headers.get('Content-Length')) > limit) {
    throw new RequestError(413, sizeError);
  }
  const reader = request.body?.getReader();
  if (!reader) throw new RequestError(400, 'The request body is empty.');
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: !json });
  const compactor = json ? createJsonTextCompactor() : null;
  let length = 0;
  let text = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) throw new RequestError(413, sizeError);
      for (let offset = 0; offset < value.length; offset += 64 * 1024) {
        const decoded = decoder.decode(value.subarray(offset, offset + 64 * 1024), { stream: true });
        text += compactor ? compactor.append(decoded) : decoded;
      }
    }
    const finalText = decoder.decode();
    text += compactor ? compactor.append(finalText) + compactor.finish() : finalText;
    if (json) text = JSON.parse(text);
  } catch (error) {
    await reader.cancel().catch(() => {});
    if (error instanceof RequestError) throw error;
    throw new RequestError(400, json ? 'Send valid UTF-8 JSON with a skill string.' : 'Send UTF-8 plain text.');
  } finally {
    reader.releaseLock();
  }
  if (json && text && Object.hasOwn(text, 'githubUrl')) {
    if (Object.hasOwn(text, 'skill') || Object.hasOwn(text, 'files')) {
      throw new RequestError(400, 'Send a repository reference or skill content.');
    }
    return { githubUrl: text.githubUrl, ref: text.ref };
  }
  if (refsOnly) throw new RequestError(400, 'Provide githubUrl to list revisions.');
  if (json && text && Object.hasOwn(text, 'files')) {
    if (Object.hasOwn(text, 'skill')) throw new RequestError(400, 'Send either files or a skill string.');
    return readPackage(text.files);
  }
  if (json) text = text?.skill;
  if (typeof text !== 'string' || !text.trim()) {
    throw new RequestError(400, 'Provide a nonempty skill.');
  }
  // Normalize lone JSON surrogate escapes the same way UTF-8 encoders do.
  text = text.toWellFormed();
  if (encoder.encode(text).byteLength > maxSkillBytes) {
    throw new RequestError(413, `The skill can be at most ${packageSizeLabel}.`);
  }
  return text;
}

function readPackage(files) {
  if (!Array.isArray(files) || !files.length) {
    throw new RequestError(400, 'Provide a nonempty files array.');
  }
  if (files.length > maxPackageFiles) throw new RequestError(413, `Folders can contain up to ${maxPackageFiles} text files.`);
  let total = 0;
  const seen = new Set();
  return files.map(file => {
    if (typeof file?.path !== 'string' || typeof file?.content !== 'string') {
      throw new RequestError(400, 'Each file must have a path and text content.');
    }
    const path = file.path.toWellFormed();
    if (path.length > maxPathLength || /[\\\p{Cc}\p{Cf}]/u.test(path) ||
        path.split('/').some(part => !part || part === '.' || part === '..') || seen.has(path)) {
      throw new RequestError(400, 'File paths must be unique and relative to the skill folder.');
    }
    seen.add(path);
    const content = file.content.toWellFormed();
    total += encoder.encode(content).byteLength;
    if (total > maxPackageBytes) throw new RequestError(413, `Folder text can be at most ${packageSizeLabel} in total.`);
    return { path, content };
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);
    if (['GET', 'HEAD'].includes(request.method) && publicSkillInput(url.pathname, url.search)) {
      return env.ASSETS.fetch(request);
    }

    try {
      if (!['/api/scan', '/api/refs'].includes(url.pathname)) {
        throw new RequestError(404, 'API endpoint not found.');
      }
      if (request.method !== 'POST') {
        return Response.json({ error: 'Use POST.' }, { status: 405, headers: { ...headers, Allow: 'POST' } });
      }
      const origin = request.headers.get('Origin');
      if (origin && origin !== url.origin) throw new RequestError(403, 'This request must come from the same site.');
      const refsOnly = url.pathname === '/api/refs';
      const skill = await readInput(request, refsOnly);
      if (refsOnly) return Response.json(await listGitHubRefs(skill.githubUrl, request.signal, env.GITHUB_IMPORT_TOKEN), { headers });
      const imported = typeof skill === 'object' && Object.hasOwn(skill, 'githubUrl') ?
        await importGitHubSkill(skill.githubUrl, request.signal, skill.ref, env.GITHUB_IMPORT_TOKEN) : undefined;
      const input = imported ? readPackage(imported.files) : skill;
      const result = typeof input === 'string' ? scan(input) : scanPackage(input);
      const snykForecast = snykReportFromFindings(result);
      const response = Response.json({ ...result, snykForecast, ...imported }, { headers });
      if (env.SCAN_ANALYTICS && ctx) {
        const inputType = imported ? 'public_url' : Array.isArray(input) ? 'folder' :
          request.headers.get('X-CheckSkill-Input-Type') === 'file' ? 'file' : 'markdown';
        ctx.waitUntil(recordScan(env.SCAN_ANALYTICS, inputType, result, snykForecast, imported?.source).catch(() => {}));
      }
      return response;
    } catch (error) {
      const expected = error instanceof RequestError;
      return Response.json({ error: expected ? error.message : 'The request could not be completed.' },
        { status: expected ? error.status : 500, headers });
    }
  }
};
