import { maxPackageFiles, maxPathLength, maxSkillBytes, maxShareCharacters } from '../public/shared.js';
import { scan, scanPackage } from './rules.js';

const maxRequest = (maxSkillBytes + maxPackageFiles * maxPathLength) * 6 + 4096;
const encoder = new TextEncoder();

const headers = {
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Robots-Tag': 'noindex',
};

class RequestError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function readInput(request, allowPackage) {
  const type = (request.headers.get('Content-Type') || '').split(';', 1)[0].trim().toLowerCase();
  const json = type === 'application/json';
  if (!json && !['text/plain', 'text/markdown', 'application/octet-stream'].includes(type)) {
    throw new RequestError(415, 'Send text/plain or JSON with a skill string.');
  }
  const limit = json ? maxRequest : maxSkillBytes;
  if (Number(request.headers.get('Content-Length')) > limit) {
    throw new RequestError(413, 'The skill can be at most 64 KiB.');
  }
  const reader = request.body?.getReader();
  if (!reader) throw new RequestError(400, 'The request body is empty.');
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: !json });
  let length = 0;
  let text = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) throw new RequestError(413, 'The skill can be at most 64 KiB.');
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    if (json) text = JSON.parse(text);
  } catch (error) {
    await reader.cancel().catch(() => {});
    if (error instanceof RequestError) throw error;
    throw new RequestError(400, json ? 'Send valid UTF-8 JSON with a skill string.' : 'Send UTF-8 plain text.');
  } finally {
    reader.releaseLock();
  }
  if (json && text && Object.hasOwn(text, 'files')) {
    if (!allowPackage || Object.hasOwn(text, 'skill')) {
      throw new RequestError(400, 'Folder input is supported by /api/scan. Send either files or a skill string.');
    }
    return readPackage(text.files);
  }
  if (json) text = text?.skill;
  if (typeof text !== 'string' || !text.trim()) {
    throw new RequestError(400, 'Provide a nonempty skill.');
  }
  // Normalize lone JSON surrogate escapes the same way UTF-8 encoders do.
  text = text.toWellFormed();
  if (encoder.encode(text).byteLength > maxSkillBytes) {
    throw new RequestError(413, 'The skill can be at most 64 KiB.');
  }
  return text;
}

function readPackage(files) {
  if (!Array.isArray(files) || !files.length) {
    throw new RequestError(400, 'Provide a nonempty files array.');
  }
  if (files.length > maxPackageFiles) throw new RequestError(413, 'Folders can contain up to 64 text files.');
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
    if (total > maxSkillBytes) throw new RequestError(413, 'Folder text can be at most 64 KiB in total.');
    return { path, content };
  });
}

async function shareUrl(skill, origin) {
  const stream = new Blob([skill]).stream().pipeThrough(new CompressionStream('gzip'));
  const compressed = new Uint8Array(await new Response(stream).arrayBuffer());
  // Reject before spreading a large array into a single function call.
  if (compressed.length > maxShareCharacters * 3 / 4) {
    throw new RequestError(413, 'This skill is too large for a share link. You can still scan it.');
  }
  const encoded = btoa(String.fromCharCode(...compressed)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return origin + '/#skill=v1.' + encoded;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);

    try {
      if (!['/api/scan', '/api/share', '/api/open'].includes(url.pathname)) {
        throw new RequestError(404, 'API endpoint not found.');
      }
      if (request.method !== 'POST') {
        return Response.json({ error: 'Use POST.' }, { status: 405, headers: { ...headers, Allow: 'POST' } });
      }
      const origin = request.headers.get('Origin');
      if (origin && origin !== url.origin) throw new RequestError(403, 'This request must come from the same site.');
      const isScan = url.pathname === '/api/scan';
      const skill = await readInput(request, isScan);
      if (isScan) return Response.json(typeof skill === 'string' ? scan(skill) : scanPackage(skill), { headers });
      const link = await shareUrl(skill, url.origin);
      if (url.pathname === '/api/share') return Response.json({ url: link }, { headers });
      return new Response(link + '\n', { headers: { ...headers, 'Content-Type': 'text/plain; charset=utf-8' } });
    } catch (error) {
      const expected = error instanceof RequestError;
      return Response.json({ error: expected ? error.message : 'The request could not be completed.' },
        { status: expected ? error.status : 500, headers });
    }
  }
};
