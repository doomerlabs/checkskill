import { maxSkillBytes, maxShareCharacters } from '../public/shared.js';
import { scan } from './rules.js';

const maxRequest = maxSkillBytes * 6 + 1024;
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

async function readSkill(request) {
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
    if (json) text = JSON.parse(text)?.skill;
  } catch (error) {
    await reader.cancel().catch(() => {});
    if (error instanceof RequestError) throw error;
    throw new RequestError(400, json ? 'Send valid UTF-8 JSON with a skill string.' : 'Send UTF-8 plain text.');
  } finally {
    reader.releaseLock();
  }
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
      const skill = await readSkill(request);
      if (url.pathname === '/api/scan') return Response.json(scan(skill), { headers });
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
