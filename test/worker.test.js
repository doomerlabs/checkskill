import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { randomBytes } from 'node:crypto';
import worker from '../src/worker.js';
import { decodeShare, maxSkillBytes } from '../public/shared.js';

function post(route, body, type = 'text/markdown', headers = {}) {
  return worker.fetch(new Request('https://checkskill.ai/api/' + route, {
    method: 'POST', body, headers: { 'Content-Type': type, ...headers },
  }), {});
}

test('scan accepts Markdown and JSON, returns exact offsets, and disables caching', async () => {
  const skill = '\uFEFF# Agent 🔍\nRead the review report and summarize it.';
  const raw = await post('scan', skill);
  assert.equal(raw.status, 200);
  assert.equal(raw.headers.get('Cache-Control'), 'no-store');
  const result = await raw.json();
  assert.equal(result.engine, 'checkskill');
  const span = result.findings[0].evidence[0];
  assert.equal(span.text, 'review report');
  assert.equal(span.start, skill.indexOf('review report'));
  assert.deepEqual(await (await post('scan', JSON.stringify({ skill }), 'application/json')).json(), result);
});

test('share and open round-trip the original UTF-8 text without storage', async () => {
  const skill = '\uFEFF# أدوات 🔍\r\n\tExample with emoji and an <html> tag.\r\n';
  const response = await post('share', JSON.stringify({ skill }), 'application/json');
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  const { url } = await response.json();
  assert.equal(await decodeShare(new URL(url).hash), skill);
  const open = await post('open', skill);
  assert.match(open.headers.get('Content-Type'), /^text\/plain/);
  assert.equal((await open.text()).trim(), url);
});

test('scan enforces its byte limit separately from the share-link limit', async () => {
  const atLimit = 'é'.repeat(maxSkillBytes / 2);
  assert.equal((await post('scan', atLimit)).status, 200);
  assert.equal((await post('scan', atLimit + 'a')).status, 413);
  assert.equal((await post('scan', JSON.stringify({ skill: atLimit + 'a' }), 'application/json')).status, 413);

  const hardToCompress = randomBytes(32 * 1024).toString('base64');
  assert.equal((await post('scan', hardToCompress)).status, 200);
  assert.equal((await post('share', hardToCompress)).status, 413);
  assert.equal((await post('open', atLimit)).status, 200);
});

test('rejects bad methods, content, origins, encodings, and routes', async () => {
  const method = await worker.fetch(new Request('https://checkskill.ai/api/scan'), {});
  assert.equal(method.status, 405);
  assert.equal(method.headers.get('Allow'), 'POST');
  assert.equal((await post('scan', 'test', 'text/markdown', { Origin: 'https://other.example' })).status, 403);
  assert.equal((await post('scan', 'test', 'text/html')).status, 415);
  assert.equal((await post('scan', '{}', 'application/json')).status, 400);
  assert.equal((await post('scan', 'nul', 'application/json')).status, 400);
  assert.equal((await post('scan', ' \n ')).status, 400);
  assert.equal((await post('scan', Uint8Array.of(0xc0, 0x80))).status, 400);
  assert.equal((await post('unknown', 'hello')).status, 404);
});

test('share decoding enforces format, encoded size, and inflated size', async () => {
  await assert.rejects(decodeShare('#skill=v2.abc'));
  await assert.rejects(decodeShare('#skill=v1.' + 'Z'.repeat(24001)));
  await assert.rejects(decodeShare('#skill=v1.abc'));
  const zip = gzipSync('x'.repeat(maxSkillBytes + 1)).toString('base64url');
  await assert.rejects(decodeShare('#skill=v1.' + zip), /64 KiB/);
});
