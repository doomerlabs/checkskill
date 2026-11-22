import { maxPackageBytes, maxPackageFiles, maxPathLength, packageSizeLabel } from '../public/shared.js';
import { RequestError } from './request-error.js';

const sha = /^[a-f0-9]{40}$/;
const gistId = /^[a-f0-9]{5,64}$/i;
const ownerName = /^[a-z0-9-]{1,39}$/i;
const repoName = /^[a-z0-9_.-]{1,100}$/i;
const binary = /\.(?:zip|rar|7z|gz|tar|pdf|png|jpe?g|gif|webp|avif|ico|icns|mp[34]|wav|woff2?|ttf|exe|dll|so|dylib|wasm)$/i;
const encodePath = path => path.split('/').map(encodeURIComponent).join('/');

function parseGitHubInput(input) {
  const invalid = () => new RequestError(400, 'Enter a public GitHub, Gist, or Skills.sh URL, or an npx skills add command.');
  if (typeof input !== 'string' || input.length > 2048) throw invalid();
  input = input.trim();
  const command = /^(?:\$\s*)?npx\s+skills\s+add\s+(?:"([^"]+)"|'([^']+)'|(\S+))(?:\s+--skill(?:\s+|=)(?:"([\w.-]+)"|'([\w.-]+)'|([\w.-]+)))?$/.exec(input);
  let skill;
  if (command) {
    input = (command[1] ?? command[2] ?? command[3]).replace(/^https\\:/, 'https:');
    if (/^[\w.-]+\/[\w.-]+$/.test(input)) input = 'https://github.com/' + input;
    skill = command[4] ?? command[5] ?? command[6];
  }
  if (/^github\.com\//i.test(input)) input = 'https://' + input;
  let url, parts;
  try {
    url = new URL(input);
    parts = url.pathname.replace(/^\/|\/$/g, '').split('/').map(decodeURIComponent);
  } catch {
    throw invalid();
  }
  if (url.username || url.password || parts.some(part => !safeFile(part))) throw invalid();
  if (url.origin === 'https://gist.github.com') {
    const [, id, ref] = parts;
    if (command || !ownerName.test(parts[0]) || !id || !gistId.test(id) || parts.length > 3 ||
        (ref && !sha.test(ref))) throw invalid();
    return { gist: id.toLowerCase(), owner: parts[0], ref, file: url.searchParams.get('file'), anchor: url.hash };
  }
  if (url.origin === 'https://raw.githubusercontent.com') {
    if (parts[2] === 'refs' && ['heads', 'tags'].includes(parts[3])) parts.splice(2, 2);
    parts.splice(2, 0, 'blob');
  }
  const [owner, repository, view, ...path] = parts;
  const registry = ['https://skills.sh', 'https://www.skills.sh'].includes(url.origin);
  if ((!registry && !['https://github.com', 'https://raw.githubusercontent.com'].includes(url.origin)) ||
      !ownerName.test(owner) || !repository || !repoName.test(repository) ||
      parts.some(part => !part || /[\\\p{Cc}\p{Cf}]/u.test(part) || part.split('/').some(p => !p || p === '.' || p === '..'))) {
    throw invalid();
  }
  const repo = repository.replace(/\.git$/i, '');
  if (!repo || repo === '.' || repo === '..') throw invalid();
  const project = `${owner}/${repo}`;
  if (registry) {
    if (command || path.length || !view || !/^[\w.-]+$/.test(view)) throw invalid();
    return { project, skill: view };
  }
  if (!view) return { project, skill };
  if (view === 'skills' && !command && url.origin === 'https://github.com' &&
      path.length === 1 && /^[\w.-]+$/.test(path[0])) {
    return { project, skill: path[0] };
  }
  if (view === 'pull' && !command && /^[1-9]\d{0,15}$/.test(path[0] ?? '') &&
      (path.length === 1 || (path.length === 2 && ['files', 'commits'].includes(path[1])))) {
    return { project, pull: path[0] };
  }
  if (skill || !['tree', 'blob'].includes(view) || !path.length || path.slice(1).some(part => part.includes('/'))) throw invalid();
  if (view === 'blob' && path.pop() !== 'SKILL.md') throw invalid();
  if (!path.length) throw invalid();
  return { project, path };
}

function safeRef(ref) {
  return typeof ref === 'string' && ref.length > 0 && ref.length <= maxPathLength &&
    !/[\s\\~^:?*\[\p{Cc}\p{Cf}]/u.test(ref) && !ref.includes('..') && !ref.includes('@{') &&
    ref.split('/').every(part => part && !part.startsWith('.') && !part.endsWith('.') && !part.endsWith('.lock'));
}

function namedFolder(paths, skill) {
  const folders = paths.filter(path => path.endsWith('/SKILL.md') || path === 'SKILL.md')
    .map(path => path === 'SKILL.md' ? '' : path.slice(0, -'/SKILL.md'.length));
  const matches = folders.filter(folder => folder.split('/').at(-1) === skill);
  if (matches.includes(`skills/${skill}`)) return `skills/${skill}`;
  if (matches.length > 1) throw new RequestError(400, 'Several folders match this skill. Enter its GitHub folder URL.');
  return matches[0] ?? (folders.length === 1 && folders[0] === '' ? '' : undefined);
}

async function readBounded(response, limit, reserve) {
  if (!response.body) throw new RequestError(502, 'GitHub returned an empty response.');
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  let text = '';
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) return text + decoder.decode();
      length += value.byteLength;
      if (length > limit) throw new RequestError(413, 'The GitHub folder exceeds the import limits.');
      reserve?.(value.byteLength);
      text += decoder.decode(value, { stream: true });
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
}

function safeFile(path) {
  return typeof path === 'string' && path.length <= maxPathLength &&
    !/[\\\p{Cc}\p{Cf}]/u.test(path) && path.split('/').every(part => part && part !== '.' && part !== '..');
}

function checkFiles(files) {
  if (files.length > maxPackageFiles || files.some(item => !Number.isSafeInteger(item.size) || item.size < 0 ||
      !safeFile(item.path)) || files.reduce((total, item) => total + item.size, 0) > maxPackageBytes) {
    throw new RequestError(413, `GitHub skill folders can contain up to ${maxPackageFiles} text files and ${packageSizeLabel} of text.`);
  }
}

function textFile(bytes, path) {
  try {
    const content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    if (!content.includes('\0')) return { path, content: content.replace(/\r\n?/g, '\n') };
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
  }
  return null;
}

async function archiveFiles(response, folder, skill) {
  if (!response.body) throw new RequestError(502, 'GitHub returned an empty source archive.');
  const reader = response.body.pipeThrough(new DecompressionStream('gzip')).getReader();
  const blockSize = 512;
  const archiveLimit = 128 * 1024 * 1024;
  const decoder = new TextDecoder();
  const string = bytes => decoder.decode(bytes).split('\0', 1)[0];
  const candidates = new Map();
  const target = skill ? `skills/${skill}` : folder;
  let insideTarget = false;
  let commit;
  let nextPath;
  let hasNestedSkill = false;
  let retainedBytes = 0;
  let scannedBytes = 0;
  let chunk = new Uint8Array();
  let position = 0;

  async function read(size, keep = true) {
    const bytes = keep ? new Uint8Array(size) : null;
    let offset = 0;
    while (offset < size) {
      if (position === chunk.length) {
        const { value, done } = await reader.read();
        if (done) throw new RequestError(502, 'GitHub returned an incomplete source archive.');
        scannedBytes += value.length;
        if (scannedBytes > archiveLimit) {
          throw new RequestError(413, 'The GitHub archive is too large to import. Upload the skill folder instead.');
        }
        chunk = value;
        position = 0;
      }
      const count = Math.min(size - offset, chunk.length - position);
      if (keep) bytes.set(chunk.subarray(position, position + count), offset);
      position += count;
      offset += count;
    }
    return bytes;
  }

  try {
    while (true) {
      const header = await read(blockSize);
      if (!header[0]) break;
      const type = String.fromCharCode(header[156]);
      const sizeField = string(header.subarray(124, 136)).trim();
      const size = /^[0-7]+$/.test(sizeField) ? Number.parseInt(sizeField, 8) : -1;
      if (!Number.isSafeInteger(size) || size < 0) throw new RequestError(502, 'GitHub returned an invalid source archive.');
      const paddedSize = Math.ceil(size / blockSize) * blockSize;

      if (type === 'g' || type === 'x') {
        if (size > 64 * 1024) throw new RequestError(502, 'GitHub returned oversized archive metadata.');
        const bytes = await read(size);
        await read(paddedSize - size, false);
        // Git uses PAX records for its commit ID and paths that do not fit in the tar header.
        for (let index = 0; index < bytes.length;) {
          const space = bytes.indexOf(32, index);
          const width = space === -1 ? 0 : Number(decoder.decode(bytes.subarray(index, space)));
          if (!Number.isSafeInteger(width) || index + width <= space + 1 || index + width > bytes.length) {
            throw new RequestError(502, 'GitHub returned invalid archive metadata.');
          }
          const record = decoder.decode(bytes.subarray(space + 1, index + width - 1));
          if (type === 'g' && record.startsWith('comment=')) commit = record.slice(8);
          if (type === 'x' && record.startsWith('path=')) nextPath = record.slice(5);
          index += width;
        }
        continue;
      }

      const dir = string(header.subarray(345, 500));
      const archivePath = nextPath ?? (dir ? dir + '/' : '') + string(header.subarray(0, 100));
      nextPath = undefined;
      const slash = archivePath.indexOf('/');
      if (slash === -1 || type === '5') {
        await read(paddedSize, false);
        continue;
      }
      const relative = archivePath.slice(slash + 1);
      // GitHub's git archive groups each directory's entries. Stop once the
      // selected directory ends so a large unrelated tail cannot block import.
      if (target) {
        const inTarget = relative.startsWith(target + '/');
        if (!inTarget && insideTarget && candidates.get(target)?.hasSkill) break;
        insideTarget ||= inTarget;
      }
      const text = (type === '0' || type === '\0') && !binary.test(relative);
      const parts = relative.split('/');
      if (skill && text && parts.length > 1 && parts.at(-1) === 'SKILL.md') {
        hasNestedSkill = true;
        retainedBytes -= candidates.get('')?.bytes ?? 0;
        candidates.delete('');
      }
      const folders = skill
        ? parts.slice(0, -1).flatMap((part, index) => part === skill ? [parts.slice(0, index + 1).join('/')] : [])
        : [];
      if (skill ? !hasNestedSkill : !folder || relative.startsWith(folder + '/')) folders.push(folder);
      const destinations = [];
      for (const name of folders) {
        if (!candidates.has(name)) {
          if (candidates.size >= maxPackageFiles) throw new RequestError(413, 'Too many matching folders in the GitHub archive.');
          candidates.set(name, { entries: [], bytes: 0, count: 0, hasSkill: false, oversized: false });
        }
        const candidate = candidates.get(name);
        candidate.count++;
        const path = relative.slice(name ? name.length + 1 : 0);
        if (text && path === 'SKILL.md') candidate.hasSkill = true;
        if (!text || candidate.oversized) continue;
        if (!safeFile(path) || candidate.entries.length >= maxPackageFiles || candidate.bytes + size > maxPackageBytes) {
          retainedBytes -= candidate.bytes;
          candidate.entries = [];
          candidate.bytes = 0;
          candidate.oversized = true;
        } else {
          destinations.push({ candidate, path });
        }
      }
      const retained = size * destinations.length;
      if (retainedBytes + retained > maxPackageBytes * 3) {
        throw new RequestError(413, 'Too many matching files in the GitHub archive. Enter the GitHub folder URL.');
      }
      const bytes = await read(size, destinations.length > 0);
      await read(paddedSize - size, false);
      for (const { candidate, path } of destinations) {
        candidate.entries.push({ path, bytes });
        candidate.bytes += size;
      }
      retainedBytes += retained;
    }
  } catch (error) {
    if (error instanceof RequestError) throw error;
    throw new RequestError(502, 'GitHub returned an unreadable source archive.');
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }

  if (!sha.test(commit)) throw new RequestError(502, 'GitHub did not identify the archive revision.');
  if (skill) {
    const markers = [...candidates].filter(([, candidate]) => candidate.hasSkill)
      .map(([name]) => name ? name + '/SKILL.md' : 'SKILL.md');
    folder = namedFolder(markers, skill);
  }
  const selected = candidates.get(folder);
  if (!selected?.hasSkill) return null;
  if (selected.oversized) throw new RequestError(413, `GitHub skill folders can contain up to ${maxPackageFiles} text files and ${packageSizeLabel} of text.`);
  const files = selected.entries.map(file => textFile(file.bytes, file.path)).filter(Boolean);
  if (!files.some(file => file.path === 'SKILL.md')) throw new RequestError(400, 'SKILL.md is not readable as UTF-8 text.');
  return { commit, files, folder, skipped: selected.count - files.length };
}

function githubClient(project, signal) {
  const apiBase = 'https://api.github.com' + (project ? '/repos/' + project : '');
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(12000)]);
  async function get(url, missing = false, accept = 'application/vnd.github+json') {
    let response;
    try {
      response = await fetch(url, { redirect: 'manual', signal: deadline, headers: {
        'User-Agent': 'CheckSkill/1.0', Accept: accept,
      } });
    } catch {
      throw new RequestError(502, 'Could not reach GitHub. Try again or upload the skill folder.');
    }
    if (response.ok) return response;
    await response.body?.cancel().catch(() => {});
    if (missing && [404, 422].includes(response.status)) return null;
    if (response.status === 429 || response.status === 403 &&
        (response.headers.get('x-ratelimit-remaining') === '0' || response.headers.has('retry-after'))) {
      throw new RequestError(429, 'GitHub is rate limiting imports. Try again later or upload the skill folder.');
    }
    throw new RequestError(502, 'GitHub could not return the requested files.');
  }
  async function json(url, missing = false, limit = 2 * 1024 * 1024) {
    const response = await get(apiBase + url, missing);
    if (!response) return null;
    try {
      return JSON.parse(await readBounded(response, limit));
    } catch (error) {
      if (error instanceof RequestError) throw error;
      throw new RequestError(502, 'GitHub returned an invalid file listing.');
    }
  }
  async function tree(id, recursive = false) {
    const result = await json(`/git/trees/${id}${recursive ? '?recursive=1' : ''}`);
    if (!Array.isArray(result?.tree) || result.truncated) {
      throw new RequestError(413, 'GitHub could not list the entire folder. Try a smaller skill folder.');
    }
    return result.tree;
  }

  return { get, json, tree, deadline };
}

async function resolveRef(client, path, maxRefParts = 8) {
  // GitHub URLs put the ref and folder in the same path. Resolve a commit first so all files come from one revision.
  for (let end = 1; end <= Math.min(path.length, maxRefParts); end++) {
    const ref = path.slice(0, end).join('/');
    const commit = await client.json(`/commits/${encodeURIComponent(ref)}?per_page=1`, true);
    if (!commit) continue;
    let id = commit.commit?.tree?.sha;
    if (!sha.test(commit.sha) || !sha.test(id)) throw new RequestError(502, 'GitHub did not return a valid revision.');
    const folder = path.slice(end);
    if (folder.length > 10) throw new RequestError(400, 'Choose a skill folder less than 11 directories deep.');
    for (const part of folder) {
      id = (await client.tree(id)).find(item => item.type === 'tree' && item.path === part)?.sha;
      if (!sha.test(id)) break;
    }
    if (sha.test(id)) return { ref, commit: commit.sha, folder: folder.join('/'), tree: id };
  }
  throw new RequestError(404, 'Could not find that public GitHub branch, commit, or folder.');
}

async function publicGitRefs(client, project) {
  const type = 'application/x-git-upload-pack-advertisement';
  const response = await client.get(`https://github.com/${project}.git/info/refs?service=git-upload-pack`, false, type);
  if (!response.headers.get('Content-Type')?.startsWith(type)) {
    await response.body?.cancel().catch(() => {});
    throw new RequestError(502, 'GitHub returned an invalid branch listing.');
  }
  const advertisement = await readBounded(response, 2 * 1024 * 1024);
  const head = /\bsymref=HEAD:refs\/heads\/([^\s\0]+)/.exec(advertisement)?.[1];
  const branches = [...advertisement.matchAll(/(?:^|\n)[a-f0-9]{4}[a-f0-9]{40} refs\/heads\/([^\r\n\0]+)/g)]
    .map(match => match[1]).filter(safeRef);
  return { head: safeRef(head) ? head : undefined, branches };
}

export async function listGitHubRefs(input, signal) {
  const source = parseGitHubInput(input);
  if (source.gist) return { project: `${source.owner}/${source.gist}`, defaultRef: source.ref ?? 'HEAD', branches: [] };
  const { project, path, skill, pull } = source;
  const client = githubClient(project, signal);
  if (pull) {
    const head = await pullHead(client, pull);
    return { project: head.project, defaultRef: head.commit, branches: [head.commit] };
  }
  let defaultRef = path ? '' : 'HEAD';
  let branches = [];
  try {
    if (path) defaultRef = (await resolveRef(client, path)).ref;
    else {
      const repo = await client.json('', true);
      if (!repo || repo.private) throw new RequestError(404, 'Could not find that public GitHub repository.');
      if (safeRef(repo.default_branch)) defaultRef = repo.default_branch;
    }
    const listed = await client.json('/branches?per_page=100');
    if (Array.isArray(listed)) branches = listed.map(branch => branch?.name).filter(safeRef);
  } catch (error) {
    if (!(error instanceof RequestError) || error.status !== 429) throw error;
    const fallback = await publicGitRefs(client, project).catch(error => {
      if (!(error instanceof RequestError)) throw error;
      return { branches: [] };
    });
    branches = fallback.branches;
    if (!path && defaultRef === 'HEAD') defaultRef = fallback.head ?? defaultRef;
    if (path && !defaultRef) {
      const supplied = path.join('/');
      defaultRef = branches.filter(ref => supplied === ref || supplied.startsWith(ref + '/'))
        .sort((a, b) => b.length - a.length)[0] ?? '';
    }
  }
  return { project, skill, defaultRef, branches: [...new Set([defaultRef, ...branches].filter(Boolean))] };
}

export async function importGitHubSkill(input, signal, preferredRef) {
  const source = parseGitHubInput(input);
  if (preferredRef !== undefined && !safeRef(preferredRef)) throw new RequestError(400, 'Enter a valid branch, tag, or commit.');
  if (source.gist) return importGist(source, signal, preferredRef);
  if (source.pull) return importPull(source, signal, preferredRef);
  return importRepository(source, signal, preferredRef);
}

async function pullHead(client, pull) {
  const result = await client.json(`/pulls/${pull}`, true);
  const repo = result?.head?.repo;
  const [owner, name, extra] = (typeof repo?.full_name === 'string' ? repo.full_name : '').split('/');
  if (!result) throw new RequestError(404, 'Could not find that public GitHub pull request.');
  if (!sha.test(result.head?.sha) || repo?.private !== false || !ownerName.test(owner) || !name ||
      !repoName.test(name) || name === '.' || name === '..' || extra !== undefined) {
    throw new RequestError(404, 'The pull request’s head repository is unavailable.');
  }
  return { project: `${owner}/${name}`, commit: result.head.sha };
}

async function importPull({ project, pull }, signal, preferredRef) {
  const client = githubClient(project, signal);
  const { project: head, commit } = await pullHead(client, pull);
  const changed = await client.json(`/pulls/${pull}/files?per_page=100`);
  if (!Array.isArray(changed) || changed.length === 100) {
    throw new RequestError(400, 'This pull request changes many files. Paste a link to the specific skill folder.');
  }
  const folders = new Set();
  for (const file of changed) {
    if (file?.status === 'removed' || !safeFile(file?.filename)) continue;
    const path = file.filename.split('/');
    if (path.at(-1) === 'SKILL.md') folders.add(path.slice(0, -1).join('/'));
    else if (path[0] === 'skills' && path.length > 2) folders.add(path.slice(0, 2).join('/'));
  }
  if (folders.size > 1) throw new RequestError(400, 'This pull request touches multiple skills. Paste a link to the specific skill folder.');
  const folder = [...folders][0] ?? '';
  return importRepository({ project: head, path: [preferredRef ?? commit, ...folder.split('/').filter(Boolean)] }, signal);
}

async function importGist({ gist, owner, ref, file, anchor }, signal, preferredRef) {
  const revision = preferredRef === 'HEAD' ? ref : preferredRef ?? ref;
  if (revision && !sha.test(revision)) throw new RequestError(400, 'Enter a Gist revision commit.');
  const client = githubClient(undefined, signal);
  const result = await client.json(`/gists/${gist}${revision ? '/' + revision : ''}`, true, maxPackageBytes + 2 * 1024 * 1024);
  if (!result?.public) throw new RequestError(404, 'Could not find that public Gist.');
  const names = Object.keys(result.files ?? {}).filter(name => safeFile(name) && !name.includes('/'));
  if (!file && anchor?.startsWith('#file-')) {
    file = names.find(name => '#file-' + name.toLowerCase().replace(/[^a-z0-9-]/g, '-') === anchor.toLowerCase());
    if (!file) throw new RequestError(404, 'Could not find that file in the Gist.');
  }
  const markdown = names.filter(name => /\.(?:md|markdown|txt)$/i.test(name));
  const name = file ?? (names.includes('SKILL.md') ? 'SKILL.md' : markdown.length === 1 ? markdown[0] : undefined);
  if (!names.includes(name)) throw new RequestError(400, 'Choose a Markdown file in the Gist or paste a Gist with one skill file.');
  const entry = result.files[name];
  checkFiles([{ path: name, size: entry?.size }]);
  let content = entry.content;
  if (entry.truncated) {
    let raw;
    try { raw = new URL(entry.raw_url); } catch { throw new RequestError(502, 'GitHub did not identify the Gist file.'); }
    if (raw.origin !== 'https://gist.githubusercontent.com' || raw.username || raw.password ||
        !raw.pathname.toLowerCase().startsWith(`/${owner.toLowerCase()}/${gist}/raw/`)) {
      throw new RequestError(502, 'GitHub returned an invalid Gist file link.');
    }
    content = await readBounded(await client.get(raw.href), entry.size);
  }
  if (typeof content !== 'string' || !content.trim() || content.includes('\0')) {
    throw new RequestError(400, 'The Gist file is empty or is not readable text.');
  }
  const commit = revision ?? result.history?.[0]?.version;
  if (!sha.test(commit)) throw new RequestError(502, 'GitHub did not identify the Gist revision.');
  return {
    files: [{ path: 'SKILL.md', content: content.replace(/\r\n?/g, '\n') }],
    source: { project: `${owner}/${gist}`, gist, gistFile: name, ref: commit, commit, folder: '', skipped: 0 },
  };
}

async function importRepository({ project, path, skill }, signal, preferredRef) {
  const client = githubClient(project, signal);
  let resolved;
  try {
    resolved = await resolveRef(client, path ?? [preferredRef ?? 'HEAD']);
    if (path && preferredRef && preferredRef !== resolved.ref) {
      resolved = await resolveRef(client, [preferredRef, ...resolved.folder.split('/').filter(Boolean)], 1);
    }
    return await scanFiles(client, project, resolved, skill);
  } catch (error) {
    if (!(error instanceof RequestError) || ![413, 429].includes(error.status)) throw error;
    const original = path ?? [preferredRef ?? 'HEAD'];
    const choices = resolved ? [[resolved.ref, resolved.folder]] : original.slice(0, 8)
      .map((_, index) => [preferredRef ?? original.slice(0, index + 1).join('/'), original.slice(index + 1).join('/')]);
    try {
      const scoped = await importWebFolder(project, choices, skill, resolved?.commit, signal);
      if (scoped) return scoped;
    } catch (scopedError) {
      if (!(scopedError instanceof RequestError) || scopedError.status !== 502) throw scopedError;
      if (error.status !== 429) throw error;
    }
    if (error.status !== 429) throw error;
    for (const [ref, folder] of choices) {
      const response = await client.get(`https://codeload.github.com/${project}/tar.gz/${encodeURIComponent(resolved?.commit ?? ref)}`, true);
      if (!response) continue;
      const result = await archiveFiles(response, folder, skill);
      const expectedCommit = resolved?.commit ?? (sha.test(ref) ? ref : undefined);
      if (result && expectedCommit && result.commit !== expectedCommit) {
        throw new RequestError(502, 'GitHub returned a different archive revision.');
      }
      if (result) return { files: result.files, source: { project, ref, folder: result.folder, commit: result.commit, skipped: result.skipped } };
    }
    throw new RequestError(404, 'Could not find the requested skill at that public GitHub revision.');
  }
}

async function webDirectory(client, project, ref, folder) {
  const response = await client.get(
    `https://github.com/${project}/tree/${encodePath(ref)}${folder ? '/' + encodePath(folder) : ''}`,
    true, 'application/json');
  if (!response) return null;
  let view;
  try {
    view = JSON.parse(await readBounded(response, 2 * 1024 * 1024))?.payload?.codeViewTreeRoute;
  } catch (error) {
    if (error instanceof RequestError) throw error;
    throw new RequestError(502, 'GitHub returned an unreadable directory listing.');
  }
  if (!view || view.path !== folder) return null;
  const commit = view.refInfo?.currentOid;
  const items = view.tree?.items;
  if (!sha.test(commit) || (sha.test(ref) && commit !== ref) || !Array.isArray(items) ||
      view.tree.totalCount !== items.length) {
    throw new RequestError(502, 'GitHub returned an incomplete directory listing.');
  }
  const prefix = folder ? folder + '/' : '';
  const names = new Set();
  for (const item of items) {
    if (!safeFile(item?.name) || item.name.includes('/') || item.path !== prefix + item.name || names.has(item.name)) {
      throw new RequestError(502, 'GitHub returned invalid directory entries.');
    }
    names.add(item.name);
  }
  return { commit, items };
}

async function importWebFolder(project, choices, skill, commit, signal) {
  const client = githubClient(project, signal);
  for (const [ref, base] of choices) {
    const folder = skill ? [base, 'skills', skill].filter(Boolean).join('/') : base;
    if (!folder) continue;
    const directory = await webDirectory(client, project, commit ?? ref, folder);
    if (!directory?.items.some(item => item.name === 'SKILL.md' && item.contentType === 'file')) continue;
    const paths = [];
    const queue = [directory.items];
    const rawBase = `https://raw.githubusercontent.com/${project}/${directory.commit}/`;
    let skipped = 0;
    for (let index = 0; index < queue.length; index++) {
      for (const item of queue[index]) {
        if (item.contentType === 'directory') {
          if (queue.length >= maxPackageFiles || item.path.split('/').length > 22) {
            throw new RequestError(413, 'The skill folder has too many nested directories.');
          }
          const child = await webDirectory(client, project, directory.commit, item.path);
          if (!child) throw new RequestError(502, 'GitHub could not list a skill subfolder.');
          queue.push(child.items);
        } else if (item.contentType === 'file' && !binary.test(item.path)) {
          if (paths.length >= maxPackageFiles) throw new RequestError(413, `Folders can contain up to ${maxPackageFiles} text files.`);
          paths.push(item.path);
        } else skipped++;
      }
    }
    let bytes = 0;
    const files = [];
    const reserve = size => {
      bytes += size;
      if (bytes > maxPackageBytes) throw new RequestError(413, `Folder text can be at most ${packageSizeLabel} in total.`);
    };
    for (let offset = 0; offset < paths.length; offset += 6) {
      const batch = await Promise.all(paths.slice(offset, offset + 6).map(async path => {
        const response = await client.get(rawBase + encodePath(path));
        try {
          const content = await readBounded(response, maxPackageBytes, reserve);
          if (!content.includes('\0')) return { path: path.slice(folder.length + 1), content: content.replace(/\r\n?/g, '\n') };
        } catch (error) {
          if (!(error instanceof TypeError) || client.deadline.aborted) throw error;
        }
        return null;
      }));
      for (const file of batch) if (file) files.push(file); else skipped++;
    }
    if (!files.some(file => file.path === 'SKILL.md')) throw new RequestError(400, 'SKILL.md is not readable as UTF-8 text.');
    return { files, source: { project, ref, commit: directory.commit, folder, skipped } };
  }
  return null;
}

async function scanFiles({ get, tree, deadline }, project, resolved, skill) {
  const listing = await tree(resolved.tree, true);
  const blobs = listing.filter(item => item.type === 'blob' && /^100(?:644|755)$/.test(item.mode));
  const folder = skill ? namedFolder(blobs.map(item => item.path), skill) : '';
  if (folder === undefined) throw new RequestError(404, 'Could not find that skill at this revision. Try its GitHub folder URL.');
  const prefix = folder ? folder + '/' : '';
  const scope = listing.filter(item => item.type !== 'tree' && item.path.startsWith(prefix));
  const wanted = blobs.filter(item => item.path.startsWith(prefix) && !binary.test(item.path))
    .map(item => ({ ...item, path: item.path.slice(prefix.length) }));
  if (!wanted.some(item => item.path === 'SKILL.md')) throw new RequestError(400, 'Choose a skill folder that contains SKILL.md.');
  checkFiles(wanted);
  const sourceFolder = [resolved.folder, folder].filter(Boolean).join('/');
  const rawBase = 'https://raw.githubusercontent.com/' + project + '/' + resolved.commit + '/';
  const files = [];
  let skipped = scope.length - wanted.length;
  for (let offset = 0; offset < wanted.length; offset += 6) {
    const batch = await Promise.all(wanted.slice(offset, offset + 6).map(async ({ path, size }) => {
      const fullPath = sourceFolder ? sourceFolder + '/' + path : path;
      const response = await get(rawBase + encodePath(fullPath));
      try {
        const content = await readBounded(response, size);
        if (!content.includes('\0')) return { path, content: content.replace(/\r\n?/g, '\n') };
      } catch (error) {
        if (error instanceof RequestError) throw error;
        if (!(error instanceof TypeError) || deadline.aborted) throw new RequestError(502, 'A GitHub file could not be downloaded.');
      }
      return null;
    }));
    for (const file of batch) if (file) files.push(file); else skipped++;
  }
  if (!files.some(file => file.path === 'SKILL.md')) throw new RequestError(400, 'SKILL.md is not readable as UTF-8 text.');
  return { files, source: { project, ref: resolved.ref, commit: resolved.commit, folder: sourceFolder, skipped } };
}
