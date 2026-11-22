import test from 'node:test';
import assert from 'node:assert/strict';
import { publicSkillInput, publicSkillPath, skillOverviewPath, snykPreviewPath } from '../public/skill-route.js';

test('public imports use a clean path for the repository default', () => {
  const base = { project: 'example/repo', folder: 'skills/demo' };
  const path = publicSkillPath({ ...base, ref: 'stable' }, 'stable');
  assert.equal(path, '/example/repo/demo');
  assert.deepEqual(publicSkillInput(path, ''), { githubUrl: 'https://skills.sh/example/repo/demo', ref: undefined });
  assert.equal(publicSkillPath({ ...base, folder: 'plugins/demo', ref: 'stable' }, 'stable', 'demo'), path);
});

test('public skill paths reopen a nondefault ref and disambiguate an explicit folder', () => {
  const ref = 'feature/demo';
  const path = publicSkillPath({ project: 'example/repo', folder: 'plugin/other/demo', ref }, 'main');
  const url = new URL(path, 'https://checkskill.ai');
  assert.equal(url.pathname, '/example/repo/demo');
  assert.deepEqual(publicSkillInput(url.pathname, url.search), {
    githubUrl: 'https://github.com/example/repo/tree/feature%2Fdemo/plugin/other/demo', ref,
  });
  assert.deepEqual(publicSkillInput('/example/repo/repo', '?folder='), {
    githubUrl: 'https://github.com/example/repo', ref: undefined,
  });
  assert.equal(publicSkillInput('/', ''), null);
});

test('Gist paths preserve the selected file and revision', () => {
  const ref = 'a'.repeat(40);
  const url = new URL(publicSkillPath({
    project: 'example/deadbeef', gist: 'deadbeef', gistFile: 'my skill.md', folder: '', ref,
  }), 'https://checkskill.ai');
  assert.deepEqual(publicSkillInput(url.pathname, url.search), {
    githubUrl: 'https://gist.github.com/example/deadbeef?file=my+skill.md', ref,
  });
});

test('Snyk report routes reopen the original skill and preserve its ref', () => {
  const overview = '/github/awesome-copilot/github-issues?ref=work%2Fbranch';
  const preview = snykPreviewPath(overview);
  assert.equal(preview, '/github/awesome-copilot/github-issues/security/snyk?ref=work%2Fbranch');
  assert.equal(skillOverviewPath(preview), overview);
  const url = new URL(preview, 'https://checkskill.ai');
  assert.deepEqual(publicSkillInput(url.pathname, url.search), {
    githubUrl: 'https://skills.sh/github/awesome-copilot/github-issues', ref: 'work/branch',
  });
});
