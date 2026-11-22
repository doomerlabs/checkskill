const skillName = /^[\w.-]+$/;
const routePath = /^\/([a-z0-9-]{1,39})\/([a-z0-9_.-]{1,100})\/([\w.-]+)\/?$/i;
const gistRoute = /^\/-\/gist\/([a-z0-9-]{1,39})\/([a-f0-9]{5,64})\/?$/i;
const securitySuffix = '/security/snyk';

export function skillOverviewPath(path) {
  const [pathname, search] = path.split('?');
  const base = pathname.replace(/\/security\/snyk\/?$/, '');
  return base !== pathname && (routePath.test(base) || gistRoute.test(base)) ?
    base + (search === undefined ? '' : '?' + search) : path;
}

export function snykPreviewPath(path) {
  const [pathname, search] = skillOverviewPath(path).split('?');
  return pathname.replace(/\/$/, '') + securitySuffix + (search === undefined ? '' : '?' + search);
}

export function publicSkillPath({ project, folder, ref, gist, gistFile }, defaultRef, skill) {
  if (gist) {
    const query = new URLSearchParams({ ref, file: gistFile });
    return `/-/gist/${project}?${query}`;
  }
  const name = folder.split('/').at(-1);
  const slug = skill ?? (skillName.test(name) ? name : project.split('/').at(-1));
  const query = new URLSearchParams();
  if (ref !== 'HEAD' && ref !== defaultRef) query.set('ref', ref);
  if (!skill && folder !== `skills/${slug}`) query.set('folder', folder);
  return `/${project}/${slug}${query.size ? '?' + query : ''}`;
}

export function publicSkillInput(path, search) {
  path = skillOverviewPath(path);
  const query = new URLSearchParams(search);
  const ref = query.get('ref') || undefined;
  const gist = gistRoute.exec(path);
  if (gist) {
    const [, owner, id] = gist;
    const file = query.get('file');
    const selection = file ? '?' + new URLSearchParams({ file }) : '';
    return { githubUrl: `https://gist.github.com/${owner}/${id}${selection}`, ref };
  }
  const match = routePath.exec(path);
  if (!match || match.slice(1).some(part => part === '.' || part === '..')) return null;
  const [, owner, repo, slug] = match;
  const project = `${owner}/${repo}`;
  const folder = query.get('folder');
  if (folder === null) return { githubUrl: `https://skills.sh/${project}/${slug}`, ref };
  const base = `https://github.com/${project}`;
  const encodedFolder = folder.split('/').map(encodeURIComponent).join('/');
  return { githubUrl: folder ? `${base}/tree/${encodeURIComponent(ref ?? 'HEAD')}/${encodedFolder}` : base, ref };
}
