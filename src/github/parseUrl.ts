const NAME = /^[A-Za-z0-9_.-]+$/;

export interface GithubRepoRef {
  owner: string;
  repo: string;
}

/**
 * Accept only `https://github.com/{owner}/{repo}` with an optional trailing slash.
 */
export function parseGithubUrl(input: string): GithubRepoRef | null {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    return null;
  }

  if (url.protocol !== 'https:' || url.hostname !== 'github.com') {
    return null;
  }
  if (url.search !== '' || url.hash !== '' || url.username !== '' || url.password !== '') {
    return null;
  }

  const parts = url.pathname.split('/').filter((part) => part.length > 0);
  if (parts.length !== 2) {
    return null;
  }

  const owner = parts[0];
  const repo = parts[1];
  if (!owner || !repo || repo.endsWith('.git')) {
    return null;
  }
  if (!NAME.test(owner) || !NAME.test(repo)) {
    return null;
  }

  return { owner, repo };
}
