import { describe, expect, it } from 'vitest';
import { parseGithubUrl } from '../src/github/parseUrl.js';

describe('parseGithubUrl', () => {
  it('accepts owner/repo URLs and an optional trailing slash', () => {
    expect(parseGithubUrl('https://github.com/acme/widgets')).toEqual({
      owner: 'acme',
      repo: 'widgets',
    });
    expect(parseGithubUrl('https://github.com/acme/widgets/')).toEqual({
      owner: 'acme',
      repo: 'widgets',
    });
  });

  it('rejects tree refs, other hosts, and non-https URLs', () => {
    expect(parseGithubUrl('https://github.com/acme/widgets/tree/main')).toBeNull();
    expect(parseGithubUrl('https://gitlab.com/acme/widgets')).toBeNull();
    expect(parseGithubUrl('http://github.com/acme/widgets')).toBeNull();
    expect(parseGithubUrl('git@github.com:acme/widgets.git')).toBeNull();
    expect(parseGithubUrl('https://github.com/acme/widgets.git')).toBeNull();
  });
});
