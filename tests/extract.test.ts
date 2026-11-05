import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import AdmZip from 'adm-zip';
import { afterEach, describe, expect, it } from 'vitest';
import {
  extractArchive,
  fetchRepository,
  MAX_ARCHIVE_BYTES,
  MAX_FILE_BYTES,
  sharedRootPrefix,
  toSafeRelative,
} from '../src/scanner/fetchRepo.js';

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'scanner-extract-'));
  directories.push(dir);
  return dir;
}

describe('archive paths', () => {
  it('strips the zipball root and rejects traversal', () => {
    expect(toSafeRelative('acme-widgets-abc/src/app.js', 'acme-widgets-abc')).toBe('src/app.js');
    expect(toSafeRelative('acme-widgets-abc/../../etc/passwd', 'acme-widgets-abc')).toBeNull();
    expect(toSafeRelative('/etc/passwd', null)).toBeNull();
    expect(sharedRootPrefix(['acme-widgets-abc/a.js', 'acme-widgets-abc/b.js'])).toBe('acme-widgets-abc');
  });
});

describe('private repositories', () => {
  it('rejects private GitHub metadata before downloading source', async () => {
    const calls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      calls.push(url);
      return new Response(JSON.stringify({ private: true, default_branch: 'main' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    try {
      await expect(
        fetchRepository({
          scanId: 'private-repo-scan',
          owner: 'acme',
          repo: 'widgets',
          githubToken: 'token',
        }),
      ).rejects.toThrow(/Private repositories are not supported/);
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(calls).toHaveLength(1);
    expect(calls[0]).toContain('/repos/acme/widgets');
    expect(calls.some((url) => url.includes('/zipball/'))).toBe(false);
  });
});

describe('extractArchive', () => {
  it('keeps source files and skips dependencies, lockfiles, and unsafe paths', async () => {
    const zip = new AdmZip();
    zip.addFile('repo-main/src/app.js', Buffer.from('console.log(1)\n'));
    zip.addFile('repo-main/package.json', Buffer.from('{"dependencies":{"lodash":"4.17.21"}}'));
    zip.addFile('repo-main/node_modules/leftpad/index.js', Buffer.from('module.exports = 1\n'));
    zip.addFile('repo-main/package-lock.json', Buffer.from('{"lock":true}'));
    zip.addFile('repo-main/../../outside.txt', Buffer.from('nope'));

    const rootDir = await tempDir();
    const extracted = await extractArchive(zip.toBuffer(), rootDir);

    expect(extracted.files.map((file) => file.path).sort()).toEqual(['package.json', 'src/app.js']);
    expect(extracted.packageJson).toMatchObject({ dependencies: { lodash: '4.17.21' } });
    expect(extracted.truncated).toBe(false);
  });

  it('marks coverage incomplete when a source file exceeds the per-file limit', async () => {
    const zip = new AdmZip();
    zip.addFile('repo-main/src/app.js', Buffer.from('console.log(1)\n'));
    zip.addFile('repo-main/src/huge.js', Buffer.alloc(MAX_FILE_BYTES + 1, 0x61));

    const rootDir = await tempDir();
    const extracted = await extractArchive(zip.toBuffer(), rootDir);

    expect(extracted.files.map((file) => file.path)).toEqual(['src/app.js']);
    expect(extracted.truncated).toBe(true);
  });

  it('marks an archive with no eligible source files as incomplete', async () => {
    const zip = new AdmZip();
    zip.addFile('repo-main/src/huge.js', Buffer.alloc(MAX_FILE_BYTES + 1, 0x61));

    const rootDir = await tempDir();
    const extracted = await extractArchive(zip.toBuffer(), rootDir);

    expect(extracted.files).toEqual([]);
    expect(extracted.truncated).toBe(true);
  });

  it('rejects an archive over the download limit', async () => {
    const rootDir = await tempDir();
    const oversized = Buffer.alloc(MAX_ARCHIVE_BYTES + 1);
    await expect(extractArchive(oversized, rootDir)).rejects.toThrow(/25 MB/);
  });
});
