import { createHash } from 'node:crypto';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import AdmZip from 'adm-zip';
import type { ScanContext, ScanFile } from './context.js';

export const MAX_ARCHIVE_BYTES = 25 * 1024 * 1024;
export const MAX_EXTRACTED_BYTES = 80 * 1024 * 1024;
export const MAX_FILES = 400;
export const MAX_FILE_BYTES = 200 * 1024;

const GITHUB_TIMEOUT_MS = 60_000;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', 'vendor']);
const SKIP_FILES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lock',
  'bun.lockb',
]);

export class RepositoryFetchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RepositoryFetchError';
  }
}

export interface FetchRepositoryInput {
  scanId: string;
  owner: string;
  repo: string;
  githubToken?: string;
}

function githubHeaders(token: string | undefined): Headers {
  const headers = new Headers({
    Accept: 'application/vnd.github+json',
    'User-Agent': 'ai-security-scanner',
    'X-GitHub-Api-Version': '2022-11-28',
  });
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  return headers;
}

async function githubGet(url: string, token: string | undefined): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(url, {
      headers: githubHeaders(token),
      redirect: 'follow',
      signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
    });
  } catch (error) {
    if (error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError')) {
      throw new RepositoryFetchError('GitHub request timed out');
    }
    throw error;
  }
  if (response.status === 404) {
    throw new RepositoryFetchError('Repository not found or is not public');
  }
  if (response.status === 403 || response.status === 429) {
    throw new RepositoryFetchError('GitHub rate limit reached while fetching the repository');
  }
  if (!response.ok) {
    throw new RepositoryFetchError(`GitHub request failed with status ${response.status}`);
  }
  return response;
}

export async function resolveDefaultBranch(
  owner: string,
  repo: string,
  token?: string,
): Promise<string> {
  const response = await githubGet(
    `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
    token,
  );
  const body = (await response.json()) as { default_branch?: unknown; private?: unknown };
  if (body.private === true) {
    throw new RepositoryFetchError('Private repositories are not supported');
  }
  if (typeof body.default_branch !== 'string' || body.default_branch.length === 0) {
    throw new RepositoryFetchError('GitHub did not return a default branch');
  }
  if (!/^[A-Za-z0-9._/-]+$/.test(body.default_branch)) {
    throw new RepositoryFetchError('GitHub returned an unexpected default branch name');
  }
  return body.default_branch;
}

async function downloadZipball(
  owner: string,
  repo: string,
  branch: string,
  token: string | undefined,
): Promise<Buffer> {
  const response = await githubGet(
    `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/zipball/${encodeURIComponent(branch)}`,
    token,
  );
  if (!response.body) {
    throw new RepositoryFetchError('GitHub returned an empty archive');
  }

  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = response.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!value) {
        continue;
      }
      total += value.byteLength;
      if (total > MAX_ARCHIVE_BYTES) {
        throw new RepositoryFetchError('Repository archive exceeds the 25 MB download limit');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks);
}

function looksBinary(content: Buffer): boolean {
  const sample = content.subarray(0, 8000);
  return sample.includes(0);
}

function shouldSkip(relativePath: string): boolean {
  const parts = relativePath.split('/');
  if (parts.some((part) => SKIP_DIRS.has(part))) {
    return true;
  }
  const base = parts[parts.length - 1] ?? '';
  return SKIP_FILES.has(base);
}

/** Drop a shared zipball root folder and reject paths that escape the extract directory. */
export function toSafeRelative(entryName: string, rootPrefix: string | null): string | null {
  const normalized = entryName.replaceAll('\\', '/');
  if (normalized.startsWith('/') || normalized.includes('\0')) {
    return null;
  }
  const parts = normalized.split('/').filter((part) => part.length > 0);
  if (parts.some((part) => part === '..' || part === '.')) {
    return null;
  }
  if (rootPrefix) {
    if (parts[0] !== rootPrefix) {
      return null;
    }
    parts.shift();
  }
  if (parts.length === 0) {
    return null;
  }
  return parts.join('/');
}

export function sharedRootPrefix(entryNames: string[]): string | null {
  const counts = new Map<string, number>();
  for (const name of entryNames) {
    if (name.endsWith('/')) {
      continue;
    }
    const parts = name.replaceAll('\\', '/').split('/').filter(Boolean);
    const first = parts[0];
    if (!first || parts.length < 2 || first === '..') {
      continue;
    }
    counts.set(first, (counts.get(first) ?? 0) + 1);
  }

  let prefix: string | null = null;
  let best = 0;
  for (const [name, count] of counts) {
    if (count > best) {
      prefix = name;
      best = count;
    }
  }
  return prefix;
}

export async function extractArchive(buffer: Buffer, rootDir: string): Promise<{
  files: ScanFile[];
  packageJson?: unknown;
  truncated: boolean;
}> {
  if (buffer.length > MAX_ARCHIVE_BYTES) {
    throw new RepositoryFetchError('Repository archive exceeds the 25 MB download limit');
  }

  let zip: AdmZip;
  try {
    zip = new AdmZip(buffer);
  } catch {
    throw new RepositoryFetchError('Repository archive could not be read');
  }

  const entries = zip.getEntries().filter((entry) => !entry.isDirectory);
  const rootPrefix = sharedRootPrefix(entries.map((entry) => entry.entryName));
  const files: ScanFile[] = [];
  let extractedBytes = 0;
  let truncated = false;

  for (const entry of entries) {
    const relative = toSafeRelative(entry.entryName, rootPrefix);
    if (!relative || shouldSkip(relative)) {
      continue;
    }

    const declaredSize = entry.header.size;
    extractedBytes += declaredSize;
    if (extractedBytes > MAX_EXTRACTED_BYTES) {
      throw new RepositoryFetchError('Repository exceeds the 80 MB extracted size limit');
    }
    if (declaredSize > MAX_FILE_BYTES) {
      truncated = true;
      continue;
    }

    const data = entry.getData();
    if (data.length > MAX_FILE_BYTES) {
      truncated = true;
      continue;
    }
    if (looksBinary(data)) {
      continue;
    }

    if (files.length >= MAX_FILES) {
      truncated = true;
      break;
    }

    const target = path.resolve(rootDir, relative);
    const root = path.resolve(rootDir);
    if (target !== root && !target.startsWith(`${root}${path.sep}`)) {
      throw new RepositoryFetchError('Archive contains a path outside the extract directory');
    }

    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, data);

    const content = data.toString('utf8');
    files.push({ path: relative, content, size: data.length });
  }

  if (files.length === 0) {
    truncated = true;
  }

  const packageFile = files.find((file) => file.path === 'package.json');
  let packageJson: unknown;
  if (packageFile) {
    try {
      packageJson = JSON.parse(packageFile.content) as unknown;
    } catch {
      packageJson = undefined;
    }
  }

  return { files, packageJson, truncated };
}

export async function fetchRepository(input: FetchRepositoryInput): Promise<ScanContext> {
  const rootDir = path.join(os.tmpdir(), 'ai-scanner', input.scanId);
  await mkdir(rootDir, { recursive: true });

  try {
    const defaultBranch = await resolveDefaultBranch(input.owner, input.repo, input.githubToken);
    const archive = await downloadZipball(input.owner, input.repo, defaultBranch, input.githubToken);
    const extracted = await extractArchive(archive, rootDir);
    return {
      scanId: input.scanId,
      owner: input.owner,
      repo: input.repo,
      defaultBranch,
      rootDir,
      files: extracted.files,
      packageJson: extracted.packageJson,
      truncated: extracted.truncated,
    };
  } catch (error) {
    await rm(rootDir, { recursive: true, force: true });
    throw error;
  }
}
