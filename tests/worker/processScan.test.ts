import { mkdtemp, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';

vi.mock('node:fs/promises', async () => {
  const actual = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
  return {
    ...actual,
    rm: vi.fn((...args: Parameters<typeof actual.rm>) => actual.rm(...args)),
  };
});
import type { Scan, ScanStatus, SecurityReview } from '../../src/domain/types.js';
import type { ScansRepository } from '../../src/db/scansRepo.js';
import type { ScanContext } from '../../src/scanner/context.js';
import { processScan } from '../../src/worker/processScan.js';

function scan(): Scan {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    githubUrl: 'https://github.com/acme/widgets',
    owner: 'acme',
    repo: 'widgets',
    defaultBranch: null,
    status: 'FETCHING_REPOSITORY',
    errorMessage: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    startedAt: new Date(),
    completedAt: null,
  };
}

describe('processScan', () => {
  it('runs rules after fetch and deletes the temporary directory', async () => {
    const stages: ScanStatus[] = [];
    let completed: SecurityReview | undefined;
    let branch: string | undefined;
    const rootDir = await mkdtemp(path.join(os.tmpdir(), 'scanner-process-'));
    const ctx: ScanContext = {
      scanId: '11111111-1111-4111-8111-111111111111',
      owner: 'acme',
      repo: 'widgets',
      defaultBranch: 'main',
      rootDir,
      files: [{ path: 'src/app.js', content: 'eval(input)\n', size: 12 }],
      truncated: false,
    };

    const repo = {
      setDefaultBranch: async (_id: string, defaultBranch: string) => {
        branch = defaultBranch;
        return scan();
      },
      updateStatus: async (_id: string, status: ScanStatus) => {
        stages.push(status);
        return scan();
      },
      complete: async (_id: string, review: SecurityReview) => {
        completed = review;
        return true;
      },
    } as unknown as ScansRepository;

    await processScan(repo, scan(), {
      fetchRepository: async () => ctx,
      runRules: () => [
        {
          id: 'abc',
          ruleId: 'dangerous-eval',
          category: 'eval',
          source: 'RULE',
          severity: 'HIGH',
          title: 'Use of eval()',
          filePath: 'src/app.js',
          lineStart: 1,
          whyItMatters: 'code execution',
          remediation: 'remove eval',
        },
      ],
    });

    expect(branch).toBe('main');
    expect(stages).toEqual(['RUNNING_RULES', 'AI_ANALYSIS', 'GENERATING_REVIEW']);
    expect(completed?.overallRisk).toBe('HIGH');
    expect(completed?.findings).toHaveLength(1);
    await expect(stat(rootDir)).rejects.toThrow();
  });

  it('keeps distinct rule and AI findings and still redacts secrets', async () => {
    let completed: SecurityReview | undefined;
    const rootDir = await mkdtemp(path.join(os.tmpdir(), 'scanner-process-'));
    const repo = {
      setDefaultBranch: async () => scan(),
      updateStatus: async () => scan(),
      complete: async (_id: string, review: SecurityReview) => {
        completed = review;
        return true;
      },
    } as unknown as ScansRepository;

    await processScan(repo, scan(), {
      fetchRepository: async () => ({
        scanId: scan().id,
        owner: 'acme',
        repo: 'widgets',
        defaultBranch: 'main',
        rootDir,
        files: [],
        truncated: false,
      }),
      runRules: () => [
        {
          id: 'rule-eval',
          ruleId: 'dangerous-eval',
          category: 'eval',
          source: 'RULE',
          severity: 'HIGH',
          title: 'Use of eval()',
          filePath: 'src/app.js',
          lineStart: 1,
          whyItMatters: 'code execution',
          remediation: 'remove eval',
        },
      ],
      analyzer: {
        enabled: true,
        analyze: async () => ({
          findings: [
            {
              id: 'ai-auth',
              ruleId: 'ai:missing-auth',
              category: 'auth',
              source: 'AI',
              severity: 'MEDIUM',
              title: 'Missing authorization check',
              filePath: 'src/admin.js',
              lineStart: 8,
              evidence: 'key=AKIAIOSFODNN7EXAMPLE',
              whyItMatters: 'Callers can reach the handler.',
              remediation: 'Check the caller.',
            },
          ],
        }),
      },
    });

    expect(completed?.findings.map((finding) => finding.id)).toEqual(['rule-eval', 'ai-auth']);
    expect(completed?.findings[1]?.evidence).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('keeps deterministic findings when AI analysis fails', async () => {
    let completed: SecurityReview | undefined;
    const rootDir = await mkdtemp(path.join(os.tmpdir(), 'scanner-process-'));
    const repo = {
      setDefaultBranch: async () => scan(),
      updateStatus: async () => scan(),
      complete: async (_id: string, review: SecurityReview) => {
        completed = review;
        return true;
      },
    } as unknown as ScansRepository;

    await processScan(repo, scan(), {
      fetchRepository: async () => ({
        scanId: scan().id,
        owner: 'acme',
        repo: 'widgets',
        defaultBranch: 'main',
        rootDir,
        files: [],
        truncated: false,
      }),
      runRules: () => [
        {
          id: 'rule-eval',
          ruleId: 'dangerous-eval',
          category: 'eval',
          source: 'RULE',
          severity: 'HIGH',
          title: 'Use of eval()',
          filePath: 'src/app.js',
          lineStart: 1,
          whyItMatters: 'code execution',
          remediation: 'remove eval',
        },
      ],
      analyzer: {
        enabled: true,
        analyze: async () => ({ findings: [], error: 'AI analysis failed' }),
      },
    });

    expect(completed?.findings.map((finding) => finding.id)).toEqual(['rule-eval']);
  });

  it('still completes the scan when temporary directory cleanup fails', async () => {
    let completed: SecurityReview | undefined;
    const rootDir = await mkdtemp(path.join(os.tmpdir(), 'scanner-process-'));
    vi.mocked(rm).mockRejectedValueOnce(new Error('permission denied'));
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
    const repo = {
      setDefaultBranch: async () => scan(),
      updateStatus: async () => scan(),
      complete: async (_id: string, review: SecurityReview) => {
        completed = review;
        return true;
      },
      fail: async () => {
        throw new Error('fail should not be called');
      },
    } as unknown as ScansRepository;

    await expect(
      processScan(repo, scan(), {
        fetchRepository: async () => ({
          scanId: scan().id,
          owner: 'acme',
          repo: 'widgets',
          defaultBranch: 'main',
          rootDir,
          files: [],
          truncated: false,
        }),
        runRules: () => [
          {
            id: 'rule-eval',
            ruleId: 'dangerous-eval',
            category: 'eval',
            source: 'RULE',
            severity: 'HIGH',
            title: 'Use of eval()',
            filePath: 'src/app.js',
            lineStart: 1,
            whyItMatters: 'code execution',
            remediation: 'remove eval',
          },
        ],
      }),
    ).resolves.toBeUndefined();

    expect(completed?.findings.map((finding) => finding.id)).toEqual(['rule-eval']);
    expect(errorLog).toHaveBeenCalledWith(
      expect.stringContaining('could not delete temporary directory'),
      'permission denied',
    );
    errorLog.mockRestore();
    await rm(rootDir, { recursive: true, force: true });
  });
});
