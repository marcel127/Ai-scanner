import { describe, expect, it } from 'vitest';
import { buildApp } from '../../src/api/app.js';
import { emptySeverityCounts, type Scan, type ScanResultRecord, type ScanStatus, type SecurityReview } from '../../src/domain/types.js';
import type { ScansRepository } from '../../src/db/scansRepo.js';

function scan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    githubUrl: 'https://github.com/acme/widgets',
    owner: 'acme',
    repo: 'widgets',
    defaultBranch: null,
    status: 'QUEUED',
    errorMessage: null,
    createdAt: new Date('2026-11-04T12:00:00.000Z'),
    updatedAt: new Date('2026-11-04T12:00:00.000Z'),
    startedAt: null,
    completedAt: null,
    ...overrides,
  };
}

function fakeRepo(initial: Scan | null, result: ScanResultRecord | null = null): ScansRepository {
  const stored = initial;
  return {
    create: async () => scan(),
    getById: async () => stored,
    getResult: async () => result,
    claimNext: async () => null,
    updateStatus: async () => null,
    complete: async () => true,
    fail: async () => true,
  } as unknown as ScansRepository;
}

describe('scan routes', () => {
  it('creates a queued scan for a public GitHub URL', async () => {
    const app = await buildApp(fakeRepo(null));
    const response = await app.inject({
      method: 'POST',
      url: '/api/scans',
      payload: { githubUrl: 'https://github.com/acme/widgets/' },
    });

    expect(response.statusCode).toBe(202);
    expect(response.json()).toMatchObject({
      id: '11111111-1111-4111-8111-111111111111',
      status: 'QUEUED',
      githubUrl: 'https://github.com/acme/widgets',
    });
    await app.close();
  });

  it('rejects unsupported GitHub URLs', async () => {
    const app = await buildApp(fakeRepo(null));
    const response = await app.inject({
      method: 'POST',
      url: '/api/scans',
      payload: { githubUrl: 'https://github.com/acme/widgets/tree/main' },
    });
    expect(response.statusCode).toBe(400);
    await app.close();
  });

  it('returns 404 for a missing scan', async () => {
    const app = await buildApp(fakeRepo(null));
    const response = await app.inject({
      method: 'GET',
      url: '/api/scans/11111111-1111-4111-8111-111111111111',
    });
    expect(response.statusCode).toBe(404);
    await app.close();
  });

  it('returns 200 only when the scan is completed', async () => {
    const review: SecurityReview = {
      overallRisk: 'INFO',
      summary: 'none',
      severityCounts: emptySeverityCounts(),
      recommendedActions: [],
      findings: [],
    };
    const record: ScanResultRecord = {
      scanId: '11111111-1111-4111-8111-111111111111',
      review,
      meta: {},
      createdAt: new Date('2026-11-04T12:05:00.000Z'),
    };
    const app = await buildApp(fakeRepo(scan({ status: 'COMPLETED' }), record));
    const response = await app.inject({
      method: 'GET',
      url: '/api/scans/11111111-1111-4111-8111-111111111111/result',
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ status: 'COMPLETED', overallRisk: 'INFO' });
    await app.close();
  });

  it.each<[ScanStatus, number]>([
    ['QUEUED', 409],
    ['FETCHING_REPOSITORY', 409],
    ['FAILED', 409],
  ])('returns %s result as %s', async (status, code) => {
    const app = await buildApp(
      fakeRepo(scan({ status, errorMessage: status === 'FAILED' ? 'boom' : null })),
    );
    const response = await app.inject({
      method: 'GET',
      url: '/api/scans/11111111-1111-4111-8111-111111111111/result',
    });
    expect(response.statusCode).toBe(code);
    if (status === 'FAILED') {
      expect(response.json()).toMatchObject({ status: 'FAILED', errorMessage: 'boom' });
    } else {
      expect(response.json()).toEqual({ status });
    }
    await app.close();
  });
});
