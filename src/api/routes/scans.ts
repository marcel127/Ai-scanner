import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { ScansRepository } from '../../db/scansRepo.js';
import type { Scan, ScanResultRecord } from '../../domain/types.js';
import { parseGithubUrl } from '../../github/parseUrl.js';

const createBodySchema = z.object({
  githubUrl: z.string().min(1),
});

const idParamsSchema = z.object({
  id: z.string().uuid(),
});

function publicScan(scan: Scan) {
  return {
    id: scan.id,
    githubUrl: scan.githubUrl,
    owner: scan.owner,
    repo: scan.repo,
    defaultBranch: scan.defaultBranch,
    status: scan.status,
    errorMessage: scan.errorMessage,
    createdAt: scan.createdAt.toISOString(),
    updatedAt: scan.updatedAt.toISOString(),
    startedAt: scan.startedAt?.toISOString() ?? null,
    completedAt: scan.completedAt?.toISOString() ?? null,
  };
}

function publicResult(record: ScanResultRecord) {
  return {
    scanId: record.scanId,
    status: 'COMPLETED' as const,
    overallRisk: record.review.overallRisk,
    summary: record.review.summary,
    severityCounts: record.review.severityCounts,
    recommendedActions: record.review.recommendedActions,
    findings: record.review.findings,
    meta: record.meta,
  };
}

export async function registerScanRoutes(
  app: FastifyInstance,
  repo: ScansRepository,
): Promise<void> {
  app.post('/api/scans', async (request, reply) => {
    const parsed = createBodySchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: 'githubUrl is required' });
    }

    const ref = parseGithubUrl(parsed.data.githubUrl);
    if (!ref) {
      return reply.code(400).send({
        error: 'githubUrl must be https://github.com/{owner}/{repo}',
      });
    }

    const scan = await repo.create({
      githubUrl: `https://github.com/${ref.owner}/${ref.repo}`,
      owner: ref.owner,
      repo: ref.repo,
    });

    return reply.code(202).send({
      id: scan.id,
      status: scan.status,
      githubUrl: scan.githubUrl,
      createdAt: scan.createdAt.toISOString(),
    });
  });

  app.get('/api/scans/:id', async (request, reply) => {
    const params = idParamsSchema.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: 'id must be a UUID' });
    }

    const scan = await repo.getById(params.data.id);
    if (!scan) {
      return reply.code(404).send({ error: 'Scan not found' });
    }
    return reply.send(publicScan(scan));
  });

  app.get('/api/scans/:id/result', async (request, reply) => {
    const params = idParamsSchema.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: 'id must be a UUID' });
    }

    const scan = await repo.getById(params.data.id);
    if (!scan) {
      return reply.code(404).send({ error: 'Scan not found' });
    }

    if (scan.status === 'FAILED') {
      return reply.code(409).send({
        status: scan.status,
        errorMessage: scan.errorMessage,
      });
    }

    if (scan.status !== 'COMPLETED') {
      return reply.code(409).send({ status: scan.status });
    }

    const result = await repo.getResult(scan.id);
    if (!result) {
      return reply.code(500).send({ error: 'Completed scan is missing a result' });
    }
    return reply.send(publicResult(result));
  });
}
