import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Fastify, { type FastifyInstance } from 'fastify';
import fastifyStatic from '@fastify/static';
import type { ScansRepository } from '../db/scansRepo.js';
import { registerScanRoutes } from './routes/scans.js';

const publicDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../public');

export async function buildApp(repo: ScansRepository): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  await registerScanRoutes(app, repo);
  await app.register(fastifyStatic, { root: publicDir });
  return app;
}
