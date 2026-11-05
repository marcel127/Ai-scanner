import { loadConfig } from '../config.js';
import { createPool } from '../db/pool.js';
import { ScansRepository } from '../db/scansRepo.js';
import { buildApp } from './app.js';

async function main(): Promise<void> {
  const config = loadConfig();
  const pool = createPool(config.databaseUrl);
  const repo = new ScansRepository(pool);
  const app = await buildApp(repo);

  const shutdown = async () => {
    await app.close();
    await pool.end();
  };
  process.on('SIGINT', () => {
    void shutdown().then(() => process.exit(0));
  });
  process.on('SIGTERM', () => {
    void shutdown().then(() => process.exit(0));
  });

  await app.listen({ port: config.port, host: '0.0.0.0' });
  console.log(`[api] listening on ${config.port}`);
}

main().catch((error: unknown) => {
  console.error('[api] fatal:', error);
  process.exit(1);
});
