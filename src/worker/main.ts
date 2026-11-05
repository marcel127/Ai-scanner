import { loadConfig } from '../config.js';
import { createPool } from '../db/pool.js';
import { ScansRepository } from '../db/scansRepo.js';
import { runWorkerLoop } from './loop.js';

async function main(): Promise<void> {
  const config = loadConfig();
  const pool = createPool(config.databaseUrl);
  const repo = new ScansRepository(pool);
  let stopping = false;

  const shutdown = () => {
    stopping = true;
    console.log('[worker] shutting down after the current cycle');
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  console.log(`[worker] polling every ${config.pollIntervalMs}ms`);
  try {
    await runWorkerLoop(repo, config, () => stopping);
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  console.error('[worker] fatal:', error);
  process.exit(1);
});
