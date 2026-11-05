import type { AppConfig } from '../config.js';
import type { ScansRepository } from '../db/scansRepo.js';
import { processScan } from './processScan.js';

function sleep(ms: number, shouldStop: () => boolean): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      clearInterval(poll);
      resolve();
    };
    const timer = setTimeout(finish, ms);
    const poll = setInterval(() => {
      if (shouldStop()) {
        finish();
      }
    }, 100);
  });
}

export async function runWorkerLoop(
  repo: ScansRepository,
  config: Pick<AppConfig, 'pollIntervalMs' | 'githubToken' | 'geminiApiKey'>,
  shouldStop: () => boolean,
): Promise<void> {
  while (!shouldStop()) {
    const scan = await repo.claimNext();
    if (!scan) {
      await sleep(config.pollIntervalMs, shouldStop);
      continue;
    }

    console.log(`[worker] claimed scan ${scan.id}`);
    try {
      await processScan(repo, scan, {
        githubToken: config.githubToken,
        geminiApiKey: config.geminiApiKey,
      });
      console.log(`[worker] completed scan ${scan.id}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown worker error';
      console.error(`[worker] scan ${scan.id} failed:`, message);
      await repo.fail(scan.id, message);
    }
  }
}
