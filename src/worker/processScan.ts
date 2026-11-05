import { rm } from 'node:fs/promises';
import type { Scan, ScanStatus } from '../domain/types.js';
import type { Finding } from '../domain/types.js';
import type { ScansRepository } from '../db/scansRepo.js';
import { createAiAnalyzer } from '../scanner/ai/index.js';
import type { AiAnalyzer } from '../scanner/ai/types.js';
import type { ScanContext } from '../scanner/context.js';
import { fetchRepository as defaultFetchRepository } from '../scanner/fetchRepo.js';
import { redactSecrets } from '../scanner/redact.js';
import { buildReview } from '../scanner/review.js';
import { runRules as defaultRunRules } from '../scanner/rules/index.js';

const AFTER_FETCH: ScanStatus[] = ['RUNNING_RULES', 'AI_ANALYSIS', 'GENERATING_REVIEW'];

export interface ProcessScanDeps {
  githubToken?: string;
  geminiApiKey?: string;
  fetchRepository?: typeof defaultFetchRepository;
  runRules?: (ctx: ScanContext) => Finding[];
  analyzer?: AiAnalyzer;
}

/**
 * Fetch the default branch, run rules, optionally ask Gemini for additional issues, then review.
 * AI failures stay inside the analyzer and do not fail the scan.
 */

function redactFinding(finding: Finding): Finding {
  return {
    ...finding,
    title: redactSecrets(finding.title),
    whyItMatters: redactSecrets(finding.whyItMatters),
    remediation: redactSecrets(finding.remediation),
    evidence: finding.evidence === undefined ? undefined : redactSecrets(finding.evidence),
  };
}
export async function processScan(
  repo: ScansRepository,
  scan: Scan,
  deps: ProcessScanDeps = {},
): Promise<void> {
  const fetchRepository = deps.fetchRepository ?? defaultFetchRepository;
  const runRules = deps.runRules ?? defaultRunRules;
  const analyzer = deps.analyzer ?? createAiAnalyzer(deps.geminiApiKey);

  const ctx = await fetchRepository({
    scanId: scan.id,
    owner: scan.owner,
    repo: scan.repo,
    githubToken: deps.githubToken,
  });

  try {
    const saved = await repo.setDefaultBranch(scan.id, ctx.defaultBranch);
    if (!saved) {
      throw new Error(`Could not save the default branch for scan ${scan.id}`);
    }

    await advance(repo, scan.id, 'RUNNING_RULES');
    const ruleFindings = runRules(ctx);

    await advance(repo, scan.id, 'AI_ANALYSIS');
    const ai = await analyzer.analyze(ctx, ruleFindings);

    await advance(repo, scan.id, 'GENERATING_REVIEW');
    const findings = [...ruleFindings, ...ai.findings].map(redactFinding);
    const review = buildReview(findings);

    await repo.complete(scan.id, review, {
      pipeline: 'review',
      filesScanned: ctx.files.length,
      truncated: ctx.truncated,
      defaultBranch: ctx.defaultBranch,
      rulesRun: ['hardcoded-secrets', 'dangerous-eval', 'vulnerable-deps'],
      aiUsed: analyzer.enabled && !ai.error,
      aiError: ai.error,
    });
  } finally {
    try {
      await rm(ctx.rootDir, { recursive: true, force: true });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown cleanup error';
      console.error(`[worker] could not delete temporary directory for scan ${scan.id}:`, message);
    }
  }
}

async function advance(
  repo: ScansRepository,
  id: string,
  status: (typeof AFTER_FETCH)[number],
): Promise<void> {
  const updated = await repo.updateStatus(id, status);
  if (!updated) {
    throw new Error(`Could not advance scan ${id} to ${status}`);
  }
}
