import type { Finding } from '../../domain/types.js';
import type { ScanContext } from '../context.js';

export interface AiAnalysis {
  findings: Finding[];
  error?: string;
}

export interface AiAnalyzer {
  readonly enabled: boolean;
  analyze(ctx: ScanContext, ruleFindings: Finding[]): Promise<AiAnalysis>;
}
