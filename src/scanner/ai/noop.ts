import type { Finding } from '../../domain/types.js';
import type { ScanContext } from '../context.js';
import type { AiAnalysis, AiAnalyzer } from './types.js';

export class NoopAnalyzer implements AiAnalyzer {
  readonly enabled = false;

  analyze(_ctx: ScanContext, _ruleFindings: Finding[]): Promise<AiAnalysis> {
    return Promise.resolve({ findings: [] });
  }
}
