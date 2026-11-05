import { createHash } from 'node:crypto';
import type { Finding, Severity } from '../../domain/types.js';
import type { ScanContext } from '../context.js';

export interface Rule {
  id: string;
  category: string;
  description: string;
  run(ctx: ScanContext): Finding[];
}

export function findingId(parts: string[]): string {
  return createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 16);
}

export function makeFinding(input: {
  ruleId: string;
  category: string;
  severity: Severity;
  title: string;
  filePath?: string;
  lineStart?: number;
  evidence?: string;
  whyItMatters: string;
  remediation: string;
}): Finding {
  return {
    id: findingId([
      input.ruleId,
      input.filePath ?? '',
      String(input.lineStart ?? ''),
      input.title,
    ]),
    ruleId: input.ruleId,
    category: input.category,
    source: 'RULE',
    severity: input.severity,
    title: input.title,
    filePath: input.filePath,
    lineStart: input.lineStart,
    evidence: input.evidence,
    whyItMatters: input.whyItMatters,
    remediation: input.remediation,
  };
}
