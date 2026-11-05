import type { Finding } from '../../domain/types.js';
import type { ScanContext } from '../context.js';
import { dangerousEvalRule } from './dangerousEval.js';
import { hardcodedSecretsRule } from './hardcodedSecrets.js';
import type { Rule } from './types.js';
import { vulnerableDepsRule } from './vulnerableDeps.js';

export const allRules: Rule[] = [hardcodedSecretsRule, dangerousEvalRule, vulnerableDepsRule];

export function runRules(ctx: ScanContext, rules: Rule[] = allRules): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    try {
      for (const finding of rule.run(ctx)) {
        findings.push(finding);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      console.error(`[rules] ${rule.id} failed: ${message}`);
    }
  }
  return findings;
}
