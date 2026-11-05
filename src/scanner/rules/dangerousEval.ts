import type { Finding } from '../../domain/types.js';
import type { ScanContext } from '../context.js';
import { makeFinding, type Rule } from './types.js';

const SOURCE_FILE = /\.(?:js|jsx|mjs|cjs|ts|tsx)$/;

export const dangerousEvalRule: Rule = {
  id: 'dangerous-eval',
  category: 'eval',
  description: 'Detects eval() and new Function() in JavaScript and TypeScript files.',
  run(ctx: ScanContext) {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!SOURCE_FILE.test(file.path)) {
        continue;
      }
      const lines = file.content.split(/\r?\n/);
      lines.forEach((line, index) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) {
          return;
        }
        const usesEval = /\beval\s*\(/.test(line);
        const usesFunction = /\bnew\s+Function\s*\(/.test(line);
        if (!usesEval && !usesFunction) {
          return;
        }
        findings.push(
          makeFinding({
            ruleId: dangerousEvalRule.id,
            category: dangerousEvalRule.category,
            severity: usesEval ? 'HIGH' : 'MEDIUM',
            title: usesEval ? 'Use of eval()' : 'Use of new Function()',
            filePath: file.path,
            lineStart: index + 1,
            evidence: line.trim().slice(0, 240),
            whyItMatters:
              'eval and the Function constructor execute strings as code. If that string includes untrusted input, an attacker can run arbitrary code in the process.',
            remediation:
              'Replace eval or new Function with a direct function call or a parser for the specific format you need.',
          }),
        );
      });
    }
    return findings;
  },
};
