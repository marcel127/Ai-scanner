import type { Finding } from '../../domain/types.js';
import { findSecrets, redactSecrets } from '../redact.js';
import type { ScanContext } from '../context.js';
import { makeFinding, type Rule } from './types.js';

const TITLE: Record<string, string> = {
  'private-key': 'Private key committed to the repository',
  'aws-access-key': 'AWS access key committed to the repository',
  'github-token': 'GitHub token committed to the repository',
  'slack-token': 'Slack token committed to the repository',
  'assigned-secret': 'Hardcoded credential assigned in source',
};

export const hardcodedSecretsRule: Rule = {
  id: 'hardcoded-secrets',
  category: 'secrets',
  description: 'Detects common hardcoded credentials and private keys.',
  run(ctx: ScanContext) {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      const lines = file.content.split(/\r?\n/);
      lines.forEach((line, index) => {
        const matches = findSecrets(line);
        const seen = new Set<string>();
        for (const match of matches) {
          if (seen.has(match.pattern)) {
            continue;
          }
          seen.add(match.pattern);
          const evidence = redactSecrets(line).slice(0, 240);
          findings.push(
            makeFinding({
              ruleId: hardcodedSecretsRule.id,
              category: hardcodedSecretsRule.category,
              severity: match.severity,
              title: TITLE[match.pattern] ?? 'Hardcoded secret',
              filePath: file.path,
              lineStart: index + 1,
              evidence,
              whyItMatters:
                'A credential in source control can be copied from git history and used by anyone who can read the repository.',
              remediation:
                'Remove the secret, rotate it, and load it from an environment variable or a secret manager. Purge it from git history if it was pushed.',
            }),
          );
        }
      });

      if (file.content.includes('BEGIN') && file.content.includes('PRIVATE KEY')) {
        const matches = findSecrets(file.content).filter((match) => match.pattern === 'private-key');
        if (matches.length > 0 && !findings.some((finding) => finding.filePath === file.path && finding.title === TITLE['private-key'])) {
          findings.push(
            makeFinding({
              ruleId: hardcodedSecretsRule.id,
              category: hardcodedSecretsRule.category,
              severity: 'CRITICAL',
              title: TITLE['private-key'] ?? 'Private key committed to the repository',
              filePath: file.path,
              evidence: '[REDACTED_PRIVATE_KEY]',
              whyItMatters:
                'A private key in the repository lets an attacker impersonate the service or user that key belongs to.',
              remediation:
                'Delete the key from the repository, revoke it, and store a replacement outside source control.',
            }),
          );
        }
      }
    }
    return findings;
  },
};
