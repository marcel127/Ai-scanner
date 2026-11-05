export type SecretSeverity = 'CRITICAL' | 'HIGH';

export interface SecretMatch {
  pattern: string;
  severity: SecretSeverity;
  value: string;
}

interface SecretPattern {
  name: string;
  severity: SecretSeverity;
  source: string;
  flags: string;
}

const PATTERNS: SecretPattern[] = [
  {
    name: 'private-key',
    severity: 'CRITICAL',
    source: '-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----',
    flags: 'g',
  },
  {
    name: 'aws-access-key',
    severity: 'CRITICAL',
    source: 'AKIA[0-9A-Z]{16}',
    flags: 'g',
  },
  {
    name: 'github-token',
    severity: 'CRITICAL',
    source: 'ghp_[A-Za-z0-9]{20,}',
    flags: 'g',
  },
  {
    name: 'slack-token',
    severity: 'HIGH',
    source: 'xox[baprs]-[A-Za-z0-9-]{10,}',
    flags: 'g',
  },
  {
    name: 'assigned-secret',
    severity: 'HIGH',
    source:
      '[\'"]?(?:api[_-]?key|secret|password|access[_-]?token)[\'"]?\\s*[:=]\\s*[\'"]?([A-Za-z0-9_\\-/.+=]{12,})[\'"]?',
    flags: 'gi',
  },
];

function mask(name: string, value: string): string {
  if (name === 'private-key') {
    return '[REDACTED_PRIVATE_KEY]';
  }
  if (name === 'aws-access-key' && value.length >= 8) {
    return `${value.slice(0, 4)}…${value.slice(-4)}`;
  }
  return '[REDACTED]';
}

function regex(pattern: SecretPattern): RegExp {
  return new RegExp(pattern.source, pattern.flags);
}

export function findSecrets(input: string): SecretMatch[] {
  const matches: SecretMatch[] = [];
  for (const pattern of PATTERNS) {
    for (const match of input.matchAll(regex(pattern))) {
      const value = match[1] && pattern.name === 'assigned-secret' ? match[1] : match[0];
      if (pattern.name === 'assigned-secret' && !/[0-9]/.test(value)) {
        continue;
      }
      matches.push({ pattern: pattern.name, severity: pattern.severity, value });
    }
  }
  return matches;
}

/** Mask secret-like substrings. Safe to run on evidence and on text sent to an AI provider. */
export function redactSecrets(input: string): string {
  let output = input;
  for (const pattern of PATTERNS) {
    output = output.replace(regex(pattern), (full, group?: string) => {
      if (pattern.name === 'assigned-secret') {
        const secret = group ?? '';
        if (!/[0-9]/.test(secret)) {
          return full;
        }
        return full.replace(secret, '[REDACTED]');
      }
      return mask(pattern.name, full);
    });
  }
  return output;
}
