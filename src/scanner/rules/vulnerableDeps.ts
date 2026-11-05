import type { Finding, Severity } from '../../domain/types.js';
import type { ScanContext } from '../context.js';
import { makeFinding, type Rule } from './types.js';

interface DeniedPackage {
  name: string;
  patched: string;
  severity: Severity;
  whyItMatters: string;
}

/** Illustrative denylist. This is not a vulnerability database. */
export const DENIED_PACKAGES: DeniedPackage[] = [
  {
    name: 'lodash',
    patched: '4.17.21',
    severity: 'HIGH',
    whyItMatters:
      'lodash versions before 4.17.21 include prototype pollution issues that can let attackers modify object behavior.',
  },
  {
    name: 'minimist',
    patched: '1.2.6',
    severity: 'HIGH',
    whyItMatters:
      'minimist versions before 1.2.6 are affected by prototype pollution when parsing untrusted arguments.',
  },
  {
    name: 'jsonwebtoken',
    patched: '9.0.0',
    severity: 'HIGH',
    whyItMatters:
      'jsonwebtoken versions before 9.0.0 have known signature and key-handling weaknesses.',
  },
];

export function parseVersion(version: string): [number, number, number] | null {
  const match = version.trim().match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!match) {
    return null;
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

export function isBelow(range: string, patched: string): boolean {
  const current = parseVersion(range);
  const fixed = parseVersion(patched);
  if (!current || !fixed) {
    return false;
  }
  for (let index = 0; index < 3; index += 1) {
    const left = current[index] ?? 0;
    const right = fixed[index] ?? 0;
    if (left < right) {
      return true;
    }
    if (left > right) {
      return false;
    }
  }
  return false;
}

function dependencyEntries(packageJson: unknown): Array<[string, string]> {
  if (!packageJson || typeof packageJson !== 'object') {
    return [];
  }
  const record = packageJson as { dependencies?: unknown; devDependencies?: unknown };
  const sections = [record.dependencies, record.devDependencies];
  const entries: Array<[string, string]> = [];
  for (const section of sections) {
    if (!section || typeof section !== 'object') {
      continue;
    }
    for (const [name, version] of Object.entries(section)) {
      if (typeof version === 'string') {
        entries.push([name, version]);
      }
    }
  }
  return entries;
}

export const vulnerableDepsRule: Rule = {
  id: 'vulnerable-deps',
  category: 'deps',
  description: 'Checks package.json against a small built-in list of known-bad versions.',
  run(ctx: ScanContext) {
    const findings: Finding[] = [];
    for (const [name, version] of dependencyEntries(ctx.packageJson)) {
      const denied = DENIED_PACKAGES.find((item) => item.name === name);
      if (!denied || !isBelow(version, denied.patched)) {
        continue;
      }
      findings.push(
        makeFinding({
          ruleId: vulnerableDepsRule.id,
          category: vulnerableDepsRule.category,
          severity: denied.severity,
          title: `${name} is below ${denied.patched}`,
          filePath: 'package.json',
          evidence: `${name}@${version}`,
          whyItMatters: denied.whyItMatters,
          remediation: `Upgrade ${name} to ${denied.patched} or newer. This check is illustrative and is not a full vulnerability database.`,
        }),
      );
    }
    return findings;
  },
};
