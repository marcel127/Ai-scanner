import { describe, expect, it } from 'vitest';
import type { Finding } from '../src/domain/types.js';
import { buildReview } from '../src/scanner/review.js';

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: 'abc',
    ruleId: 'dangerous-eval',
    category: 'eval',
    source: 'RULE',
    severity: 'HIGH',
    title: 'Use of eval()',
    filePath: 'src/app.js',
    whyItMatters: 'It can run untrusted code.',
    remediation: 'Remove the eval call.',
    ...overrides,
  };
}

describe('buildReview', () => {
  it('ranks risk, counts severities, and recommends the top actions', () => {
    const review = buildReview([
      finding({
        id: 'low',
        severity: 'LOW',
        title: 'Minor',
        filePath: 'src/other.js',
        remediation: 'Tighten the check.',
      }),
      finding({ id: 'high', severity: 'HIGH', title: 'Use of eval()' }),
    ]);

    expect(review.overallRisk).toBe('HIGH');
    expect(review.severityCounts).toMatchObject({ HIGH: 1, LOW: 1, CRITICAL: 0 });
    expect(review.findings.map((item) => item.id)).toEqual(['high', 'low']);
    expect(review.recommendedActions[0]).toMatchObject({
      priority: 1,
      title: 'Remove the eval call.',
      relatedFindingIds: ['high'],
    });
    expect(review.summary).toContain('Found 2 issue(s) across 2 file(s)');
  });

  it('keeps one recommended action for repeated lines of the same issue', () => {
    const review = buildReview([
      finding({ id: 'a', lineStart: 32, evidence: 'eval(a)' }),
      finding({ id: 'b', lineStart: 33, evidence: 'eval(b)' }),
      finding({
        id: 'c',
        ruleId: 'hardcoded-secrets',
        title: 'Hardcoded credential assigned in source',
        remediation: 'Remove the secret.',
        whyItMatters: 'It can be copied from git history.',
      }),
    ]);

    expect(review.summary).toContain('Top concerns: Use of eval(); Hardcoded credential assigned in source.');
    expect(review.recommendedActions).toHaveLength(2);
    expect(review.recommendedActions[0]).toMatchObject({
      title: 'Remove the eval call.',
      relatedFindingIds: ['a', 'b'],
    });
  });

  it('returns an informational review when there are no findings', () => {
    const review = buildReview([]);
    expect(review.overallRisk).toBe('INFO');
    expect(review.recommendedActions).toEqual([]);
    expect(review.summary).toMatch(/No security issues/);
  });
});
