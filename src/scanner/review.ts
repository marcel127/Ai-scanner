import {
  emptySeverityCounts,
  SEVERITY_WEIGHT,
  type Finding,
  type SecurityReview,
  type Severity,
} from '../domain/types.js';

function headline(text: string): string {
  const sentence = text.split(/(?<=\.)\s/)[0]?.trim() || text.trim();
  if (sentence.length <= 160) {
    return sentence;
  }
  return `${sentence.slice(0, 157)}...`;
}

function recommendedActions(findings: Finding[]): SecurityReview['recommendedActions'] {
  const actions: SecurityReview['recommendedActions'] = [];
  const indexByKey = new Map<string, number>();
  for (const finding of findings) {
    const key = `${finding.ruleId}|${headline(finding.remediation)}`;
    const existingIndex = indexByKey.get(key);
    if (existingIndex !== undefined) {
      actions[existingIndex]?.relatedFindingIds.push(finding.id);
      continue;
    }
    if (actions.length >= 5) {
      continue;
    }
    indexByKey.set(key, actions.length);
    actions.push({
      priority: actions.length + 1,
      title: headline(finding.remediation),
      rationale: finding.whyItMatters,
      relatedFindingIds: [finding.id],
    });
  }
  return actions;
}

function highestSeverity(findings: Finding[]): Severity {
  let best: Severity = 'INFO';
  for (const finding of findings) {
    if (SEVERITY_WEIGHT[finding.severity] > SEVERITY_WEIGHT[best]) {
      best = finding.severity;
    }
  }
  return best;
}

export function buildReview(findings: Finding[]): SecurityReview {
  const sorted = [...findings].sort((left, right) => {
    const bySeverity = SEVERITY_WEIGHT[right.severity] - SEVERITY_WEIGHT[left.severity];
    if (bySeverity !== 0) {
      return bySeverity;
    }
    return (left.filePath ?? '').localeCompare(right.filePath ?? '');
  });

  const severityCounts = emptySeverityCounts();
  for (const finding of sorted) {
    severityCounts[finding.severity] += 1;
  }

  const overallRisk = sorted.length === 0 ? 'INFO' : highestSeverity(sorted);
  const fileCount = new Set(sorted.map((finding) => finding.filePath).filter(Boolean)).size;
  const concernTitles: string[] = [];
  for (const finding of sorted) {
    if (concernTitles.includes(finding.title)) {
      continue;
    }
    concernTitles.push(finding.title);
    if (concernTitles.length === 3) {
      break;
    }
  }
  const topConcerns = concernTitles.join('; ');

  const summary =
    sorted.length === 0
      ? 'No security issues were found in the scanned files.'
      : `Found ${sorted.length} issue(s) across ${fileCount} file(s). Highest severity is ${overallRisk}. Top concerns: ${topConcerns}.`;

  return {
    overallRisk,
    summary,
    severityCounts,
    recommendedActions: recommendedActions(sorted),
    findings: sorted,
  };
}
