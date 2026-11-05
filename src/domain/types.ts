export const SCAN_STATUSES = [
  'QUEUED',
  'FETCHING_REPOSITORY',
  'RUNNING_RULES',
  'AI_ANALYSIS',
  'GENERATING_REVIEW',
  'COMPLETED',
  'FAILED',
] as const;

export type ScanStatus = (typeof SCAN_STATUSES)[number];

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;

export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export type SeverityCounts = Record<Severity, number>;

export interface Finding {
  id: string;
  ruleId: string;
  category: string;
  source: 'RULE' | 'AI';
  severity: Severity;
  title: string;
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
  evidence?: string;
  whyItMatters: string;
  remediation: string;
}

export interface RecommendedAction {
  priority: number;
  title: string;
  rationale: string;
  relatedFindingIds: string[];
}

export interface SecurityReview {
  overallRisk: Severity;
  summary: string;
  severityCounts: SeverityCounts;
  recommendedActions: RecommendedAction[];
  findings: Finding[];
}

export interface Scan {
  id: string;
  githubUrl: string;
  owner: string;
  repo: string;
  defaultBranch: string | null;
  status: ScanStatus;
  errorMessage: string | null;
  createdAt: Date;
  updatedAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
}

export interface ScanResultRecord {
  scanId: string;
  review: SecurityReview;
  meta: Record<string, unknown>;
  createdAt: Date;
}

export function emptySeverityCounts(): SeverityCounts {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
}
