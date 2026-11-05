export interface ScanFile {
  path: string;
  content: string;
  size: number;
}

export interface ScanContext {
  scanId: string;
  owner: string;
  repo: string;
  defaultBranch: string;
  rootDir: string;
  files: ScanFile[];
  packageJson?: unknown;
  truncated: boolean;
}
