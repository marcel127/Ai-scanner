import type { Finding } from '../../domain/types.js';
import type { ScanContext, ScanFile } from '../context.js';
import { findSecrets, redactSecrets } from '../redact.js';

const MAX_FILES = 8;
const MAX_TOTAL_CHARS = 40_000;
const MAX_FILE_CHARS = 8_000;
const INTERESTING_PATH = /(auth|middleware|session|password|secret|token|login|security)/i;

export interface ModelFile {
  path: string;
  content: string;
}

export function redactFileForModel(content: string): string {
  const maskedLines = content.split(/\r?\n/).map((line) => {
    if (findSecrets(line).length > 0) {
      return '[REDACTED_LINE]';
    }
    return line;
  });
  return redactSecrets(maskedLines.join('\n'));
}

function rank(file: ScanFile, flagged: Set<string>): number {
  let score = Math.min(file.size, 5000) / 5000;
  if (file.path === 'package.json') {
    score += 100;
  }
  if (INTERESTING_PATH.test(file.path)) {
    score += 50;
  }
  if (flagged.has(file.path)) {
    score += 30;
  }
  return score;
}

/** Choose a small redacted slice of the repository for the model. */
export function selectFilesForModel(ctx: ScanContext, ruleFindings: Finding[]): ModelFile[] {
  const flagged = new Set(
    ruleFindings.map((finding) => finding.filePath).filter((filePath): filePath is string => Boolean(filePath)),
  );
  const ranked = [...ctx.files].sort(
    (left, right) => rank(right, flagged) - rank(left, flagged),
  );

  const selected: ModelFile[] = [];
  let used = 0;
  for (const file of ranked) {
    if (selected.length >= MAX_FILES) {
      break;
    }
    let content = redactFileForModel(file.content);
    if (content.length > MAX_FILE_CHARS) {
      content = content.slice(0, MAX_FILE_CHARS);
    }
    if (used + content.length > MAX_TOTAL_CHARS) {
      continue;
    }
    used += content.length;
    selected.push({ path: file.path, content });
  }
  return selected;
}
