import { createHash } from 'node:crypto';
import type { Finding } from '../../domain/types.js';
import { aiFindingSchema, aiResponseSchema } from '../../domain/schemas.js';
import { redactSecrets } from '../redact.js';

function slug(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40);
  return normalized || 'finding';
}

function safePath(filePath: string | undefined): string | undefined {
  if (!filePath) {
    return undefined;
  }
  const normalized = filePath.replaceAll('\\', '/').replace(/^\.\//, '');
  if (normalized.startsWith('/') || normalized.split('/').includes('..')) {
    return undefined;
  }
  return normalized;
}

function readJson(text: string): unknown {
  const trimmed = text.trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  return JSON.parse(fenced?.[1] ?? trimmed) as unknown;
}

export function parseAiFindings(text: string): { findings: Finding[]; error?: string } {
  let payload: unknown;
  try {
    payload = readJson(text);
  } catch {
    return { findings: [], error: 'AI response was not valid JSON' };
  }

  const envelope = aiResponseSchema.safeParse(payload);
  if (!envelope.success) {
    return { findings: [], error: 'AI response did not match the expected shape' };
  }

  const findings: Finding[] = [];
  for (const item of envelope.data.findings) {
    const parsed = aiFindingSchema.safeParse(item);
    if (!parsed.success) {
      continue;
    }
    const category = (parsed.data.category ?? 'other').toLowerCase().replace(/[^a-z0-9_-]/g, '') || 'other';
    const title = redactSecrets(parsed.data.title);
    const filePath = safePath(parsed.data.filePath);
    const lineStart = parsed.data.lineStart;
    findings.push({
      id: createHash('sha256')
        .update(`ai|${category}|${filePath ?? ''}|${lineStart ?? ''}|${title}`)
        .digest('hex')
        .slice(0, 16),
      ruleId: `ai:${slug(title)}`,
      category,
      source: 'AI',
      severity: parsed.data.severity,
      title,
      filePath,
      lineStart,
      evidence: parsed.data.evidence ? redactSecrets(parsed.data.evidence) : undefined,
      whyItMatters: redactSecrets(parsed.data.whyItMatters),
      remediation: redactSecrets(parsed.data.remediation),
    });
  }

  if (envelope.data.findings.length > 0 && findings.length === 0) {
    return { findings: [], error: 'AI findings failed validation' };
  }
  return { findings };
}
