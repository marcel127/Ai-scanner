import { z } from 'zod';
import { SEVERITIES } from './types.js';

export const aiFindingSchema = z.object({
  severity: z.enum(SEVERITIES),
  title: z.string().trim().min(1).max(200),
  category: z.string().trim().min(1).max(40).optional(),
  filePath: z.string().trim().min(1).max(300).optional(),
  lineStart: z.number().int().positive().optional(),
  whyItMatters: z.string().trim().min(1).max(2000),
  remediation: z.string().trim().min(1).max(2000),
  evidence: z.string().trim().min(1).max(500).optional(),
});

export const aiResponseSchema = z.object({
  findings: z.array(z.unknown()).max(30),
});

export type AiFindingInput = z.infer<typeof aiFindingSchema>;
