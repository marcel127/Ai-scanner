import { createGeminiAnalyzer } from './gemini.js';
import { NoopAnalyzer } from './noop.js';
import type { AiAnalyzer } from './types.js';

export function createAiAnalyzer(apiKey: string | undefined): AiAnalyzer {
  if (!apiKey) {
    return new NoopAnalyzer();
  }
  return createGeminiAnalyzer(apiKey);
}

export type { AiAnalyzer, AiAnalysis } from './types.js';
