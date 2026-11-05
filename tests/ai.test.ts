import { describe, expect, it } from 'vitest';
import type { Finding } from '../src/domain/types.js';
import type { ScanContext } from '../src/scanner/context.js';
import { GeminiAnalyzer } from '../src/scanner/ai/gemini.js';
import { parseAiFindings } from '../src/scanner/ai/parse.js';
import { redactFileForModel } from '../src/scanner/ai/selectFiles.js';

const aws = 'AKIAIOSFODNN7EXAMPLE';

function context(): ScanContext {
  return {
    scanId: 'scan-1',
    owner: 'acme',
    repo: 'widgets',
    defaultBranch: 'main',
    rootDir: '/tmp/unused',
    truncated: false,
    files: [
      {
        path: 'src/config.js',
        size: 40,
        content: `const key = "${aws}";\nconsole.log('ok');\n`,
      },
    ],
  };
}

describe('AI output validation', () => {
  it('accepts a valid finding and redacts evidence', () => {
    const result = parseAiFindings(
      JSON.stringify({
        findings: [
          {
            severity: 'HIGH',
            title: 'Hardcoded key',
            category: 'secrets',
            filePath: 'src/config.js',
            lineStart: 1,
            whyItMatters: 'Anyone with the repo can use it.',
            remediation: 'Rotate it.',
            evidence: `key=${aws}`,
          },
        ],
      }),
    );

    expect(result.error).toBeUndefined();
    expect(result.findings[0]?.source).toBe('AI');
    expect(result.findings[0]?.evidence).not.toContain(aws);
  });

  it('gives different IDs to the same issue at different locations', () => {
    const finding = {
      severity: 'MEDIUM',
      title: 'Missing authorization check',
      category: 'auth',
      whyItMatters: 'A caller can reach the handler.',
      remediation: 'Check the caller.',
    };
    const result = parseAiFindings(
      JSON.stringify({
        findings: [
          { ...finding, filePath: 'src/a.js', lineStart: 10 },
          { ...finding, filePath: 'src/b.js', lineStart: 4 },
        ],
      }),
    );

    expect(result.findings).toHaveLength(2);
    expect(result.findings[0]?.id).not.toBe(result.findings[1]?.id);
  });

  it('rejects a response that is not JSON and drops invalid findings', () => {
    expect(parseAiFindings('not json').error).toMatch(/JSON/);
    const dropped = parseAiFindings(JSON.stringify({ findings: [{ title: 'missing fields' }] }));
    expect(dropped.findings).toEqual([]);
    expect(dropped.error).toMatch(/validation/);
  });
});

describe('Gemini analyzer input', () => {
  it('does not send detected secrets to the model', async () => {
    let prompt = '';
    const analyzer = new GeminiAnalyzer(async (value) => {
      prompt = value;
      return JSON.stringify({ findings: [] });
    });

    const result = await analyzer.analyze(context(), []);
    expect(result.findings).toEqual([]);
    expect(prompt).not.toContain(aws);
    expect(redactFileForModel(`const key = "${aws}";`)).not.toContain(aws);
  });

  it('sends known rule findings and tells Gemini to skip issues they already cover', async () => {
    let prompt = '';
    const analyzer = new GeminiAnalyzer(async (value) => {
      prompt = value;
      return JSON.stringify({ findings: [] });
    });
    const known: Finding = {
      id: 'rule-1',
      ruleId: 'dangerous-eval',
      category: 'eval',
      source: 'RULE',
      severity: 'HIGH',
      title: 'Use of eval()',
      filePath: 'src/app.js',
      lineStart: 4,
      whyItMatters: 'code execution',
      remediation: 'remove eval',
    };

    await analyzer.analyze(context(), [known]);
    const body = JSON.parse(prompt) as {
      instruction: string;
      knownRuleFindings: Array<{ ruleId: string; title: string; filePath: string; lineStart: number }>;
    };

    expect(body.knownRuleFindings).toEqual([
      expect.objectContaining({
        ruleId: 'dangerous-eval',
        title: 'Use of eval()',
        filePath: 'src/app.js',
        lineStart: 4,
      }),
    ]);
    expect(body.instruction).toMatch(/additional/i);
    expect(body.instruction).toMatch(/already covered/i);
  });

  it('returns no findings when the model fails', async () => {
    const analyzer = new GeminiAnalyzer(async () => {
      throw new Error('network down');
    });
    const result = await analyzer.analyze(context(), []);
    expect(result).toEqual({ findings: [], error: 'AI analysis failed' });
  });
});
