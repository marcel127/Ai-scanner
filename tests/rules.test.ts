import { describe, expect, it, vi } from 'vitest';
import type { Finding } from '../src/domain/types.js';
import type { ScanContext } from '../src/scanner/context.js';
import { dangerousEvalRule } from '../src/scanner/rules/dangerousEval.js';
import { hardcodedSecretsRule } from '../src/scanner/rules/hardcodedSecrets.js';
import { runRules } from '../src/scanner/rules/index.js';
import { vulnerableDepsRule } from '../src/scanner/rules/vulnerableDeps.js';

function context(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    scanId: 'scan-1',
    owner: 'acme',
    repo: 'widgets',
    defaultBranch: 'main',
    rootDir: '/tmp/unused',
    files: [],
    truncated: false,
    ...overrides,
  };
}

describe('hardcoded secrets rule', () => {
  it('reports a redacted secret and ignores ordinary strings', () => {
    const findings = hardcodedSecretsRule.run(
      context({
        files: [
          {
            path: 'src/config.js',
            size: 40,
            content: 'const key = "AKIAIOSFODNN7EXAMPLE";\nconst name = "hello";\n',
          },
        ],
      }),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'hardcoded-secrets',
      category: 'secrets',
      severity: 'CRITICAL',
      filePath: 'src/config.js',
      lineStart: 1,
    });
    expect(findings[0]?.evidence).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(findings[0]?.evidence).toContain('AKIA…MPLE');
  });
});

describe('dangerous eval rule', () => {
  it('flags eval in source files and skips comments and other languages', () => {
    const findings = dangerousEvalRule.run(
      context({
        files: [
          { path: 'src/app.js', size: 20, content: '// eval(safe)\neval(input)\nnew Function(code)\n' },
          { path: 'README.md', size: 10, content: 'eval(input)\n' },
        ],
      }),
    );

    expect(findings.map((finding) => finding.title)).toEqual(['Use of eval()', 'Use of new Function()']);
    expect(findings[0]?.severity).toBe('HIGH');
    expect(findings[1]?.severity).toBe('MEDIUM');
  });
});

describe('vulnerable dependency rule', () => {
  it('flags a denylisted package below the patched version', () => {
    const findings = vulnerableDepsRule.run(
      context({
        packageJson: {
          dependencies: { lodash: '4.17.19', react: '18.2.0' },
          devDependencies: { minimist: '^1.2.6' },
        },
      }),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'vulnerable-deps',
      category: 'deps',
      filePath: 'package.json',
      evidence: 'lodash@4.17.19',
    });
  });

  it('skips semver ranges such as ^4.17.19', () => {
    const findings = vulnerableDepsRule.run(
      context({
        packageJson: {
          dependencies: { lodash: '^4.17.19' },
        },
      }),
    );

    expect(findings).toHaveLength(0);
  });
});

describe('runRules', () => {
  it('keeps later findings when one rule throws', () => {
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
    const found: Finding = {
      id: '1',
      ruleId: 'ok',
      category: 'eval',
      source: 'RULE',
      severity: 'HIGH',
      title: 'Use of eval()',
      whyItMatters: 'code execution',
      remediation: 'remove eval',
    };

    const findings = runRules(context(), [
      {
        id: 'broken',
        category: 'other',
        description: 'fails',
        run() {
          throw new Error('boom');
        },
      },
      {
        id: 'ok',
        category: 'eval',
        description: 'returns findings',
        run: () => [found, { ...found, id: '2' }],
      },
    ]);

    expect(findings.map((finding) => finding.id)).toEqual(['1', '2']);
    expect(errorLog).toHaveBeenCalledWith('[rules] broken failed: boom');
    errorLog.mockRestore();
  });
});
