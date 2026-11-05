import { describe, expect, it } from 'vitest';
import { findSecrets, redactSecrets } from '../src/scanner/redact.js';

describe('redactSecrets', () => {
  it('masks AWS keys, tokens, and assigned secrets', () => {
    const aws = 'AKIAIOSFODNN7EXAMPLE';
    expect(redactSecrets(`key=${aws}`)).toBe('key=AKIA…MPLE');
    expect(redactSecrets('api_key = "abcd1234efgh5678"')).toBe('api_key = "[REDACTED]"');
    expect(redactSecrets('token = "xoxb-1234567890-abcdefghij"')).toContain('[REDACTED]');
    expect(redactSecrets('const name = "hello"')).toBe('const name = "hello"');
  });

  it('redacts JSON property credentials', () => {
    const json = '{"api_key":"abcd1234efgh5678","password":"exampleSecret123"}';
    const redacted = redactSecrets(json);

    expect(redacted).toBe('{"api_key":"[REDACTED]","password":"[REDACTED]"}');
    expect(redacted).not.toContain('abcd1234efgh5678');
    expect(redacted).not.toContain('exampleSecret123');
    expect(findSecrets(json).map((match) => match.pattern)).toEqual([
      'assigned-secret',
      'assigned-secret',
    ]);
  });

  it('masks a private key block', () => {
    const pem = [
      '-----BEGIN PRIVATE KEY-----',
      'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7',
      '-----END PRIVATE KEY-----',
    ].join('\n');
    expect(redactSecrets(pem)).toBe('[REDACTED_PRIVATE_KEY]');
    expect(findSecrets(pem)[0]?.pattern).toBe('private-key');
  });
});
