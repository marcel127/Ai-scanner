import { config as loadDotenv } from 'dotenv';

loadDotenv();

export interface AppConfig {
  databaseUrl: string;
  port: number;
  pollIntervalMs: number;
  geminiApiKey: string | undefined;
  githubToken: string | undefined;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function intEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) {
    throw new Error(`Environment variable ${name} must be an integer`);
  }
  return parsed;
}

export function loadConfig(): AppConfig {
  return {
    databaseUrl: required('DATABASE_URL'),
    port: intEnv('PORT', 3000),
    pollIntervalMs: intEnv('POLL_INTERVAL_MS', 1500),
    geminiApiKey: process.env.GEMINI_API_KEY?.trim() || undefined,
    githubToken: process.env.GITHUB_TOKEN?.trim() || undefined,
  };
}
