CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scan_status') THEN
    CREATE TYPE scan_status AS ENUM (
      'QUEUED',
      'FETCHING_REPOSITORY',
      'RUNNING_RULES',
      'AI_ANALYSIS',
      'GENERATING_REVIEW',
      'COMPLETED',
      'FAILED'
    );
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS scans (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  github_url      TEXT NOT NULL,
  owner           TEXT NOT NULL,
  repo            TEXT NOT NULL,
  default_branch  TEXT,
  status          scan_status NOT NULL DEFAULT 'QUEUED',
  error_message   TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at      TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS scans_queued_claim_idx
  ON scans (created_at)
  WHERE status = 'QUEUED';

CREATE TABLE IF NOT EXISTS scan_results (
  scan_id              UUID PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
  overall_risk         TEXT NOT NULL,
  summary              TEXT NOT NULL,
  severity_counts      JSONB NOT NULL,
  recommended_actions  JSONB NOT NULL,
  findings             JSONB NOT NULL,
  meta                 JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
