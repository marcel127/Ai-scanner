import type {
  Scan,
  ScanResultRecord,
  ScanStatus,
  SecurityReview,
  SeverityCounts,
} from '../domain/types.js';
import type { DbPool } from './pool.js';

interface ScanRow {
  id: string;
  github_url: string;
  owner: string;
  repo: string;
  default_branch: string | null;
  status: ScanStatus;
  error_message: string | null;
  created_at: Date;
  updated_at: Date;
  started_at: Date | null;
  completed_at: Date | null;
}

interface ResultRow {
  scan_id: string;
  overall_risk: SecurityReview['overallRisk'];
  summary: string;
  severity_counts: SeverityCounts;
  recommended_actions: SecurityReview['recommendedActions'];
  findings: SecurityReview['findings'];
  meta: Record<string, unknown>;
  created_at: Date;
}

function mapScan(row: ScanRow): Scan {
  return {
    id: row.id,
    githubUrl: row.github_url,
    owner: row.owner,
    repo: row.repo,
    defaultBranch: row.default_branch,
    status: row.status,
    errorMessage: row.error_message,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    startedAt: row.started_at,
    completedAt: row.completed_at,
  };
}

function mapResult(row: ResultRow): ScanResultRecord {
  return {
    scanId: row.scan_id,
    review: {
      overallRisk: row.overall_risk,
      summary: row.summary,
      severityCounts: row.severity_counts,
      recommendedActions: row.recommended_actions,
      findings: row.findings,
    },
    meta: row.meta ?? {},
    createdAt: row.created_at,
  };
}

const SCAN_COLUMNS = `
  id, github_url, owner, repo, default_branch, status, error_message,
  created_at, updated_at, started_at, completed_at
`;

export class ScansRepository {
  constructor(private readonly pool: DbPool) {}

  async create(input: { githubUrl: string; owner: string; repo: string }): Promise<Scan> {
    const result = await this.pool.query<ScanRow>(
      `INSERT INTO scans (github_url, owner, repo)
       VALUES ($1, $2, $3)
       RETURNING ${SCAN_COLUMNS}`,
      [input.githubUrl, input.owner, input.repo],
    );
    const row = result.rows[0];
    if (!row) {
      throw new Error('Insert did not return a scan');
    }
    return mapScan(row);
  }

  async setDefaultBranch(id: string, defaultBranch: string): Promise<Scan | null> {
    const result = await this.pool.query<ScanRow>(
      `UPDATE scans
       SET default_branch = $2,
           updated_at = now()
       WHERE id = $1
       RETURNING ${SCAN_COLUMNS}`,
      [id, defaultBranch],
    );
    const row = result.rows[0];
    return row ? mapScan(row) : null;
  }

  async getById(id: string): Promise<Scan | null> {
    const result = await this.pool.query<ScanRow>(
      `SELECT ${SCAN_COLUMNS} FROM scans WHERE id = $1`,
      [id],
    );
    const row = result.rows[0];
    return row ? mapScan(row) : null;
  }

  async getResult(id: string): Promise<ScanResultRecord | null> {
    const result = await this.pool.query<ResultRow>(
      `SELECT scan_id, overall_risk, summary, severity_counts, recommended_actions,
              findings, meta, created_at
       FROM scan_results
       WHERE scan_id = $1`,
      [id],
    );
    const row = result.rows[0];
    return row ? mapResult(row) : null;
  }

  /**
   * Claim the oldest QUEUED scan in one transaction. SKIP LOCKED so a second
   * worker skips a row another transaction already holds.
   */
  async claimNext(): Promise<Scan | null> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query<ScanRow>(
        `UPDATE scans
         SET status = 'FETCHING_REPOSITORY',
             started_at = COALESCE(started_at, now()),
             updated_at = now()
         WHERE id = (
           SELECT id FROM scans
           WHERE status = 'QUEUED'
           ORDER BY created_at
           FOR UPDATE SKIP LOCKED
           LIMIT 1
         )
         RETURNING ${SCAN_COLUMNS}`,
      );
      await client.query('COMMIT');
      const row = result.rows[0];
      return row ? mapScan(row) : null;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async updateStatus(id: string, status: ScanStatus): Promise<Scan | null> {
    const result = await this.pool.query<ScanRow>(
      `UPDATE scans
       SET status = $2,
           updated_at = now()
       WHERE id = $1
       RETURNING ${SCAN_COLUMNS}`,
      [id, status],
    );
    const row = result.rows[0];
    return row ? mapScan(row) : null;
  }

  async complete(
    id: string,
    review: SecurityReview,
    meta: Record<string, unknown>,
  ): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `INSERT INTO scan_results (
           scan_id, overall_risk, summary, severity_counts, recommended_actions, findings, meta
         ) VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, $7::jsonb)`,
        [
          id,
          review.overallRisk,
          review.summary,
          JSON.stringify(review.severityCounts),
          JSON.stringify(review.recommendedActions),
          JSON.stringify(review.findings),
          JSON.stringify(meta),
        ],
      );
      const updated = await client.query(
        `UPDATE scans
         SET status = 'COMPLETED',
             error_message = NULL,
             completed_at = now(),
             updated_at = now()
         WHERE id = $1`,
        [id],
      );
      if (updated.rowCount !== 1) {
        throw new Error(`Could not complete scan ${id}`);
      }
      await client.query('COMMIT');
      return true;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async fail(id: string, errorMessage: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE scans
       SET status = 'FAILED',
           error_message = $2,
           completed_at = now(),
           updated_at = now()
       WHERE id = $1`,
      [id, errorMessage],
    );
    return result.rowCount === 1;
  }
}
