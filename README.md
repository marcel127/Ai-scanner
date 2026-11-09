# AI Security Scan Review

Small proof of concept for reviewing a public GitHub repository. A user submits `https://github.com/{owner}/{repo}`, a worker scans the default branch, and the UI shows a prioritized security review.

## What it does

1. `POST /api/scans` stores a scan as `QUEUED` and returns immediately.
2. A worker claims the job from PostgreSQL with `FOR UPDATE SKIP LOCKED`.
3. The worker downloads the default-branch ZIP, runs three deterministic rules, and optionally asks Gemini.
4. Rule findings and any additional Gemini findings are combined, turned into a review, and stored. The UI polls scan status and then loads the result.

Repository code is never executed. Best-effort secret redaction is applied before storing evidence or sending source code to Gemini. If AI analysis fails, the deterministic findings still complete the scan.

## Run with Docker

```
docker compose up --build
```

Open [http://localhost:3000](http://localhost:3000/).

Compose starts PostgreSQL, runs migrations once, then starts the API and one worker.

## Run locally

Copy `.env.example` to `.env` and configure `DATABASE_URL`.

Install dependencies and prepare the database:

```
npm install
npm run db:up
npm run db:migrate
```

Then start the API and worker in separate terminals:

```
npm run dev:api
```

```
npm run dev:worker
```

The API and worker do not migrate on startup. Run `npm run db:migrate` before either process.

Optional environment variables:

- `GEMINI_API_KEY` enables the Gemini analyzer. Without it, the scan still completes using deterministic rules.
- `GITHUB_TOKEN` raises the GitHub API rate limit for public repositories.

## API

- `POST /api/scans` with `{ "githubUrl": "https://github.com/owner/repo" }` → `202 Accepted`.
- `GET /api/scans/:id` → current status. Progress in the UI is derived from this status.
- `GET /api/scans/:id/result` → `200` when `COMPLETED`, `409` while running or `FAILED`, and `404` when missing.

Only `https://github.com/{owner}/{repo}` is accepted. Branch URLs such as `/tree/main` are rejected. The worker uses the repository's default branch. A repository whose GitHub metadata says `private: true` is rejected before any source is downloaded, including when `GITHUB_TOKEN` is set.

## Scanner

Three deterministic rules are implemented:

- **Hardcoded secrets:** Detects common patterns that may indicate exposed credentials.
- **Dangerous code execution:** Detects usage of `eval()` and `new Function()`.
- **Vulnerable dependencies:** Checks a small `package.json` denylist (`lodash`, `minimist`, `jsonwebtoken`).

The dependency denylist is illustrative, not a complete or up-to-date vulnerability database. Only exact versions such as `4.17.19` are compared. Ranges such as `^`, `~`, and `>=` are skipped.

### Repository limits

- 25 MB compressed archive.
- 80 MB extracted content.
- 400 text files.
- 200 KB per file.

Directories such as `node_modules`, build output, and lockfiles are skipped. A source file over 200 KB is skipped and the scan is marked partial. A repository with no eligible source files is also partial, so an empty result is not a clean review. Repository files are extracted into a temporary directory, and cleanup is attempted when processing finishes.

These limits are practical safeguards for a small POC, intended to bound resource usage and processing time. They are not based on production benchmarks.

## Analysis

The pipeline runs in the following order:

1. Run deterministic security rules.
2. Select relevant repository files for Gemini.
3. Provide Gemini with the selected source code and existing rule findings.
4. Combine deterministic findings with any additional AI findings.
5. Generate a prioritized security review.

Gemini receives the rule findings as `knownRuleFindings` and is instructed to report only additional vulnerabilities. It should skip an issue the rules already covered, even when the wording differs, but may still report a different vulnerability in the same file.

If Gemini finds no additional issues, it returns an empty findings list.

### AI file selection

Gemini analyzes a selected subset of the repository:

- Up to 8 files.
- Up to 8,000 characters per file.
- Up to 40,000 characters in total.

Files are prioritized using a simple ranking heuristic based on security-related paths, `package.json`, and existing rule findings.

This keeps AI analysis bounded in terms of input size and processing cost, but it does not guarantee complete vulnerability coverage. Gemini may miss issues in files that were not selected.

### Findings and recommendations

Rule findings and AI findings are concatenated. There is no separate deduplication step. Avoiding duplicates depends on the Gemini instructions and is not guaranteed.

The review generator:

- Sorts findings by severity.
- Calculates severity counts and overall risk.
- Generates a short summary.
- Groups matching remediation recommendations and links them to their related finding IDs.
- Returns up to five prioritized recommended actions.

Overall risk is determined by the highest finding severity. This is a simple POC approach rather than a comprehensive risk-scoring model.

## Failure handling

The worker claims the oldest `QUEUED` scan, processes it, then marks it `COMPLETED` or `FAILED` and moves on to the next queued scan.

A failed scan is never automatically returned to `QUEUED`.

Fetch errors, inaccessible repositories, rate limits, GitHub timeouts, and archives exceeding size limits mark the scan `FAILED` and store an `error_message`.

Each deterministic rule is isolated so that a failure in one rule does not prevent the others from executing.

An AI failure does not fail the scan. The system continues using the deterministic findings.

Automatic retries and backoff are intentionally omitted. If the worker process crashes during an active scan, that scan can remain in an intermediate status such as `FETCHING_REPOSITORY` or `RUNNING_RULES`.

A production system would use durable queue recovery, bounded retries with backoff, and improved monitoring.

## Tests

Run the test suite:

```
npm test
```

Build the TypeScript project:

```
npm run build
```

The tests cover core scanning functionality and supporting utilities. The system can also be tested end-to-end by starting Docker Compose and submitting a public GitHub repository through the UI.
