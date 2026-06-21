# RUNBOOK: SENTINEL Pipeline Operations

## 1. Prerequisites
- Python 3.11 minimum
- Docker & Docker Compose
- Valid `.env` configuration file
- ReportLab font assets in `./assets/fonts`

## 2. Initial Deployment
1. Clone repository and setup environment variables using `.env.example`.
2. Build the production image: `docker build -t sentinel-engine:latest --target runtime .`
3. Validate schemas: `docker run sentinel-engine validate --quick-check`
4. Mount output volumes and config directories.
5. Execute end-to-end dry run: `docker run -v ./data:/app/data sentinel-engine score /app/data/sample_responses.csv --dry-run`

## 3. Cron Configuration
**Schedule:** `0 2 * * *` (Daily at 02:00 UTC)
**Justification:** Aligns with standard API rate-limit resets (ANCHOR:Q5 regulatory context) and ensures fresh batch runs before the start of business hours globally. Daily runs capture external signal decay effectively.

## 4. Log Monitoring
Alerting thresholds configured via JSON Lines parsing:
- **`FATAL`**: Immediate pager escalation. Implies pipeline halt.
- **`ERROR` / `EXTERNAL_DATA_STALE`**: Ticket generation. Investigate API health.
- **`WARN` / `THRESHOLD_VIOLATION`**: Alert Risk Manager for manual review.
- **`GAP_DETECTED`**: Tracked via dashboard; no direct alert unless count > 50 in one batch.

## 5. Incident Response
- **Exit Code 0:** Full success. No action.
- **Exit Code 1:** Pipeline failure. Check `correlation_id` in logs. Validate schema formatting, memory limits, and file permissions. Fix data/config and re-run.
- **Exit Code 2:** Audit failure. Null rates exceeded or lineage hashes missing. Do NOT trust partial output. Investigate missing weight/questionnaire definitions.

## 6. Auditor Interaction Guide
To trace score lineage:
1. Open the vendor PDF report and extract the `score_data_hash` from the cover page footer.
2. Cross-reference `score_data_hash` in the `output/audit_log.jsonl`.
3. Locate the associated `weight_config_hash` and `questionnaire_version_hash`.
4. Run the validation utility against the historical schema files to reproduce identical hashes, proving the mathematical foundation of the score.

## 7. Performance Tuning
- **Batch Size:** Set `BATCH_SIZE=100` by default. Increase to `250` for high-memory instances (8GB+).
- **Worker Count:** Single-threaded execution for determinism. I/O boundaries use asyncio. Maximize chunk processing speed by pre-validating large CSVs.

## 8. Rollback Procedure
1. Identify the problematic `weight_config_hash` via logs.
2. Edit `rules/weight_config.yaml` or restore from version control.
3. Reload weights via `SIGHUP` or restart the container.
4. Issue full re-assessment command targeting the specific `assessment_date` partition to overwrite corrupted scores.
