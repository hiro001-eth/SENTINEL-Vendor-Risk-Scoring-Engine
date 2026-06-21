# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-06-19

### Added
- **Slack / Teams / Generic Webhook Alerts** — real-time notifications on High Risk classification, category floor violations, and pipeline completion. Zero code changes required — configure via `WEBHOOK_URL` in `.env`.
- **Cross-Framework Compliance Mapper** — maps any failed control category to equivalent requirements across SOC 2 TSC, ISO 27001:2022 Annex A, NIST CSF 2.0, and PCI-DSS v4.0 simultaneously.
- **Executive Summary API endpoint** (`GET /assessments/{run_id}/executive-summary`) — board-ready JSON report with portfolio posture (CRITICAL/ELEVATED/ACCEPTABLE), aggregated FAIR financial exposure, compliance coverage scores per framework, and prioritised C-suite recommendations.
- **Compliance Map API endpoint** (`GET /assessments/{run_id}/compliance-map`) — per-vendor and portfolio-wide cross-framework control exposure map.
- **Health Check endpoint** (`GET /health`) — live system metrics including uptime, run counts, webhook status, and output directory writability.
- **Docker production deployment** — multi-stage `Dockerfile` with non-root user, health check, and `docker-compose.yml` for one-command launch with persistent volume mounts.
- **Updated `.env.example`** — full documentation for all settings including Slack and Teams webhook configuration examples.
- **31-test suite** — expanded from 12 to 31 tests covering all 8 API endpoints, webhook payload builders, send success/failure paths, FAIR model, MITRE mapping, and trend analysis.

## [1.1.0] - 2026-06-19

### Added
- FastAPI REST API wrapper featuring endpoints for CSV scoring uploads, status/audit checking, and report downloads.
- MITRE ATT&CK Mapping of questionnaire control failures to threat actor tactics and techniques (e.g. T1078 Valid Accounts).
- FAIR-aligned Quantitative Risk modeling calculating ARO, SLE, ALE, and Residual Risk Value in USD.
- Remediation Ticket Tracker with SLA enforcement (30/60/90 days) based on vendor risk tiers.
- Multi-framework pre-built schemas for SOC 2, ISO 27001, NIST CSF 2.0, and PCI-DSS v4.0.
- Trend Analysis tracking score deltas, gap changes, and improvement velocity across assessment cycles.
- Dynamic run ID anchors (SENTINEL-YYYYMMDD-HHMMSS-RANDOM) for cryptographic lineage.

## [1.0.0] - 2026-06-18

### Added
- Complete deterministic multi-domain vendor risk scoring engine.
- Cryptographic lineage tracking (SHA-256 hashes for schemas, weights, responses).
- Category floor control implementation to cap scores on single-domain failures.
- CLI tool structure with support for scoring, validation, audit logs, and PDF generation.
- Async live intelligence blending (BitSight, HaveIBeenPwned).
- Exclusive file locking (`fcntl.flock`) for atomic weight version rollbacks.
- Memory-bounded CSV streaming ingestion via pandas.
- Comprehensive ReportLab PDF/A compliant document generator.
- 43 custom typed exceptions across pipeline stages.
- Initial unit test suite for scoring & classification.
- Standard MIT License.
