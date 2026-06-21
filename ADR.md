# Architecture Decision Records (ADR)

## ADR 1: Scoring Determinism & Pure Functions
- **Stage:** Scoring
- **Status:** Accepted
- **Context:** Score computations must be strictly reproducible to satisfy NIST SP 800-30 Rev.1. Floating point drift and dictionary insertion order non-determinism cause audit failures.
- **Decision:** Implement `ScoringEngine` as a pure function. Freeze inputs via Pydantic (`frozen=True`) and apply Decimal quantization to 4 places.
- **Rationale:** ANCHOR:Q8 computation engine evaluation and Q4 mathematical constraints enforce strict functional determinism.
- **Consequences:** Mutating responses in-place is impossible. `CategoryFloorException` becomes deterministic.
- **Invariant:** ANCHOR:I1_score_determinism_impossibility

## ADR 2: Hash-Based Lineage Guarantee
- **Stage:** Ingestion & Export
- **Status:** Accepted
- **Context:** Vendor assessments lack traceability back to the specific version of the questionnaire and weights used.
- **Decision:** Calculate SHA-256 canonical JSON byte hashes for schemas, weights, and responses. Propagate to `ScoreModel`.
- **Rationale:** Ensures tamper-evident provenance. Aligned with NIST SP 800-161.
- **Consequences:** Forces failure on malformed input rather than silent continuation.
- **Invariant:** ANCHOR:I2_lineage_impossibility

## ADR 3: Immutable Classification Thresholds
- **Stage:** Classification
- **Status:** Accepted
- **Context:** Ad-hoc manual threshold overrides create inconsistent portfolio risk distribution.
- **Decision:** `ThresholdConfig` is strictly immutable. Runtime parameter overrides raise `ThresholdOverrideException`.
- **Rationale:** ANCHOR:Q5 threshold calibration mapped to ISO 27005 dictates that threshold alteration requires an audit event and a full portfolio recalculation.
- **Consequences:** Analysts cannot tweak thresholds to pass a specific vendor.
- **Invariant:** ANCHOR:I3_threshold_drift_impossibility

## ADR 4: External Data Freshness & Staleness Rejection
- **Stage:** External Enrichment
- **Status:** Accepted
- **Context:** Blending outdated external security signals skews risk metrics.
- **Decision:** Enforce TTL on external signals. Reject and fallback to internal scores with `external_data_expired` flags if TTL exceeded.
- **Rationale:** ANCHOR:Q6 external signal blending strategy.
- **Consequences:** API latency or stale records won't pollute risk scores.
- **Invariant:** ANCHOR:I4_external_staleness_impossibility

## ADR 5: Silent Gap Prevention
- **Stage:** Validation & Scoring
- **Status:** Accepted
- **Context:** Unanswered questions historically removed from denominator, artificially inflating scores.
- **Decision:** Treat null, unsure, or omitted responses as 0.0. Denominator reduction only valid for verified "Not Applicable" flags.
- **Rationale:** ANCHOR:Q2 response scoring rubric explicitly maps empty/unsure to 0.0 with `gap_flag=True`.
- **Consequences:** Incomplete questionnaires score poorly by default, forcing vendor remediation.
- **Invariant:** ANCHOR:I5_silent_gap_impossibility

## ADR 6: Tamper-Evident Report Verification
- **Stage:** Report Generation
- **Status:** Accepted
- **Context:** PDF reports are vulnerable to post-generation modification.
- **Decision:** Compute SHA-256 of canonical `ScoreModel` JSON and embed it into PDF `/Custom` metadata and printed footer.
- **Rationale:** ANCHOR:Q10 and Q11 PDF library capabilities.
- **Consequences:** Modifications invalidate the PDF checksum, rendering the document untrusted.
- **Invariant:** ANCHOR:I6_report_tamper_impossibility

## ADR 7: Bounded Memory via Batch Generator Architecture
- **Stage:** Ingestion to Export (End-to-End)
- **Status:** Accepted
- **Context:** 10,000 vendor row datasets cause Out-Of-Memory exceptions when materialized fully.
- **Decision:** Implement purely generator-driven pipeline. `pandas.read_csv(chunksize=X)` feeds batches that are scored, written, and garbage collected before the next iteration.
- **Rationale:** ANCHOR:Q7 format evaluation. Ensures O(batch_size) scaling.
- **Consequences:** Aggregations spanning the entire dataset (e.g., total portfolio stats) must be done incrementally or via the final Parquet store.
- **Invariant:** ANCHOR:I7_memory_bound_impossibility
