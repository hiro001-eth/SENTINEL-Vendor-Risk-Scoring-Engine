"""
Immutable module-level constants.
"""
from typing import Dict, TypedDict, Optional
from enum import Enum

class TierBounds(TypedDict):
    min_score_inclusive: float
    max_score_inclusive: float
    description: str

CLASSIFICATION_TIERS: Dict[str, TierBounds] = {
    "Low": {
        "min_score_inclusive": 70.0,
        "max_score_inclusive": 100.0,
        "description": "Acceptable risk level with standard monitoring"
    },
    "Medium": {
        "min_score_inclusive": 40.0,
        "max_score_inclusive": 69.9999,
        "description": "Elevated risk requiring enhanced oversight or remediation plan"
    },
    "High": {
        "min_score_inclusive": 0.0,
        "max_score_inclusive": 39.9999,
        "description": "Unacceptable risk requiring immediate remediation or contract termination consideration"
    }
}

class ScoreMap(TypedDict):
    score: Optional[float]
    gap_flag: bool
    description: str

RESPONSE_SCORE_MAP: Dict[str, ScoreMap] = {
    "yes": {"score": 1.0, "gap_flag": False, "description": "Control fully implemented"},
    "partial": {"score": 0.5, "gap_flag": False, "description": "Control partially implemented with compensating evidence"},
    "no": {"score": 0.0, "gap_flag": True, "description": "Control not implemented"},
    "unsure": {"score": 0.0, "gap_flag": True, "description": "Vendor uncertain — treated as gap"},
    "na": {"score": None, "gap_flag": False, "description": "Not applicable — reduces denominator only if schema permits"}
}

CSV_COLUMNS = [
    "vendor_id",
    "vendor_name",
    "assessment_date",
    "total_score",
    "classification_tier",
    "category_data_handling_score",
    "category_access_controls_score",
    "category_incident_response_score",
    "category_business_continuity_score",
    "category_encryption_score",
    "category_compliance_score",
    "category_subprocessor_score",
    "gap_unanswered_count",
    "gap_critical_count",
    "external_bitsight_score",
    "external_breach_flag",
    "weight_config_hash",
    "questionnaire_version_hash",
    "response_snapshot_hash",
    "computed_at",
    "assessment_run_id"
]

class LogEventType(str, Enum):
    ASSESSMENT_START = "ASSESSMENT_START"
    ASSESSMENT_COMPLETE = "ASSESSMENT_COMPLETE"
    VENDOR_SCORED = "VENDOR_SCORED"
    GAP_DETECTED = "GAP_DETECTED"
    EXTERNAL_DATA_FETCHED = "EXTERNAL_DATA_FETCHED"
    EXTERNAL_DATA_STALE = "EXTERNAL_DATA_STALE"
    THRESHOLD_VIOLATION = "THRESHOLD_VIOLATION"
    REPORT_GENERATED = "REPORT_GENERATED"
    REPORT_VERIFIED = "REPORT_VERIFIED"
    EXPORT_WRITTEN = "EXPORT_WRITTEN"
    AUDIT_COMPLETE = "AUDIT_COMPLETE"
