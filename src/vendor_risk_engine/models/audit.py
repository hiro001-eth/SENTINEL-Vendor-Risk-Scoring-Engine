"""
Assessment run metadata and audit log entry models.
"""
from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional, Literal
from vendor_risk_engine.constants import LogEventType

class AssessmentRunMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    run_id: str
    start_time: datetime
    end_time: Optional[datetime]
    pipeline_version: str
    python_version: str
    dependency_lockfile_hash: str
    weight_config_hash: str
    questionnaire_version_hash: str
    total_vendors_scored: int
    total_reports_generated: int
    total_gaps_detected: int
    external_sync_successful: bool

class AuditLogEntry(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    timestamp_utc: datetime
    correlation_id: str
    assessment_run_id: str
    stage_name: str
    event_type: LogEventType
    log_severity: str
    message: str
    vendor_id: Optional[str] = None
    score: Optional[float] = None
    classification_tier: Optional[str] = None
    extra: dict = {}

class HealthCheckResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    check_name: str
    passed: bool
    details: str
    severity: Literal["INFO", "WARN", "FATAL"]
