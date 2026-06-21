"""
Score computation output models.
"""
from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Literal

class CategoryScore(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    category_id: str
    raw_score: float
    weighted_score: float
    max_possible: float
    gap_count: int

class ExternalSignal(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    source: Literal["BitSight", "SecurityScorecard", "HaveIBeenPwned"]
    raw_value: str
    normalized_score: float
    assessed_at: datetime
    is_fresh: bool

class VendorScore(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    vendor_id: str
    vendor_name: str
    total_score: float
    category_scores: list[CategoryScore]
    classification_tier: str
    weight_config_hash: str
    questionnaire_version_hash: str
    response_snapshot_hash: str
    external_signals: list[ExternalSignal]
    gap_total_count: int
    gap_critical_count: int
    computed_at: datetime
