"""
Rules models for Weight and Threshold configs.
"""
from pydantic import BaseModel, ConfigDict
from typing import Dict, Optional
from vendor_risk_engine.constants import TierBounds

class ThresholdConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    version: str
    thresholds: Dict[str, TierBounds]
    boundary_handling: str

class WeightConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    version: str
    category_weights: Dict[str, float]
    question_weights: Dict[str, Dict[str, float]]
    category_floor: Optional[float]
    config_hash: str = ""
