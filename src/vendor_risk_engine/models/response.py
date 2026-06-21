"""
Vendor responses models.
"""
from pydantic import BaseModel, ConfigDict
from datetime import datetime, date
from typing import Optional

class VendorResponse(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    question_id: str
    response_value: str
    evidence_text: Optional[str]
    responded_at: datetime

class ResponseSet(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    vendor_id: str
    vendor_name: str
    assessment_date: date
    responded_by: str
    responses: list[VendorResponse]

class ValidatedResponse(ResponseSet):
    model_config = ConfigDict(frozen=True)
    
    completeness_score: float
    gap_list: list[str]
    response_hash: str
