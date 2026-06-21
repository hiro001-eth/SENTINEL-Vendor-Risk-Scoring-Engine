"""
Questionnaire schema structure models.
"""
from pydantic import BaseModel, ConfigDict
from typing import Literal

class Question(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    question_id: str
    question_text: str
    response_type: Literal["yes", "no", "partial", "na", "unsure"]
    weight: float
    is_critical: bool
    is_applicable_default: bool
    evidence_required: bool

class Category(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    category_id: str
    category_name: str
    category_weight: float
    questions: list[Question]

class QuestionnaireSet(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    schema_version: str
    categories: list[Category]
    version_hash: str
