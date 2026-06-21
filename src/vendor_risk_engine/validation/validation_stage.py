"""
Validation stage confirming responses align with schema.
"""
import structlog
from typing import Generator
from vendor_risk_engine.models.response import ResponseSet, ValidatedResponse
from vendor_risk_engine.models.questionnaire import QuestionnaireSet
from vendor_risk_engine.utils.hash_utils import sha256_model
from vendor_risk_engine.scoring.gap_analyzer import GapAnalyzer

logger = structlog.get_logger(__name__)

class ValidationStage:
    def __init__(self, questionnaire: QuestionnaireSet):
        self.questionnaire = questionnaire
        self.gap_analyzer = GapAnalyzer()

    def validate_batch(self, batch: list[ResponseSet]) -> list[ValidatedResponse]:
        validated = []
        for response_set in batch:
            response_hash = sha256_model(response_set)
            
            temp_valid = ValidatedResponse(
                **response_set.model_dump(),
                completeness_score=0.0,
                gap_list=[],
                response_hash=response_hash
            )
            
            gaps = self.gap_analyzer.analyze(temp_valid, self.questionnaire)
            gap_strings = [f"{g.question_id}: {g.recommendation}" for g in gaps]
            
            total_questions = sum(len(c.questions) for c in self.questionnaire.categories)
            completeness = 100.0 if total_questions == 0 else ((total_questions - len(gaps)) / total_questions) * 100.0
            
            validated.append(ValidatedResponse(
                **response_set.model_dump(),
                completeness_score=completeness,
                gap_list=gap_strings,
                response_hash=response_hash
            ))
            
        return validated
