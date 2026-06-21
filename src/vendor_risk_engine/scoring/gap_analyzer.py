"""
Gap detection and reporting utility.
"""
from vendor_risk_engine.models.response import ValidatedResponse
from vendor_risk_engine.models.questionnaire import QuestionnaireSet
from vendor_risk_engine.constants import RESPONSE_SCORE_MAP
from typing import Dict, List
from pydantic import BaseModel

class GapItem(BaseModel):
    category_id: str
    question_id: str
    question_text: str
    is_critical: bool
    response_value: str
    recommendation: str

class GapAnalyzer:
    def analyze(self, response: ValidatedResponse, questionnaire: QuestionnaireSet) -> List[GapItem]:
        gaps = []
        for cat in questionnaire.categories:
            for q in cat.questions:
                resp = next((r for r in response.responses if r.question_id == q.question_id), None)
                r_val = resp.response_value.lower() if resp else "empty"
                
                map_entry = RESPONSE_SCORE_MAP.get(r_val, {"gap_flag": True, "score": 0.0, "description": ""})
                if map_entry.get("gap_flag", True):
                    gaps.append(
                        GapItem(
                            category_id=cat.category_id,
                            question_id=q.question_id,
                            question_text=q.question_text,
                            is_critical=q.is_critical,
                            response_value=r_val,
                            recommendation=f"Provide evidence or implement control for {q.question_text}"
                        )
                    )
        return gaps

    def _identify_critical_gaps(self, gaps: List[GapItem]) -> List[GapItem]:
        return [g for g in gaps if g.is_critical]

    def _generate_recommendations(self, gaps: List[GapItem]) -> List[str]:
        return [g.recommendation for g in gaps]

    def _categorize_by_domain(self, gaps: List[GapItem]) -> Dict[str, List[GapItem]]:
        result = {}
        for g in gaps:
            result.setdefault(g.category_id, []).append(g)
        return result
