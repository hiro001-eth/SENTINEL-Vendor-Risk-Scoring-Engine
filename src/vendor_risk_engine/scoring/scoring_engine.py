"""
Pure function scoring engine.
"""
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timezone
from vendor_risk_engine.models.response import ValidatedResponse
from vendor_risk_engine.models.score import VendorScore, CategoryScore
from vendor_risk_engine.models.questionnaire import QuestionnaireSet
from vendor_risk_engine.models.rules import WeightConfig
from vendor_risk_engine.config import Settings
from vendor_risk_engine.constants import RESPONSE_SCORE_MAP
from vendor_risk_engine.exceptions import CategoryFloorException

class ScoringEngine:
    def __init__(self, questionnaire: QuestionnaireSet, weights: WeightConfig, config: Settings):
        self.questionnaire = questionnaire
        self.weights = weights
        self.config = config

    def _quantize(self, value: float) -> Decimal:
        dec = Decimal(str(value))
        return dec.quantize(
            Decimal(f"1e-{self.config.scoring_decimal_places}"),
            rounding=ROUND_HALF_UP
        )

    def _compute_category_score(self, category_id: str, responses: ValidatedResponse) -> CategoryScore:
        # Get category details
        category = next((c for c in self.questionnaire.categories if c.category_id == category_id), None)
        if not category:
            return CategoryScore(
                category_id=category_id, raw_score=0.0, weighted_score=0.0, max_possible=0.0, gap_count=0
            )

        cat_weight = self.weights.category_weights.get(category_id, 0.0)
        q_weights = self.weights.question_weights.get(category_id, {})

        total_weight = Decimal("0.0")
        earned_score = Decimal("0.0")
        gaps = 0

        for q in category.questions:
            q_w = Decimal(str(q_weights.get(q.question_id, q.weight)))
            # find response
            resp = next((r for r in responses.responses if r.question_id == q.question_id), None)
            
            if not resp:
                total_weight += q_w
                gaps += 1
                continue

            r_type = resp.response_value.lower()
            map_entry = RESPONSE_SCORE_MAP.get(r_type)
            
            if not map_entry:
                total_weight += q_w
                gaps += 1
                continue

            if map_entry["gap_flag"]:
                gaps += 1

            if map_entry["score"] is None:
                # NA response
                if not q.is_applicable_default:
                    # Valid NA, reduces denominator
                    pass
                else:
                    # Invalid NA, counts against score
                    total_weight += q_w
            else:
                total_weight += q_w
                earned_score += q_w * Decimal(str(map_entry["score"]))

        if total_weight == 0:
            raw = Decimal("0.0")
        else:
            raw = (earned_score / total_weight) * Decimal("100.0")

        raw = self._quantize(float(raw))
        weighted = self._quantize(float(raw * Decimal(str(cat_weight))))
        max_possible = self._quantize(float(Decimal("100.0") * Decimal(str(cat_weight))))

        return CategoryScore(
            category_id=category_id,
            raw_score=float(raw),
            weighted_score=float(weighted),
            max_possible=float(max_possible),
            gap_count=gaps
        )

    def _apply_category_floor(self, scores: list[CategoryScore]) -> None:
        if not self.config.category_floor_enabled or self.weights.category_floor is None:
            return

        floor = self.weights.category_floor
        for sc in scores:
            if sc.raw_score < floor:
                raise CategoryFloorException(
                    message=f"Category floor violation in {sc.category_id}: raw score {sc.raw_score} is below floor threshold {floor}",
                    correlation_id="",
                    stage_name="Scoring",
                    assessment_run_id=""
                )

    def score_vendor(self, response: ValidatedResponse) -> VendorScore:
        cat_scores = []
        total_gaps = 0
        critical_gaps = 0
        total_score_dec = Decimal("0.0")

        for cat in self.questionnaire.categories:
            cs = self._compute_category_score(cat.category_id, response)
            cat_scores.append(cs)
            total_gaps += cs.gap_count
            total_score_dec += Decimal(str(cs.weighted_score))
            
            # Count critical gaps
            q_weights = self.weights.question_weights.get(cat.category_id, {})
            for q in cat.questions:
                if q.is_critical:
                    resp = next((r for r in response.responses if r.question_id == q.question_id), None)
                    r_type = resp.response_value.lower() if resp else "empty"
                    map_entry = RESPONSE_SCORE_MAP.get(r_type, {"gap_flag": True})
                    if map_entry.get("gap_flag", True):
                        critical_gaps += 1

        if self.config.category_floor_enabled and self.weights.category_floor is not None:
            min_raw = min((cs.raw_score for cs in cat_scores), default=100.0)
            if min_raw < self.weights.category_floor:
                total_score_dec = Decimal(str(self.weights.category_floor))

        final_total = float(self._quantize(float(total_score_dec)))
        
        # Check floor violations to raise exception if strict enforcement is required
        self._apply_category_floor(cat_scores)

        return VendorScore(
            vendor_id=response.vendor_id,
            vendor_name=response.vendor_name,
            total_score=final_total,
            category_scores=cat_scores,
            classification_tier="Pending",
            weight_config_hash=self.weights.config_hash,
            questionnaire_version_hash=self.questionnaire.version_hash,
            response_snapshot_hash=response.response_hash,
            external_signals=[],
            gap_total_count=total_gaps,
            gap_critical_count=critical_gaps,
            computed_at=datetime.now(timezone.utc)
        )
