"""
Deterministic classification engine.
"""
from vendor_risk_engine.models.score import VendorScore
from vendor_risk_engine.models.rules import ThresholdConfig
from vendor_risk_engine.constants import CLASSIFICATION_TIERS
from vendor_risk_engine.exceptions import ThresholdOverrideException
from vendor_risk_engine.config import Settings

class ClassificationEngine:
    def __init__(self, thresholds: ThresholdConfig):
        self.thresholds = thresholds
        self._validate_threshold_frozen()

    def _validate_threshold_frozen(self) -> None:
        pass # Pydantic frozen=True handles this

    def _apply_boundary_semantics(self, total_score: float) -> str:
        # Determine classification based on strict threshold evaluation
        for tier_name, bounds in self.thresholds.thresholds.items():
            min_val = bounds["min_score_inclusive"]
            max_val = bounds["max_score_inclusive"]
            if min_val <= total_score <= max_val:
                return tier_name
        
        # Fallback to defaults
        for tier_name, bounds in CLASSIFICATION_TIERS.items():
            if bounds["min_score_inclusive"] <= total_score <= bounds["max_score_inclusive"]:
                return tier_name
        return "Unknown"

    def classify(self, score: VendorScore) -> VendorScore:
        tier = self._apply_boundary_semantics(score.total_score)
        
        # We need to create a new model because it is frozen
        return score.model_copy(update={"classification_tier": tier})
