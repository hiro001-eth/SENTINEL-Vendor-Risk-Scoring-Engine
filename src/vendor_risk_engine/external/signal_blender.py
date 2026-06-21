"""
External signal blending engine.
"""
from vendor_risk_engine.models.score import VendorScore, ExternalSignal
from vendor_risk_engine.config import Settings
from vendor_risk_engine.exceptions import SignalBlendException
import structlog

logger = structlog.get_logger(__name__)

class SignalBlender:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _filter_stale_signals(self, signals: list[ExternalSignal]) -> list[ExternalSignal]:
        return [s for s in signals if s.is_fresh]

    def _compute_weighted_blend(self, internal: float, external: float) -> float:
        # 70% internal, 30% external
        return (0.7 * internal) + (0.3 * external)

    def _fallback_to_internal(self, vendor_score: VendorScore) -> VendorScore:
        logger.info("falling_back_to_internal_score", vendor_id=vendor_score.vendor_id)
        return vendor_score

    def blend(self, vendor_score: VendorScore, signals: list[ExternalSignal]) -> VendorScore:
        fresh_signals = self._filter_stale_signals(signals)
        if not fresh_signals:
            return self._fallback_to_internal(vendor_score)
            
        try:
            avg_external = sum(s.normalized_score for s in fresh_signals) / len(fresh_signals)
            blended = self._compute_weighted_blend(vendor_score.total_score, avg_external)
            
            return vendor_score.model_copy(
                update={
                    "total_score": round(blended, self.settings.scoring_decimal_places),
                    "external_signals": fresh_signals
                }
            )
        except Exception as e:
            raise SignalBlendException(f"Failed to blend signals: {str(e)}", correlation_id="", stage_name="ExternalEnrichment", assessment_run_id="")
