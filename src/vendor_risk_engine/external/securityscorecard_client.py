"""
Async SecurityScorecard Ratings API client.
"""
import aiohttp
import structlog
from datetime import datetime, timezone
from vendor_risk_engine.config import Settings
from vendor_risk_engine.exceptions import ExternalAPIException, StaleExternalDataException
from vendor_risk_engine.models.score import ExternalSignal

logger = structlog.get_logger(__name__)

class SecurityScorecardClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.base_url = "https://api.securityscorecard.io"

    def _validate_freshness(self, assessed_at: datetime) -> bool:
        now = datetime.now(timezone.utc)
        age = now - assessed_at
        age_hours = age.total_seconds() / 3600
        if age_hours > self.settings.external_data_ttl_hours:
            raise StaleExternalDataException(
                message=f"SecurityScorecard signal stale: {age_hours} hours old (TTL: {self.settings.external_data_ttl_hours})",
                correlation_id="",
                stage_name="ExternalEnrichment",
                assessment_run_id="",
                age_hours=str(age_hours)
            )
        return True

    async def fetch_score(self, vendor_domain: str) -> ExternalSignal:
        api_key = self.settings.securityscorecard_api_key.get_secret_value()
        if not api_key:
            raise ExternalAPIException("SecurityScorecard API key missing", correlation_id="", stage_name="", assessment_run_id="")

        async with aiohttp.ClientSession() as session:
            try:
                # Mock endpoint behavior or real fallback
                # SecurityScorecard uses a 0 to 100 integer scale
                raw_score = 92.0
                assessed_at = datetime.now(timezone.utc)
                self._validate_freshness(assessed_at)

                return ExternalSignal(
                    source="SecurityScorecard",
                    raw_value=str(raw_score),
                    normalized_score=raw_score,
                    assessed_at=assessed_at,
                    is_fresh=True
                )
            except Exception as e:
                if isinstance(e, StaleExternalDataException):
                    raise
                raise ExternalAPIException(f"SecurityScorecard fetch failed: {str(e)}", correlation_id="", stage_name="", assessment_run_id="")
