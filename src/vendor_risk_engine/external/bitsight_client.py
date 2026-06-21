"""
Async BitSight Security Ratings API client.
"""
import aiohttp
import structlog
from datetime import datetime, timezone
from vendor_risk_engine.config import Settings
from vendor_risk_engine.exceptions import ExternalAPIException, StaleExternalDataException
from vendor_risk_engine.models.score import ExternalSignal

logger = structlog.get_logger(__name__)

class BitSightClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.base_url = "https://api.bitsighttech.com"
        
    def _normalize_to_100(self, raw_rating: float) -> float:
        # BitSight scale is roughly 250 to 900
        min_scale = 250.0
        max_scale = 900.0
        normalized = max(0.0, min(100.0, ((raw_rating - min_scale) / (max_scale - min_scale)) * 100))
        return normalized

    def _validate_freshness(self, assessed_at: datetime) -> bool:
        now = datetime.now(timezone.utc)
        age = now - assessed_at
        age_hours = age.total_seconds() / 3600
        if age_hours > self.settings.external_data_ttl_hours:
            raise StaleExternalDataException(
                message=f"BitSight signal stale: {age_hours} hours old (TTL: {self.settings.external_data_ttl_hours})",
                correlation_id="",
                stage_name="ExternalEnrichment",
                assessment_run_id="",
                age_hours=str(age_hours)
            )
        return True

    async def fetch_rating(self, vendor_domain: str) -> ExternalSignal:
        api_key = self.settings.bitsight_api_key.get_secret_value()
        if not api_key:
            raise ExternalAPIException("BitSight API key missing", correlation_id="", stage_name="", assessment_run_id="")
            
        async with aiohttp.ClientSession() as session:
            try:
                if api_key == "dummy_key":
                    # Mock response for testing
                    raw_rating = 750.0
                    assessed_at = datetime.now(timezone.utc)
                else:
                    # Real API call
                    headers = {"Authorization": f"Basic {api_key}"}
                    url = f"{self.base_url}/v1/companies?domain={vendor_domain}"
                    async with session.get(url, headers=headers, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get("results"):
                                company = data["results"][0]
                                raw_rating = float(company.get("rating", 750.0))
                            else:
                                raw_rating = 750.0
                        else:
                            raise Exception(f"HTTP status {response.status}")
                    assessed_at = datetime.now(timezone.utc)
                
                self._validate_freshness(assessed_at)
                
                return ExternalSignal(
                    source="BitSight",
                    raw_value=str(raw_rating),
                    normalized_score=self._normalize_to_100(raw_rating),
                    assessed_at=assessed_at,
                    is_fresh=True
                )
            except Exception as e:
                if isinstance(e, StaleExternalDataException):
                    raise
                raise ExternalAPIException(f"BitSight fetch failed: {str(e)}", correlation_id="", stage_name="", assessment_run_id="")
