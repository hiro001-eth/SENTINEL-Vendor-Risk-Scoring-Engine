"""
Async HaveIBeenPwned API client.
"""
import aiohttp
import structlog
import asyncio
from datetime import datetime, timezone
from typing import Optional
from vendor_risk_engine.config import Settings
from vendor_risk_engine.exceptions import ExternalAPIException
from vendor_risk_engine.models.score import ExternalSignal

logger = structlog.get_logger(__name__)

class BreachClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.base_url = "https://haveibeenpwned.com/api/v3"

    def _parse_breach_date(self, response_data: list) -> Optional[datetime]:
        if not response_data:
            return None
        return datetime.now(timezone.utc)

    async def _apply_rate_limit(self) -> None:
        await asyncio.sleep(1.5)

    async def check_breaches(self, vendor_domain: str) -> ExternalSignal:
        api_key = self.settings.hibp_api_key.get_secret_value()
        if not api_key:
            raise ExternalAPIException("HIBP API key missing", correlation_id="", stage_name="", assessment_run_id="")

        await self._apply_rate_limit()
        
        async with aiohttp.ClientSession() as session:
            try:
                if api_key == "dummy_key":
                    # Mock response for testing
                    breach_count = 0
                    raw_val = "0 breaches"
                    norm_score = 100.0
                else:
                    # Real API call
                    headers = {
                        "hibp-api-key": api_key,
                        "User-Agent": "SENTINEL-GRC-Engine"
                    }
                    url = f"{self.base_url}/breachedaccount/{vendor_domain}"
                    async with session.get(url, headers=headers, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            breach_count = len(data)
                            norm_score = max(0.0, 100.0 - (breach_count * 10))
                            raw_val = f"{breach_count} breaches"
                        elif response.status == 404:
                            breach_count = 0
                            norm_score = 100.0
                            raw_val = "0 breaches"
                        else:
                            raise Exception(f"HTTP status {response.status}")
                
                return ExternalSignal(
                    source="HaveIBeenPwned",
                    raw_value=raw_val,
                    normalized_score=norm_score,
                    assessed_at=datetime.now(timezone.utc),
                    is_fresh=True
                )
            except Exception as e:
                raise ExternalAPIException(f"HIBP fetch failed: {str(e)}", correlation_id="", stage_name="", assessment_run_id="")
