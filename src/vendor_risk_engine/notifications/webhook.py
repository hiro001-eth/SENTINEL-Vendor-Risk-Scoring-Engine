"""
Webhook notification system for real-time GRC alerting.
Supports Slack, Microsoft Teams, and generic HTTP webhooks.
"""
import aiohttp
import structlog
import json
from typing import Optional, Dict, Any
from enum import Enum

logger = structlog.get_logger(__name__)


class WebhookProvider(str, Enum):
    SLACK = "slack"
    TEAMS = "teams"
    GENERIC = "generic"


class WebhookNotifier:
    """
    Sends structured GRC alerts to external collaboration platforms.
    
    Usage:
        notifier = WebhookNotifier(
            provider=WebhookProvider.SLACK,
            webhook_url="https://hooks.slack.com/services/T00/B00/XXXX"
        )
        await notifier.send_high_risk_alert(vendor_name="Acme", score=28.5, run_id="SENTINEL-...")
    """

    def __init__(self, provider: WebhookProvider, webhook_url: str):
        self.provider = provider
        self.webhook_url = webhook_url

    def _build_slack_payload(self, title: str, fields: Dict[str, str], color: str = "#cc0000") -> dict:
        attachment_fields = [{"title": k, "value": v, "short": True} for k, v in fields.items()]
        return {
            "attachments": [
                {
                    "color": color,
                    "title": f"🛡️ SENTINEL GRC — {title}",
                    "fields": attachment_fields,
                    "footer": "SENTINEL Vendor Risk Scoring Engine",
                    "ts": __import__("time").time()
                }
            ]
        }

    def _build_teams_payload(self, title: str, fields: Dict[str, str], color: str = "#cc0000") -> dict:
        facts = [{"name": k, "value": v} for k, v in fields.items()]
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color.lstrip("#"),
            "summary": f"SENTINEL GRC — {title}",
            "sections": [
                {
                    "activityTitle": f"🛡️ SENTINEL GRC — {title}",
                    "facts": facts,
                    "markdown": True
                }
            ]
        }

    def _build_generic_payload(self, title: str, fields: Dict[str, str], color: str = "#cc0000") -> dict:
        return {
            "source": "SENTINEL-GRC",
            "event": title,
            "data": fields,
            "severity": color
        }

    def _build_payload(self, title: str, fields: Dict[str, str], color: str = "#cc0000") -> dict:
        if self.provider == WebhookProvider.SLACK:
            return self._build_slack_payload(title, fields, color)
        elif self.provider == WebhookProvider.TEAMS:
            return self._build_teams_payload(title, fields, color)
        else:
            return self._build_generic_payload(title, fields, color)

    async def _send(self, payload: dict) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status in (200, 201, 204):
                        logger.info("webhook_sent", provider=self.provider.value, status=response.status)
                        return True
                    else:
                        logger.error("webhook_failed", provider=self.provider.value, status=response.status)
                        return False
        except Exception as e:
            logger.error("webhook_error", provider=self.provider.value, error=str(e))
            return False

    async def send_high_risk_alert(
        self,
        vendor_name: str,
        vendor_id: str,
        score: float,
        tier: str,
        run_id: str,
        gap_count: int,
        ale_usd: Optional[float] = None
    ) -> bool:
        """Send an alert when a vendor is classified as High risk."""
        fields = {
            "Vendor": f"{vendor_name} ({vendor_id})",
            "Risk Score": f"{score:.1f} / 100",
            "Classification": f"🔴 {tier} Risk",
            "Assessment Run": run_id,
            "Control Gaps": str(gap_count),
        }
        if ale_usd is not None:
            fields["Est. Annual Loss"] = f"${ale_usd:,.2f} USD"
        return await self._send(self._build_payload("HIGH RISK VENDOR DETECTED", fields, "#cc0000"))

    async def send_pipeline_complete(
        self,
        run_id: str,
        total_vendors: int,
        total_gaps: int,
        high_risk_count: int
    ) -> bool:
        """Send a summary notification when the pipeline finishes."""
        color = "#cc0000" if high_risk_count > 0 else "#36a64f"
        fields = {
            "Assessment Run": run_id,
            "Vendors Scored": str(total_vendors),
            "Total Gaps": str(total_gaps),
            "High Risk Vendors": str(high_risk_count),
        }
        return await self._send(self._build_payload("ASSESSMENT COMPLETE", fields, color))

    async def send_threshold_violation(
        self,
        vendor_name: str,
        vendor_id: str,
        category: str,
        raw_score: float,
        floor: float,
        run_id: str
    ) -> bool:
        """Send an alert when a category floor violation is detected."""
        fields = {
            "Vendor": f"{vendor_name} ({vendor_id})",
            "Failed Category": category,
            "Category Score": f"{raw_score:.1f}",
            "Floor Threshold": f"{floor:.1f}",
            "Assessment Run": run_id,
        }
        return await self._send(self._build_payload("CATEGORY FLOOR VIOLATION", fields, "#ff9900"))
