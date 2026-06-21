"""
Unit tests for webhook notification system.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from vendor_risk_engine.notifications.webhook import WebhookNotifier, WebhookProvider


class TestWebhookPayloadBuilders:
    """Test that each provider builds the correct payload shape."""

    def setup_method(self):
        self.notifier = WebhookNotifier(
            provider=WebhookProvider.SLACK,
            webhook_url="https://hooks.slack.com/test"
        )

    def test_slack_payload_has_attachments(self):
        payload = self.notifier._build_slack_payload(
            "TEST TITLE", {"Key": "Value"}, "#cc0000"
        )
        assert "attachments" in payload
        assert payload["attachments"][0]["title"] == "🛡️ SENTINEL GRC — TEST TITLE"
        assert payload["attachments"][0]["color"] == "#cc0000"

    def test_teams_payload_has_message_card(self):
        teams_notifier = WebhookNotifier(
            provider=WebhookProvider.TEAMS,
            webhook_url="https://outlook.office.com/webhook/test"
        )
        payload = teams_notifier._build_teams_payload(
            "TEST TITLE", {"Key": "Value"}, "#36a64f"
        )
        assert payload["@type"] == "MessageCard"
        assert "SENTINEL GRC" in payload["summary"]
        assert len(payload["sections"]) == 1

    def test_generic_payload_has_source(self):
        gen_notifier = WebhookNotifier(
            provider=WebhookProvider.GENERIC,
            webhook_url="https://example.com/webhook"
        )
        payload = gen_notifier._build_generic_payload(
            "TEST TITLE", {"Key": "Value"}, "#cc0000"
        )
        assert payload["source"] == "SENTINEL-GRC"
        assert payload["event"] == "TEST TITLE"
        assert payload["data"] == {"Key": "Value"}


class TestWebhookSend:
    """Test actual send with mocked aiohttp."""

    @pytest.mark.anyio
    async def test_send_high_risk_alert_success(self):
        notifier = WebhookNotifier(
            provider=WebhookProvider.SLACK,
            webhook_url="https://hooks.slack.com/test"
        )
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await notifier.send_high_risk_alert(
                vendor_name="DangerCorp",
                vendor_id="V-DANGER",
                score=22.5,
                tier="High",
                run_id="SENTINEL-TEST-001",
                gap_count=5,
                ale_usd=375000.0
            )
        assert result is True

    @pytest.mark.anyio
    async def test_send_returns_false_on_network_error(self):
        notifier = WebhookNotifier(
            provider=WebhookProvider.SLACK,
            webhook_url="https://hooks.slack.com/test"
        )
        with patch("aiohttp.ClientSession", side_effect=Exception("network error")):
            result = await notifier.send_high_risk_alert(
                vendor_name="TestVendor",
                vendor_id="V-001",
                score=30.0,
                tier="High",
                run_id="SENTINEL-TEST-002",
                gap_count=3,
            )
        assert result is False


@pytest.fixture
def anyio_backend():
    return "asyncio"
