"""
Unit tests for the GRC Continuous Monitoring system.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from vendor_risk_engine.scoring.continuous_monitoring import GRCContinuousMonitor
from vendor_risk_engine.db.models import Vendor, RemediationTicket
from vendor_risk_engine.models.score import ExternalSignal
from tests.conftest import TestingSessionLocal


@pytest.mark.anyio
@patch("vendor_risk_engine.external.bitsight_client.BitSightClient.fetch_rating")
@patch("vendor_risk_engine.external.securityscorecard_client.SecurityScorecardClient.fetch_score")
@patch("vendor_risk_engine.external.breach_client.BreachClient.check_breaches")
async def test_continuous_monitoring_stable(mock_breach, mock_ssc, mock_bitsight):
    # Setup mocks
    mock_bitsight.return_value = ExternalSignal(
        source="BitSight",
        raw_value="750.0",
        normalized_score=76.92,
        assessed_at=datetime.now(timezone.utc),
        is_fresh=True
    )
    mock_ssc.return_value = ExternalSignal(
        source="SecurityScorecard",
        raw_value="85.0",
        normalized_score=85.0,
        assessed_at=datetime.now(timezone.utc),
        is_fresh=True
    )
    mock_breach.return_value = ExternalSignal(
        source="HaveIBeenPwned",
        raw_value="0",
        normalized_score=100.0,
        assessed_at=datetime.now(timezone.utc),
        is_fresh=True
    )

    db = TestingSessionLocal()
    # Add a vendor
    vendor_id = "V-MONITOR-1"
    vendor = db.query(Vendor).filter(Vendor.id == vendor_id).first()
    if not vendor:
        vendor = Vendor(
            id=vendor_id,
            name="Monitor Corp 1",
            domain="monitor1.com",
            contact_email="security@monitor1.com"
        )
        db.add(vendor)
        db.commit()

    monitor = GRCContinuousMonitor(db)
    
    # Run monitoring
    results = await monitor.monitor_all_vendors()
    
    # Cleanup DB
    db.delete(vendor)
    db.commit()
    db.close()

    assert len(results) >= 1
    v_res = next(r for r in results if r["vendor_id"] == vendor_id)
    assert v_res["status"] == "Stable"
    assert v_res["avg_external_score"] > 50.0


@pytest.mark.anyio
@patch("vendor_risk_engine.external.bitsight_client.BitSightClient.fetch_rating")
@patch("vendor_risk_engine.external.securityscorecard_client.SecurityScorecardClient.fetch_score")
@patch("vendor_risk_engine.external.breach_client.BreachClient.check_breaches")
async def test_continuous_monitoring_degraded(mock_breach, mock_ssc, mock_bitsight):
    # Setup mocks with low scores (average < 50.0)
    mock_bitsight.return_value = ExternalSignal(
        source="BitSight",
        raw_value="300.0",
        normalized_score=10.0,
        assessed_at=datetime.now(timezone.utc),
        is_fresh=True
    )
    mock_ssc.return_value = ExternalSignal(
        source="SecurityScorecard",
        raw_value="40.0",
        normalized_score=40.0,
        assessed_at=datetime.now(timezone.utc),
        is_fresh=True
    )
    mock_breach.return_value = ExternalSignal(
        source="HaveIBeenPwned",
        raw_value="1",
        normalized_score=0.0,
        assessed_at=datetime.now(timezone.utc),
        is_fresh=True
    )

    db = TestingSessionLocal()
    # Add a vendor
    vendor_id = "V-MONITOR-2"
    vendor = db.query(Vendor).filter(Vendor.id == vendor_id).first()
    if not vendor:
        vendor = Vendor(
            id=vendor_id,
            name="Monitor Corp 2",
            domain="monitor2.com",
            contact_email="security@monitor2.com"
        )
        db.add(vendor)
        db.commit()

    monitor = GRCContinuousMonitor(db)
    
    # Mock notifier
    mock_notifier = AsyncMock()
    monitor.notifier = mock_notifier

    # Run monitoring
    results = await monitor.monitor_all_vendors()
    
    # Check if a ticket was created
    ticket = db.query(RemediationTicket).filter(
        RemediationTicket.vendor_id == vendor_id,
        RemediationTicket.category_id == "EXT_INTEL"
    ).first()
    
    # Cleanup DB
    db.delete(vendor)
    if ticket:
        db.delete(ticket)
    db.commit()
    db.close()

    assert len(results) >= 1
    v_res = next(r for r in results if r["vendor_id"] == vendor_id)
    assert v_res["status"] == "Degraded"
    
    # Check that mock notifier was called
    mock_notifier.send_high_risk_alert.assert_called_once()
    args, kwargs = mock_notifier.send_high_risk_alert.call_args
    assert kwargs["vendor_id"] == vendor_id
    assert kwargs["tier"] == "High"
    assert kwargs["ale_usd"] == 25000.0
    assert ticket is not None


@pytest.fixture
def anyio_backend():
    return "asyncio"
