"""
Continuous Security Monitoring & Auto-updater Engine.
Periodically fetches external signal ratings (BitSight, HaveIBeenPwned, SecurityScorecard),
re-evaluates risk, and alerts on significant posture degradation.
"""
import asyncio
import structlog
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from vendor_risk_engine.config import get_settings
from vendor_risk_engine.db.models import Vendor, RemediationTicket
from vendor_risk_engine.external.bitsight_client import BitSightClient
from vendor_risk_engine.external.securityscorecard_client import SecurityScorecardClient
from vendor_risk_engine.external.breach_client import BreachClient
from vendor_risk_engine.external.signal_blender import SignalBlender
from vendor_risk_engine.notifications.webhook import WebhookNotifier, WebhookProvider
from vendor_risk_engine.connectors.integration_manager import IntegrationManager

logger = structlog.get_logger(__name__)

class GRCContinuousMonitor:
    def __init__(self, db: Session):
        self.db = db
        self.settings = get_settings()
        
        self.bitsight = BitSightClient(self.settings)
        self.ssc = SecurityScorecardClient(self.settings)
        self.hibp = BreachClient(self.settings)
        self.blender = SignalBlender(self.settings)
        
        self.notifier = None
        if self.settings.webhook_url:
            self.notifier = WebhookNotifier(
                provider=WebhookProvider(self.settings.webhook_provider),
                webhook_url=self.settings.webhook_url
            )
        self.integration = IntegrationManager(self.db)

    async def monitor_all_vendors(self, score_drop_threshold: float = 15.0) -> list:
        """
        Refresh external security signals for all database vendors.
        Raises alerts if score drops significantly.
        """
        vendors = self.db.query(Vendor).all()
        if not vendors:
            logger.info("no_vendors_in_db_for_continuous_monitoring")
            return []

        logger.info("starting_continuous_monitoring_cycle", vendor_count=len(vendors))
        results = []

        for v in vendors:
            # Gather tasks
            bs_task = self.bitsight.fetch_rating(v.name)
            ssc_task = self.ssc.fetch_score(v.name)
            hibp_task = self.hibp.check_breaches(v.name)

            try:
                # Resolve external tasks
                signals = await asyncio.gather(bs_task, ssc_task, hibp_task, return_exceptions=True)
                valid_signals = []
                for s in signals:
                    if isinstance(s, Exception):
                        logger.error("continuous_monitor_external_api_failure", vendor_id=v.id, error=str(s))
                    else:
                        valid_signals.append(s)

                if not valid_signals:
                    logger.warn("no_valid_external_signals_fetched", vendor_id=v.id)
                    continue

                # Calculate avg external score
                avg_external = sum(s.normalized_score for s in valid_signals) / len(valid_signals)
                
                # Check for critical degradation (e.g. external rating drop)
                if avg_external < 50.0:
                    logger.warn("critical_external_score_drop_detected", vendor_id=v.id, score=avg_external)
                    
                    # 1. Trigger internal alert
                    if self.notifier:
                        await self.notifier.send_high_risk_alert(
                            vendor_name=v.name,
                            vendor_id=v.id,
                            score=avg_external,
                            tier="High",
                            run_id="CONTINUOUS_MONITOR",
                            gap_count=0,
                            ale_usd=25000.0
                        )

                    # 2. Open Jira remediation ticket
                    await self.integration.create_remediation_ticket(
                        vendor_id=v.id,
                        category_id="EXT_INTEL",
                        question_id="EXT_SCORE_DEGRADATION",
                        priority="High"
                    )

                results.append({
                    "vendor_id": v.id,
                    "vendor_name": v.name,
                    "avg_external_score": round(avg_external, 2),
                    "signals_count": len(valid_signals),
                    "status": "Degraded" if avg_external < 50.0 else "Stable"
                })

            except Exception as e:
                logger.error("failed_monitoring_vendor", vendor_id=v.id, error=str(e))

        return results
