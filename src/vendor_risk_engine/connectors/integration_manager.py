"""
Jira and ServiceNow bidirectional connector.
Manages creating, updating, and syncing vendor security remediation tickets.
"""
import aiohttp
import structlog
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from vendor_risk_engine.config import get_settings
from vendor_risk_engine.db.models import RemediationTicket

logger = structlog.get_logger(__name__)

class IntegrationManager:
    def __init__(self, db: Session):
        self.db = db
        self.settings = get_settings()

    async def create_remediation_ticket(self, vendor_id: str, category_id: str, question_id: str, priority: str = "Medium") -> RemediationTicket:
        """Create a remediation ticket in the database and push it to Jira/ServiceNow if configured."""
        # 1. Check if ticket already exists for this vendor and control
        existing = self.db.query(RemediationTicket).filter(
            RemediationTicket.vendor_id == vendor_id,
            RemediationTicket.category_id == category_id,
            RemediationTicket.question_id == question_id,
            RemediationTicket.status != "Resolved"
        ).first()

        if existing:
            return existing

        # 2. Initialize ticket object
        ticket = RemediationTicket(
            vendor_id=vendor_id,
            category_id=category_id,
            question_id=question_id,
            priority=priority,
            status="Open",
            created_at=datetime.now(timezone.utc)
        )
        self.db.add(ticket)
        self.db.commit()
        self.db.refresh(ticket)

        # 3. Push to external systems (Jira / ServiceNow)
        jira_url = getattr(self.settings, "jira_url", None)
        jira_token = getattr(self.settings, "jira_token", None)

        if jira_url and jira_token:
            external_key = await self._push_to_jira(ticket, jira_url, jira_token)
            if external_key:
                ticket.external_key = external_key
                self.db.commit()
        else:
            # Simulate external key for mock/local GRC testing
            ticket.external_key = f"SENTINEL-JIRA-{ticket.id}"
            self.db.commit()
            logger.info("simulated_external_ticket_creation", ticket_id=ticket.id, ext_key=ticket.external_key)

        return ticket

    async def sync_external_status(self, external_key: str, new_status: str) -> bool:
        """
        Synchronise status change from Jira/ServiceNow webhook callback.
        If a ticket is closed externally, close it in SENTINEL.
        """
        ticket = self.db.query(RemediationTicket).filter(
            RemediationTicket.external_key == external_key
        ).first()

        if not ticket:
            logger.warn("remediation_ticket_not_found_for_sync", external_key=external_key)
            return False

        if new_status.lower() in ["done", "closed", "resolved", "completed"]:
            ticket.status = "Resolved"
            ticket.resolved_at = datetime.now(timezone.utc)
        elif new_status.lower() in ["in progress", "in-progress", "under review"]:
            ticket.status = "In-Progress"
        else:
            ticket.status = "Open"

        self.db.commit()
        logger.info("remediation_ticket_status_synced", ticket_id=ticket.id, status=ticket.status)
        return True

    async def _push_to_jira(self, ticket: RemediationTicket, url: str, token: str) -> str | None:
        """Post a new issue to the Jira REST API."""
        payload = {
            "fields": {
                "project": {"key": "GRC"},
                "summary": f"Vendor Remediation Required: {ticket.vendor_id} - Control {ticket.question_id}",
                "description": (
                    f"A critical security gap has been identified during assessment.\n"
                    f"Vendor ID: {ticket.vendor_id}\n"
                    f"Failed Control: {ticket.question_id} (Category: {ticket.category_id})\n"
                    f"Tracked internally in SENTINEL: Ticket ID {ticket.id}"
                ),
                "issuetype": {"name": "Task"},
                "priority": {"name": "High" if ticket.priority == "High" else "Medium"}
            }
        }
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        try:
            async with aiohttp.ClientSession() as session:
                endpoint = f"{url.rstrip('/')}/rest/api/2/issue"
                async with session.post(endpoint, json=payload, headers=headers, timeout=10) as resp:
                    if resp.status == 201:
                        data = await resp.json()
                        return str(data.get("key"))
                    else:
                        logger.error("jira_api_push_failed", status=resp.status)
        except Exception as e:
            logger.error("jira_connection_failed", error=str(e))
        return None
