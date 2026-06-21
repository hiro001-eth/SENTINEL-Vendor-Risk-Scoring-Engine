"""
Unit and integration tests for SENTINEL's Enterprise GRC features.
Covers: Registration, Login, Magic Links, AI PDF Verification, and Jira syncing.
"""
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from vendor_risk_engine.api.app import app
from vendor_risk_engine.db.models import User, Vendor, AssessmentInvitation, RemediationTicket
from tests.conftest import TestingSessionLocal

client = TestClient(app)

# ── Test User Registration & Login ───────────────────────────────────────────
def test_auth_registration_and_login():
    # 1. Register a new user
    reg_payload = {"email": "admin@sentinel.grc", "password": "securepassword123", "role": "Admin"}
    resp = client.post("/auth/register", json=reg_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["email"] == "admin@sentinel.grc"
    assert data["role"] == "Admin"

    # 2. Prevent duplicate registrations
    resp_dup = client.post("/auth/register", json=reg_payload)
    assert resp_dup.status_code == 400

    # 3. Successful login
    login_payload = {"email": "admin@sentinel.grc", "password": "securepassword123"}
    resp_login = client.post("/auth/login", json=login_payload)
    assert resp_login.status_code == 200
    assert "token" in resp_login.json()

    # 4. Failed login with invalid password
    bad_login = {"email": "admin@sentinel.grc", "password": "wrongpassword"}
    resp_bad = client.post("/auth/login", json=bad_login)
    assert resp_bad.status_code == 401


# ── Test Magic Links ──────────────────────────────────────────────────────────
def test_magic_links_flow():
    # 1. Generate a magic link invitation
    invite_payload = {
        "vendor_name": "TestCorp",
        "vendor_domain": "testcorp.com",
        "contact_email": "security@testcorp.com"
    }
    resp = client.post("/invitations/", json=invite_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert "magic_link" in data
    assert data["vendor_id"] == "V-TESTCORP"

    token = data["token"]

    # 2. Access portal with valid magic token
    resp_portal = client.get(f"/portal/assess?token={token}")
    assert resp_portal.status_code == 200
    assert "SENTINEL" in resp_portal.text

    # 3. Access portal with invalid token
    resp_bad = client.get("/portal/assess?token=invalid.token.signature")
    assert resp_bad.status_code == 400


# ── Test AI Auto-Assessor ─────────────────────────────────────────────────────
@patch("vendor_risk_engine.ai.assessor.PdfReader")
def test_ai_auto_assessor_fallback(mock_pdf_reader):
    # Mock PDF extraction pages
    mock_page = MagicMock()
    mock_page.extract_text.return_value = "We enforce MFA (multi-factor authentication) across all services. Backups are run daily."
    mock_pdf_reader.return_value.pages = [mock_page]

    # Create dummy pdf file content
    files = {"file": ("soc2.pdf", b"%PDF-1.4 mock pdf data", "application/pdf")}
    data = {"controls": "MFA,Backups,Encryption"}

    resp = client.post("/assessments/auto-assess", files=files, data=data)
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 3

    mfa_result = next(r for r in results if r["control_name"] == "MFA")
    assert mfa_result["is_present"] is True
    assert mfa_result["page_number"] == 1
    assert "MFA" in mfa_result["evidence_quote"]

    enc_result = next(r for r in results if r["control_name"] == "Encryption")
    assert enc_result["is_present"] is False


# ── Test Jira Sync Webhook ────────────────────────────────────────────────────
def test_jira_webhook_synchronization():
    db = TestingSessionLocal()
    # Pre-populate vendor if it doesn't exist
    vendor = db.query(Vendor).filter(Vendor.id == "V-TESTCORP").first()
    if not vendor:
        vendor = Vendor(
            id="V-TESTCORP",
            name="TestCorp",
            domain="testcorp.com",
            contact_email="security@testcorp.com"
        )
        db.add(vendor)
        db.commit()

    ticket = RemediationTicket(
        vendor_id="V-TESTCORP",
        category_id="CAT_DH",
        question_id="Q_DH_01",
        priority="High",
        status="Open",
        external_key="SENTINEL-JIRA-TEST"
    )
    db.add(ticket)
    db.commit()
    db.close()

    # Trigger Jira webhook
    payload = {"issue_key": "SENTINEL-JIRA-TEST", "status": "Closed"}
    resp = client.post("/integrations/jira-webhook", json=payload)
    assert resp.status_code == 200

    # Verify status is updated
    resp_list = client.get("/remediation/tickets")
    assert resp_list.status_code == 200
    tickets = resp_list.json()
    test_ticket = next(t for t in tickets if t["external_key"] == "SENTINEL-JIRA-TEST")
    assert test_ticket["status"] == "Resolved"
