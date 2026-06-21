"""
API endpoint integration tests — covers all 8 production routes.
"""
from fastapi.testclient import TestClient
from vendor_risk_engine.api.app import app
import pytest

client = TestClient(app)

# ── Shared CSV payload ──────────────────────────────────────────────────────
_CSV = (
    "vendor_id,vendor_name,assessment_date,responded_by,"
    "Q_DH_01,Q_AC_01,Q_IR_01,Q_BC_01,Q_ENC_01\n"
    "V-API-01,APIVendor,2026-06-19,TestUser,"
    "yes,yes,yes,yes,yes\n"
)
_CSV_HIGH_RISK = (
    "vendor_id,vendor_name,assessment_date,responded_by,"
    "Q_DH_01,Q_AC_01,Q_IR_01,Q_BC_01,Q_ENC_01\n"
    "V-API-02,RiskyVendor,2026-06-19,TestUser,"
    "no,no,no,no,no\n"
)

# Cache run_id across tests in this module
_run_id = None
_high_run_id = None


def _upload(csv_data: str) -> dict:
    files = {"file": ("test.csv", csv_data, "text/csv")}
    resp = client.post("/assessments/", files=files)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ── System ────────────────────────────────────────────────────────────────────
class TestHealth:
    def test_health_returns_ok(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["version"] == "1.2.0"
        assert "uptime_seconds" in data
        assert isinstance(data["total_runs"], int)
        assert isinstance(data["webhook_configured"], bool)
        assert isinstance(data["output_dir_writable"], bool)


# ── Dashboard ─────────────────────────────────────────────────────────────────
class TestDashboard:
    def test_root_serves_html(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "SENTINEL" in resp.text
        assert "text/html" in resp.headers["content-type"]


# ── Assessments list ─────────────────────────────────────────────────────────
class TestListAssessments:
    def test_list_returns_array(self):
        resp = client.get("/assessments/")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


# ── Submit + full run ─────────────────────────────────────────────────────────
class TestSubmitAssessment:
    def test_upload_low_risk_vendor(self):
        global _run_id
        data = _upload(_CSV)
        _run_id = data["run_id"]
        assert _run_id.startswith("SENTINEL-")
        assert data["total_vendors_scored"] == 1
        assert data["status"] == "COMPLETED"

    def test_upload_rejects_non_csv(self):
        files = {"file": ("bad.txt", "not a csv", "text/plain")}
        resp = client.post("/assessments/", files=files)
        assert resp.status_code == 400

    def test_run_appears_in_list(self):
        resp = client.get("/assessments/")
        ids = [r["run_id"] for r in resp.json()]
        assert _run_id in ids


# ── Run detail + audit log ────────────────────────────────────────────────────
class TestRunDetail:
    def test_get_existing_run(self):
        assert _run_id is not None
        resp = client.get(f"/assessments/{_run_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["metadata"]["run_id"] == _run_id
        assert isinstance(data["events"], list)
        assert len(data["events"]) > 0

    def test_get_nonexistent_run_returns_404(self):
        resp = client.get("/assessments/SENTINEL-DOESNOTEXIST-0000")
        assert resp.status_code == 404

    def test_events_contain_vendor_scored(self):
        resp = client.get(f"/assessments/{_run_id}")
        event_types = [e["event_type"] for e in resp.json()["events"]]
        assert "VENDOR_SCORED" in event_types


# ── Executive summary ─────────────────────────────────────────────────────────
class TestExecutiveSummary:
    def test_executive_summary_returns_posture(self):
        assert _run_id is not None
        resp = client.get(f"/assessments/{_run_id}/executive-summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "portfolio_overview" in data
        assert data["portfolio_overview"]["total_vendors_assessed"] >= 1
        assert data["portfolio_overview"]["overall_posture"] in ("CRITICAL", "ELEVATED", "ACCEPTABLE", "NO_DATA")

    def test_executive_summary_has_fair_data(self):
        resp = client.get(f"/assessments/{_run_id}/executive-summary")
        data = resp.json()
        assert "financial_exposure" in data
        assert "total_annual_loss_expectancy_usd" in data.get("financial_exposure", {})

    def test_executive_summary_has_recommendations(self):
        resp = client.get(f"/assessments/{_run_id}/executive-summary")
        data = resp.json()
        assert isinstance(data.get("recommendations"), list)
        assert len(data["recommendations"]) > 0

    def test_executive_summary_404_for_bad_run(self):
        resp = client.get("/assessments/FAKE-RUN-ID/executive-summary")
        assert resp.status_code == 404


# ── Compliance map ────────────────────────────────────────────────────────────
class TestComplianceMap:
    def test_compliance_map_returns_portfolio(self):
        assert _run_id is not None
        resp = client.get(f"/assessments/{_run_id}/compliance-map")
        assert resp.status_code == 200
        data = resp.json()
        assert data["run_id"] == _run_id
        assert "portfolio_compliance_map" in data
        assert "vendor_compliance_details" in data

    def test_compliance_map_404_for_bad_run(self):
        resp = client.get("/assessments/FAKE-RUN-ID/compliance-map")
        assert resp.status_code == 404


# ── PDF report download ───────────────────────────────────────────────────────
class TestReportDownload:
    def test_download_pdf_for_scored_vendor(self):
        assert _run_id is not None
        resp = client.get(f"/assessments/{_run_id}/vendors/V-API-01/report")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"

    def test_download_pdf_404_for_unknown_vendor(self):
        resp = client.get(f"/assessments/{_run_id}/vendors/V-NONEXISTENT/report")
        assert resp.status_code == 404
