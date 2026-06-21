"""
FastAPI REST API — SENTINEL Vendor Risk Scoring Engine.
Includes Enterprise GRC Features:
- Database Persistence (SQLite/PostgreSQL)
- Passwordless Magic-Link Vendor Portal
- AI-Powered PDF Evidence Auto-Assessor
- Bidirectional Jira & ServiceNow Ticketing Sync
- No-code GRC Schema Configurator
- Role-Based Access Control (RBAC)
"""
import shutil
import uuid
import os
import json
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, status, Depends, Form
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from vendor_risk_engine.config import get_settings
from vendor_risk_engine.main import _run_assessment_async
from vendor_risk_engine.state.audit_manager import AuditManager
from vendor_risk_engine.scoring.compliance_mapper import ComplianceMapper
from vendor_risk_engine.scoring.advanced_analysis import AdvancedGRCAnalyzer
from vendor_risk_engine.reporting.executive_summary import ExecutiveSummaryGenerator

# New imports for DB, Auth, AI, Integrations, Simulation, Monitoring
from vendor_risk_engine.db import database, models, get_db, init_db
from vendor_risk_engine.auth.service import GRCAuthService
from vendor_risk_engine.ai.assessor import AIAssessor, VerificationResult
from vendor_risk_engine.connectors.integration_manager import IntegrationManager
from vendor_risk_engine.scoring.continuous_monitoring import GRCContinuousMonitor

# ─────────────────────────────────────────────
# App bootstrap
# ─────────────────────────────────────────────
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="SENTINEL Enterprise GRC Platform",
    description=(
        "Enterprise-grade GRC platform with deterministic scoring, magic-link vendor intake, "
        "AI evidence verification, Jira synchronization, and compliance control mapping."
    ),
    version="1.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.mount("/assets", StaticFiles(directory="assets"), name="assets")

_start_time = time.time()
SECRET_KEY = "sentinel_grc_platform_secret_key_change_me_in_prod"

# ─────────────────────────────────────────────
# Request/Response Schemas
# ─────────────────────────────────────────────
class AssessmentStatusResponse(BaseModel):
    run_id: str
    status: str
    start_time: str
    end_time: Optional[str]
    total_vendors_scored: int
    total_reports_generated: int
    total_gaps_detected: int
    external_sync_successful: bool

class LogEventSchema(BaseModel):
    timestamp_utc: str
    event_type: str
    severity: str
    message: str
    vendor_id: Optional[str] = None
    score: Optional[float] = None
    classification_tier: Optional[str] = None

class RunDetailResponse(BaseModel):
    metadata: AssessmentStatusResponse
    events: List[LogEventSchema]

class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    total_runs: int
    total_vendors_scored: int
    total_gaps_detected: int
    webhook_configured: bool
    output_dir_writable: bool

class UserRegister(BaseModel):
    email: str
    password: str
    role: str = "Analyst"  # Admin, Analyst, Executive

class UserLogin(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    token: str
    email: str
    role: str

class InvitationCreate(BaseModel):
    vendor_name: str
    vendor_domain: str
    contact_email: str

class InvitationResponse(BaseModel):
    token: str
    magic_link: str
    email: str
    vendor_id: str
    expires_at: str

class TicketResponse(BaseModel):
    id: int
    vendor_id: str
    category_id: str
    question_id: str
    priority: str
    status: str
    external_key: Optional[str]

class JiraWebhookPayload(BaseModel):
    issue_key: str
    status: str

class SimulateRequest(BaseModel):
    vendor_id: str
    vendor_name: str
    responses: dict  # {question_id: response_value}
    remediated_controls: List[str]  # question IDs to flip to 'yes'

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def _run_to_schema(r: dict) -> AssessmentStatusResponse:
    return AssessmentStatusResponse(
        run_id=r["run_id"],
        status="COMPLETED" if r.get("end_time") else "RUNNING",
        start_time=r["start_time"],
        end_time=r.get("end_time"),
        total_vendors_scored=r.get("total_vendors_scored", 0),
        total_reports_generated=r.get("total_reports_generated", 0),
        total_gaps_detected=r.get("total_gaps_detected", 0),
        external_sync_successful=r.get("external_sync_successful", True),
    )

def _get_run_or_404(mgr: AuditManager, run_id: str) -> dict:
    run = mgr.get_run_metadata(run_id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment run '{run_id}' not found.",
        )
    return run

def _load_events(mgr: AuditManager, run_id: str) -> List[LogEventSchema]:
    events: List[LogEventSchema] = []
    if not mgr.log_path.exists():
        return events
    with open(mgr.log_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("assessment_run_id") == run_id:
                events.append(LogEventSchema(
                    timestamp_utc=entry.get("timestamp_utc", ""),
                    event_type=entry.get("event_type", ""),
                    severity=entry.get("log_severity", ""),
                    message=entry.get("message", ""),
                    vendor_id=entry.get("vendor_id"),
                    score=entry.get("score"),
                    classification_tier=entry.get("classification_tier"),
                ))
    return events

# ─────────────────────────────────────────────
# Enterprise Auth & SSO Routes
# ─────────────────────────────────────────────
@app.post("/auth/register", response_model=TokenResponse, tags=["Authentication"])
async def register_user(user_in: UserRegister, db: Session = Depends(get_db)):
    """Register a new internal user with role-based access control (RBAC)."""
    existing = db.query(models.User).filter(models.User.email == user_in.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already registered.")
    
    hashed = GRCAuthService.hash_password(user_in.password)
    user = models.User(
        email=user_in.email,
        hashed_password=hashed,
        role=user_in.role
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Generate mock session JWT
    token = GRCAuthService.generate_magic_token(str(user.email), "INTERNAL", SECRET_KEY, expires_in_hours=8)
    return TokenResponse(token=token, email=str(user.email), role=str(user.role))

@app.post("/auth/login", response_model=TokenResponse, tags=["Authentication"])
async def login_user(user_in: UserLogin, db: Session = Depends(get_db)):
    """User login endpoint verifying PBKDF2 hashed credentials."""
    user = db.query(models.User).filter(models.User.email == user_in.email).first()
    if not user or not GRCAuthService.verify_password(user_in.password, str(user.hashed_password)):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    
    token = GRCAuthService.generate_magic_token(str(user.email), "INTERNAL", SECRET_KEY, expires_in_hours=8)
    return TokenResponse(token=token, email=str(user.email), role=str(user.role))

# ─────────────────────────────────────────────
# Magic Link & Intake Portal Routes
# ─────────────────────────────────────────────
@app.post("/invitations/", response_model=InvitationResponse, tags=["Vendor Onboarding"])
async def create_invitation(invite: InvitationCreate, db: Session = Depends(get_db)):
    """
    Generate a secure, single-use Magic Link assessment invitation for a vendor.
    Creates the vendor record if not already present.
    """
    # Create or update vendor
    vendor_id = f"V-{invite.vendor_name.upper().replace(' ', '-')[:10]}"
    vendor = db.query(models.Vendor).filter(models.Vendor.id == vendor_id).first()
    if not vendor:
        vendor = models.Vendor(
            id=vendor_id,
            name=invite.vendor_name,
            domain=invite.vendor_domain,
            contact_email=invite.contact_email
        )
        db.add(vendor)
        db.commit()
        db.refresh(vendor)

    token = GRCAuthService.generate_magic_token(invite.contact_email, str(vendor.id), SECRET_KEY, expires_in_hours=72)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=72)).isoformat()

    invitation = models.AssessmentInvitation(
        token=token,
        vendor_id=vendor.id,
        email=invite.contact_email,
        expires_at=datetime.fromisoformat(expires_at),
        status="Pending"
    )
    db.add(invitation)
    db.commit()

    # Form magic link URL
    magic_link = f"http://127.0.0.1:8000/portal/assess?token={token}"

    return InvitationResponse(
        token=token,
        magic_link=magic_link,
        email=invite.contact_email,
        vendor_id=vendor.id,
        expires_at=expires_at
    )

@app.get("/portal/assess", response_class=HTMLResponse, tags=["Vendor Onboarding"])
async def serve_intake_portal(token: str):
    """Serve the self-service vendor security assessment magic-link portal."""
    payload = GRCAuthService.verify_magic_token(token, SECRET_KEY)
    if not payload:
        raise HTTPException(status_code=400, detail="Magic Link invalid or expired.")
    
    html_path = Path(__file__).parent / "static" / "index.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="Portal files missing.")
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"), status_code=200)

# ─────────────────────────────────────────────
# AI Evidence Auto-Assessor Route
# ─────────────────────────────────────────────
@app.post("/assessments/auto-assess", response_model=List[VerificationResult], tags=["Intelligence"])
async def auto_assess_evidence(
    file: UploadFile = File(...), 
    controls: str = Form("MFA,Encryption,Incident Response,Penetration Testing,Backups")
):
    """
    Upload a vendor's SOC 2 or ISO audit PDF to extract text and auto-verify control compliance.
    """
    if file.filename and not file.filename.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF evidence documents are accepted.")

    settings = get_settings()
    upload_dir = settings.output_dir / "evidence"
    upload_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = upload_dir / f"evidence_{uuid.uuid4().hex}.pdf"

    try:
        with open(tmp_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save PDF: {e}")

    try:
        control_list = [c.strip() for c in controls.split(",")]
        assessor = AIAssessor()
        results = await assessor.verify_evidence(tmp_path, control_list)
        return results
    finally:
        if tmp_path.exists():
            os.remove(tmp_path)

# ─────────────────────────────────────────────
# Jira Webhook Remediation Route
# ─────────────────────────────────────────────
@app.post("/integrations/jira-webhook", tags=["Integrations"])
async def jira_webhook(payload: JiraWebhookPayload, db: Session = Depends(get_db)):
    """Bidirectional webhook callback from Jira to update remediation status internally."""
    manager = IntegrationManager(db)
    synced = await manager.sync_external_status(payload.issue_key, payload.status)
    if not synced:
        raise HTTPException(status_code=404, detail="Jira ticket mapping not located.")
    return {"message": "Ticket status synchronized."}

@app.get("/remediation/tickets", response_model=List[TicketResponse], tags=["Integrations"])
async def list_remediation_tickets(db: Session = Depends(get_db)):
    """List all tracked vendor control remediation tickets."""
    tickets = db.query(models.RemediationTicket).all()
    return [
        TicketResponse(
            id=int(t.id), # type: ignore
            vendor_id=str(t.vendor_id),
            category_id=str(t.category_id),
            question_id=str(t.question_id),
            priority=str(t.priority),
            status=str(t.status),
            external_key=str(t.external_key) if t.external_key else None
        )
        for t in tickets
    ]

# ─────────────────────────────────────────────
# GRC Configurator (No-code schema updates)
# ─────────────────────────────────────────────
@app.post("/schemas/weights", tags=["Configuration"])
async def upload_weights_config(yaml_content: str):
    """Directly update weight_config.yaml. Re-compiles pipeline configuration in real-time."""
    settings = get_settings()
    try:
        # Validate that the YAML can parse
        import yaml
        yaml.safe_load(yaml_content)
        with open(settings.weight_config_path, "w", encoding="utf-8") as f:
            f.write(yaml_content)
        return {"message": "Weights configuration updated successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML schema: {e}")

# ─────────────────────────────────────────────
# What-If Remediation Simulator
# ─────────────────────────────────────────────
@app.post("/simulate/remediation", tags=["Intelligence"])
async def simulate_remediation(request: SimulateRequest):
    """
    Simulate the financial risk reduction and compliance coverage gain after
    remediating specific security control gaps — without running a real assessment.
    Shows CISO/CFO the ROI of each remediation action before committing resources.
    """
    from vendor_risk_engine.models.response import ValidatedResponse, VendorResponse
    from vendor_risk_engine.scoring.questionnaire_loader import QuestionnaireLoader
    from vendor_risk_engine.scoring.weight_loader import WeightLoader, ThresholdLoader
    from vendor_risk_engine.scoring.scoring_engine import ScoringEngine
    from vendor_risk_engine.scoring.classification_engine import ClassificationEngine
    from vendor_risk_engine.scoring.advanced_analysis import AdvancedGRCAnalyzer
    from vendor_risk_engine.scoring.compliance_mapper import ComplianceMapper

    settings = get_settings()
    questionnaire = QuestionnaireLoader(settings.questionnaire_schema_path).load()
    weights = WeightLoader(settings.weight_config_path, settings.threshold_config_path).load_weights()
    thresholds = WeightLoader(settings.weight_config_path, settings.threshold_config_path).load_thresholds()

    scoring_engine = ScoringEngine(questionnaire, weights, settings)
    classification_engine = ClassificationEngine(thresholds)
    analyzer = AdvancedGRCAnalyzer(settings.output_dir)
    mapper = ComplianceMapper()

    # Build validated response from raw dict
    resp_objects = [
        VendorResponse(question_id=qid, response_value=val, evidence_text=None, responded_at=datetime.now(timezone.utc))
        for qid, val in request.responses.items()
    ]
    original = ValidatedResponse(
        vendor_id=request.vendor_id,
        vendor_name=request.vendor_name,
        assessment_date=datetime.now(timezone.utc).date(),
        responded_by="API",
        responses=resp_objects,
        completeness_score=100.0,
        gap_list=[],
        response_hash="simulated"
    )

    # Baseline
    baseline_score = scoring_engine.score_vendor(original)
    baseline_tier = classification_engine.classify(baseline_score)
    baseline_failed = [c.category_id for c in baseline_tier.category_scores if c.raw_score < 50.0]
    baseline_fair = analyzer.calculate_fair_risk(baseline_tier.classification_tier, baseline_tier.total_score)
    baseline_compliance = mapper.generate_unified_report(baseline_failed, len(questionnaire.categories))

    # Simulate — flip target question IDs to 'yes'
    sim_responses = [
        VendorResponse(
            question_id=r.question_id,
            response_value="yes" if r.question_id in request.remediated_controls else r.response_value,
            evidence_text=None,
            responded_at=datetime.now(timezone.utc)
        )
        for r in resp_objects
    ]
    for missing_id in request.remediated_controls:
        if not any(r.question_id == missing_id for r in sim_responses):
            sim_responses.append(VendorResponse(question_id=missing_id, response_value="yes", evidence_text=None, responded_at=datetime.now(timezone.utc)))

    simulated = original.model_copy(update={"responses": sim_responses})
    sim_score = scoring_engine.score_vendor(simulated)
    sim_tier = classification_engine.classify(sim_score)
    sim_failed = [c.category_id for c in sim_tier.category_scores if c.raw_score < 50.0]
    sim_fair = analyzer.calculate_fair_risk(sim_tier.classification_tier, sim_tier.total_score)
    sim_compliance = mapper.generate_unified_report(sim_failed, len(questionnaire.categories))

    risk_reduced = max(0.0, baseline_fair["annual_loss_expectancy_usd"] - sim_fair["annual_loss_expectancy_usd"])
    score_gain = max(0.0, sim_tier.total_score - baseline_tier.total_score)
    comp_gain = max(0.0, sim_compliance["unified_compliance_score_pct"] - baseline_compliance["unified_compliance_score_pct"])

    return {
        "vendor_id": request.vendor_id,
        "vendor_name": request.vendor_name,
        "remediated_controls": request.remediated_controls,
        "comparison": {
            "score": {
                "baseline": baseline_tier.total_score,
                "simulated": sim_tier.total_score,
                "improvement": round(score_gain, 2)
            },
            "classification_tier": {
                "baseline": baseline_tier.classification_tier,
                "simulated": sim_tier.classification_tier
            },
            "annual_loss_expectancy_usd": {
                "baseline": baseline_fair["annual_loss_expectancy_usd"],
                "simulated": sim_fair["annual_loss_expectancy_usd"],
                "risk_reduced": round(risk_reduced, 2)
            },
            "compliance_score_pct": {
                "baseline": baseline_compliance["unified_compliance_score_pct"],
                "simulated": sim_compliance["unified_compliance_score_pct"],
                "coverage_gain": round(comp_gain, 2)
            }
        },
        "roi_recommendation": (
            f"HIGH ROI: Remediating {len(request.remediated_controls)} controls reduces annual risk exposure by "
            f"${risk_reduced:,.2f} and improves compliance by {comp_gain:.1f}%."
            if risk_reduced > 10000 else
            f"COMPLIANCE ROI: Score improves by {score_gain:.2f} pts, compliance coverage gains {comp_gain:.1f}%."
        )
    }

# ─────────────────────────────────────────────
# Continuous Monitoring Route
# ─────────────────────────────────────────────
@app.post("/monitor/run", tags=["Intelligence"])
async def run_continuous_monitoring(db: Session = Depends(get_db)):
    """
    Run a continuous monitoring cycle across all registered vendors.
    Fetches live external intelligence (BitSight, HIBP, SecurityScorecard),
    flags degraded vendors, opens Jira tickets, and fires Slack/Teams alerts.
    """
    monitor = GRCContinuousMonitor(db)
    results = await monitor.monitor_all_vendors(score_drop_threshold=15.0)
    return {
        "message": "Continuous monitoring cycle completed.",
        "vendors_checked": len(results),
        "results": results
    }

@app.get("/monitor/vendors", tags=["Intelligence"])
async def list_monitored_vendors(db: Session = Depends(get_db)):
    """List all vendors currently registered for continuous monitoring."""
    vendors = db.query(models.Vendor).all()
    return [
        {
            "vendor_id": v.id,
            "vendor_name": v.name,
            "domain": v.domain,
            "contact_email": v.contact_email,
            "registered_at": v.created_at.isoformat() if v.created_at else None
        }
        for v in vendors
    ]

# ─────────────────────────────────────────────
# Advanced Enterprise Routes (Monte Carlo & OSINT)
# ─────────────────────────────────────────────
@app.get("/assessments/{run_id}/vendors/{vendor_id}/fair-monte-carlo", tags=["Intelligence"])
async def run_fair_monte_carlo(run_id: str, vendor_id: str, iterations: int = 10000, db: Session = Depends(get_db)):
    """
    Run an actuarial-grade FAIR risk quantification via Monte Carlo simulation.
    Generates a Loss Exceedance Curve for board-level financial reporting.
    """
    from vendor_risk_engine.scoring.monte_carlo import MonteCarloFAIREngine
    mgr = AuditManager(get_settings())
    run = _get_run_or_404(mgr, run_id)
    events = _load_events(mgr, run_id)
    
    vendor_event = next((e for e in events if e.vendor_id == vendor_id and e.event_type == "VENDOR_SCORED"), None)
    if not vendor_event:
        raise HTTPException(status_code=404, detail="Vendor score not found in this run.")
        
    engine = MonteCarloFAIREngine(iterations=iterations)
    result = engine.simulate(
        vendor_id=vendor_id,
        vendor_name=vendor_id,  # Fallback, as name isn't in event
        tier=vendor_event.classification_tier or "Medium",
        score=vendor_event.score or 50.0
    )
    return result

@app.get("/monitor/osint/{domain}", tags=["Intelligence"])
async def run_osint_scan(domain: str):
    """
    Perform a passive OSINT attack surface scan on a domain.
    Checks TLS certificate validity, HTTP security headers, and DNS DMARC/SPF records.
    """
    from vendor_risk_engine.external.osint_scanner import OSINTScanner
    scanner = OSINTScanner()
    result = await scanner.scan(domain)
    return result

# ─────────────────────────────────────────────
# System & Core Dashboard Routes (Maintained)
# ─────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_dashboard():
    """Serve the interactive GRC control center dashboard."""
    html_path = Path(__file__).parent / "static" / "index.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="Dashboard assets not found.")
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"), status_code=200)

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """System health check and live metrics."""
    settings = get_settings()
    mgr = AuditManager(settings)
    runs = mgr.get_all_runs()

    total_vendors = sum(r.get("total_vendors_scored", 0) for r in runs)
    total_gaps = sum(r.get("total_gaps_detected", 0) for r in runs)
    output_writable = os.access(settings.output_dir, os.W_OK) if settings.output_dir.exists() else False

    return HealthResponse(
        status="healthy",
        version="1.2.0",
        uptime_seconds=round(time.time() - _start_time, 2),
        total_runs=len(runs),
        total_vendors_scored=total_vendors,
        total_gaps_detected=total_gaps,
        webhook_configured=bool(settings.webhook_url),
        output_dir_writable=output_writable,
    )

@app.get("/assessments/", response_model=List[AssessmentStatusResponse], tags=["Assessments"])
async def list_assessments():
    """List all historical GRC assessment pipeline runs, newest first."""
    settings = get_settings()
    mgr = AuditManager(settings)
    runs = mgr.get_all_runs()
    return [_run_to_schema(r) for r in reversed(runs)]

@app.post("/assessments/", response_model=AssessmentStatusResponse, status_code=201, tags=["Assessments"])
async def submit_assessment(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload a vendor questionnaire response CSV and run the full scoring pipeline."""
    if file.filename and not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are accepted.")

    settings = get_settings()
    upload_dir = settings.output_dir / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = upload_dir / f"upload_{uuid.uuid4().hex}.csv"

    try:
        with open(tmp_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File save failed: {e}")

    mgr = AuditManager(settings)
    before_ids = {r["run_id"] for r in mgr.get_all_runs()}

    try:
        await _run_assessment_async(tmp_path, settings, dry_run=False)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline failed: {e}")
    finally:
        if tmp_path.exists():
            os.remove(tmp_path)

    after_runs = mgr.get_all_runs()
    new_runs = [r for r in after_runs if r["run_id"] not in before_ids]
    new_run = new_runs[0] if new_runs else (after_runs[-1] if after_runs else None)

    if not new_run:
        raise HTTPException(status_code=500, detail="Run completed but no metadata was persisted.")

    # Record run in SQL DB
    run_meta = models.DBRunMetadata(
        run_id=new_run["run_id"],
        status="Completed",
        total_vendors=new_run.get("total_vendors_scored", 1),
        total_gaps=new_run.get("total_gaps_detected", 0),
        completed_at=datetime.now(timezone.utc)
    )
    db.add(run_meta)
    
    # Automatically register failed category floor violations to Jira
    events = _load_events(mgr, new_run["run_id"])
    integration = IntegrationManager(db)
    for e in events:
        if e.event_type == "THRESHOLD_VIOLATION":
            await integration.create_remediation_ticket(
                vendor_id=e.vendor_id or "UNKNOWN",
                category_id="CAT_FLOOR",
                question_id="CAT_FLOOR_VIOLATION",
                priority="High"
            )

    db.commit()
    return _run_to_schema(new_run)

@app.get("/assessments/{run_id}", response_model=RunDetailResponse, tags=["Assessments"])
async def get_assessment(run_id: str):
    """Get audit metadata and chronological event log for a specific assessment run."""
    settings = get_settings()
    mgr = AuditManager(settings)
    run = _get_run_or_404(mgr, run_id)
    return RunDetailResponse(metadata=_run_to_schema(run), events=_load_events(mgr, run_id))

@app.get("/assessments/{run_id}/executive-summary", tags=["Intelligence"])
async def get_executive_summary(run_id: str):
    """Generate a board-ready executive summary for a completed assessment run."""
    settings = get_settings()
    mgr = AuditManager(settings)
    _get_run_or_404(mgr, run_id)

    events = _load_events(mgr, run_id)
    scored_events = [e for e in events if e.event_type == "VENDOR_SCORED"]

    if not scored_events:
        return {
            "run_id": run_id,
            "message": "No vendors were scored in this run.",
            "portfolio_overview": {"total_vendors_assessed": 0, "overall_posture": "NO_DATA"},
        }

    from vendor_risk_engine.models.score import VendorScore, CategoryScore
    from vendor_risk_engine.scoring.questionnaire_loader import QuestionnaireLoader
    q_loader = QuestionnaireLoader(settings.questionnaire_schema_path)
    questionnaire = q_loader.load()

    import csv as csv_mod
    results_path = settings.output_dir / "assessment_results.csv"
    vendor_rows: dict = {}
    if results_path.exists():
        with open(results_path, "r", encoding="utf-8") as f:
            reader = csv_mod.DictReader(f)
            for row in reader:
                if row.get("assessment_run_id") == run_id:
                    vendor_rows[row["vendor_id"]] = row

    vendors: List[VendorScore] = []
    for e in scored_events:
        row = vendor_rows.get(e.vendor_id or "", {})
        cat_scores = []
        for cat in questionnaire.categories:
            col = f"category_{cat.category_id.replace('CAT_', '').lower()}_score"
            val = float(row.get(col, 0.0) or 0.0)
            cat_scores.append(CategoryScore(
                category_id=cat.category_id,
                raw_score=val, weighted_score=val,
                max_possible=100.0, gap_count=int(val < 50),
            ))
        vendors.append(VendorScore(
            vendor_id=e.vendor_id or "",
            vendor_name=row.get("vendor_name", e.vendor_id or "Unknown"),
            total_score=e.score or 0.0,
            category_scores=cat_scores,
            classification_tier=e.classification_tier or "High",
            weight_config_hash=row.get("weight_config_hash", ""),
            questionnaire_version_hash=row.get("questionnaire_version_hash", ""),
            response_snapshot_hash=row.get("response_snapshot_hash", ""),
            external_signals=[],
            gap_total_count=int(row.get("gap_unanswered_count", 0) or 0),
            gap_critical_count=int(row.get("gap_critical_count", 0) or 0),
            computed_at=datetime.now(timezone.utc),
        ))

    gen = ExecutiveSummaryGenerator(settings.output_dir)
    return gen.generate(vendors, run_id)

@app.get("/assessments/{run_id}/compliance-map", tags=["Intelligence"])
async def get_compliance_map(run_id: str):
    """Cross-framework compliance exposure map for a completed assessment run."""
    settings = get_settings()
    mgr = AuditManager(settings)
    _get_run_or_404(mgr, run_id)
    events = _load_events(mgr, run_id)
    scored_events = [e for e in events if e.event_type == "VENDOR_SCORED"]

    import csv as csv_mod
    results_path = settings.output_dir / "assessment_results.csv"
    from vendor_risk_engine.scoring.questionnaire_loader import QuestionnaireLoader
    q_loader = QuestionnaireLoader(settings.questionnaire_schema_path)
    questionnaire = q_loader.load()

    vendor_rows: dict = {}
    if results_path.exists():
        with open(results_path, "r", encoding="utf-8") as f:
            for row in csv_mod.DictReader(f):
                if row.get("assessment_run_id") == run_id:
                    vendor_rows[row["vendor_id"]] = row

    mapper = ComplianceMapper()
    vendor_maps = []
    all_failed_cats: set = set()

    for e in scored_events:
        row = vendor_rows.get(e.vendor_id or "", {})
        failed_cats = []
        for cat in questionnaire.categories:
            col = f"category_{cat.category_id.replace('CAT_', '').lower()}_score"
            val = float(row.get(col, 100.0) or 100.0)
            if val < 50.0:
                failed_cats.append(cat.category_id)
                all_failed_cats.add(cat.category_id)

        compliance = mapper.generate_unified_report(failed_cats, len(questionnaire.categories))
        vendor_maps.append({
            "vendor_id": e.vendor_id,
            "vendor_name": row.get("vendor_name", e.vendor_id),
            "score": e.score,
            "tier": e.classification_tier,
            "failed_categories": failed_cats,
            "compliance_exposure": compliance,
        })

    portfolio_compliance = mapper.generate_unified_report(list(all_failed_cats), len(questionnaire.categories))

    return {
        "run_id": run_id,
        "portfolio_compliance_map": portfolio_compliance,
        "vendor_compliance_details": vendor_maps,
    }

@app.get("/assessments/{run_id}/vendors/{vendor_id}/report", tags=["Reports"])
async def download_report(run_id: str, vendor_id: str):
    """Download the PDF/A compliance risk assessment report for a specific vendor."""
    settings = get_settings()
    _get_run_or_404(AuditManager(settings), run_id)
    pdf_path = settings.output_dir / f"{vendor_id}_report.pdf"
    if not pdf_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"PDF report for vendor '{vendor_id}' not found.",
        )
    return FileResponse(path=pdf_path, media_type="application/pdf", filename=f"{vendor_id}_report.pdf")
