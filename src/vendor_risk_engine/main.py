"""
Typer CLI entrypoint.
"""
import typer
import asyncio
import sys
import uuid
import json
import yaml
from pathlib import Path
from datetime import datetime, timezone
import structlog
from vendor_risk_engine.config import get_settings
from vendor_risk_engine.exceptions import PipelineBaseException, CategoryFloorException
from vendor_risk_engine import configure_logging

from vendor_risk_engine.scoring.questionnaire_loader import QuestionnaireLoader
from vendor_risk_engine.scoring.weight_loader import WeightLoader
from vendor_risk_engine.scoring.scoring_engine import ScoringEngine
from vendor_risk_engine.scoring.classification_engine import ClassificationEngine
from vendor_risk_engine.ingestion.ingestion_stage import IngestionStage
from vendor_risk_engine.validation.validation_stage import ValidationStage
from vendor_risk_engine.export.export_stage import ExportStage
from vendor_risk_engine.external.bitsight_client import BitSightClient
from vendor_risk_engine.external.breach_client import BreachClient
from vendor_risk_engine.external.securityscorecard_client import SecurityScorecardClient
from vendor_risk_engine.external.signal_blender import SignalBlender
from vendor_risk_engine.reporting.pdf_generator import PDFGenerator
from vendor_risk_engine.state.audit_manager import AuditManager
from vendor_risk_engine.constants import LogEventType
from vendor_risk_engine.notifications.webhook import WebhookNotifier, WebhookProvider
from vendor_risk_engine.scoring.advanced_analysis import AdvancedGRCAnalyzer
from vendor_risk_engine.scoring.compliance_mapper import ComplianceMapper

app = typer.Typer(help="SENTINEL Vendor Risk Scoring Engine")
logger = structlog.get_logger(__name__)

@app.command()
def score(input_path: str, dry_run: bool = False):
    """Run full assessment pipeline."""
    configure_logging()
    settings = get_settings()
    try:
        typer.echo(f"Scoring pipeline started for {input_path}")
        asyncio.run(_run_assessment_async(Path(input_path), settings, dry_run))
        typer.secho("Pipeline completed successfully.", fg=typer.colors.GREEN)
        sys.exit(0)
    except PipelineBaseException as e:
        typer.secho(f"Pipeline failed: {str(e)}", fg=typer.colors.RED)
        sys.exit(1)
    except Exception as e:
        typer.secho(f"Unexpected error: {str(e)}", fg=typer.colors.RED)
        sys.exit(2)

async def _run_assessment_async(input_path: Path, settings, dry_run: bool):
    run_id = f"SENTINEL-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"
    logger.info("pipeline_start", input_path=str(input_path), run_id=run_id)
    
    q_loader = QuestionnaireLoader(settings.questionnaire_schema_path)
    questionnaire = q_loader.load()
    
    w_loader = WeightLoader(settings.weight_config_path, settings.threshold_config_path)
    weights = w_loader.load_weights()
    thresholds = w_loader.load_thresholds()
    
    ingestor = IngestionStage(settings)
    validator = ValidationStage(questionnaire)
    scorer = ScoringEngine(questionnaire, weights, settings)
    classifier = ClassificationEngine(thresholds)
    
    bitsight = BitSightClient(settings)
    ssc = SecurityScorecardClient(settings)
    hibp = BreachClient(settings)
    blender = SignalBlender(settings)
    
    exporter = ExportStage(settings.output_dir)
    reporter = PDFGenerator(settings)
    
    audit_mgr = AuditManager(settings)
    audit_mgr.start_run(run_id, weights.config_hash, questionnaire.version_hash)

    # Optional webhook notifier
    notifier = None
    if settings.webhook_url:
        notifier = WebhookNotifier(
            provider=WebhookProvider(settings.webhook_provider),
            webhook_url=settings.webhook_url
        )

    analyzer = AdvancedGRCAnalyzer(settings.output_dir)
    compliance_mapper = ComplianceMapper()
    
    total_vendors = 0
    total_reports = 0
    total_gaps = 0
    external_sync_successful = True
    
    for chunk_idx, chunk in enumerate(ingestor.stream_responses(input_path)):
        validated = validator.validate_batch(chunk)
        
        scored_batch = []
        for valid_response in validated:
            try:
                score_model = scorer.score_vendor(valid_response)
                classified_model = classifier.classify(score_model)
                
                if not dry_run:
                    bs_task = bitsight.fetch_rating(classified_model.vendor_name)
                    ssc_task = ssc.fetch_score(classified_model.vendor_name)
                    hibp_task = hibp.check_breaches(classified_model.vendor_name)
                    
                    try:
                        signals = await asyncio.gather(bs_task, ssc_task, hibp_task, return_exceptions=True)
                        valid_signals = []
                        for s in signals:
                            if isinstance(s, Exception):
                                logger.error("external_api_failure", error=str(s))
                                external_sync_successful = False
                            else:
                                valid_signals.append(s)
                    except Exception as e:
                        logger.error("external_api_failure", error=str(e))
                        valid_signals = []
                        external_sync_successful = False
                        
                    blended_model = blender.blend(classified_model, valid_signals)
                else:
                    blended_model = classified_model
                    
                scored_batch.append(blended_model)
                total_vendors += 1
                total_gaps += blended_model.gap_total_count
                
                reporter.generate(blended_model, [], [], run_id)
                total_reports += 1
                
                # Emit logs
                audit_mgr.emit_log(
                    run_id=run_id,
                    stage_name="Scoring",
                    event_type=LogEventType.VENDOR_SCORED,
                    severity="INFO",
                    message=f"Vendor {blended_model.vendor_name} scored. Total: {blended_model.total_score}. Tier: {blended_model.classification_tier}",
                    vendor_id=blended_model.vendor_id,
                    score=blended_model.total_score,
                    classification_tier=blended_model.classification_tier
                )
                
                if blended_model.gap_critical_count > 0:
                    audit_mgr.emit_log(
                        run_id=run_id,
                        stage_name="GapAnalysis",
                        event_type=LogEventType.GAP_DETECTED,
                        severity="WARN",
                        message=f"Vendor {blended_model.vendor_name} has {blended_model.gap_critical_count} critical gaps.",
                        vendor_id=blended_model.vendor_id
                    )

                # Fire high-risk webhook alert
                if notifier and blended_model.classification_tier == "High":
                    fair = analyzer.calculate_fair_risk(blended_model.classification_tier, blended_model.total_score)
                    await notifier.send_high_risk_alert(
                        vendor_name=blended_model.vendor_name,
                        vendor_id=blended_model.vendor_id,
                        score=blended_model.total_score,
                        tier=blended_model.classification_tier,
                        run_id=run_id,
                        gap_count=blended_model.gap_total_count,
                        ale_usd=fair["annual_loss_expectancy_usd"]
                    )

            except CategoryFloorException as e:
                typer.secho(f"POLICY VIOLATION: Vendor {valid_response.vendor_name} failed category floor check. {str(e)}", fg=typer.colors.YELLOW)
                audit_mgr.emit_log(
                    run_id=run_id,
                    stage_name="Scoring",
                    event_type=LogEventType.THRESHOLD_VIOLATION,
                    severity="ERROR",
                    message=f"Category floor check failed: {str(e)}",
                    vendor_id=valid_response.vendor_id
                )
            
        exporter.write_batch("assessment_results.csv", scored_batch, run_id, append=(chunk_idx > 0))

    audit_mgr.complete_run(run_id, total_vendors, total_reports, total_gaps, external_sync_successful)

    # Fire pipeline-complete webhook
    if notifier:
        high_risk_count = sum(1 for r in audit_mgr.get_all_runs() if r.get("run_id") == run_id)
        await notifier.send_pipeline_complete(
            run_id=run_id,
            total_vendors=total_vendors,
            total_gaps=total_gaps,
            high_risk_count=high_risk_count
        )

@app.command()
def report(results_csv: str = "./output/assessment_results.csv"):
    """Generate PDF from existing scores."""
    configure_logging()
    settings = get_settings()
    import csv
    from vendor_risk_engine.models.score import VendorScore, CategoryScore
    
    typer.echo(f"Re-generating reports from {results_csv}...")
    
    q_loader = QuestionnaireLoader(settings.questionnaire_schema_path)
    questionnaire = q_loader.load()
    
    reporter = PDFGenerator(settings)
    
    if not Path(results_csv).exists():
        typer.secho(f"Results file {results_csv} does not exist.", fg=typer.colors.RED)
        sys.exit(1)
        
    try:
        with open(results_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                cat_scores = []
                for cat in questionnaire.categories:
                    col_name = f"category_{cat.category_id.replace('CAT_', '').lower()}_score"
                    val = float(row[col_name]) if col_name in row and row[col_name] else 0.0
                    cat_scores.append(CategoryScore(
                        category_id=cat.category_id,
                        raw_score=val,
                        weighted_score=val,
                        max_possible=100.0,
                        gap_count=0
                    ))
                
                score_model = VendorScore(
                    vendor_id=row["vendor_id"],
                    vendor_name=row["vendor_name"],
                    total_score=float(row["total_score"]),
                    category_scores=cat_scores,
                    classification_tier=row["classification_tier"],
                    weight_config_hash=row.get("weight_config_hash", ""),
                    questionnaire_version_hash=row.get("questionnaire_version_hash", ""),
                    response_snapshot_hash=row.get("response_snapshot_hash", ""),
                    external_signals=[],
                    gap_total_count=int(row.get("gap_unanswered_count", 0)),
                    gap_critical_count=int(row.get("gap_critical_count", 0)),
                    computed_at=datetime.fromisoformat(row["computed_at"])
                )
                
                reporter.generate(score_model, [], [], row.get("assessment_run_id", "SENTINEL-REPORT-REGEN"))
                count += 1
            
            typer.secho(f"Successfully re-generated {count} PDF reports.", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"Failed to generate reports: {str(e)}", fg=typer.colors.RED)
        sys.exit(1)

@app.command()
def validate(quick_check: bool = False):
    """Validate configs and schemas."""
    configure_logging()
    settings = get_settings()
    typer.echo("Validating configuration...")
    
    try:
        typer.echo("Loading questionnaire schema...")
        q_loader = QuestionnaireLoader(settings.questionnaire_schema_path)
        questionnaire = q_loader.load()
        typer.secho(f"  Passed. Hash: {questionnaire.version_hash}", fg=typer.colors.GREEN)
        
        typer.echo("Loading weights and thresholds...")
        w_loader = WeightLoader(settings.weight_config_path, settings.threshold_config_path)
        weights = w_loader.load_weights()
        thresholds = w_loader.load_thresholds()
        typer.secho(f"  Passed. Weight Hash: {weights.config_hash}", fg=typer.colors.GREEN)
        
        typer.echo("Verifying category configuration alignment...")
        q_cats = {c.category_id for c in questionnaire.categories}
        w_cats = set(weights.category_weights.keys())
        if q_cats != w_cats:
            missing_in_weights = q_cats - w_cats
            missing_in_schema = w_cats - q_cats
            if missing_in_weights:
                typer.secho(f"  Warning: Categories in schema missing from weights: {missing_in_weights}", fg=typer.colors.YELLOW)
            if missing_in_schema:
                typer.secho(f"  Warning: Categories in weights missing from schema: {missing_in_schema}", fg=typer.colors.YELLOW)
        else:
            typer.secho("  Passed. All category definitions aligned.", fg=typer.colors.GREEN)
            
        typer.echo("Verifying risk classification threshold bounds...")
        ranges = sorted(thresholds.thresholds.values(), key=lambda x: x["min_score_inclusive"])
        overlap = False
        for i in range(len(ranges) - 1):
            if ranges[i]["max_score_inclusive"] >= ranges[i+1]["min_score_inclusive"]:
                overlap = True
                
        if overlap:
            typer.secho("  Warning: Overlapping threshold ranges detected.", fg=typer.colors.YELLOW)
        else:
            typer.secho("  Passed. Classification bounds are contiguous.", fg=typer.colors.GREEN)
            
        if not quick_check:
            typer.echo("Checking API credential configurations...")
            if not settings.bitsight_api_key.get_secret_value():
                typer.echo("  BitSight API Key: Missing (running in fallback mode)")
            else:
                typer.secho("  BitSight API Key: Configured", fg=typer.colors.GREEN)
                
            if not settings.securityscorecard_api_key.get_secret_value():
                typer.echo("  SecurityScorecard API Key: Missing (running in fallback mode)")
            else:
                typer.secho("  SecurityScorecard API Key: Configured", fg=typer.colors.GREEN)
                
            if not settings.hibp_api_key.get_secret_value():
                typer.echo("  HaveIBeenPwned API Key: Missing (running in fallback mode)")
            else:
                typer.secho("  HaveIBeenPwned API Key: Configured", fg=typer.colors.GREEN)
        
        typer.secho("Validation complete. Engine is ready.", fg=typer.colors.GREEN)
        
    except Exception as e:
        typer.secho(f"Validation failed: {str(e)}", fg=typer.colors.RED)
        sys.exit(1)

@app.command()
def audit(run_id: str = typer.Argument("", help="The run ID to query")):
    """View last run metadata."""
    configure_logging()
    settings = get_settings()
    mgr = AuditManager(settings)
    
    if run_id:
        typer.echo(f"Fetching audit log for run {run_id}...")
        run = mgr.get_run_metadata(run_id)
        if not run:
            typer.secho(f"Run {run_id} not found.", fg=typer.colors.RED)
            sys.exit(1)
            
        typer.echo(json.dumps(run, indent=2))
        
        log_path = mgr.log_path
        if log_path.exists():
            typer.echo("\n--- Related Audit Log Events ---")
            with open(log_path, "r", encoding="utf-8") as f:
                for line in f:
                    entry = json.loads(line)
                    if entry.get("assessment_run_id") == run_id:
                        time_str = entry.get("timestamp_utc", "")
                        event = entry.get("event_type", "")
                        msg = entry.get("message", "")
                        typer.echo(f"[{time_str}] {event:<25} - {msg}")
    else:
        typer.echo("Listing all historical assessment runs:")
        runs = mgr.get_all_runs()
        if not runs:
            typer.echo("No historical runs found.")
            return
            
        typer.echo(f"{'Run ID':<35} {'Start Time':<25} {'End Time':<25} {'Scored':<8} {'Gaps':<6} {'Sync':<6}")
        typer.echo("-" * 110)
        for r in runs:
            typer.echo(f"{r['run_id']:<35} {r['start_time']:<25} {str(r['end_time']):<25} {r['total_vendors_scored']:<8} {r['total_gaps_detected']:<6} {r['external_sync_successful']:<6}")

@app.command()
def api(host: str = "127.0.0.1", port: int = 8000):
    """Start the FastAPI REST API server."""
    configure_logging()
    import uvicorn
    typer.echo(f"Starting SENTINEL GRC API server on http://{host}:{port}...")
    uvicorn.run("vendor_risk_engine.api.app:app", host=host, port=port, reload=False)

if __name__ == "__main__":
    app()
