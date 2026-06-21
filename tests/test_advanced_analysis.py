import pytest
from pathlib import Path
from vendor_risk_engine.scoring.advanced_analysis import AdvancedGRCAnalyzer
from vendor_risk_engine.models.score import VendorScore
from vendor_risk_engine.models.response import ValidatedResponse
from datetime import datetime, timezone

def test_mitre_mapping():
    analyzer = AdvancedGRCAnalyzer(Path("dummy"))
    failed_cats = ["CAT_DATA_HANDLING", "CAT_ACCESS_CONTROLS"]
    mapped = analyzer.map_mitre_gaps(failed_cats)
    
    assert len(mapped) > 0
    ids = {item["technique_id"] for item in mapped}
    assert "T1041" in ids  # Data Handling
    assert "T1078" in ids  # Access Controls

def test_fair_risk():
    analyzer = AdvancedGRCAnalyzer(Path("dummy"))
    
    high_risk = analyzer.calculate_fair_risk("High", 35.0)
    assert high_risk["annualized_rate_of_occurrence"] == 1.5
    assert high_risk["annual_loss_expectancy_usd"] > 0.0
    
    low_risk = analyzer.calculate_fair_risk("Low", 95.0)
    assert low_risk["annualized_rate_of_occurrence"] == 0.1
    assert low_risk["annual_loss_expectancy_usd"] < high_risk["annual_loss_expectancy_usd"]

def test_remediation_tickets():
    analyzer = AdvancedGRCAnalyzer(Path("dummy"))
    
    score = VendorScore(
        vendor_id="V-123",
        vendor_name="Test Vendor",
        total_score=50.0,
        category_scores=[],
        classification_tier="Medium",
        weight_config_hash="hash",
        questionnaire_version_hash="hash",
        response_snapshot_hash="hash",
        external_signals=[],
        gap_total_count=1,
        gap_critical_count=0,
        computed_at=datetime.now(timezone.utc)
    )
    
    response = ValidatedResponse(
        vendor_id="V-123",
        vendor_name="Test Vendor",
        assessment_date=datetime.now(timezone.utc).date(),
        responded_by="User",
        responses=[],
        completeness_score=80.0,
        gap_list=["Q_AC_01: MFA recommendation"],
        response_hash="hash"
    )
    
    tickets = analyzer.generate_remediation_tickets(score, response)
    assert len(tickets) == 1
    assert tickets[0]["vendor_id"] == "V-123"
    assert tickets[0]["sla_days"] == 60  # Medium Risk SLA
    assert "MFA recommendation" in tickets[0]["action_required"]

def test_trends(tmp_path):
    analyzer = AdvancedGRCAnalyzer(tmp_path)
    
    # First check: no history file
    first_run = analyzer.analyze_trends("V-ABC", 80.0, 1)
    assert first_run["previous_score"] is None
    assert "No History" in first_run["velocity_status"]
    
    # Create fake CSV with history
    csv_file = tmp_path / "assessment_results.csv"
    with open(csv_file, "w", encoding="utf-8") as f:
        f.write("vendor_id,total_score,gap_unanswered_count\n")
        f.write("V-ABC,75.0,2\n")
        
    next_run = analyzer.analyze_trends("V-ABC", 85.0, 1)
    assert next_run["previous_score"] == 75.0
    assert next_run["score_delta"] == 10.0
    assert next_run["gap_delta"] == -1
    assert next_run["velocity_status"] == "IMPROVING"
