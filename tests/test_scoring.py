import pytest
from datetime import datetime, date, timezone
from vendor_risk_engine.models.response import ResponseSet, VendorResponse, ValidatedResponse
from vendor_risk_engine.models.questionnaire import QuestionnaireSet, Category, Question
from vendor_risk_engine.models.rules import WeightConfig, ThresholdConfig
from vendor_risk_engine.scoring.scoring_engine import ScoringEngine
from vendor_risk_engine.scoring.classification_engine import ClassificationEngine
from vendor_risk_engine.config import Settings

@pytest.fixture
def anyio_backend():
    return "asyncio"

@pytest.fixture
def sample_questionnaire():
    return QuestionnaireSet(
        schema_version="1.0.0",
        categories=[
            Category(
                category_id="CAT_A",
                category_name="Category A",
                category_weight=0.6,
                questions=[
                    Question(
                        question_id="Q_A_01",
                        question_text="Question A1",
                        response_type="yes",
                        weight=1.0,
                        is_critical=True,
                        is_applicable_default=True,
                        evidence_required=False
                    )
                ]
            ),
            Category(
                category_id="CAT_B",
                category_name="Category B",
                category_weight=0.4,
                questions=[
                    Question(
                        question_id="Q_B_01",
                        question_text="Question B1",
                        response_type="yes",
                        weight=1.0,
                        is_critical=False,
                        is_applicable_default=True,
                        evidence_required=False
                    )
                ]
            )
        ],
        version_hash="test_version_hash"
    )

@pytest.fixture
def sample_weights():
    return WeightConfig(
        version="1.0.0",
        category_weights={"CAT_A": 0.6, "CAT_B": 0.4},
        question_weights={"CAT_A": {"Q_A_01": 1.0}, "CAT_B": {"Q_B_01": 1.0}},
        category_floor=30.0,
        config_hash="test_config_hash"
    )

@pytest.fixture
def sample_thresholds():
    return ThresholdConfig(
        version="1.0.0",
        boundary_handling="inclusive_exclusive",
        thresholds={
            "Low": {"min_score_inclusive": 70.0, "max_score_inclusive": 100.0, "description": "Low Risk"},
            "Medium": {"min_score_inclusive": 40.0, "max_score_inclusive": 69.9999, "description": "Medium Risk"},
            "High": {"min_score_inclusive": 0.0, "max_score_inclusive": 39.9999, "description": "High Risk"}
        }
    )

@pytest.fixture
def settings():
    return Settings(
        questionnaire_schema_path="dummy",
        weight_config_path="dummy",
        threshold_config_path="dummy",
        scoring_decimal_places=2,
        category_floor_enabled=True
    )

def test_scoring_engine_perfect_responses(sample_questionnaire, sample_weights, settings):
    # Perfect yes responses
    responses = [
        VendorResponse(question_id="Q_A_01", response_value="yes", evidence_text=None, responded_at=datetime.now(timezone.utc)),
        VendorResponse(question_id="Q_B_01", response_value="yes", evidence_text=None, responded_at=datetime.now(timezone.utc))
    ]
    response_set = ValidatedResponse(
        vendor_id="V-001",
        vendor_name="Acme",
        assessment_date=date.today(),
        responded_by="Analyst",
        responses=responses,
        completeness_score=100.0,
        gap_list=[],
        response_hash="hash"
    )
    
    engine = ScoringEngine(sample_questionnaire, sample_weights, settings)
    score = engine.score_vendor(response_set)
    
    # 0.6 * 100 + 0.4 * 100 = 100.0
    assert score.total_score == 100.0
    assert score.gap_total_count == 0
    assert score.gap_critical_count == 0

def test_scoring_engine_with_no_responses(sample_questionnaire, sample_weights, settings):
    from vendor_risk_engine.exceptions import CategoryFloorException
    # No responses for CAT_A (0/100) and yes for CAT_B (100/100)
    # CAT_A weighted score: 0.0, CAT_B weighted score: 40.0
    # CAT_A score (0.0) is below floor (30.0).
    responses = [
        VendorResponse(question_id="Q_A_01", response_value="no", evidence_text=None, responded_at=datetime.now(timezone.utc)),
        VendorResponse(question_id="Q_B_01", response_value="yes", evidence_text=None, responded_at=datetime.now(timezone.utc))
    ]
    response_set = ValidatedResponse(
        vendor_id="V-002",
        vendor_name="GlobalTech",
        assessment_date=date.today(),
        responded_by="Analyst",
        responses=responses,
        completeness_score=100.0,
        gap_list=[],
        response_hash="hash"
    )
    
    engine = ScoringEngine(sample_questionnaire, sample_weights, settings)
    with pytest.raises(CategoryFloorException):
        engine.score_vendor(response_set)

def test_classification_engine(sample_thresholds):
    classifier = ClassificationEngine(sample_thresholds)
    
    # We construct mock vendor scores with different totals
    from vendor_risk_engine.models.score import VendorScore
    
    def get_mock_score(total):
        return VendorScore(
            vendor_id="V-TEST",
            vendor_name="Test",
            total_score=total,
            category_scores=[],
            classification_tier="Pending",
            weight_config_hash="hash",
            questionnaire_version_hash="hash",
            response_snapshot_hash="hash",
            external_signals=[],
            gap_total_count=0,
            gap_critical_count=0,
            computed_at=datetime.now(timezone.utc)
        )
        
    c1 = classifier.classify(get_mock_score(85.0))
    assert c1.classification_tier == "Low"
    
    c2 = classifier.classify(get_mock_score(55.0))
    assert c2.classification_tier == "Medium"
    
    c3 = classifier.classify(get_mock_score(25.0))
    assert c3.classification_tier == "High"

def test_audit_manager(tmp_path):
    from vendor_risk_engine.state.audit_manager import AuditManager
    from vendor_risk_engine.config import Settings
    
    # Create temp settings pointing to temp output dir
    settings = Settings(
        questionnaire_schema_path="dummy",
        weight_config_path="dummy",
        threshold_config_path="dummy",
        output_dir=tmp_path
    )
    
    mgr = AuditManager(settings)
    run_id = "TEST-RUN-123"
    
    mgr.start_run(run_id, "weight_hash", "questionnaire_hash")
    runs = mgr.get_all_runs()
    assert len(runs) == 1
    assert runs[0]["run_id"] == run_id
    assert runs[0]["end_time"] is None
    
    mgr.complete_run(run_id, 5, 5, 12, True)
    run_detail = mgr.get_run_metadata(run_id)
    assert run_detail["total_vendors_scored"] == 5
    assert run_detail["end_time"] is not None

@pytest.mark.anyio
async def test_securityscorecard_client():
    from vendor_risk_engine.external.securityscorecard_client import SecurityScorecardClient
    from vendor_risk_engine.config import Settings
    
    settings = Settings(
        questionnaire_schema_path="dummy",
        weight_config_path="dummy",
        threshold_config_path="dummy",
        securityscorecard_api_key="dummy_key"
    )
    
    client = SecurityScorecardClient(settings)
    signal = await client.fetch_score("example.com")
    assert signal.source == "SecurityScorecard"
    assert signal.normalized_score == 92.0
    assert signal.is_fresh is True

