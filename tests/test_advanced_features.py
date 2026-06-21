"""
Unit tests for Advanced Enterprise Features:
- Monte Carlo FAIR Risk Simulation
- Passive OSINT Attack Surface Scanner
"""
import pytest
from vendor_risk_engine.scoring.monte_carlo import MonteCarloFAIREngine
from vendor_risk_engine.external.osint_scanner import OSINTScanner

def test_monte_carlo_fair_simulation():
    engine = MonteCarloFAIREngine(iterations=1000, seed=42)
    
    # Simulate for a High Risk vendor
    res_high = engine.simulate("V-1", "DangerCorp", "High", 20.0)
    assert res_high.iterations == 1000
    assert res_high.mean_ale_usd > 500_000
    assert res_high.prob_exceeding_100k > 0.8
    assert len(res_high.histogram_buckets) == 10

    # Simulate for a Low Risk vendor
    res_low = engine.simulate("V-2", "SafeCorp", "Low", 95.0)
    assert res_low.mean_ale_usd < res_high.mean_ale_usd
    assert res_low.prob_exceeding_1m < res_high.prob_exceeding_1m

@pytest.mark.anyio
async def test_osint_scanner_scoring():
    scanner = OSINTScanner()
    
    # Test scoring computation directly
    score_perfect = scanner._compute_score(
        tls=None, # will mock below
        headers=[],
        dns=None,
        findings=[]
    )
    # With everything missing, score drops drastically (100 - 30 for TLS - 10 for DNS = 60.0)
    assert score_perfect == 60.0

    # Test aggregate findings
    findings, recs = scanner._aggregate_findings(tls=None, headers=[], dns=None)
    assert len(findings) == 0

@pytest.fixture
def anyio_backend():
    return "asyncio"
