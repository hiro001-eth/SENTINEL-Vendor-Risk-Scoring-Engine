"""
Monte Carlo FAIR Risk Simulation Engine.
Runs actuarial-grade probabilistic simulations using PERT/Beta distributions
for Threat Event Frequency (TEF) and Lognormal distributions for Loss Magnitude (LM).
Produces Loss Exceedance Curves and confidence intervals for board-level financial reporting.
"""
import math
import random
import structlog
from typing import Dict, List, Optional
from pydantic import BaseModel

logger = structlog.get_logger(__name__)


class MonteCarloResult(BaseModel):
    """Output of a single vendor Monte Carlo FAIR simulation."""
    vendor_id: str
    vendor_name: str
    iterations: int
    # Core FAIR outputs
    mean_ale_usd: float
    median_ale_usd: float
    p5_ale_usd: float       # 5th percentile (best-case)
    p95_ale_usd: float      # 95th percentile (worst-case)
    max_ale_usd: float
    std_dev_ale_usd: float
    # Loss Exceedance thresholds
    prob_exceeding_100k: float
    prob_exceeding_500k: float
    prob_exceeding_1m: float
    # Input parameters used
    tef_min: float
    tef_mode: float
    tef_max: float
    lm_mean: float
    lm_std: float
    # Distribution of ALE values for charting
    histogram_buckets: List[Dict]


class MonteCarloFAIREngine:
    """
    Actuarial-grade FAIR risk quantification via Monte Carlo simulation.

    Unlike static ALE = ARO × SLE calculations, this engine models risk as
    a probability distribution, giving CISOs and boards the ability to reason
    about tail-risk scenarios (e.g., "What is the 5% worst-case exposure?").
    """

    def __init__(self, iterations: int = 10000, seed: Optional[int] = None):
        self.iterations = iterations
        if seed is not None:
            random.seed(seed)

    def _pert_sample(self, low: float, mode: float, high: float) -> float:
        """
        Sample from a PERT (Beta) distribution.
        PERT distributions are the standard actuarial model for expert-estimated
        frequency data where min, most-likely, and max values are known.
        """
        if high <= low:
            return mode
        # PERT shape parameter (lambda = 4 is standard)
        lam = 4.0
        mean = (low + lam * mode + high) / (lam + 2)

        # Derive alpha and beta for the Beta distribution
        if mean == mode:
            alpha = 1.0 + lam / 2.0
        else:
            alpha = ((mean - low) * (2 * mode - low - high)) / ((mode - mean) * (high - low))

        beta_param = alpha * (high - mean) / (mean - low) if (mean - low) != 0 else alpha

        # Clamp to avoid degenerate distributions
        alpha = max(alpha, 0.5)
        beta_param = max(beta_param, 0.5)

        # Sample from Beta(alpha, beta) and scale to [low, high]
        sample = random.betavariate(alpha, beta_param)
        return low + sample * (high - low)

    def _lognormal_sample(self, mean_val: float, std_val: float) -> float:
        """
        Sample from a Lognormal distribution.
        Lognormal is the standard actuarial model for financial loss magnitude
        because losses are bounded at zero and right-skewed.
        """
        if std_val <= 0 or mean_val <= 0:
            return mean_val
        # Convert arithmetic mean/std to log-space parameters
        variance = std_val ** 2
        mu = math.log(mean_val ** 2 / math.sqrt(variance + mean_val ** 2))
        sigma = math.sqrt(math.log(1 + variance / mean_val ** 2))
        return random.lognormvariate(mu, sigma)

    def _derive_parameters(self, tier: str, score: float) -> Dict:
        """
        Derive FAIR simulation parameters from the vendor's risk tier and score.
        These calibrations are based on Verizon DBIR and Ponemon Institute baselines.
        """
        if tier == "High":
            tef_min, tef_mode, tef_max = 0.8, 1.5, 4.0
            lm_mean = 420000.0
            lm_std = 180000.0
        elif tier == "Medium":
            tef_min, tef_mode, tef_max = 0.1, 0.5, 1.5
            lm_mean = 250000.0
            lm_std = 100000.0
        else:  # Low
            tef_min, tef_mode, tef_max = 0.01, 0.1, 0.4
            lm_mean = 120000.0
            lm_std = 50000.0

        # Adjust loss magnitude by security posture: weaker posture → higher losses
        posture_multiplier = 1.0 + (100.0 - score) / 200.0
        lm_mean *= posture_multiplier
        lm_std *= posture_multiplier

        return {
            "tef_min": tef_min, "tef_mode": tef_mode, "tef_max": tef_max,
            "lm_mean": round(lm_mean, 2), "lm_std": round(lm_std, 2)
        }

    def simulate(self, vendor_id: str, vendor_name: str, tier: str, score: float) -> MonteCarloResult:
        """
        Run a full Monte Carlo FAIR simulation for a single vendor.
        Returns statistical summary and histogram data for visualization.
        """
        params = self._derive_parameters(tier, score)
        ale_samples = []

        for _ in range(self.iterations):
            # 1. Sample Threat Event Frequency (TEF) from PERT distribution
            tef = self._pert_sample(params["tef_min"], params["tef_mode"], params["tef_max"])

            # 2. Sample Loss Magnitude (LM) from Lognormal distribution
            lm = self._lognormal_sample(params["lm_mean"], params["lm_std"])

            # 3. ALE = TEF × LM
            ale = tef * lm
            ale_samples.append(ale)

        # Sort for percentile calculations
        ale_samples.sort()
        n = len(ale_samples)

        # Percentile helper
        def percentile(p: float) -> float:
            idx = int(p / 100.0 * n)
            idx = min(idx, n - 1)
            return ale_samples[idx]

        mean_ale = sum(ale_samples) / n
        median_ale = percentile(50)
        p5_ale = percentile(5)
        p95_ale = percentile(95)
        max_ale = ale_samples[-1]

        variance = sum((x - mean_ale) ** 2 for x in ale_samples) / n
        std_dev = math.sqrt(variance)

        # Loss exceedance probabilities
        prob_100k = sum(1 for x in ale_samples if x > 100000) / n
        prob_500k = sum(1 for x in ale_samples if x > 500000) / n
        prob_1m = sum(1 for x in ale_samples if x > 1000000) / n

        # Build histogram buckets for charting (10 buckets)
        bucket_count = 10
        bucket_width = (max_ale - ale_samples[0]) / bucket_count if max_ale > ale_samples[0] else 1.0
        histogram = []
        for i in range(bucket_count):
            low_bound = ale_samples[0] + i * bucket_width
            high_bound = low_bound + bucket_width
            count = sum(1 for x in ale_samples if low_bound <= x < high_bound)
            histogram.append({
                "range_low_usd": round(low_bound, 2),
                "range_high_usd": round(high_bound, 2),
                "frequency": count,
                "pct_of_total": round(count / n * 100, 2)
            })

        logger.info(
            "monte_carlo_simulation_complete",
            vendor_id=vendor_id,
            iterations=self.iterations,
            mean_ale=round(mean_ale, 2),
            p95_ale=round(p95_ale, 2)
        )

        return MonteCarloResult(
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            iterations=self.iterations,
            mean_ale_usd=round(mean_ale, 2),
            median_ale_usd=round(median_ale, 2),
            p5_ale_usd=round(p5_ale, 2),
            p95_ale_usd=round(p95_ale, 2),
            max_ale_usd=round(max_ale, 2),
            std_dev_ale_usd=round(std_dev, 2),
            prob_exceeding_100k=round(prob_100k, 4),
            prob_exceeding_500k=round(prob_500k, 4),
            prob_exceeding_1m=round(prob_1m, 4),
            tef_min=params["tef_min"],
            tef_mode=params["tef_mode"],
            tef_max=params["tef_max"],
            lm_mean=params["lm_mean"],
            lm_std=params["lm_std"],
            histogram_buckets=histogram
        )
