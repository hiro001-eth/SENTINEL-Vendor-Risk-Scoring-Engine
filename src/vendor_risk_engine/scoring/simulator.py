"""
What-If Remediation Simulator.
Simulates the impact of remediating specific control gaps on the overall risk posture,
FAIR Annual Loss Expectancy (ALE), and multi-framework compliance mapping.
"""
from typing import List, Dict, Any
from vendor_risk_engine.config import get_settings
from vendor_risk_engine.models.response import ValidatedResponse, SingleQuestionResponse
from vendor_risk_engine.scoring.scoring_engine import ScoringEngine
from vendor_risk_engine.scoring.classification_engine import ClassificationEngine
from vendor_risk_engine.scoring.advanced_analysis import AdvancedGRCAnalyzer
from vendor_risk_engine.scoring.compliance_mapper import ComplianceMapper
from vendor_risk_engine.scoring.questionnaire_loader import QuestionnaireLoader
from vendor_risk_engine.scoring.rules_loader import WeightLoader, ThresholdLoader

class GRCWhatIfSimulator:
    def __init__(self):
        self.settings = get_settings()
        self.q_loader = QuestionnaireLoader(self.settings.questionnaire_schema_path)
        self.w_loader = WeightLoader(self.settings.weight_config_path)
        self.t_loader = ThresholdLoader(self.settings.threshold_config_path)

        self.questionnaire = self.q_loader.load()
        self.weights = self.w_loader.load()
        self.thresholds = self.t_loader.load()

        self.scoring_engine = ScoringEngine(self.questionnaire, self.weights, self.settings)
        self.classification_engine = ClassificationEngine(self.thresholds)
        self.analyzer = AdvancedGRCAnalyzer(self.settings.output_dir)
        self.compliance_mapper = ComplianceMapper()

    def simulate(
        self, 
        original_response: ValidatedResponse, 
        remediated_question_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Simulate the GRC, FAIR, and compliance posture after resolving a set of gaps.
        """
        # 1. Run baseline scoring
        baseline_score = self.scoring_engine.score_vendor(original_response)
        baseline_tier = self.classification_engine.classify(baseline_score)
        
        # Calculate baseline compliance exposure
        baseline_failed_cats = [
            cat.category_id for cat in baseline_tier.category_scores if cat.raw_score < 50.0
        ]
        baseline_compliance = self.compliance_mapper.generate_unified_report(
            baseline_failed_cats, len(self.questionnaire.categories)
        )
        
        # Calculate baseline FAIR ALE
        baseline_fair = self.analyzer.compute_fair_risk(baseline_tier)

        # 2. Construct simulated response by forcing target question answers to 'yes'
        simulated_responses = []
        for q_resp in original_response.responses:
            if q_resp.question_id in remediated_question_ids:
                simulated_responses.append(SingleQuestionResponse(
                    question_id=q_resp.question_id,
                    response_value="yes"
                ))
            else:
                simulated_responses.append(q_resp)
        
        # Handle case where a question was not present in the original responses
        for target_id in remediated_question_ids:
            if not any(r.question_id == target_id for r in simulated_responses):
                simulated_responses.append(SingleQuestionResponse(
                    question_id=target_id,
                    response_value="yes"
                ))

        simulated_validated = original_response.model_copy(update={"responses": simulated_responses})

        # 3. Run simulated scoring
        sim_score = self.scoring_engine.score_vendor(simulated_validated)
        sim_tier = self.classification_engine.classify(sim_score)
        
        # Calculate simulated compliance exposure
        sim_failed_cats = [
            cat.category_id for cat in sim_tier.category_scores if cat.raw_score < 50.0
        ]
        sim_compliance = self.compliance_mapper.generate_unified_report(
            sim_failed_cats, len(self.questionnaire.categories)
        )
        
        # Calculate simulated FAIR ALE
        sim_fair = self.analyzer.compute_fair_risk(sim_tier)

        # 4. Compute ROI Metrics
        financial_risk_reduced_usd = max(0.0, baseline_fair.annual_loss_expectancy_usd - sim_fair.annual_loss_expectancy_usd)
        
        baseline_comp_pct = baseline_compliance["unified_compliance_score_pct"]
        sim_comp_pct = sim_compliance["unified_compliance_score_pct"]
        compliance_coverage_gain_pct = max(0.0, sim_comp_pct - baseline_comp_pct)

        score_improvement = max(0.0, sim_tier.total_score - baseline_tier.total_score)

        return {
            "vendor_id": original_response.vendor_id,
            "vendor_name": original_response.vendor_name,
            "remediated_controls": remediated_question_ids,
            "comparison": {
                "score": {
                    "baseline": baseline_tier.total_score,
                    "simulated": sim_tier.total_score,
                    "improvement": round(score_improvement, 2)
                },
                "classification_tier": {
                    "baseline": baseline_tier.classification_tier,
                    "simulated": sim_tier.classification_tier
                },
                "annual_loss_expectancy_usd": {
                    "baseline": baseline_fair.annual_loss_expectancy_usd,
                    "simulated": sim_fair.annual_loss_expectancy_usd,
                    "risk_reduced": round(financial_risk_reduced_usd, 2)
                },
                "compliance_score_pct": {
                    "baseline": baseline_comp_pct,
                    "simulated": sim_comp_pct,
                    "coverage_gain": round(compliance_coverage_gain_pct, 2)
                }
            },
            "roi_recommendation": self._generate_recommendation(
                financial_risk_reduced_usd, 
                compliance_coverage_gain_pct, 
                score_improvement
            )
        }

    def _generate_recommendation(self, risk_reduced: float, comp_gain: float, score_gain: float) -> str:
        if risk_reduced > 50000:
            return (
                f"HIGH ROI: Remediation reduces estimated annual exposure by ${risk_reduced:,.2f} "
                f"and increases compliance coverage by {comp_gain}%. This should be prioritised immediately."
            )
        elif comp_gain > 10.0:
            return (
                f"COMPLIANCE ROI: Resolving these gaps improves compliance mapping by {comp_gain}% "
                f"and score by {score_gain:,.2f} points. Recommended to satisfy audit obligations."
            )
        return "LOW ROI: The simulated remediation yields minor improvements in financial and GRC posture."
