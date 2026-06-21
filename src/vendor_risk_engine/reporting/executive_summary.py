"""
Executive board-ready summary generator.

Produces a structured, C-suite-ready risk overview that translates
technical vendor risk scores into business-impact language.
"""
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timezone

from vendor_risk_engine.scoring.advanced_analysis import AdvancedGRCAnalyzer
from vendor_risk_engine.scoring.compliance_mapper import ComplianceMapper
from vendor_risk_engine.models.score import VendorScore


class ExecutiveSummaryGenerator:
    """
    Generates a board-ready JSON summary from a list of scored vendors.
    Designed to be consumed by the API layer and rendered in the dashboard.
    """

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.analyzer = AdvancedGRCAnalyzer(output_dir)
        self.mapper = ComplianceMapper()

    def generate(self, vendors: List[VendorScore], run_id: str) -> Dict:
        """
        Generate a full executive summary from a batch of scored vendors.
        """
        if not vendors:
            return self._empty_summary(run_id)

        total = len(vendors)
        high_risk = [v for v in vendors if v.classification_tier == "High"]
        medium_risk = [v for v in vendors if v.classification_tier == "Medium"]
        low_risk = [v for v in vendors if v.classification_tier == "Low"]

        # Aggregate financial exposure
        total_ale = 0.0
        total_rrv = 0.0
        vendor_details = []

        for v in vendors:
            fair = self.analyzer.calculate_fair_risk(v.classification_tier, v.total_score)
            total_ale += fair["annual_loss_expectancy_usd"]
            total_rrv += fair["residual_risk_value_usd"]

            # Cross-framework compliance impact
            failed_cats = [cs.category_id for cs in v.category_scores if cs.gap_count > 0]
            compliance = self.mapper.generate_unified_report(failed_cats, len(v.category_scores))

            # MITRE threat surface
            mitre_techs = self.analyzer.map_mitre_gaps(failed_cats)

            vendor_details.append({
                "vendor_id": v.vendor_id,
                "vendor_name": v.vendor_name,
                "score": v.total_score,
                "tier": v.classification_tier,
                "gap_count": v.gap_total_count,
                "critical_gaps": v.gap_critical_count,
                "fair_analysis": fair,
                "compliance_impact": compliance,
                "mitre_techniques": len(mitre_techs),
                "mitre_critical": len([t for t in mitre_techs if t.get("severity") == "CRITICAL"]),
            })

        # Sort by score ascending (worst vendors first)
        vendor_details.sort(key=lambda x: x["score"])

        # Determine overall posture
        if len(high_risk) > 0:
            posture = "CRITICAL"
            posture_description = f"{len(high_risk)} vendor(s) classified as High Risk requiring immediate remediation."
        elif len(medium_risk) > total * 0.5:
            posture = "ELEVATED"
            posture_description = f"Over 50% of vendors ({len(medium_risk)}) are Medium Risk. Enhanced oversight recommended."
        else:
            posture = "ACCEPTABLE"
            posture_description = "Vendor portfolio risk is within acceptable tolerance levels."

        # Compliance posture aggregation
        all_failed_cats = set()
        total_cats = 0
        for v in vendors:
            for cs in v.category_scores:
                total_cats += 1
                if cs.gap_count > 0:
                    all_failed_cats.add(cs.category_id)
        
        portfolio_compliance = self.mapper.generate_unified_report(list(all_failed_cats), max(total_cats, 1))

        return {
            "report_type": "EXECUTIVE_SUMMARY",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "assessment_run_id": run_id,
            "portfolio_overview": {
                "total_vendors_assessed": total,
                "high_risk_count": len(high_risk),
                "medium_risk_count": len(medium_risk),
                "low_risk_count": len(low_risk),
                "overall_posture": posture,
                "posture_description": posture_description,
            },
            "financial_exposure": {
                "total_annual_loss_expectancy_usd": round(total_ale, 2),
                "total_residual_risk_value_usd": round(total_rrv, 2),
                "average_ale_per_vendor_usd": round(total_ale / total, 2) if total > 0 else 0,
                "highest_exposure_vendor": vendor_details[0]["vendor_name"] if vendor_details else "N/A",
                "highest_exposure_ale_usd": vendor_details[0]["fair_analysis"]["annual_loss_expectancy_usd"] if vendor_details else 0,
            },
            "compliance_posture": portfolio_compliance,
            "vendor_risk_matrix": vendor_details,
            "recommendations": self._generate_recommendations(high_risk, medium_risk, total_ale),
        }

    def _generate_recommendations(self, high_risk: List[VendorScore], medium_risk: List[VendorScore], total_ale: float) -> List[str]:
        recs = []
        if high_risk:
            names = ", ".join([v.vendor_name for v in high_risk[:3]])
            recs.append(f"IMMEDIATE ACTION: Initiate 30-day remediation plans for high-risk vendors: {names}.")
            recs.append("ESCALATION: Schedule executive review of high-risk vendor contracts within 2 weeks.")
        if medium_risk:
            recs.append(f"OVERSIGHT: Assign enhanced monitoring for {len(medium_risk)} medium-risk vendor(s).")
        if total_ale > 500000:
            recs.append(f"BUDGET: Total annualized loss exposure is ${total_ale:,.0f}. Consider cyber insurance review.")
        if total_ale > 1000000:
            recs.append("STRATEGIC: Portfolio-wide vendor diversification analysis recommended to reduce concentration risk.")
        if not recs:
            recs.append("MAINTAIN: Current vendor portfolio risk is within acceptable bounds. Continue quarterly assessments.")
        return recs

    def _empty_summary(self, run_id: str) -> Dict:
        return {
            "report_type": "EXECUTIVE_SUMMARY",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "assessment_run_id": run_id,
            "portfolio_overview": {
                "total_vendors_assessed": 0,
                "overall_posture": "NO_DATA",
                "posture_description": "No vendors have been assessed in this run.",
            },
            "financial_exposure": {},
            "compliance_posture": {},
            "vendor_risk_matrix": [],
            "recommendations": ["Run an assessment with vendor response data to generate the executive summary."],
        }
