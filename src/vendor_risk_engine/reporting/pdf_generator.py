"""
ReportLab-based PDF generator.
"""
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
import structlog
from pathlib import Path
from vendor_risk_engine.config import Settings
from vendor_risk_engine.models.score import VendorScore
from vendor_risk_engine.models.report import ReportArtifact, ReportMetadata
from vendor_risk_engine.utils.hash_utils import sha256_model
from vendor_risk_engine.scoring.advanced_analysis import AdvancedGRCAnalyzer
from datetime import datetime, timezone

logger = structlog.get_logger(__name__)

class PDFGenerator:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.output_dir = settings.output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.styles = getSampleStyleSheet()

    def generate(self, score: VendorScore, gaps: list, recommendations: list, assessment_run_id: str) -> ReportArtifact:
        score_hash = sha256_model(score)
        
        pdf_path = self.output_dir / f"{score.vendor_id}_report.pdf"
        doc = SimpleDocTemplate(str(pdf_path), pagesize=letter)
        
        story = []
        
        # Add Title and Logo if exists
        logo_path = self.settings.report_logo_path
        if logo_path.exists():
            from reportlab.platypus import Image
            try:
                story.append(Image(str(logo_path), width=80, height=80))
                story.append(Spacer(1, 10))
            except Exception as e:
                logger.warn("logo_rendering_failed", error=str(e))

        story.append(Paragraph(f"Vendor Risk Assessment: {score.vendor_name}", self.styles['Title']))
        story.append(Spacer(1, 12))
        
        meta_data = [
            ["Vendor ID", score.vendor_id],
            ["Classification", score.classification_tier],
            ["Total Score", f"{score.total_score:.2f}"],
            ["Gaps Found", str(score.gap_total_count)],
            ["Assessment Date", score.computed_at.strftime("%Y-%m-%d")],
            ["Score Data Hash", score_hash[:16] + "..."]
        ]
        
        t = Table(meta_data, colWidths=[150, 250])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (1, 0), (1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(t)
        story.append(Spacer(1, 15))
        
        # Advanced GRC Analytics
        analyzer = AdvancedGRCAnalyzer(self.output_dir)
        
        # 1. FAIR Risk Quantification
        story.append(Paragraph("FAIR Quantitative Risk Analysis", self.styles['Heading2']))
        story.append(Spacer(1, 6))
        
        fair = analyzer.calculate_fair_risk(score.classification_tier, score.total_score)
        fair_data = [
            ["Annualized Rate of Occurrence (ARO)", f"{fair['annualized_rate_of_occurrence']} incidents/yr"],
            ["Single Loss Expectancy (SLE)", f"${fair['single_loss_expectancy_usd']:,.2f} USD"],
            ["Annual Loss Expectancy (ALE)", f"${fair['annual_loss_expectancy_usd']:,.2f} USD"],
            ["Residual Risk Value (RRV)", f"${fair['residual_risk_value_usd']:,.2f} USD"]
        ]
        
        t_fair = Table(fair_data, colWidths=[220, 180])
        t_fair.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#eaeaea')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(t_fair)
        story.append(Spacer(1, 15))
        
        # 2. MITRE ATT&CK Threat Mapping
        story.append(Paragraph("MITRE ATT&CK Threat Mapping", self.styles['Heading2']))
        story.append(Spacer(1, 6))
        
        failed_cats = [cs.category_id for cs in score.category_scores if cs.gap_count > 0]
        mitre_techs = analyzer.map_mitre_gaps(failed_cats)
        
        if mitre_techs:
            mitre_data = [["Technique ID", "Name", "Tactic", "Severity"]]
            for tech in mitre_techs:
                mitre_data.append([tech["technique_id"], tech["name"], tech["tactic"], tech["severity"]])
                
            t_mitre = Table(mitre_data, colWidths=[80, 120, 140, 60])
            t_mitre.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#cc3333')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.whitesmoke])
            ]))
            story.append(t_mitre)
        else:
            story.append(Paragraph("No critical control failures detected. Zero MITRE ATT&CK threats mapped.", self.styles['BodyText']))
            
        story.append(Spacer(1, 15))
        
        doc.build(story)
        
        logger.info("report_generated", vendor_id=score.vendor_id, path=str(pdf_path))
        
        metadata = ReportMetadata(
            vendor_id=score.vendor_id,
            assessment_run_id=assessment_run_id,
            generated_at=datetime.now(timezone.utc),
            score_data_hash=score_hash,
            weight_config_hash=score.weight_config_hash,
            questionnaire_version_hash=score.questionnaire_version_hash
        )
        
        return ReportArtifact(
            vendor_id=score.vendor_id,
            pdf_path=pdf_path,
            file_size_bytes=pdf_path.stat().st_size,
            metadata=metadata
        )
