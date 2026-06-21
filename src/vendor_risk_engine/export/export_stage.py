"""
Export stage formatting CSV with exact schema and lineage hashes.
"""
import csv
import structlog
from pathlib import Path
from vendor_risk_engine.models.score import VendorScore
from vendor_risk_engine.constants import CSV_COLUMNS
from vendor_risk_engine.exceptions import NullRateViolationException

logger = structlog.get_logger(__name__)

class ExportStage:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write_batch(self, file_name: str, batch: list[VendorScore], assessment_run_id: str, append: bool = False) -> None:
        file_path = self.output_dir / file_name
        mode = "a" if append else "w"
        write_header = not append or not file_path.exists()
        
        null_hashes = 0
        total_records = len(batch)
        
        if total_records == 0:
            return

        with open(file_path, mode, newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction='ignore')
            if write_header:
                writer.writeheader()
                
            for score in batch:
                if not score.weight_config_hash or not score.questionnaire_version_hash or not score.response_snapshot_hash:
                    null_hashes += 1
                    
                cat_dict = {f"category_{cs.category_id.replace('CAT_', '').lower()}_score": cs.weighted_score for cs in score.category_scores}
                
                external_bitsight = next((s.normalized_score for s in score.external_signals if s.source == "BitSight"), None)
                breach_flag = any(s.source == "HaveIBeenPwned" for s in score.external_signals)

                row = {
                    "vendor_id": score.vendor_id,
                    "vendor_name": score.vendor_name,
                    "assessment_date": score.computed_at.date().isoformat(),
                    "total_score": score.total_score,
                    "classification_tier": score.classification_tier,
                    "gap_unanswered_count": score.gap_total_count,
                    "gap_critical_count": score.gap_critical_count,
                    "external_bitsight_score": external_bitsight,
                    "external_breach_flag": breach_flag,
                    "weight_config_hash": score.weight_config_hash,
                    "questionnaire_version_hash": score.questionnaire_version_hash,
                    "response_snapshot_hash": score.response_snapshot_hash,
                    "computed_at": score.computed_at.isoformat(),
                    "assessment_run_id": assessment_run_id
                }
                
                row.update(cat_dict)
                writer.writerow(row)

        null_rate = null_hashes / total_records
        if null_rate > 0.001:
            raise NullRateViolationException(
                message=f"Export null rate {null_rate} exceeded 0.001 limit",
                correlation_id="",
                stage_name="Export",
                assessment_run_id=""
            )
