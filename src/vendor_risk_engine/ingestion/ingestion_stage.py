"""
Ingestion stage using pandas chunksize to bound memory allocation.
"""
import pandas as pd
from pathlib import Path
from typing import Generator
import structlog
from datetime import datetime, timezone
from vendor_risk_engine.models.response import VendorResponse, ResponseSet
from vendor_risk_engine.config import Settings

logger = structlog.get_logger(__name__)

class IngestionStage:
    def __init__(self, settings: Settings):
        self.settings = settings

    def stream_responses(self, file_path: Path) -> Generator[list[ResponseSet], None, None]:
        """Stream chunks of response sets from a CSV file."""
        logger.info("starting_ingestion", file_path=str(file_path))
        
        try:
            chunk_iter = pd.read_csv(file_path, chunksize=self.settings.batch_size)
            
            for chunk_idx, chunk in enumerate(chunk_iter):
                response_sets = []
                for _, row in chunk.iterrows():
                    vendor_id = str(row.get("vendor_id", "UNKNOWN"))
                    vendor_name = str(row.get("vendor_name", "Unknown Vendor"))
                    date_str = str(row.get("assessment_date", datetime.now().date().isoformat()))
                    responded_by = str(row.get("responded_by", "Unknown Analyst"))
                    
                    try:
                        parsed_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                    except ValueError:
                        parsed_date = datetime.now().date()
                        
                    responses = []
                    
                    for col in chunk.columns:
                        if col.startswith("Q_"):
                            val = str(row[col]) if not pd.isna(row[col]) else "empty"
                            evidence = str(row.get(f"{col}_evidence", "")) if f"{col}_evidence" in chunk.columns else None
                            responses.append(VendorResponse(
                                question_id=col,
                                response_value=val,
                                evidence_text=evidence if evidence and evidence != "nan" else None,
                                responded_at=datetime.now(timezone.utc)
                            ))
                            
                    response_sets.append(ResponseSet(
                        vendor_id=vendor_id,
                        vendor_name=vendor_name,
                        assessment_date=parsed_date,
                        responded_by=responded_by,
                        responses=responses
                    ))
                    
                logger.info("ingested_chunk", chunk_index=chunk_idx, batch_size=len(response_sets))
                yield response_sets
                
        except Exception as e:
            logger.error("ingestion_failed", error=str(e))
            raise
