"""
Report artifact metadata models.
"""
from pydantic import BaseModel, ConfigDict
from datetime import datetime
from pathlib import Path

class ReportSection(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    section_name: str
    content_blocks: list[str]
    chart_paths: list[Path]

class ReportMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    vendor_id: str
    assessment_run_id: str
    generated_at: datetime
    score_data_hash: str
    weight_config_hash: str
    questionnaire_version_hash: str

class ReportArtifact(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    vendor_id: str
    pdf_path: Path
    file_size_bytes: int
    metadata: ReportMetadata
