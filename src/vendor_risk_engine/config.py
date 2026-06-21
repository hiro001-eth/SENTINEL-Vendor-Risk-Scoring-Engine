"""
Configuration module.
"""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr, PositiveInt
from typing import Literal, Optional
from functools import lru_cache

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # QuestionnaireSettings
    questionnaire_schema_path: Path
    weight_config_path: Path
    threshold_config_path: Path
    
    # ExternalSettings
    bitsight_api_key: SecretStr = SecretStr("")
    securityscorecard_api_key: SecretStr = SecretStr("")
    hibp_api_key: SecretStr = SecretStr("")
    external_data_ttl_hours: PositiveInt = 168

    # ScoringSettings
    scoring_decimal_places: PositiveInt = 4
    batch_size: PositiveInt = 100
    category_floor_enabled: bool = True

    # ReportSettings
    report_font_path: Path = Path("./assets/fonts")
    report_logo_path: Optional[Path] = None
    pdf_a_compliance: bool = True
    output_dir: Path = Path("./output")

    # PipelineSettings
    log_level: Literal["DEBUG", "INFO", "WARN", "ERROR"] = "INFO"
    assessment_run_id_prefix: str = "SENTINEL"

    # NotificationSettings (optional)
    webhook_url: Optional[str] = None
    webhook_provider: Literal["slack", "teams", "generic"] = "slack"

@lru_cache()
def get_settings() -> Settings:
    """Return cached Settings singleton."""
    return Settings()
