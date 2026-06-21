"""Questionnaire schema loader."""
import yaml
from pathlib import Path
from vendor_risk_engine.models.questionnaire import QuestionnaireSet
from vendor_risk_engine.utils.hash_utils import sha256_file
from vendor_risk_engine.exceptions import QuestionnaireLoadException

class QuestionnaireLoader:
    def __init__(self, schema_path: Path):
        self.schema_path = schema_path

    def load(self) -> QuestionnaireSet:
        try:
            with open(self.schema_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            
            if "version" in data and "schema_version" not in data:
                data["schema_version"] = data.pop("version")
            data["version_hash"] = sha256_file(self.schema_path)
            return QuestionnaireSet(**data)
        except Exception as e:
            raise QuestionnaireLoadException(
                message=f"Failed to load schema: {str(e)}",
                correlation_id="",
                stage_name="Initialization",
                assessment_run_id=""
            )
