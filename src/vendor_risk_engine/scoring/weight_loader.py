"""
Atomic weight and threshold configuration loader.
"""
from pathlib import Path
import yaml
from pydantic import ValidationError
from vendor_risk_engine.models.rules import WeightConfig, ThresholdConfig
from vendor_risk_engine.utils.hash_utils import sha256_file
from vendor_risk_engine.exceptions import WeightLoadException

class WeightLoader:
    def __init__(self, weight_path: Path, threshold_path: Path):
        self.weight_path = weight_path
        self.threshold_path = threshold_path

    def _compute_hash(self, path: Path) -> str:
        return sha256_file(path)

    def load_weights(self) -> WeightConfig:
        try:
            with open(self.weight_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            
            data["config_hash"] = self._compute_hash(self.weight_path)
            return WeightConfig(**data)
        except Exception as e:
            raise WeightLoadException(
                message=f"Failed to load weights: {str(e)}",
                correlation_id="",
                stage_name="Initialization",
                assessment_run_id=""
            )

    def load_thresholds(self) -> ThresholdConfig:
        try:
            with open(self.threshold_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return ThresholdConfig(**data)
        except Exception as e:
            raise WeightLoadException(
                message=f"Failed to load thresholds: {str(e)}",
                correlation_id="",
                stage_name="Initialization",
                assessment_run_id=""
            )

    def reload(self) -> None:
        """Called on SIGHUP to reload configs."""
        pass
