"""
Manager for persistent assessment run metadata and structured audit logs.
"""
import json
import os
import fcntl
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List
from vendor_risk_engine.config import Settings
from vendor_risk_engine.models.audit import AssessmentRunMetadata, AuditLogEntry
from vendor_risk_engine.constants import LogEventType

class AuditManager:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.audit_dir = settings.output_dir / "audit"
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.audit_dir / "audit_log.jsonl"
        self.runs_path = self.audit_dir / "runs.json"
        
        # Initialize empty runs file if not exists
        if not self.runs_path.exists():
            self._save_runs([])

    def _acquire_lock(self, path: Path):
        # Open lock file to ensure atomic file updates
        lock_path = path.with_suffix(".lock")
        f = open(lock_path, "w")
        fcntl.flock(f, fcntl.LOCK_EX)
        return f

    def _release_lock(self, lock_file):
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()

    def _load_runs(self) -> List[dict]:
        lock = self._acquire_lock(self.runs_path)
        try:
            if not self.runs_path.exists() or self.runs_path.stat().st_size == 0:
                return []
            with open(self.runs_path, "r", encoding="utf-8") as f:
                return json.load(f)
        finally:
            self._release_lock(lock)

    def _save_runs(self, runs: List[dict]) -> None:
        lock = self._acquire_lock(self.runs_path)
        try:
            with open(self.runs_path, "w", encoding="utf-8") as f:
                json.dump(runs, f, indent=2)
        finally:
            self._release_lock(lock)

    def start_run(self, run_id: str, weight_hash: str, questionnaire_hash: str) -> None:
        runs = self._load_runs()
        
        # Remove if already exists (highly unlikely due to timestamps)
        runs = [r for r in runs if r["run_id"] != run_id]
        
        metadata = {
            "run_id": run_id,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "end_time": None,
            "pipeline_version": "1.0.0",
            "python_version": "3.11",
            "dependency_lockfile_hash": "N/A",
            "weight_config_hash": weight_hash,
            "questionnaire_version_hash": questionnaire_hash,
            "total_vendors_scored": 0,
            "total_reports_generated": 0,
            "total_gaps_detected": 0,
            "external_sync_successful": True
        }
        
        runs.append(metadata)
        self._save_runs(runs)
        
        self.emit_log(
            run_id=run_id,
            stage_name="PipelineStart",
            event_type=LogEventType.ASSESSMENT_START,
            severity="INFO",
            message=f"Assessment run {run_id} started."
        )

    def emit_log(
        self,
        run_id: str,
        stage_name: str,
        event_type: LogEventType,
        severity: str,
        message: str,
        vendor_id: Optional[str] = None,
        score: Optional[float] = None,
        classification_tier: Optional[str] = None,
        extra: dict = {}
    ) -> None:
        entry = AuditLogEntry(
            timestamp_utc=datetime.now(timezone.utc),
            correlation_id="",
            assessment_run_id=run_id,
            stage_name=stage_name,
            event_type=event_type,
            log_severity=severity,
            message=message,
            vendor_id=vendor_id,
            score=score,
            classification_tier=classification_tier,
            extra=extra
        )
        
        lock = self._acquire_lock(self.log_path)
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(entry.model_dump_json() + "\n")
        finally:
            self._release_lock(lock)

    def complete_run(
        self,
        run_id: str,
        total_vendors: int,
        total_reports: int,
        total_gaps: int,
        external_sync: bool
    ) -> None:
        runs = self._load_runs()
        updated = False
        for r in runs:
            if r["run_id"] == run_id:
                r["end_time"] = datetime.now(timezone.utc).isoformat()
                r["total_vendors_scored"] = total_vendors
                r["total_reports_generated"] = total_reports
                r["total_gaps_detected"] = total_gaps
                r["external_sync_successful"] = external_sync
                updated = True
                break
        
        if updated:
            self._save_runs(runs)
            
        self.emit_log(
            run_id=run_id,
            stage_name="PipelineEnd",
            event_type=LogEventType.ASSESSMENT_COMPLETE,
            severity="INFO",
            message=f"Assessment run {run_id} completed successfully."
        )

    def get_run_metadata(self, run_id: str) -> Optional[dict]:
        runs = self._load_runs()
        for r in runs:
            if r["run_id"] == run_id:
                return r
        return None

    def get_all_runs(self) -> List[dict]:
        return self._load_runs()
