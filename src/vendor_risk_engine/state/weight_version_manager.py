"""
Atomic tracking of active weight configuration hash.
"""
import json
import fcntl
from pathlib import Path
from datetime import datetime, timezone
import contextlib
from typing import Optional
from pydantic import BaseModel, ConfigDict

class WeightState(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    active_weight_hash: str
    previous_weight_hash: Optional[str]
    activated_at: datetime
    activated_by: str

class WeightVersionManager:
    def __init__(self, state_path: Path):
        self.state_path = state_path
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            with open(self.state_path, 'w') as f:
                json.dump({
                    "active_weight_hash": "INITIAL",
                    "previous_weight_hash": None,
                    "activated_at": datetime.now(timezone.utc).isoformat(),
                    "activated_by": "system"
                }, f)

    @contextlib.contextmanager
    def _acquire_lock(self):
        f = open(self.state_path, "r+")
        try:
            fcntl.flock(f, fcntl.LOCK_EX)
            yield f
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
            f.close()

    def load(self) -> WeightState:
        with self._acquire_lock() as f:
            data = json.load(f)
            return WeightState(**data)

    def activate(self, weight_hash: str, user: str) -> None:
        with self._acquire_lock() as f:
            data = json.load(f)
            new_state = WeightState(
                active_weight_hash=weight_hash,
                previous_weight_hash=data.get("active_weight_hash"),
                activated_at=datetime.now(timezone.utc),
                activated_by=user
            )
            f.seek(0)
            f.truncate()
            f.write(new_state.model_dump_json(exclude_none=True))

    def rollback(self) -> WeightState:
        with self._acquire_lock() as f:
            data = json.load(f)
            prev_hash = data.get("previous_weight_hash")
            if not prev_hash:
                raise RuntimeError("No previous weight hash to rollback to")
                
            new_state = WeightState(
                active_weight_hash=prev_hash,
                previous_weight_hash=None,
                activated_at=datetime.now(timezone.utc),
                activated_by="rollback"
            )
            f.seek(0)
            f.truncate()
            f.write(new_state.model_dump_json(exclude_none=True))
            return new_state
