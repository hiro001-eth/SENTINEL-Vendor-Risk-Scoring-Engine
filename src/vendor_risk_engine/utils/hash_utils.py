"""
SHA-256 computation utilities.
"""
import hashlib
import json
from pathlib import Path
from pydantic import BaseModel

def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()

def sha256_model(model: BaseModel) -> str:
    """Compute deterministic SHA-256 of a Pydantic model via canonical JSON."""
    canonical_dict = model.model_dump(exclude_none=True, by_alias=True, mode='json')
    canonical_str = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    
    return sha256_bytes(canonical_str)

def sha256_file(path: Path) -> str:
    """Compute SHA-256 of a file."""
    with open(path, "rb") as f:
        return sha256_bytes(f.read())
