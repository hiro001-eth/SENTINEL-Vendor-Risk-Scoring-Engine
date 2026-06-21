#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Automatically add the src/ directory to the Python path so imports work
sys.path.insert(0, str(Path(__file__).parent / "src"))

from vendor_risk_engine.main import app

if __name__ == "__main__":
    # If you just run `python main.py` without arguments, default to starting the API
    if len(sys.argv) == 1:
        print("Starting SENTINEL API server...")
        sys.argv.extend(["api", "--host", "127.0.0.1", "--port", "8000"])
    
    # Run the Typer/FastAPI CLI app
    app()
