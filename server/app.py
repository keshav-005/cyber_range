"""FastAPI entry point for the CyberRange environment server.

This module re-exports the app from cyber_range.server.app to satisfy
the OpenEnv validator's expected `server/app.py` path.
"""

import sys
import os

# Ensure the project root is on sys.path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_range.server.app import app, main  # noqa: E402, F401

if __name__ == "__main__":
    main()
