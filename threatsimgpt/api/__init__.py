"""REST API for ThreatSimGPT.

Provides FastAPI-based REST endpoints for threat simulation,
scenario management, and system integration.
"""

from threatsimgpt.api.main import app

__all__ = [
    "app",
]
