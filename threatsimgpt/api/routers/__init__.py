"""API Routers for ThreatSimGPT."""

from .manuals import router as manuals_router
from .knowledge import router as knowledge_router

__all__ = ["manuals_router", "knowledge_router"]
