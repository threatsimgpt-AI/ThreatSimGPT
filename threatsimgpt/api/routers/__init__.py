"""API Routers for ThreatSimGPT."""

from .manuals import router as manuals_router
from .knowledge import router as knowledge_router
from .feedback import router as feedback_router

__all__ = ["manuals_router", "knowledge_router", "feedback_router"]
