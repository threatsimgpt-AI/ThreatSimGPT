"""Safety and ethics enforcement.

Provides content filtering, compliance checking,
and ethical use validation capabilities.

Author: Temi Adebola (TSG-RED Lead)
Updated: 13 January 2026 (Security Hardening)
"""

from threatsimgpt.safety.models import SafetyResult, SafetyLevel
from threatsimgpt.safety.exceptions import (
    SafetyViolationError,
    ContentFilterError,
    PolicyViolationError,
    ComplianceError,
)
from threatsimgpt.safety.content_filter import (
    ContentFilter,
    FilterResult,
    FilterConfig,
    RiskLevel,
    ContentCategory,
    OutputSanitizer,
    AuthorizationValidator,
    RateLimiter,
    get_global_filter,
    set_global_filter,
)

__all__ = [
    # Legacy models
    "SafetyResult",
    "SafetyLevel",
    # Exceptions
    "SafetyViolationError",
    "ContentFilterError",
    "PolicyViolationError",
    "ComplianceError",
    # Content Filter (Hardened)
    "ContentFilter",
    "FilterResult",
    "FilterConfig",
    "RiskLevel",
    "ContentCategory",
    "OutputSanitizer",
    "AuthorizationValidator",
    "RateLimiter",
    "get_global_filter",
    "set_global_filter",
]
