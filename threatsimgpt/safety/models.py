"""Safety models placeholder.

This will be fully implemented in Week 9.
"""

from enum import Enum


class SafetyLevel(str, Enum):
    """Safety levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SafetyResult:
    """Safety check result."""
    def __init__(self, approved: bool = True):
        self.approved = approved
