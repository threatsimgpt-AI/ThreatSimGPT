"""
Blue Team Operations Module

This module provides comprehensive blue team operational capabilities
for ThreatSimGPT, including authorization, incident response, and
security operations automation.

Author: Ibrahim Hassan
Created: March 2026
Purpose: Implement missing blue team features
Issues: #32, #36, #38 + additional capabilities
"""

from .authorization import BlueTeamAuthorization
from .models import BlueTeamRole, Permission, AuthorizationRequest
from .exceptions import BlueTeamAuthError, InsufficientPermissionsError

__version__ = "1.0.0"
__all__ = [
    "BlueTeamAuthorization",
    "BlueTeamRole",
    "Permission",
    "AuthorizationRequest",
    "BlueTeamAuthError",
    "InsufficientPermissionsError",
]
