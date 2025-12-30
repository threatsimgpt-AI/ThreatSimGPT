"""ThreatSimGPT Intelligence Module.

Real-time OSINT and reconnaissance capabilities for enhanced threat simulation.
This module provides internet-connected intelligence gathering for realistic,
up-to-date attack scenarios based on live target information.
"""

from .models import (
    IntelligenceProfile,
    CompanyIntelligence,
    SocialMediaIntelligence,
    ThreatIntelligence,
    OSINTResult,
    IntelligenceSource,
    ConfidenceLevel
)

from .services import (
    OSINTService,
    LinkedInIntelligence,
    CompanyProfileService,
    SocialMediaMonitor,
    ThreatIntelligenceService,
    DomainAnalysisService
)

from .integrations import (
    IntelligenceEngine,
    LLMIntelligenceIntegrator,
    RealTimeReconnaissanceService
)

__all__ = [
    # Models
    "IntelligenceProfile",
    "CompanyIntelligence",
    "SocialMediaIntelligence",
    "ThreatIntelligence",
    "OSINTResult",
    "IntelligenceSource",
    "ConfidenceLevel",

    # Services
    "OSINTService",
    "LinkedInIntelligence",
    "CompanyProfileService",
    "SocialMediaMonitor",
    "ThreatIntelligenceService",
    "DomainAnalysisService",

    # Integrations
    "IntelligenceEngine",
    "LLMIntelligenceIntegrator",
    "RealTimeReconnaissanceService"
]
