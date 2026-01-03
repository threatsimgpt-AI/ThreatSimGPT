"""Detection Rule Generator for ThreatSimGPT.

This module generates SIEM detection rules from attack scenarios.
Supports multiple formats: Sigma, Splunk SPL, Elastic KQL, and Microsoft Sentinel.

Author: David Onoja (Blue Team)
Issue: #25 - Build Detection Rule Generator (SIEM)
"""

from .models import (
    DetectionRule,
    DetectionLogic,
    LogSourceConfig,
    MitreMapping,
    RuleFormat,
    RuleMetadata,
    RuleSeverity,
    RuleStatus,
)
from .generator import DetectionRuleGenerator
from .sigma import SigmaRuleGenerator
from .splunk import SplunkRuleGenerator
from .elastic import ElasticRuleGenerator
from .sentinel import SentinelRuleGenerator
from .validator import RuleValidator, ValidationResult

__all__ = [
    # Models
    "DetectionRule",
    "DetectionLogic",
    "LogSourceConfig",
    "MitreMapping",
    "RuleFormat",
    "RuleMetadata",
    "RuleSeverity",
    "RuleStatus",
    # Generators
    "DetectionRuleGenerator",
    "SigmaRuleGenerator",
    "SplunkRuleGenerator",
    "ElasticRuleGenerator",
    "SentinelRuleGenerator",
    # Validation
    "RuleValidator",
    "ValidationResult",
]
