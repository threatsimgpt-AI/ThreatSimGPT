"""Configuration management and validation.

Handles YAML configuration loading, schema validation,
and configuration object management.
"""

from threatsimgpt.config.models import (
    ThreatScenario,
    ThreatType,
    DeliveryVector,
    TargetProfile,
    SimulationParameters,
)
from threatsimgpt.config.loader import ConfigurationLoader, ThreatSimGPTConfig, load_config
from threatsimgpt.config.validator import ConfigurationValidator
from threatsimgpt.config.exceptions import (
    ConfigurationError,
    ValidationError,
    SchemaError,
)
from threatsimgpt.config.validate_env import (
    validate_environment,
    print_environment_status,
    get_missing_vars,
)

__all__ = [
    "ThreatScenario",
    "ThreatType",
    "DeliveryVector",
    "TargetProfile",
    "SimulationParameters",
    "ConfigurationLoader",
    "ThreatSimGPTConfig",
    "load_config",
    "ConfigurationValidator",
    "ConfigurationError",
    "ValidationError",
    "SchemaError",
    "validate_environment",
    "print_environment_status",
    "get_missing_vars",
]
