"""Core data models for ThreatSimGPT functionality.

This module provides the core data structures used throughout the ThreatSimGPT system.
These models are used for threat scenarios, simulation results, and system state management.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from enum import Enum
from dataclasses import dataclass, field
from uuid import uuid4


class SimulationStatus(str, Enum):
    """Status of a threat simulation."""
    NOT_STARTED = "not_started"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ThreatType(str, Enum):
    """Types of threat scenarios."""
    PHISHING = "phishing"
    MALWARE = "malware"
    SOCIAL_ENGINEERING = "social_engineering"
    NETWORK_INTRUSION = "network_intrusion"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    CUSTOM = "custom"


@dataclass
class ThreatScenario:
    """Data model for threat scenarios."""

    name: str
    threat_type: Union[ThreatType, str]
    description: str = ""
    severity: str = "medium"
    target_systems: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    scenario_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        """Validate scenario data after initialization."""
        if not self.name.strip():
            raise ValueError("Scenario name cannot be empty")

        if self.severity not in ["low", "medium", "high", "critical"]:
            raise ValueError("Severity must be one of: low, medium, high, critical")

        # Ensure threat_type is properly typed
        if isinstance(self.threat_type, str):
            try:
                self.threat_type = ThreatType(self.threat_type)
            except ValueError:
                # If it's not a valid enum value, keep as string for flexibility
                pass

    @classmethod
    def from_yaml_config(cls, yaml_scenario) -> 'ThreatScenario':
        """Create ThreatScenario from YAML configuration."""
        return cls(
            name=yaml_scenario.metadata.name,
            threat_type=yaml_scenario.threat_type,
            description=yaml_scenario.metadata.description,
            severity="medium",  # Default severity
            target_systems=[],
            attack_vectors=[],
            metadata={
                "yaml_config": True,
                "difficulty_level": yaml_scenario.difficulty_level,
                "estimated_duration": yaml_scenario.estimated_duration,
                "target_profile": {
                    "role": yaml_scenario.target_profile.role,
                    "department": yaml_scenario.target_profile.department
                }
            }
        )


@dataclass
class SimulationStage:
    """Data model for individual simulation stages."""

    stage_type: str
    content: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    stage_id: str = field(default_factory=lambda: str(uuid4()))
    duration_seconds: Optional[float] = None
    success: bool = True
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate stage data after initialization."""
        if not self.stage_type.strip():
            raise ValueError("Stage type cannot be empty")
        if not self.content.strip():
            raise ValueError("Stage content cannot be empty")


@dataclass
class SimulationResult:
    """Data model for simulation results."""

    status: SimulationStatus
    scenario_id: str
    result_id: str = field(default_factory=lambda: str(uuid4()))
    stages: List[SimulationStage] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    total_duration_seconds: Optional[float] = None
    success_rate: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Calculate derived fields after initialization."""
        if self.stages:
            successful_stages = sum(1 for stage in self.stages if stage.success)
            self.success_rate = successful_stages / len(self.stages)

        if self.end_time and self.start_time:
            self.total_duration_seconds = (self.end_time - self.start_time).total_seconds()

    def add_stage(self, stage: SimulationStage) -> None:
        """Add a stage to the simulation result."""
        self.stages.append(stage)
        # Recalculate success rate
        if self.stages:
            successful_stages = sum(1 for s in self.stages if s.success)
            self.success_rate = successful_stages / len(self.stages)

    def mark_completed(self, success: bool = True, error_message: Optional[str] = None) -> None:
        """Mark the simulation as completed."""
        self.end_time = datetime.utcnow()
        self.status = SimulationStatus.COMPLETED if success else SimulationStatus.FAILED
        self.error_message = error_message
        if self.start_time:
            self.total_duration_seconds = (self.end_time - self.start_time).total_seconds()


# Import exception classes from exceptions module to avoid duplication
from .exceptions import ThreatSimGPTError, SimulationError, ConfigurationError, ValidationError


# Type aliases for convenience
ScenarioDict = Dict[str, Any]
ResultDict = Dict[str, Any]
StageDict = Dict[str, Any]
