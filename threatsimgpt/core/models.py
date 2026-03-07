"""Core data models for ThreatSimGPT functionality.

This module provides the core data structures used throughout the ThreatSimGPT system.
These models are used for threat scenarios, simulation results, and system state management.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from enum import Enum
from dataclasses import dataclass, field
from uuid import uuid4
from pydantic import BaseModel, Field


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


# Enhanced Detection Models for Detection-Optimized Scenarios

class DetectionIndicatorType(str, Enum):
    """Types of detection indicators in scenarios."""
    PROCESS_CREATION = "process_creation"
    NETWORK_CONNECTION = "network_connection"
    FILE_ACCESS = "file_access"
    REGISTRY_MODIFICATION = "registry_modification"
    API_CALL = "api_call"
    EMAIL_EVENT = "email_event"
    DNS_QUERY = "dns_query"
    AUTHENTICATION_EVENT = "authentication_event"
    COMMAND_EXECUTION = "command_execution"
    WEB_REQUEST = "web_request"


class AttackStage(str, Enum):
    """MITRE ATT&CK attack stages."""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_CONTROL = "command_control"
    IMPACT = "impact"


class DetectionIndicator(BaseModel):
    """Individual detection indicator within a scenario."""
    
    indicator_id: str = Field(default_factory=lambda: str(uuid4()))
    indicator_type: DetectionIndicatorType = Field(..., description="Type of indicator")
    attack_stage: AttackStage = Field(..., description="Attack stage when this occurs")
    
    # Observable details
    process_name: Optional[str] = Field(None, description="Process name (for process indicators)")
    process_path: Optional[str] = Field(None, description="Full process path")
    command_line: Optional[str] = Field(None, description="Command line arguments")
    parent_process: Optional[str] = Field(None, description="Parent process name")
    
    # Network details
    source_ip: Optional[str] = Field(None, description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    destination_port: Optional[int] = Field(None, description="Destination port")
    protocol: Optional[str] = Field(None, description="Protocol (TCP/UDP)")
    domain: Optional[str] = Field(None, description="Domain name")
    
    # File details
    file_path: Optional[str] = Field(None, description="File path accessed/created")
    file_hash: Optional[str] = Field(None, description="File hash (MD5/SHA256)")
    file_extension: Optional[str] = Field(None, description="File extension")
    
    # Email details
    sender_email: Optional[str] = Field(None, description="Email sender")
    recipient_email: Optional[str] = Field(None, description="Email recipient")
    subject_keywords: Optional[List[str]] = Field(None, description="Suspicious subject keywords")
    attachment_names: Optional[List[str]] = Field(None, description="Suspicious attachment names")
    link_urls: Optional[List[str]] = Field(None, description="Malicious link URLs")
    
    # Detection characteristics
    rarity_score: float = Field(0.5, description="How rare this indicator is (0-1)")
    false_positive_rate: float = Field(0.1, description="Estimated false positive rate")
    detection_confidence: float = Field(0.8, description="Confidence in detection logic")
    
    # Temporal patterns
    time_patterns: Optional[Dict[str, Any]] = Field(None, description="Temporal patterns (hours, frequency)")
    correlation_window: Optional[int] = Field(None, description="Correlation window in seconds")
    
    # MITRE mapping
    mitre_technique_id: Optional[str] = Field(None, description="MITRE ATT&CK technique ID")
    mitre_tactic_id: Optional[str] = Field(None, description="MITRE ATT&CK tactic ID")
    
    # Detection logic hints
    detection_logic: Optional[str] = Field(None, description="Natural language detection logic")
    required_log_sources: List[str] = Field(default_factory=list, description="Required log sources")
    correlation_indicators: List[str] = Field(default_factory=list, description="IDs of correlated indicators")


class AttackPattern(BaseModel):
    """Attack pattern linking multiple indicators."""
    
    pattern_id: str = Field(default_factory=lambda: str(uuid4()))
    pattern_name: str = Field(..., description="Pattern name")
    pattern_description: str = Field(..., description="Pattern description")
    
    # Pattern structure
    indicator_sequence: List[str] = Field(..., description="Sequence of indicator IDs")
    sequence_type: str = Field(default="ordered", description="ordered/unordered/conditional")
    
    # Timing
    typical_duration_seconds: Optional[int] = Field(None, description="Typical attack duration")
    max_gap_seconds: Optional[int] = Field(None, description="Maximum gap between indicators")
    
    # MITRE mapping
    primary_technique_id: str = Field(..., description="Primary MITRE technique")
    secondary_techniques: List[str] = Field(default_factory=list, description="Secondary techniques")
    
    # Detection characteristics
    detection_difficulty: str = Field(default="medium", description="easy/medium/hard/expert")
    required_correlation: bool = Field(default=False, description="Requires correlation across logs")
    min_confidence_threshold: float = Field(default=0.7, description="Minimum confidence for alert")


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
    
    # Enhanced detection-optimized fields
    attack_patterns: List[AttackPattern] = field(default_factory=list)
    detection_indicators: List[DetectionIndicator] = field(default_factory=list)
    target_profile: Dict[str, Any] = field(default_factory=dict)
    difficulty_level: int = 5
    high_value_indicators: List[str] = field(default_factory=list)
    correlation_opportunities: List[Dict[str, Any]] = field(default_factory=list)
    suggested_rule_count: int = 1
    priority_indicators: List[str] = field(default_factory=list)
    detection_strategies: List[str] = field(default_factory=list)

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

    def get_indicators_by_stage(self, stage: AttackStage) -> List[DetectionIndicator]:
        """Get all indicators for a specific attack stage."""
        return [ind for ind in self.detection_indicators if ind.attack_stage == stage]
    
    def get_indicators_by_type(self, indicator_type: DetectionIndicatorType) -> List[DetectionIndicator]:
        """Get all indicators of a specific type."""
        return [ind for ind in self.detection_indicators if ind.indicator_type == indicator_type]
    
    def get_high_confidence_indicators(self, min_confidence: float = 0.8) -> List[DetectionIndicator]:
        """Get indicators above confidence threshold."""
        return [ind for ind in self.detection_indicators if ind.detection_confidence >= min_confidence]
    
    def get_correlation_candidates(self) -> List[Dict[str, Any]]:
        """Find indicators that should be correlated for detection."""
        candidates = []
        
        # Group by process/command line patterns
        process_groups = {}
        for ind in self.detection_indicators:
            if ind.process_name:
                key = ind.process_name
                if key not in process_groups:
                    process_groups[key] = []
                process_groups[key].append(ind)
        
        # Find process groups with multiple indicators
        for process, indicators in process_groups.items():
            if len(indicators) > 1:
                candidates.append({
                    "type": "process_sequence",
                    "process": process,
                    "indicators": [ind.indicator_id for ind in indicators],
                    "time_window": 300  # 5 minutes
                })
        
        return candidates

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
    
    # Enhanced quality metrics
    detection_coverage_score: float = 0.0
    mitre_coverage_percentage: float = 0.0
    false_positive_estimate: float = 0.0
    scenario_effectiveness: float = 0.0
    rule_generation_quality: float = 0.0
    quality_metrics: Dict[str, float] = field(default_factory=dict)
    detection_analysis: Dict[str, Any] = field(default_factory=dict)

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
    
    def calculate_quality_metrics(self, scenario: 'ThreatScenario') -> None:
        """Calculate enhanced quality metrics for the simulation."""
        if not scenario.detection_indicators:
            return
        
        # Detection coverage based on indicator quality
        high_confidence_indicators = scenario.get_high_confidence_indicators(0.8)
        self.detection_coverage_score = len(high_confidence_indicators) / len(scenario.detection_indicators)
        
        # MITRE coverage percentage
        unique_techniques = set(ind.mitre_technique_id for ind in scenario.detection_indicators if ind.mitre_technique_id)
        self.mitre_coverage_percentage = len(unique_techniques) / 15  # Assuming ~15 common techniques
        
        # False positive estimate
        total_fp_rate = sum(ind.false_positive_rate for ind in scenario.detection_indicators)
        self.false_positive_estimate = total_fp_rate / len(scenario.detection_indicators)
        
        # Scenario effectiveness (combination of coverage and low FP rate)
        self.scenario_effectiveness = self.detection_coverage_score * (1 - self.false_positive_estimate)
        
        # Rule generation quality
        self.rule_generation_quality = min(1.0, self.scenario_effectiveness * self.mitre_coverage_percentage)
        
        # Store detailed metrics
        self.quality_metrics = {
            "detection_coverage": self.detection_coverage_score,
            "mitre_coverage": self.mitre_coverage_percentage,
            "false_positive_rate": self.false_positive_estimate,
            "scenario_effectiveness": self.scenario_effectiveness,
            "rule_generation_quality": self.rule_generation_quality,
            "indicator_count": len(scenario.detection_indicators),
            "attack_pattern_count": len(scenario.attack_patterns),
            "correlation_opportunities": len(scenario.correlation_opportunities)
        }


# Import exception classes from exceptions module to avoid duplication
from .exceptions import ThreatSimGPTError, SimulationError, ConfigurationError, ValidationError


# Type aliases for convenience
ScenarioDict = Dict[str, Any]
ResultDict = Dict[str, Any]
StageDict = Dict[str, Any]
