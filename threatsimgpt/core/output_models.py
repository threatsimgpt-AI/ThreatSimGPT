"""Validated simulation output models for ThreatSimGPT.

Defines structure and validation for simulation results saved to log files.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from pydantic import BaseModel, Field, field_validator
import uuid


class OutputFormat(str, Enum):
    """Supported output formats for simulation results."""
    JSON = "json"
    YAML = "yaml"
    HTML = "html"
    MARKDOWN = "markdown"


class ContentType(str, Enum):
    """Types of generated content."""
    EMAIL = "email"
    SMS = "sms"
    DOCUMENT = "document"
    WEB_PAGE = "web_page"
    PHONE_SCRIPT = "phone_script"
    MALWARE_SAMPLE = "malware_sample"
    SOCIAL_POST = "social_post"
    OTHER = "other"


class SimulationStatus(str, Enum):
    """Simulation execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ProviderInfo(BaseModel):
    """Information about the LLM provider used."""
    name: str = Field(..., description="Provider name (openai, anthropic, openrouter)")
    model: str = Field(..., description="Specific model used")
    api_version: Optional[str] = Field(None, description="API version if applicable")
    response_time_ms: Optional[int] = Field(None, description="Response time in milliseconds")
    token_usage: Optional[Dict[str, int]] = Field(None, description="Token usage statistics")


class ContentGeneration(BaseModel):
    """Details about generated content."""
    content_type: ContentType = Field(..., description="Type of content generated")
    content: str = Field(..., description="The actual generated content")
    prompt_used: str = Field(..., description="Prompt that generated this content")
    provider_info: ProviderInfo = Field(..., description="Provider information")
    safety_validated: bool = Field(True, description="Whether content passed safety validation")
    educational_markers: List[str] = Field(default_factory=list, description="Educational indicators included")
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Generation timestamp")

    @field_validator('content')
    @classmethod
    def content_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("Generated content cannot be empty")
        return v


class TargetProfile(BaseModel):
    """Target profile information used in simulation."""
    role: str = Field(..., description="Target's role/position")
    department: str = Field(..., description="Department or business unit")
    seniority: str = Field(..., description="Seniority level")
    industry: str = Field(..., description="Industry sector")
    security_awareness: int = Field(..., ge=1, le=10, description="Security awareness level (1-10)")
    additional_attributes: Dict[str, Any] = Field(default_factory=dict, description="Additional profile data")


class ScenarioMetadata(BaseModel):
    """Metadata about the threat scenario."""
    name: str = Field(..., description="Scenario name")
    description: str = Field(..., description="Scenario description")
    threat_type: str = Field(..., description="Type of threat simulated")
    delivery_vector: str = Field(..., description="How the threat is delivered")
    difficulty_level: int = Field(..., ge=1, le=10, description="Difficulty level (1-10)")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")
    scenario_file: Optional[str] = Field(None, description="Source scenario file path")


class SimulationMetrics(BaseModel):
    """Quantitative metrics from the simulation."""
    success_rate: float = Field(..., ge=0, le=100, description="Success rate percentage")
    stages_completed: int = Field(..., ge=0, description="Number of stages completed")
    total_stages: int = Field(..., ge=1, description="Total number of stages")
    duration_seconds: float = Field(..., ge=0, description="Total simulation duration")
    errors_encountered: int = Field(default=0, ge=0, description="Number of errors during simulation")
    warnings_issued: int = Field(default=0, ge=0, description="Number of warnings issued")


class QualityAssessment(BaseModel):
    """Quality assessment of the simulation results."""
    realism_score: Optional[int] = Field(None, ge=1, le=10, description="Realism score (1-10)")
    educational_value: Optional[int] = Field(None, ge=1, le=10, description="Educational value (1-10)")
    safety_compliance: bool = Field(True, description="Whether simulation complies with safety guidelines")
    content_appropriateness: bool = Field(True, description="Whether content is appropriate for training")
    detection_indicators: List[str] = Field(default_factory=list, description="Indicators for security teams")


class SimulationOutput(BaseModel):
    """Complete validated simulation output structure."""

    # Core identification
    simulation_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique simulation identifier")
    version: str = Field("1.0", description="Output format version")

    # Timing information
    created_at: datetime = Field(default_factory=datetime.utcnow, description="When simulation was created")
    started_at: Optional[datetime] = Field(None, description="When simulation started")
    completed_at: Optional[datetime] = Field(None, description="When simulation completed")

    # Status and results
    status: SimulationStatus = Field(..., description="Current simulation status")
    success: bool = Field(..., description="Whether simulation was successful")
    error_message: Optional[str] = Field(None, description="Error message if failed")

    # Scenario information
    scenario: ScenarioMetadata = Field(..., description="Scenario metadata")
    target_profile: TargetProfile = Field(..., description="Target profile used")

    # Generated content
    generated_content: List[ContentGeneration] = Field(default_factory=list, description="All generated content")

    # Metrics and assessment
    metrics: SimulationMetrics = Field(..., description="Simulation metrics")
    quality_assessment: QualityAssessment = Field(..., description="Quality assessment")

    # Additional data
    logs: List[str] = Field(default_factory=list, description="Simulation log messages")
    recommendations: List[str] = Field(default_factory=list, description="Post-simulation recommendations")
    artifacts: Dict[str, Any] = Field(default_factory=dict, description="Additional artifacts (files, links, etc.)")

    # Environment information
    environment: Dict[str, str] = Field(default_factory=dict, description="Environment information")

    @field_validator('simulation_id')
    @classmethod
    def validate_simulation_id(cls, v):
        try:
            uuid.UUID(v)
            return v
        except ValueError:
            raise ValueError("simulation_id must be a valid UUID")

    @field_validator('generated_content')
    @classmethod
    def at_least_one_content(cls, v):
        if not v:
            return v  # Allow empty for failed simulations
        return v

    def add_log_entry(self, message: str) -> None:
        """Add a log entry with timestamp."""
        timestamp = datetime.utcnow().isoformat()
        self.logs.append(f"[{timestamp}] {message}")

    def mark_started(self) -> None:
        """Mark simulation as started."""
        self.started_at = datetime.utcnow()
        self.status = SimulationStatus.RUNNING
        self.add_log_entry("Simulation started")

    def mark_completed(self, success: bool = True, error_message: Optional[str] = None) -> None:
        """Mark simulation as completed."""
        self.completed_at = datetime.utcnow()
        self.success = success
        self.status = SimulationStatus.COMPLETED if success else SimulationStatus.FAILED
        self.error_message = error_message
        self.add_log_entry(f"Simulation completed - Success: {success}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return self.dict(by_alias=True, exclude_none=False)

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_yaml(self) -> str:
        """Convert to YAML string."""
        import yaml
        return yaml.dump(self.to_dict(), default_flow_style=False, allow_unicode=True)


class SimulationOutputValidator:
    """Validator for simulation output data."""

    @staticmethod
    def validate_output(data: Dict[str, Any]) -> SimulationOutput:
        """Validate raw simulation data and return validated output."""
        try:
            return SimulationOutput(**data)
        except Exception as e:
            raise ValueError(f"Invalid simulation output format: {e}")

    @staticmethod
    def validate_json_string(json_str: str) -> SimulationOutput:
        """Validate JSON string and return validated output."""
        import json
        try:
            data = json.loads(json_str)
            return SimulationOutputValidator.validate_output(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")

    @staticmethod
    def validate_yaml_string(yaml_str: str) -> SimulationOutput:
        """Validate YAML string and return validated output."""
        import yaml
        try:
            data = yaml.safe_load(yaml_str)
            return SimulationOutputValidator.validate_output(data)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML format: {e}")


# Example usage and template
def create_example_output() -> SimulationOutput:
    """Create an example simulation output for reference."""
    return SimulationOutput(
        status=SimulationStatus.COMPLETED,
        success=True,
        scenario=ScenarioMetadata(
            name="Test Phishing Simulation",
            description="Educational phishing email simulation",
            threat_type="phishing",
            delivery_vector="email",
            difficulty_level=3,
            mitre_techniques=["T1566.002"]
        ),
        target_profile=TargetProfile(
            role="General Employee",
            department="IT",
            seniority="mid",
            industry="technology",
            security_awareness=5
        ),
        generated_content=[
            ContentGeneration(
                content_type=ContentType.EMAIL,
                content="Subject: Urgent IT Security Update\n\nDear Employee...",
                prompt_used="Create educational phishing email...",
                provider_info=ProviderInfo(
                    name="openrouter",
                    model="anthropic/claude-3-haiku",
                    response_time_ms=1200,
                    token_usage={"prompt_tokens": 150, "completion_tokens": 300}
                )
            )
        ],
        metrics=SimulationMetrics(
            success_rate=100.0,
            stages_completed=1,
            total_stages=1,
            duration_seconds=2.5
        ),
        quality_assessment=QualityAssessment(
            realism_score=8,
            educational_value=9,
            detection_indicators=["Suspicious sender domain", "Urgent language"]
        ),
        recommendations=[
            "Review email security training materials",
            "Update phishing detection tools"
        ]
    )
