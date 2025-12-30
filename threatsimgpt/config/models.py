"""Comprehensive configuration models for ThreatSimGPT.

This module defines the complete YAML schema using Pydantic models for
threat scenario configurations, validation, and type safety.
"""

import re
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator


class ThreatType(str, Enum):
    """Types of cybersecurity threats that can be simulated."""

    PHISHING = "phishing"
    SPEAR_PHISHING = "spear_phishing"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    SOCIAL_ENGINEERING = "social_engineering"
    INSIDER_THREAT = "insider_threat"
    APT = "advanced_persistent_threat"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    WATERING_HOLE = "watering_hole"
    SUPPLY_CHAIN = "supply_chain"
    PHYSICAL_SECURITY = "physical_security"
    VISHING = "voice_phishing"
    SMISHING = "sms_phishing"


class DeliveryVector(str, Enum):
    """Methods used to deliver threat scenarios."""

    EMAIL = "email"
    SMS = "sms"
    SOCIAL_MEDIA = "social_media"
    PHONE_CALL = "phone_call"
    USB_DEVICE = "usb_device"
    NETWORK_INTRUSION = "network_intrusion"
    PHYSICAL_ACCESS = "physical_access"
    WEB_APPLICATION = "web_application"
    MOBILE_APP = "mobile_app"
    QR_CODE = "qr_code"
    MESSAGING_APP = "messaging_app"
    VIDEO_CONFERENCE = "video_conference"


class SeniorityLevel(str, Enum):
    """Organizational seniority levels for target profiling."""

    ENTRY = "entry"
    JUNIOR = "junior"
    MID = "mid"
    SENIOR = "senior"
    LEAD = "lead"
    MANAGER = "manager"
    DIRECTOR = "director"
    VP = "vice_president"
    SVP = "senior_vice_president"
    EXECUTIVE = "executive"
    C_LEVEL = "c_level"


class TechnicalLevel(str, Enum):
    """Technical sophistication levels for targets."""

    BASIC = "basic"
    MODERATE = "moderate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class IndustryType(str, Enum):
    """Industry categories for target organizations."""

    TECHNOLOGY = "technology"
    FINANCIAL_SERVICES = "financial_services"
    HEALTHCARE = "healthcare"
    GOVERNMENT = "government"
    EDUCATION = "education"
    RETAIL = "retail"
    MANUFACTURING = "manufacturing"
    ENERGY = "energy"
    TELECOMMUNICATIONS = "telecommunications"
    MEDIA = "media"
    LEGAL = "legal"
    CONSULTING = "consulting"
    NON_PROFIT = "non_profit"
    STARTUP = "startup"
    OTHER = "other"


class CompanySize(str, Enum):
    """Organization size categories."""

    STARTUP = "startup"  # 1-10 employees
    SMALL = "small"      # 11-50 employees
    MEDIUM = "medium"    # 51-200 employees
    LARGE = "large"      # 201-1000 employees
    ENTERPRISE = "enterprise"  # 1000+ employees


class DifficultyLevel(int, Enum):
    """Simulation difficulty levels (1-10 scale)."""

    TRIVIAL = 1
    VERY_EASY = 2
    EASY = 3
    MODERATE_EASY = 4
    MODERATE = 5
    MODERATE_HARD = 6
    HARD = 7
    VERY_HARD = 8
    EXPERT = 9
    EXTREME = 10


class ScenarioMetadata(BaseModel):
    """Metadata for threat scenarios."""

    name: str = Field(..., description="Human-readable scenario name", min_length=3, max_length=100)
    description: str = Field(..., description="Detailed scenario description", min_length=10, max_length=500)
    version: str = Field(default="1.0.0", description="Scenario version", pattern=r"^\d+\.\d+\.\d+$")
    author: Optional[str] = Field(None, description="Scenario author", max_length=100)
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(default_factory=datetime.utcnow, description="Last update timestamp")
    tags: List[str] = Field(default_factory=list, description="Scenario tags for categorization")
    references: List[str] = Field(default_factory=list, description="External references and sources")


class TargetProfile(BaseModel):
    """Comprehensive target profile for threat scenarios."""

    # Personal characteristics
    role: str = Field(..., description="Job role/title", min_length=2, max_length=100)
    seniority: SeniorityLevel = Field(..., description="Organizational seniority level")
    department: str = Field(..., description="Department or team", min_length=2, max_length=50)
    technical_level: TechnicalLevel = Field(..., description="Technical sophistication level")

    # Organizational context
    industry: Optional[IndustryType] = Field(None, description="Industry sector")
    company_size: Optional[CompanySize] = Field(None, description="Organization size")
    company_name: Optional[str] = Field(None, description="Company name (if simulating specific org)", max_length=100)

    # Behavioral patterns
    typical_working_hours: Optional[str] = Field(None, description="Typical working hours pattern")
    communication_style: Optional[str] = Field(None, description="Preferred communication style")
    security_awareness_level: Optional[int] = Field(None, ge=1, le=10, description="Security awareness (1-10)")

    # Personal details (for social engineering)
    interests: List[str] = Field(default_factory=list, description="Personal/professional interests")
    social_media_presence: Optional[Dict[str, Any]] = Field(None, description="Social media activity patterns")

    @field_validator('role')
    @classmethod
    def validate_role(cls, v):
        """Validate role field."""
        if not v.strip():
            raise ValueError("Role cannot be empty")
        return v.strip().title()


class BehavioralPattern(BaseModel):
    """Behavioral patterns and tactics for threat simulation."""

    # MITRE ATT&CK integration
    mitre_attack_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    mitre_attack_tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK tactic names")

    # Psychological tactics
    psychological_triggers: List[str] = Field(
        default_factory=list,
        description="Psychological triggers (urgency, authority, fear, etc.)"
    )
    social_engineering_tactics: List[str] = Field(
        default_factory=list,
        description="Social engineering approaches"
    )

    # Technical approaches
    technical_methods: List[str] = Field(
        default_factory=list,
        description="Technical methods and tools used"
    )
    evasion_techniques: List[str] = Field(
        default_factory=list,
        description="Security evasion techniques"
    )

    @field_validator('mitre_attack_techniques')
    @classmethod
    def validate_mitre_techniques(cls, v):
        """Validate MITRE ATT&CK technique format."""
        if isinstance(v, list):
            for technique in v:
                pattern = r'^T\d{4}(\.\d{3})?$'
                if not re.match(pattern, technique):
                    raise ValueError(f"Invalid MITRE ATT&CK technique format: {technique}")
        return v


class SimulationParameters(BaseModel):
    """Parameters controlling simulation execution."""

    # Execution control
    max_iterations: int = Field(default=3, ge=1, le=10, description="Maximum simulation iterations")
    max_duration_minutes: int = Field(default=60, ge=5, le=480, description="Maximum duration in minutes")
    escalation_enabled: bool = Field(default=True, description="Enable dynamic escalation")
    response_adaptation: bool = Field(default=True, description="Adapt based on target responses")

    # Realism settings
    time_pressure_simulation: bool = Field(default=False, description="Simulate time pressure scenarios")
    multi_stage_attack: bool = Field(default=False, description="Enable multi-stage attack simulation")
    persistence_simulation: bool = Field(default=False, description="Simulate attacker persistence")

    # Content generation
    language: str = Field(default="en", description="Content language code")
    tone: str = Field(default="professional", description="Communication tone")
    urgency_level: int = Field(default=5, ge=1, le=10, description="Urgency level (1-10)")

    # Compliance and safety
    compliance_mode: bool = Field(default=True, description="Enable compliance checking")
    content_filtering: bool = Field(default=True, description="Enable content filtering")
    audit_logging: bool = Field(default=True, description="Enable comprehensive audit logging")

    @field_validator('language')
    @classmethod
    def validate_language(cls, v):
        """Validate language code format."""
        if not re.match(r'^[a-z]{2}(-[A-Z]{2})?$', v):
            raise ValueError("Language must be in format 'en' or 'en-US'")
        return v


class ThreatScenario(BaseModel):
    """Complete threat scenario configuration."""

    # Core identification
    metadata: ScenarioMetadata = Field(..., description="Scenario metadata and identification")
    threat_type: ThreatType = Field(..., description="Type of threat being simulated")
    delivery_vector: DeliveryVector = Field(..., description="Method of threat delivery")

    # Target and context
    target_profile: TargetProfile = Field(..., description="Target profile and characteristics")
    behavioral_pattern: BehavioralPattern = Field(..., description="Attack patterns and tactics")

    # Simulation control
    difficulty_level: DifficultyLevel = Field(..., description="Simulation difficulty (1-10)")
    estimated_duration: int = Field(..., ge=5, le=480, description="Estimated duration in minutes")
    simulation_parameters: SimulationParameters = Field(
        default_factory=SimulationParameters,
        description="Simulation execution parameters"
    )

    # Custom extensions
    custom_parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Custom scenario-specific parameters"
    )

    # Validation rules
    @model_validator(mode='after')
    def validate_scenario_consistency(self):
        """Validate scenario consistency and logical constraints."""
        threat_type = self.threat_type
        delivery_vector = self.delivery_vector
        difficulty = self.difficulty_level
        duration = self.estimated_duration

        # Validate threat type and delivery vector compatibility
        incompatible_combinations = {
            ThreatType.RANSOMWARE: [DeliveryVector.SMS, DeliveryVector.PHONE_CALL],
            ThreatType.VISHING: [DeliveryVector.EMAIL, DeliveryVector.SMS],
            ThreatType.SMISHING: [DeliveryVector.EMAIL, DeliveryVector.PHONE_CALL]
        }

        if threat_type in incompatible_combinations:
            if delivery_vector in incompatible_combinations[threat_type]:
                raise ValueError(f"Incompatible combination: {threat_type} with {delivery_vector}")

        # Validate duration based on difficulty
        if difficulty and duration:
            difficulty_value = difficulty.value if hasattr(difficulty, 'value') else difficulty
            min_duration = difficulty_value * 5  # Minimum 5 minutes per difficulty level
            if duration < min_duration:
                raise ValueError(f"Duration too short for difficulty {difficulty}: minimum {min_duration} minutes")

        return self

    class Config:
        """Pydantic configuration."""
        use_enum_values = True
        validate_assignment = True
        extra = "forbid"  # Reject unknown fields
        json_schema_extra = {
            "example": {
                "metadata": {
                    "name": "Executive Phishing Campaign",
                    "description": "Sophisticated spear-phishing attack targeting C-level executives",
                    "version": "1.0.0",
                    "author": "Security Team",
                    "tags": ["phishing", "executive", "high-priority"]
                },
                "threat_type": "spear_phishing",
                "delivery_vector": "email",
                "target_profile": {
                    "role": "Chief Executive Officer",
                    "seniority": "c_level",
                    "department": "executive",
                    "technical_level": "moderate",
                    "industry": "financial_services",
                    "company_size": "enterprise"
                },
                "behavioral_pattern": {
                    "mitre_attack_techniques": ["T1566.001", "T1566.002"],
                    "psychological_triggers": ["authority", "urgency", "curiosity"],
                    "social_engineering_tactics": ["pretexting", "impersonation"]
                },
                "difficulty_level": 8,
                "estimated_duration": 45,
                "simulation_parameters": {
                    "max_iterations": 3,
                    "escalation_enabled": True,
                    "response_adaptation": True,
                    "urgency_level": 8
                }
            }
        }
