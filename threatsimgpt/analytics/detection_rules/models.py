"""Data models for Detection Rule Generator.

Defines the core data structures for SIEM detection rules.

Author: David Onoja (Blue Team)
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from pydantic import BaseModel, Field, ConfigDict


class RuleFormat(str, Enum):
    """Supported detection rule formats."""
    SIGMA = "sigma"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    SENTINEL = "sentinel"
    YARA = "yara"  # Future support
    SNORT = "snort"  # Future support


class RuleSeverity(str, Enum):
    """Rule severity levels aligned with SIEM standards."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleStatus(str, Enum):
    """Rule lifecycle status."""
    EXPERIMENTAL = "experimental"
    TEST = "test"
    STABLE = "stable"
    DEPRECATED = "deprecated"


class LogSource(str, Enum):
    """Common log sources for detection rules."""
    WINDOWS_SECURITY = "windows_security"
    WINDOWS_SYSMON = "windows_sysmon"
    WINDOWS_POWERSHELL = "windows_powershell"
    LINUX_SYSLOG = "linux_syslog"
    LINUX_AUDITD = "linux_auditd"
    NETWORK_FIREWALL = "network_firewall"
    NETWORK_DNS = "network_dns"
    NETWORK_PROXY = "network_proxy"
    EMAIL_GATEWAY = "email_gateway"
    CLOUD_AWS = "cloud_aws"
    CLOUD_AZURE = "cloud_azure"
    CLOUD_GCP = "cloud_gcp"
    ENDPOINT_EDR = "endpoint_edr"
    WEB_SERVER = "web_server"
    DATABASE = "database"
    CUSTOM = "custom"


class MitreMapping(BaseModel):
    """MITRE ATT&CK mapping for a detection rule."""
    
    tactic_id: str = Field(..., description="MITRE tactic ID (e.g., TA0001)")
    tactic_name: str = Field(..., description="Tactic name (e.g., Initial Access)")
    technique_id: str = Field(..., description="MITRE technique ID (e.g., T1566)")
    technique_name: str = Field(..., description="Technique name (e.g., Phishing)")
    sub_technique_id: Optional[str] = Field(None, description="Sub-technique ID (e.g., T1566.001)")
    sub_technique_name: Optional[str] = Field(None, description="Sub-technique name")
    
    @property
    def full_technique_id(self) -> str:
        """Get full technique ID including sub-technique."""
        if self.sub_technique_id:
            return self.sub_technique_id
        return self.technique_id
    
    def to_sigma_tags(self) -> List[str]:
        """Convert to Sigma tag format."""
        tags = [
            f"attack.{self.tactic_name.lower().replace(' ', '_')}",
            f"attack.{self.technique_id.lower()}",
        ]
        if self.sub_technique_id:
            tags.append(f"attack.{self.sub_technique_id.lower()}")
        return tags


class DetectionLogic(BaseModel):
    """Detection logic definition for a rule."""
    
    # Selection criteria
    selection: Dict[str, Any] = Field(
        default_factory=dict,
        description="Field-value pairs for positive selection"
    )
    
    # Filter criteria (exclusions)
    filter: Optional[Dict[str, Any]] = Field(
        None,
        description="Field-value pairs to exclude from detection"
    )
    
    # Condition expression
    condition: str = Field(
        "selection",
        description="Boolean condition combining selection and filter"
    )
    
    # Aggregation for correlation rules
    aggregation: Optional[Dict[str, Any]] = Field(
        None,
        description="Aggregation settings for correlation (count, timeframe, etc.)"
    )
    
    # Time window for the detection
    timeframe: Optional[str] = Field(
        None,
        description="Time window for detection (e.g., 5m, 1h, 24h)"
    )
    
    def to_sigma_detection(self) -> Dict[str, Any]:
        """Convert to Sigma detection section format."""
        detection = {
            "selection": self.selection,
            "condition": self.condition,
        }
        if self.filter:
            detection["filter"] = self.filter
        if self.timeframe:
            detection["timeframe"] = self.timeframe
        return detection


class RuleMetadata(BaseModel):
    """Metadata for a detection rule."""
    
    author: str = Field("ThreatSimGPT", description="Rule author")
    date: str = Field(
        default_factory=lambda: datetime.now().strftime("%Y/%m/%d"),
        description="Rule creation date"
    )
    modified: Optional[str] = Field(None, description="Last modification date")
    
    # References and documentation
    references: List[str] = Field(
        default_factory=list,
        description="External references (URLs, papers, etc.)"
    )
    
    # False positive guidance
    false_positives: List[str] = Field(
        default_factory=list,
        description="Known false positive scenarios"
    )
    
    # Tags for categorization
    tags: List[str] = Field(
        default_factory=list,
        description="Custom tags for rule categorization"
    )
    
    # Related rules
    related_rules: List[str] = Field(
        default_factory=list,
        description="IDs of related detection rules"
    )
    
    # Source scenario
    source_scenario_id: Optional[str] = Field(
        None,
        description="ID of the ThreatSimGPT scenario that generated this rule"
    )


class LogSourceConfig(BaseModel):
    """Log source configuration for detection rules."""
    
    category: Optional[str] = Field(None, description="Log category (process_creation, etc.)")
    product: Optional[str] = Field(None, description="Product name (windows, linux, etc.)")
    service: Optional[str] = Field(None, description="Service name (security, sysmon, etc.)")
    definition: Optional[str] = Field(None, description="Custom log source definition")


class DetectionRule(BaseModel):
    """Complete detection rule model."""
    
    # Identification
    rule_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique rule identifier"
    )
    title: str = Field(..., description="Human-readable rule title")
    name: Optional[str] = Field(None, description="Rule name (slug format)")
    
    # Classification
    status: RuleStatus = Field(
        RuleStatus.EXPERIMENTAL,
        description="Rule maturity status"
    )
    severity: RuleSeverity = Field(
        RuleSeverity.MEDIUM,
        description="Alert severity level"
    )
    
    # Description
    description: str = Field(..., description="Detailed rule description")
    
    # Log source configuration
    logsource: LogSourceConfig = Field(
        default_factory=LogSourceConfig,
        description="Log source specification"
    )
    
    # Detection logic
    detection: DetectionLogic = Field(..., description="Detection logic definition")
    
    # MITRE ATT&CK mapping
    mitre_attack: List[MitreMapping] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique mappings"
    )
    
    # Metadata
    metadata: RuleMetadata = Field(
        default_factory=RuleMetadata,
        description="Rule metadata"
    )
    
    # Output format tracking
    formats_generated: List[RuleFormat] = Field(
        default_factory=list,
        description="Formats this rule has been exported to"
    )
    
    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Rule creation timestamp"
    )
    updated_at: Optional[datetime] = Field(
        None,
        description="Last update timestamp"
    )
    
    def get_sigma_tags(self) -> List[str]:
        """Get all Sigma-compatible tags."""
        tags = list(self.metadata.tags)
        for mapping in self.mitre_attack:
            tags.extend(mapping.to_sigma_tags())
        return list(set(tags))
    
    def get_severity_level(self) -> int:
        """Get numeric severity level (1-5)."""
        levels = {
            RuleSeverity.INFORMATIONAL: 1,
            RuleSeverity.LOW: 2,
            RuleSeverity.MEDIUM: 3,
            RuleSeverity.HIGH: 4,
            RuleSeverity.CRITICAL: 5,
        }
        return levels.get(self.severity, 3)

    model_config = ConfigDict(use_enum_values=True)


class RuleGenerationRequest(BaseModel):
    """Request model for rule generation."""
    
    scenario_id: Optional[str] = Field(None, description="Source scenario ID")
    scenario_name: str = Field(..., description="Attack scenario name")
    scenario_description: str = Field(..., description="Attack scenario description")
    
    # Attack details
    attack_type: str = Field(..., description="Type of attack (phishing, malware, etc.)")
    attack_vectors: List[str] = Field(default_factory=list, description="Attack vectors used")
    target_systems: List[str] = Field(default_factory=list, description="Target systems")
    
    # MITRE mapping (optional - can be auto-detected)
    mitre_techniques: List[str] = Field(
        default_factory=list,
        description="MITRE technique IDs (e.g., T1566.001)"
    )
    
    # Output preferences
    formats: List[RuleFormat] = Field(
        default=[RuleFormat.SIGMA],
        description="Desired output formats"
    )
    severity_override: Optional[RuleSeverity] = Field(
        None,
        description="Override auto-detected severity"
    )
    
    # Customization
    custom_fields: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional custom fields for rule generation"
    )


class RuleGenerationResult(BaseModel):
    """Result of rule generation."""
    
    success: bool = Field(..., description="Whether generation succeeded")
    rule: Optional[DetectionRule] = Field(None, description="Generated rule object")
    
    # Exported formats
    sigma_yaml: Optional[str] = Field(None, description="Sigma YAML output")
    splunk_spl: Optional[str] = Field(None, description="Splunk SPL query")
    elastic_kql: Optional[str] = Field(None, description="Elastic KQL query")
    sentinel_kql: Optional[str] = Field(None, description="Sentinel KQL query")
    
    # Validation results
    validation_passed: bool = Field(True, description="Whether validation passed")
    validation_errors: List[str] = Field(default_factory=list, description="Validation errors")
    validation_warnings: List[str] = Field(default_factory=list, description="Validation warnings")
    
    # Generation metadata
    generation_time_ms: float = Field(0, description="Time taken to generate (ms)")
    generated_at: datetime = Field(default_factory=datetime.utcnow)
