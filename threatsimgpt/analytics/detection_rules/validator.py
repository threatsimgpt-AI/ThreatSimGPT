"""Rule Validator for Detection Rules.

Provides comprehensive validation for all detection rule formats.

Author: David Onoja (Blue Team)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .models import DetectionRule, RuleFormat


class ValidationSeverity(str, Enum):
    """Severity of validation issues."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    """A single validation issue."""
    severity: ValidationSeverity
    code: str
    message: str
    field: Optional[str] = None
    suggestion: Optional[str] = None


@dataclass 
class ValidationResult:
    """Result of rule validation."""
    is_valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    format: Optional[RuleFormat] = None
    
    @property
    def errors(self) -> List[ValidationIssue]:
        """Get only error-level issues."""
        return [i for i in self.issues if i.severity == ValidationSeverity.ERROR]
    
    @property
    def warnings(self) -> List[ValidationIssue]:
        """Get only warning-level issues."""
        return [i for i in self.issues if i.severity == ValidationSeverity.WARNING]
    
    def add_error(self, code: str, message: str, field: str = None, suggestion: str = None):
        """Add an error issue."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.ERROR,
            code=code,
            message=message,
            field=field,
            suggestion=suggestion,
        ))
        self.is_valid = False
    
    def add_warning(self, code: str, message: str, field: str = None, suggestion: str = None):
        """Add a warning issue."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.WARNING,
            code=code,
            message=message,
            field=field,
            suggestion=suggestion,
        ))
    
    def add_info(self, code: str, message: str, field: str = None):
        """Add an informational issue."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.INFO,
            code=code,
            message=message,
            field=field,
        ))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_valid": self.is_valid,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "issues": [
                {
                    "severity": issue.severity,
                    "code": issue.code,
                    "message": issue.message,
                    "field": issue.field,
                    "suggestion": issue.suggestion,
                }
                for issue in self.issues
            ]
        }


class RuleValidator:
    """Validates detection rules across all formats."""
    
    def __init__(self):
        """Initialize the validator."""
        pass
    
    def validate(self, rule: DetectionRule) -> ValidationResult:
        """Validate a DetectionRule object.
        
        Args:
            rule: DetectionRule to validate
            
        Returns:
            ValidationResult with all issues found
        """
        result = ValidationResult(is_valid=True)
        
        # Validate basic fields
        self._validate_identification(rule, result)
        self._validate_metadata(rule, result)
        self._validate_detection_logic(rule, result)
        self._validate_logsource(rule, result)
        self._validate_mitre_mappings(rule, result)
        
        # Quality checks
        self._check_quality(rule, result)
        
        return result
    
    def validate_sigma(self, sigma_yaml: str) -> ValidationResult:
        """Validate Sigma YAML content.
        
        Args:
            sigma_yaml: Sigma rule in YAML format
            
        Returns:
            ValidationResult
        """
        from .sigma import SigmaRuleGenerator
        
        result = ValidationResult(is_valid=True, format=RuleFormat.SIGMA)
        generator = SigmaRuleGenerator()
        is_valid, errors = generator.validate(sigma_yaml)
        
        for error in errors:
            result.add_error("SIGMA_SYNTAX", error)
        
        return result
    
    def validate_splunk(self, spl_query: str) -> ValidationResult:
        """Validate Splunk SPL content.
        
        Args:
            spl_query: Splunk SPL query
            
        Returns:
            ValidationResult
        """
        from .splunk import SplunkRuleGenerator
        
        result = ValidationResult(is_valid=True, format=RuleFormat.SPLUNK)
        generator = SplunkRuleGenerator()
        is_valid, errors = generator.validate(spl_query)
        
        for error in errors:
            result.add_error("SPLUNK_SYNTAX", error)
        
        return result
    
    def validate_elastic(self, elastic_json: str) -> ValidationResult:
        """Validate Elastic rule JSON.
        
        Args:
            elastic_json: Elastic detection rule JSON
            
        Returns:
            ValidationResult
        """
        from .elastic import ElasticRuleGenerator
        
        result = ValidationResult(is_valid=True, format=RuleFormat.ELASTIC)
        generator = ElasticRuleGenerator()
        is_valid, errors = generator.validate(elastic_json)
        
        for error in errors:
            result.add_error("ELASTIC_SYNTAX", error)
        
        return result
    
    def validate_sentinel(self, sentinel_content: str) -> ValidationResult:
        """Validate Sentinel rule content.
        
        Args:
            sentinel_content: Sentinel rule (KQL + ARM template)
            
        Returns:
            ValidationResult
        """
        from .sentinel import SentinelRuleGenerator
        
        result = ValidationResult(is_valid=True, format=RuleFormat.SENTINEL)
        generator = SentinelRuleGenerator()
        is_valid, errors = generator.validate(sentinel_content)
        
        for error in errors:
            result.add_error("SENTINEL_SYNTAX", error)
        
        return result
    
    def _validate_identification(self, rule: DetectionRule, result: ValidationResult):
        """Validate rule identification fields."""
        
        if not rule.title or len(rule.title) < 5:
            result.add_error(
                "TITLE_TOO_SHORT",
                "Rule title must be at least 5 characters",
                field="title",
                suggestion="Provide a descriptive title that explains what the rule detects"
            )
        
        if len(rule.title) > 200:
            result.add_warning(
                "TITLE_TOO_LONG",
                "Rule title is very long (>200 chars)",
                field="title",
                suggestion="Consider shortening the title"
            )
        
        if not rule.description or len(rule.description) < 20:
            result.add_warning(
                "DESCRIPTION_SHORT",
                "Rule description should be at least 20 characters",
                field="description",
                suggestion="Provide a detailed description of what the rule detects and why"
            )
    
    def _validate_metadata(self, rule: DetectionRule, result: ValidationResult):
        """Validate rule metadata."""
        
        if not rule.metadata.author:
            result.add_warning(
                "NO_AUTHOR",
                "Rule has no author specified",
                field="metadata.author"
            )
        
        if not rule.metadata.references:
            result.add_info(
                "NO_REFERENCES",
                "Consider adding references to threat reports or documentation",
                field="metadata.references"
            )
        
        if not rule.metadata.false_positives:
            result.add_warning(
                "NO_FALSE_POSITIVES",
                "Consider documenting known false positive scenarios",
                field="metadata.false_positives",
                suggestion="Add scenarios where this rule might trigger incorrectly"
            )
    
    def _validate_detection_logic(self, rule: DetectionRule, result: ValidationResult):
        """Validate detection logic."""
        
        if not rule.detection.selection:
            result.add_error(
                "EMPTY_SELECTION",
                "Detection logic has no selection criteria",
                field="detection.selection",
                suggestion="Add field-value pairs to match events"
            )
        
        if not rule.detection.condition:
            result.add_error(
                "NO_CONDITION",
                "Detection logic has no condition",
                field="detection.condition",
                suggestion="Add a condition like 'selection' or 'selection and not filter'"
            )
        
        # Check for overly broad rules
        selection_fields = len(rule.detection.selection)
        if selection_fields < 2:
            result.add_warning(
                "BROAD_RULE",
                "Rule has very few selection criteria and may generate many false positives",
                field="detection.selection",
                suggestion="Add more specific field conditions to reduce false positives"
            )
        
        # Check for wildcard-only patterns
        for field, value in rule.detection.selection.items():
            if isinstance(value, str) and value in ("*", ".*", "**"):
                result.add_warning(
                    "WILDCARD_ONLY",
                    f"Field '{field}' matches everything - this is likely too broad",
                    field=f"detection.selection.{field}"
                )
    
    def _validate_logsource(self, rule: DetectionRule, result: ValidationResult):
        """Validate log source configuration."""
        
        logsource = rule.logsource
        if not logsource.category and not logsource.product and not logsource.service:
            result.add_error(
                "NO_LOGSOURCE",
                "Rule has no log source specified",
                field="logsource",
                suggestion="Specify at least one of: category, product, or service"
            )
    
    def _validate_mitre_mappings(self, rule: DetectionRule, result: ValidationResult):
        """Validate MITRE ATT&CK mappings."""
        
        if not rule.mitre_attack:
            result.add_warning(
                "NO_MITRE_MAPPING",
                "Rule has no MITRE ATT&CK mapping",
                field="mitre_attack",
                suggestion="Map the rule to relevant MITRE ATT&CK techniques"
            )
            return
        
        for i, mapping in enumerate(rule.mitre_attack):
            # Validate technique ID format
            if not mapping.technique_id.startswith("T"):
                result.add_error(
                    "INVALID_TECHNIQUE_ID",
                    f"Invalid MITRE technique ID: {mapping.technique_id}",
                    field=f"mitre_attack[{i}].technique_id",
                    suggestion="Use format like T1566 or T1566.001"
                )
            
            # Validate tactic ID format
            if not mapping.tactic_id.startswith("TA"):
                result.add_error(
                    "INVALID_TACTIC_ID",
                    f"Invalid MITRE tactic ID: {mapping.tactic_id}",
                    field=f"mitre_attack[{i}].tactic_id",
                    suggestion="Use format like TA0001"
                )
    
    def _check_quality(self, rule: DetectionRule, result: ValidationResult):
        """Run quality checks on the rule."""
        
        # Check severity appropriateness
        selection_size = len(rule.detection.selection)
        has_filter = rule.detection.filter is not None
        
        # Get severity value (handle both enum and string)
        severity_value = rule.severity.value if hasattr(rule.severity, 'value') else str(rule.severity)
        
        # High/Critical severity rules should be more specific
        if severity_value in ("high", "critical"):
            if selection_size < 3 and not has_filter:
                result.add_warning(
                    "HIGH_SEVERITY_BROAD",
                    f"High/critical severity rule has few selection criteria ({selection_size})",
                    suggestion="Consider adding more specific criteria or reducing severity"
                )
        
        # Check for detection coverage
        mitre_count = len(rule.mitre_attack)
        if mitre_count > 5:
            result.add_info(
                "MANY_TECHNIQUES",
                f"Rule maps to {mitre_count} MITRE techniques - consider splitting",
            )


def validate_rule(rule: DetectionRule) -> ValidationResult:
    """Convenience function to validate a rule.
    
    Args:
        rule: DetectionRule to validate
        
    Returns:
        ValidationResult
    """
    validator = RuleValidator()
    return validator.validate(rule)


def validate_format(content: str, format: RuleFormat) -> ValidationResult:
    """Validate content in a specific format.
    
    Args:
        content: Rule content string
        format: Target format
        
    Returns:
        ValidationResult
    """
    validator = RuleValidator()
    
    if format == RuleFormat.SIGMA:
        return validator.validate_sigma(content)
    elif format == RuleFormat.SPLUNK:
        return validator.validate_splunk(content)
    elif format == RuleFormat.ELASTIC:
        return validator.validate_elastic(content)
    elif format == RuleFormat.SENTINEL:
        return validator.validate_sentinel(content)
    else:
        result = ValidationResult(is_valid=False)
        result.add_error("UNSUPPORTED_FORMAT", f"Format {format} is not supported")
        return result
