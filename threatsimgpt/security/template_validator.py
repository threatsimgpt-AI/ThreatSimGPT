"""Template Security Validator for ThreatSimGPT.

This module provides comprehensive security validation for threat scenario templates,
detecting injection attacks, malicious content, path traversal, and other security
issues that could compromise the system or enable abuse.

Security Categories Validated:
- Injection Attacks: YAML injection, command injection, code injection
- Path Traversal: Directory traversal, symlink attacks
- Malicious Content: Harmful URLs, credential patterns, PII exposure
- Resource Abuse: DoS patterns, excessive resource consumption
- Compliance: Ethical boundaries, content policy violations
"""

import hashlib
import ipaddress
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field


class SecuritySeverity(str, Enum):
    """Security finding severity levels aligned with CVSS."""
    
    CRITICAL = "critical"  # 9.0-10.0: Immediate action required
    HIGH = "high"          # 7.0-8.9: Should be fixed urgently
    MEDIUM = "medium"      # 4.0-6.9: Should be addressed
    LOW = "low"            # 0.1-3.9: Minor issue
    INFO = "info"          # Informational finding


class SecurityCategory(str, Enum):
    """Categories of security findings."""
    
    INJECTION = "injection"
    PATH_TRAVERSAL = "path_traversal"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    MALICIOUS_URL = "malicious_url"
    PII_EXPOSURE = "pii_exposure"
    RESOURCE_ABUSE = "resource_abuse"
    YAML_SECURITY = "yaml_security"
    CONTENT_POLICY = "content_policy"
    ENCODING_ATTACK = "encoding_attack"
    SCHEMA_VIOLATION = "schema_violation"


@dataclass
class SecurityFinding:
    """Represents a security issue found during validation."""
    
    severity: SecuritySeverity
    category: SecurityCategory
    title: str
    description: str
    location: str  # Path in the template (e.g., "metadata.name" or "custom_parameters.url")
    value_preview: str  # Sanitized preview of the problematic value
    remediation: str
    cwe_id: Optional[str] = None  # Common Weakness Enumeration ID
    cvss_vector: Optional[str] = None
    mitre_technique: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "value_preview": self.value_preview,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "cvss_vector": self.cvss_vector,
            "mitre_technique": self.mitre_technique,
        }


@dataclass
class SecurityValidationResult:
    """Complete result of security validation."""
    
    is_secure: bool
    findings: List[SecurityFinding]
    scan_timestamp: datetime
    scan_duration_ms: float
    template_hash: str
    validation_id: str
    
    # Aggregated statistics
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    def __post_init__(self):
        """Calculate severity counts after initialization."""
        for finding in self.findings:
            if finding.severity == SecuritySeverity.CRITICAL:
                self.critical_count += 1
            elif finding.severity == SecuritySeverity.HIGH:
                self.high_count += 1
            elif finding.severity == SecuritySeverity.MEDIUM:
                self.medium_count += 1
            elif finding.severity == SecuritySeverity.LOW:
                self.low_count += 1
            else:
                self.info_count += 1
    
    @property
    def blocking_findings(self) -> List[SecurityFinding]:
        """Return findings that should block template usage."""
        return [f for f in self.findings 
                if f.severity in (SecuritySeverity.CRITICAL, SecuritySeverity.HIGH)]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "is_secure": self.is_secure,
            "validation_id": self.validation_id,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "scan_duration_ms": self.scan_duration_ms,
            "template_hash": self.template_hash,
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "findings": [f.to_dict() for f in self.findings],
        }


class TemplateSecurityValidator:
    """Comprehensive security validator for threat scenario templates.
    
    This validator implements defense-in-depth with multiple security checks:
    1. Input sanitization and encoding validation
    2. Injection attack detection (YAML, command, code, SQL)
    3. Path traversal and file inclusion prevention
    4. Credential and secret detection
    5. Malicious URL and domain detection
    6. PII exposure detection
    7. Resource abuse prevention
    8. Content policy enforcement
    
    Usage:
        validator = TemplateSecurityValidator()
        result = validator.validate_template(template_data)
        if not result.is_secure:
            for finding in result.blocking_findings:
                print(f"[{finding.severity}] {finding.title}: {finding.description}")
    """
    
    # ==================== Pattern Definitions ====================
    
    # YAML/Command Injection patterns
    YAML_INJECTION_PATTERNS = [
        # YAML directives and anchors that could be exploited
        (r'!!python/', "Python object deserialization"),
        (r'!!ruby/', "Ruby object deserialization"),
        (r'!!perl/', "Perl object deserialization"),
        (r'!!java/', "Java object deserialization"),
        (r'!!\w+/\w+', "Generic YAML tag injection"),
        (r'<<:\s*\*', "YAML merge key with anchor reference"),
        (r'\*[a-zA-Z_]\w*', "YAML anchor reference"),
        (r'&[a-zA-Z_]\w*', "YAML anchor definition"),
        # YAML multi-document exploits
        (r'^---\s*$', "YAML document separator"),
        (r'^\.\.\.\s*$', "YAML document end marker"),
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        # Shell command injection
        (r'[;&|`$]\s*\w+', "Shell metacharacter sequence"),
        (r'\$\([^)]+\)', "Command substitution $(...)"),
        (r'`[^`]+`', "Backtick command substitution"),
        (r'\|\s*\w+', "Pipe to command"),
        (r'>\s*[/\w]', "Output redirection"),
        (r'<\s*[/\w]', "Input redirection"),
        # Common dangerous commands
        (r'\b(rm|chmod|chown|wget|curl|nc|netcat|bash|sh|python|perl|ruby)\s+-?[a-zA-Z]', 
         "Dangerous command pattern"),
        (r'/bin/sh', "Direct shell reference"),
        (r'/bin/bash', "Direct bash reference"),
    ]
    
    CODE_INJECTION_PATTERNS = [
        # Python code injection
        (r'__import__\s*\(', "Python __import__() call"),
        (r'eval\s*\(', "Python eval() call"),
        (r'exec\s*\(', "Python exec() call"),
        (r'compile\s*\(', "Python compile() call"),
        (r'getattr\s*\([^,]+,\s*[\'"][^\'"]+[\'"]\s*\)', "Python getattr() with string"),
        (r'setattr\s*\(', "Python setattr() call"),
        (r'globals\s*\(\s*\)', "Python globals() access"),
        (r'locals\s*\(\s*\)', "Python locals() access"),
        (r'__builtins__', "Python builtins access"),
        (r'__class__', "Python class dunder access"),
        (r'__mro__', "Python MRO access"),
        (r'__subclasses__', "Python subclasses access"),
        # JavaScript/Node.js patterns
        (r'require\s*\([\'"]', "Node.js require()"),
        (r'process\.env', "Node.js process.env access"),
        (r'child_process', "Node.js child_process"),
        # Template injection
        (r'\{\{\s*.*\s*\}\}', "Template expression {{}}"),
        (r'\{%\s*.*\s*%\}', "Jinja/Template tag"),
        (r'\$\{[^}]+\}', "Template variable ${...}"),
    ]
    
    SQL_INJECTION_PATTERNS = [
        (r"'\s*OR\s+'?1'?\s*=\s*'?1", "SQL OR injection"),
        (r"'\s*;\s*(DROP|DELETE|UPDATE|INSERT)", "SQL statement injection"),
        (r"UNION\s+(ALL\s+)?SELECT", "SQL UNION injection"),
        (r"--\s*$", "SQL comment injection"),
        (r"/\*.*\*/", "SQL block comment"),
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        (r'\.\./', "Parent directory traversal"),
        (r'\.\.\\', "Windows parent directory traversal"),
        (r'%2e%2e[/\\]', "URL-encoded traversal"),
        (r'%252e%252e', "Double URL-encoded traversal"),
        (r'\.\.%00', "Null byte injection with traversal"),
        (r'/etc/passwd', "Unix password file access"),
        (r'/etc/shadow', "Unix shadow file access"),
        (r'C:\\Windows', "Windows system directory"),
        (r'\\\\[a-zA-Z0-9]+\\', "UNC path"),
        (r'file://', "File protocol URL"),
    ]
    
    # Credential patterns (must be case-insensitive)
    CREDENTIAL_PATTERNS = [
        # API Keys and tokens
        (r'(?:api[_-]?key|apikey)\s*[:=]\s*[\'"]?[\w-]{20,}', "API key exposure"),
        (r'(?:secret[_-]?key|secretkey)\s*[:=]\s*[\'"]?[\w-]{20,}', "Secret key exposure"),
        (r'(?:access[_-]?token|accesstoken)\s*[:=]\s*[\'"]?[\w-]{20,}', "Access token exposure"),
        (r'(?:auth[_-]?token|authtoken)\s*[:=]\s*[\'"]?[\w-]{20,}', "Auth token exposure"),
        (r'bearer\s+[\w-]+\.[\w-]+\.[\w-]+', "JWT Bearer token"),
        # Cloud provider patterns
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
        (r'(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*[\w/+=]{40}', "AWS Secret Key"),
        (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key"),
        (r'sk-proj-[a-zA-Z0-9]{20,}', "OpenAI Project API Key"),
        (r'sk-ant-api\d{2}-[\w-]{40,}', "Anthropic API Key"),
        (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
        (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
        (r'gho_[0-9a-zA-Z]{36}', "GitHub OAuth Token"),
        (r'glpat-[\w-]{20}', "GitLab Personal Access Token"),
        # Database connection strings
        (r'(?:postgres|mysql|mongodb)://[^\s]+:[^\s]+@', "Database connection string"),
        (r'(?:redis|amqp)://[^\s]*:[^\s]*@', "Message queue connection string"),
        # Password patterns
        (r'(?:password|passwd|pwd)\s*[:=]\s*[\'"]?[^\s\'"]{8,}', "Hardcoded password"),
        (r'(?:private[_-]?key)\s*[:=]', "Private key reference"),
    ]
    
    # PII patterns
    PII_PATTERNS = [
        # Email addresses (real, not templated)
        (r'[a-zA-Z0-9._%+-]+@(?!example\.|test\.|placeholder\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 
         "Real email address"),
        # Social Security Numbers
        (r'\b\d{3}-\d{2}-\d{4}\b', "SSN format"),
        # Credit card numbers
        (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', 
         "Credit card number"),
        # Phone numbers (US format with area code)
        (r'\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', "US phone number"),
        # IP addresses (private ranges are OK)
        (r'\b(?!10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)'
         r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', "Public IP address"),
    ]
    
    # Malicious URL patterns
    MALICIOUS_URL_PATTERNS = [
        # Known malicious TLDs
        (r'https?://[^\s]+\.(?:xyz|top|click|gq|ml|ga|cf|tk|work|date|racing)(?:/|$)', 
         "Suspicious TLD"),
        # URL shorteners (can hide malicious URLs)
        (r'https?://(?:bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|j\.mp)', 
         "URL shortener"),
        # Data URLs with scripts
        (r'data:text/html', "Data URL with HTML"),
        (r'javascript:', "JavaScript URL"),
        (r'vbscript:', "VBScript URL"),
        # Suspicious URL patterns
        (r'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', "IP-based URL"),
        (r'@[^\s/]+\.[a-z]+/', "URL with embedded credentials"),
        # Phishing indicators
        (r'login.*\.(?!example\.|test\.)[a-z]+\.[a-z]+', "Potential phishing domain"),
        (r'secure.*bank', "Potential phishing keyword"),
        (r'verify.*account', "Potential phishing keyword"),
    ]
    
    # Resource abuse patterns
    RESOURCE_ABUSE_PATTERNS = [
        # Extremely long strings
        (r'.{10000,}', "Excessively long string (potential DoS)"),
        # Nested structures (potential YAML bomb)
        (r'(\w+:\s*\n\s+){20,}', "Deeply nested structure"),
        # Large numeric values
        (r'\b\d{15,}\b', "Extremely large number"),
        # Repeated patterns (potential ReDoS)
        (r'(.+)\1{100,}', "Excessive repetition"),
    ]
    
    # Content policy violations
    CONTENT_POLICY_PATTERNS = [
        # Actual malicious payloads (not simulated)
        (r'<script[^>]*>.*</script>', "Embedded script tag"),
        (r'<iframe[^>]*>', "Embedded iframe"),
        (r'on\w+\s*=\s*[\'"]', "Event handler attribute"),
        # Potentially harmful content indicators
        (r'\b(ransomware|malware)\s+(?:download|execute|deploy)', 
         "Actual malware reference"),
        (r'\b(exploit|vulnerability)\s+(?:code|payload)', "Exploit code reference"),
    ]
    
    # Encoding attack patterns
    ENCODING_ATTACK_PATTERNS = [
        # Unicode attacks
        (r'[\x00-\x08\x0b\x0c\x0e-\x1f]', "Control character"),
        (r'\\u0000', "Null character escape"),
        (r'%00', "URL-encoded null"),
        # UTF-7 attacks
        (r'\+ADw-', "UTF-7 encoded <"),
        (r'\+AD4-', "UTF-7 encoded >"),
        # Overlong UTF-8
        (r'%c0%ae', "Overlong UTF-8 dot"),
    ]
    
    # Allowed domains for URLs in templates
    ALLOWED_URL_DOMAINS = {
        'attack.mitre.org',
        'cve.mitre.org',
        'd3fend.mitre.org',
        'nvd.nist.gov',
        'cwe.mitre.org',
        'owasp.org',
        'sans.org',
        'nist.gov',
        'github.com',
        'docs.microsoft.com',
        'learn.microsoft.com',
        'cloud.google.com',
        'docs.aws.amazon.com',
        'wikipedia.org',
        'example.com',
        'example.org',
        'example.net',
        'test.com',
        'localhost',
    }
    
    # Fields that should never contain executable content
    RESTRICTED_FIELDS = {
        'metadata.name',
        'metadata.author',
        'metadata.version',
        'target_profile.role',
        'target_profile.department',
        'target_profile.company_name',
        'simulation_parameters.language',
        'simulation_parameters.tone',
    }
    
    # Maximum allowed values for numeric fields
    MAX_VALUES = {
        'simulation_parameters.max_iterations': 10,
        'simulation_parameters.max_duration_minutes': 480,
        'simulation_parameters.urgency_level': 10,
        'difficulty_level': 10,
        'estimated_duration': 480,
        'target_profile.security_awareness_level': 10,
    }
    
    # String length limits
    MAX_STRING_LENGTHS = {
        'metadata.name': 200,
        'metadata.description': 2000,
        'metadata.author': 100,
        'target_profile.role': 100,
        'target_profile.department': 100,
        'default': 5000,
    }
    
    def __init__(
        self,
        strict_mode: bool = True,
        allow_url_shorteners: bool = False,
        allow_ip_urls: bool = False,
        custom_allowed_domains: Optional[Set[str]] = None,
        enable_pii_detection: bool = True,
        enable_credential_detection: bool = True,
    ):
        """Initialize the security validator.
        
        Args:
            strict_mode: If True, treat warnings as errors
            allow_url_shorteners: Allow URL shortener links
            allow_ip_urls: Allow IP-based URLs
            custom_allowed_domains: Additional allowed domains for URLs
            enable_pii_detection: Enable PII detection checks
            enable_credential_detection: Enable credential/secret detection
        """
        self.strict_mode = strict_mode
        self.allow_url_shorteners = allow_url_shorteners
        self.allow_ip_urls = allow_ip_urls
        self.enable_pii_detection = enable_pii_detection
        self.enable_credential_detection = enable_credential_detection
        
        # Merge custom allowed domains
        self.allowed_domains = self.ALLOWED_URL_DOMAINS.copy()
        if custom_allowed_domains:
            self.allowed_domains.update(custom_allowed_domains)
        
        # Compile all patterns for performance
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for better performance."""
        self._compiled_patterns: Dict[str, List[Tuple[re.Pattern, str]]] = {}
        
        pattern_groups = [
            ('yaml_injection', self.YAML_INJECTION_PATTERNS),
            ('command_injection', self.COMMAND_INJECTION_PATTERNS),
            ('code_injection', self.CODE_INJECTION_PATTERNS),
            ('sql_injection', self.SQL_INJECTION_PATTERNS),
            ('path_traversal', self.PATH_TRAVERSAL_PATTERNS),
            ('credential', self.CREDENTIAL_PATTERNS),
            ('pii', self.PII_PATTERNS),
            ('malicious_url', self.MALICIOUS_URL_PATTERNS),
            ('resource_abuse', self.RESOURCE_ABUSE_PATTERNS),
            ('content_policy', self.CONTENT_POLICY_PATTERNS),
            ('encoding_attack', self.ENCODING_ATTACK_PATTERNS),
        ]
        
        for group_name, patterns in pattern_groups:
            compiled = []
            for pattern, description in patterns:
                try:
                    flags = re.IGNORECASE if group_name in ('credential', 'sql_injection') else 0
                    compiled.append((re.compile(pattern, flags), description))
                except re.error as e:
                    # Log compilation error but continue
                    print(f"Warning: Failed to compile pattern '{pattern}': {e}")
            self._compiled_patterns[group_name] = compiled
    
    def validate_template(
        self,
        template_data: Union[Dict[str, Any], str, Path],
    ) -> SecurityValidationResult:
        """Validate a template for security issues.
        
        Args:
            template_data: Template as dict, YAML string, or file path
            
        Returns:
            SecurityValidationResult with all findings
        """
        start_time = datetime.utcnow()
        findings: List[SecurityFinding] = []
        
        # Parse template if needed
        if isinstance(template_data, (str, Path)):
            template_data, parse_findings = self._parse_template(template_data)
            findings.extend(parse_findings)
            if template_data is None:
                # Parsing failed completely
                return self._create_result(
                    findings=findings,
                    template_hash="PARSE_FAILED",
                    start_time=start_time,
                )
        
        # Calculate template hash for tracking
        template_hash = self._calculate_hash(template_data)
        
        # Run all security checks
        findings.extend(self._check_injection_attacks(template_data))
        findings.extend(self._check_path_traversal(template_data))
        
        if self.enable_credential_detection:
            findings.extend(self._check_credential_exposure(template_data))
        
        findings.extend(self._check_malicious_urls(template_data))
        
        if self.enable_pii_detection:
            findings.extend(self._check_pii_exposure(template_data))
        
        findings.extend(self._check_resource_abuse(template_data))
        findings.extend(self._check_encoding_attacks(template_data))
        findings.extend(self._check_content_policy(template_data))
        findings.extend(self._check_schema_security(template_data))
        
        return self._create_result(
            findings=findings,
            template_hash=template_hash,
            start_time=start_time,
        )
    
    def validate_template_file(self, file_path: Path) -> SecurityValidationResult:
        """Validate a template file for security issues.
        
        Args:
            file_path: Path to the template file
            
        Returns:
            SecurityValidationResult with all findings
        """
        return self.validate_template(file_path)
    
    def _parse_template(
        self, 
        template_source: Union[str, Path]
    ) -> Tuple[Optional[Dict[str, Any]], List[SecurityFinding]]:
        """Safely parse a template from string or file.
        
        Args:
            template_source: YAML string or file path
            
        Returns:
            Tuple of (parsed dict or None, list of findings)
        """
        findings: List[SecurityFinding] = []
        
        try:
            if isinstance(template_source, Path):
                if not template_source.exists():
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.HIGH,
                        category=SecurityCategory.SCHEMA_VIOLATION,
                        title="Template file not found",
                        description=f"The specified template file does not exist: {template_source}",
                        location="file_path",
                        value_preview=str(template_source),
                        remediation="Verify the file path is correct and the file exists",
                    ))
                    return None, findings
                
                # Check file size before reading
                file_size = template_source.stat().st_size
                if file_size > 1_000_000:  # 1MB limit
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.HIGH,
                        category=SecurityCategory.RESOURCE_ABUSE,
                        title="Template file too large",
                        description=f"Template file exceeds maximum size limit: {file_size:,} bytes",
                        location="file_path",
                        value_preview=str(template_source),
                        remediation="Reduce template file size to under 1MB",
                        cwe_id="CWE-400",
                    ))
                    return None, findings
                
                with open(template_source, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()
            else:
                yaml_content = template_source
            
            # Use safe_load to prevent arbitrary code execution
            template_data = yaml.safe_load(yaml_content)
            
            if template_data is None:
                findings.append(SecurityFinding(
                    severity=SecuritySeverity.MEDIUM,
                    category=SecurityCategory.SCHEMA_VIOLATION,
                    title="Empty template",
                    description="Template parsed to empty/null content",
                    location="root",
                    value_preview="null",
                    remediation="Provide valid template content",
                ))
                return {}, findings
            
            if not isinstance(template_data, dict):
                findings.append(SecurityFinding(
                    severity=SecuritySeverity.HIGH,
                    category=SecurityCategory.SCHEMA_VIOLATION,
                    title="Invalid template structure",
                    description=f"Template root must be a dictionary, got {type(template_data).__name__}",
                    location="root",
                    value_preview=str(type(template_data)),
                    remediation="Ensure template root is a YAML mapping/dictionary",
                ))
                return None, findings
            
            return template_data, findings
            
        except yaml.YAMLError as e:
            findings.append(SecurityFinding(
                severity=SecuritySeverity.HIGH,
                category=SecurityCategory.YAML_SECURITY,
                title="YAML parsing error",
                description=f"Failed to parse YAML: {str(e)[:200]}",
                location="root",
                value_preview=str(e)[:100],
                remediation="Fix YAML syntax errors",
                cwe_id="CWE-20",
            ))
            return None, findings
        except Exception as e:
            findings.append(SecurityFinding(
                severity=SecuritySeverity.HIGH,
                category=SecurityCategory.SCHEMA_VIOLATION,
                title="Template parsing error",
                description=f"Unexpected error parsing template: {str(e)[:200]}",
                location="root",
                value_preview=str(e)[:100],
                remediation="Review template format and content",
            ))
            return None, findings
    
    def _calculate_hash(self, template_data: Dict[str, Any]) -> str:
        """Calculate SHA-256 hash of template content."""
        content = yaml.dump(template_data, default_flow_style=False, sort_keys=True)
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]
    
    def _create_result(
        self,
        findings: List[SecurityFinding],
        template_hash: str,
        start_time: datetime,
    ) -> SecurityValidationResult:
        """Create a SecurityValidationResult from findings."""
        end_time = datetime.utcnow()
        duration_ms = (end_time - start_time).total_seconds() * 1000
        
        # Determine if template is secure
        blocking_severities = {SecuritySeverity.CRITICAL, SecuritySeverity.HIGH}
        if self.strict_mode:
            blocking_severities.add(SecuritySeverity.MEDIUM)
        
        is_secure = not any(
            f.severity in blocking_severities for f in findings
        )
        
        return SecurityValidationResult(
            is_secure=is_secure,
            findings=findings,
            scan_timestamp=start_time,
            scan_duration_ms=duration_ms,
            template_hash=template_hash,
            validation_id=secrets.token_hex(8),
        )
    
    def _check_value_against_patterns(
        self,
        value: str,
        patterns: List[Tuple[re.Pattern, str]],
        location: str,
        category: SecurityCategory,
        severity: SecuritySeverity,
        cwe_id: Optional[str] = None,
        mitre_technique: Optional[str] = None,
    ) -> List[SecurityFinding]:
        """Check a value against a list of patterns."""
        findings: List[SecurityFinding] = []
        
        for pattern, description in patterns:
            if pattern.search(value):
                # Truncate and sanitize the value preview
                preview = value[:100].replace('\n', '\\n')
                if len(value) > 100:
                    preview += "..."
                
                findings.append(SecurityFinding(
                    severity=severity,
                    category=category,
                    title=f"Potential {description}",
                    description=f"Detected pattern indicating {description} at '{location}'",
                    location=location,
                    value_preview=preview,
                    remediation=self._get_remediation(category),
                    cwe_id=cwe_id,
                    mitre_technique=mitre_technique,
                ))
        
        return findings
    
    def _get_remediation(self, category: SecurityCategory) -> str:
        """Get remediation advice for a security category."""
        remediations = {
            SecurityCategory.INJECTION: "Remove or escape special characters that could be interpreted as code or commands",
            SecurityCategory.PATH_TRAVERSAL: "Use absolute paths or validate path components; remove '..' sequences",
            SecurityCategory.CREDENTIAL_EXPOSURE: "Remove hardcoded credentials; use environment variables or secret management",
            SecurityCategory.MALICIOUS_URL: "Verify URL legitimacy; use only known-good domains from the allowlist",
            SecurityCategory.PII_EXPOSURE: "Remove or anonymize personally identifiable information",
            SecurityCategory.RESOURCE_ABUSE: "Reduce resource consumption; limit string lengths and nesting depth",
            SecurityCategory.YAML_SECURITY: "Use safe YAML features; avoid custom tags and anchors",
            SecurityCategory.CONTENT_POLICY: "Remove content that violates security policies",
            SecurityCategory.ENCODING_ATTACK: "Use standard UTF-8 encoding; remove control characters",
            SecurityCategory.SCHEMA_VIOLATION: "Ensure template conforms to the expected schema",
        }
        return remediations.get(category, "Review and fix the security issue")
    
    def _traverse_dict(
        self,
        data: Dict[str, Any],
        path: str = "",
    ) -> List[Tuple[str, Any]]:
        """Recursively traverse a dictionary and yield (path, value) tuples."""
        items: List[Tuple[str, Any]] = []
        
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            
            if isinstance(value, dict):
                items.extend(self._traverse_dict(value, current_path))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    item_path = f"{current_path}[{i}]"
                    if isinstance(item, dict):
                        items.extend(self._traverse_dict(item, item_path))
                    else:
                        items.append((item_path, item))
            else:
                items.append((current_path, value))
        
        return items
    
    def _check_injection_attacks(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for various injection attack patterns."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            # YAML injection
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['yaml_injection'],
                location=location,
                category=SecurityCategory.YAML_SECURITY,
                severity=SecuritySeverity.HIGH,
                cwe_id="CWE-502",  # Deserialization of Untrusted Data
                mitre_technique="T1059",  # Command and Scripting Interpreter
            ))
            
            # Command injection (higher severity for certain fields)
            severity = SecuritySeverity.CRITICAL if location in self.RESTRICTED_FIELDS else SecuritySeverity.HIGH
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['command_injection'],
                location=location,
                category=SecurityCategory.INJECTION,
                severity=severity,
                cwe_id="CWE-78",  # OS Command Injection
                mitre_technique="T1059",
            ))
            
            # Code injection
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['code_injection'],
                location=location,
                category=SecurityCategory.INJECTION,
                severity=SecuritySeverity.CRITICAL,
                cwe_id="CWE-94",  # Improper Control of Generation of Code
                mitre_technique="T1059",
            ))
            
            # SQL injection
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['sql_injection'],
                location=location,
                category=SecurityCategory.INJECTION,
                severity=SecuritySeverity.HIGH,
                cwe_id="CWE-89",  # SQL Injection
            ))
        
        return findings
    
    def _check_path_traversal(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for path traversal attempts."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['path_traversal'],
                location=location,
                category=SecurityCategory.PATH_TRAVERSAL,
                severity=SecuritySeverity.HIGH,
                cwe_id="CWE-22",  # Path Traversal
                mitre_technique="T1083",  # File and Directory Discovery
            ))
        
        return findings
    
    def _check_credential_exposure(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for exposed credentials and secrets."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['credential'],
                location=location,
                category=SecurityCategory.CREDENTIAL_EXPOSURE,
                severity=SecuritySeverity.CRITICAL,
                cwe_id="CWE-798",  # Use of Hard-coded Credentials
                mitre_technique="T1552",  # Unsecured Credentials
            ))
        
        return findings
    
    def _check_malicious_urls(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for potentially malicious URLs."""
        findings: List[SecurityFinding] = []
        
        # URL extraction pattern
        url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
        
        # Dangerous protocol patterns
        dangerous_protocols = [
            (r'javascript:', "JavaScript URL protocol"),
            (r'vbscript:', "VBScript URL protocol"),
            (r'data:text/html', "Data URL with HTML content"),
        ]
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            # Check for dangerous protocols first
            for pattern_str, description in dangerous_protocols:
                if re.search(pattern_str, value, re.IGNORECASE):
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.HIGH,
                        category=SecurityCategory.MALICIOUS_URL,
                        title=f"Dangerous URL protocol: {description}",
                        description=f"Detected {description} which can be used for XSS attacks",
                        location=location,
                        value_preview=value[:100],
                        remediation="Remove dangerous URL protocols; use only https:// URLs",
                        cwe_id="CWE-79",  # Cross-site Scripting (XSS)
                        mitre_technique="T1059.007",  # JavaScript
                    ))
            
            # Find all HTTP/HTTPS URLs in the value
            urls = url_pattern.findall(value)
            
            for url in urls:
                url_findings = self._validate_url(url, location)
                findings.extend(url_findings)
            
            # Check against malicious URL patterns
            if not self.allow_url_shorteners:
                findings.extend(self._check_value_against_patterns(
                    value=value,
                    patterns=[p for p in self._compiled_patterns['malicious_url'] 
                              if 'shortener' in p[1].lower()],
                    location=location,
                    category=SecurityCategory.MALICIOUS_URL,
                    severity=SecuritySeverity.MEDIUM,
                    cwe_id="CWE-601",  # URL Redirection
                ))
            
            if not self.allow_ip_urls:
                findings.extend(self._check_value_against_patterns(
                    value=value,
                    patterns=[p for p in self._compiled_patterns['malicious_url'] 
                              if 'IP-based' in p[1]],
                    location=location,
                    category=SecurityCategory.MALICIOUS_URL,
                    severity=SecuritySeverity.MEDIUM,
                ))
        
        return findings
    
    def _validate_url(self, url: str, location: str) -> List[SecurityFinding]:
        """Validate a specific URL for security issues."""
        findings: List[SecurityFinding] = []
        
        try:
            parsed = urlparse(url)
            
            # Check domain against allowlist
            domain = parsed.netloc.lower()
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Check if domain is in allowlist (including subdomains)
            domain_allowed = False
            for allowed in self.allowed_domains:
                if domain == allowed or domain.endswith(f'.{allowed}'):
                    domain_allowed = True
                    break
            
            if not domain_allowed and domain and not domain.startswith('localhost'):
                # Check if it's a suspicious TLD
                suspicious_tlds = {'.xyz', '.top', '.click', '.gq', '.ml', '.ga', '.cf', '.tk'}
                has_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)
                
                if has_suspicious_tld:
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.HIGH,
                        category=SecurityCategory.MALICIOUS_URL,
                        title="URL with suspicious TLD",
                        description=f"URL uses a TLD commonly associated with malicious sites",
                        location=location,
                        value_preview=url[:100],
                        remediation="Use domains from the allowed list or known legitimate sources",
                        cwe_id="CWE-601",
                    ))
                elif not self._is_known_legitimate_domain(domain):
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.LOW,
                        category=SecurityCategory.MALICIOUS_URL,
                        title="URL domain not in allowlist",
                        description=f"URL domain '{domain}' is not in the approved allowlist",
                        location=location,
                        value_preview=url[:100],
                        remediation="Add domain to allowlist if legitimate, or use approved domains",
                    ))
            
            # Check for IP-based URLs
            if not self.allow_ip_urls:
                try:
                    ipaddress.ip_address(domain)
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.MEDIUM,
                        category=SecurityCategory.MALICIOUS_URL,
                        title="IP-based URL",
                        description="URLs should use domain names, not IP addresses",
                        location=location,
                        value_preview=url[:100],
                        remediation="Use a domain name instead of an IP address",
                    ))
                except ValueError:
                    pass  # Not an IP address
            
            # Check for credential in URL
            if '@' in parsed.netloc:
                findings.append(SecurityFinding(
                    severity=SecuritySeverity.HIGH,
                    category=SecurityCategory.CREDENTIAL_EXPOSURE,
                    title="Credentials in URL",
                    description="URL contains embedded credentials",
                    location=location,
                    value_preview=url[:50] + "..." if len(url) > 50 else url,
                    remediation="Remove credentials from URL; use proper authentication",
                    cwe_id="CWE-522",
                ))
                
        except (ValueError, AttributeError):
            # URL parsing errors are expected for malformed URLs - skip validation
            pass
        
        return findings
    
    def _is_known_legitimate_domain(self, domain: str) -> bool:
        """Check if domain is a known legitimate domain."""
        legitimate_patterns = [
            r'\.gov$',
            r'\.edu$',
            r'\.mil$',
            r'microsoft\.com$',
            r'google\.com$',
            r'amazon\.com$',
            r'cloudflare\.com$',
        ]
        return any(re.search(p, domain) for p in legitimate_patterns)
    
    def _check_pii_exposure(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for exposed personally identifiable information."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['pii'],
                location=location,
                category=SecurityCategory.PII_EXPOSURE,
                severity=SecuritySeverity.HIGH,
                cwe_id="CWE-359",  # Exposure of Private Personal Information
            ))
        
        return findings
    
    def _check_resource_abuse(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for resource abuse patterns."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            # Check string lengths
            if isinstance(value, str):
                max_length = self.MAX_STRING_LENGTHS.get(
                    location, 
                    self.MAX_STRING_LENGTHS['default']
                )
                if len(value) > max_length:
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.MEDIUM,
                        category=SecurityCategory.RESOURCE_ABUSE,
                        title="String exceeds maximum length",
                        description=f"String at '{location}' is {len(value):,} characters (max: {max_length:,})",
                        location=location,
                        value_preview=value[:50] + "...",
                        remediation=f"Reduce string length to under {max_length:,} characters",
                        cwe_id="CWE-400",  # Uncontrolled Resource Consumption
                    ))
                
                # Check for resource abuse patterns
                findings.extend(self._check_value_against_patterns(
                    value=value,
                    patterns=self._compiled_patterns['resource_abuse'],
                    location=location,
                    category=SecurityCategory.RESOURCE_ABUSE,
                    severity=SecuritySeverity.MEDIUM,
                    cwe_id="CWE-400",
                ))
            
            # Check numeric values
            elif isinstance(value, (int, float)):
                max_value = self.MAX_VALUES.get(location)
                if max_value is not None and value > max_value:
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.MEDIUM,
                        category=SecurityCategory.RESOURCE_ABUSE,
                        title="Numeric value exceeds maximum",
                        description=f"Value {value} at '{location}' exceeds maximum {max_value}",
                        location=location,
                        value_preview=str(value),
                        remediation=f"Reduce value to {max_value} or less",
                        cwe_id="CWE-400",
                    ))
        
        # Check nesting depth
        depth = self._get_max_depth(template_data)
        if depth > 15:
            findings.append(SecurityFinding(
                severity=SecuritySeverity.MEDIUM,
                category=SecurityCategory.RESOURCE_ABUSE,
                title="Excessive nesting depth",
                description=f"Template has nesting depth of {depth} (max recommended: 15)",
                location="root",
                value_preview=f"depth={depth}",
                remediation="Reduce nesting depth to prevent stack overflow",
                cwe_id="CWE-674",  # Uncontrolled Recursion
            ))
        
        return findings
    
    def _get_max_depth(self, data: Any, current_depth: int = 0) -> int:
        """Calculate maximum nesting depth of a data structure."""
        if current_depth > 50:  # Safety limit
            return current_depth
        
        if isinstance(data, dict):
            if not data:
                return current_depth
            return max(self._get_max_depth(v, current_depth + 1) for v in data.values())
        elif isinstance(data, list):
            if not data:
                return current_depth
            return max(self._get_max_depth(item, current_depth + 1) for item in data)
        else:
            return current_depth
    
    def _check_encoding_attacks(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for encoding-based attacks."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['encoding_attack'],
                location=location,
                category=SecurityCategory.ENCODING_ATTACK,
                severity=SecuritySeverity.HIGH,
                cwe_id="CWE-838",  # Inappropriate Encoding for Output Context
            ))
        
        return findings
    
    def _check_content_policy(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for content policy violations."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['content_policy'],
                location=location,
                category=SecurityCategory.CONTENT_POLICY,
                severity=SecuritySeverity.HIGH,
                cwe_id="CWE-79",  # XSS
            ))
        
        return findings
    
    def _check_schema_security(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for schema-related security issues."""
        findings: List[SecurityFinding] = []
        
        # Check for unexpected top-level keys
        expected_keys = {
            'metadata', 'threat_type', 'delivery_vector', 'target_profile',
            'behavioral_pattern', 'difficulty_level', 'estimated_duration',
            'simulation_parameters', 'custom_parameters'
        }
        
        for key in template_data.keys():
            if key not in expected_keys:
                findings.append(SecurityFinding(
                    severity=SecuritySeverity.LOW,
                    category=SecurityCategory.SCHEMA_VIOLATION,
                    title="Unexpected top-level key",
                    description=f"Key '{key}' is not part of the expected schema",
                    location=key,
                    value_preview=str(key),
                    remediation="Remove unexpected keys or move to custom_parameters",
                ))
        
        # Check custom_parameters for suspicious keys
        custom_params = template_data.get('custom_parameters', {})
        if isinstance(custom_params, dict):
            suspicious_keys = {'__', 'eval', 'exec', 'import', 'system', 'shell', 'cmd'}
            for key in custom_params.keys():
                key_lower = key.lower()
                if any(sus in key_lower for sus in suspicious_keys):
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.HIGH,
                        category=SecurityCategory.INJECTION,
                        title="Suspicious custom parameter key",
                        description=f"Custom parameter key '{key}' contains suspicious pattern",
                        location=f"custom_parameters.{key}",
                        value_preview=key,
                        remediation="Rename the key to not include suspicious patterns",
                        cwe_id="CWE-94",
                    ))
        
        return findings
    
    def sanitize_template(
        self,
        template_data: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Sanitize a template by removing or escaping dangerous content.
        
        Args:
            template_data: Template to sanitize
            
        Returns:
            Tuple of (sanitized template, list of modifications made)
        """
        import copy
        sanitized = copy.deepcopy(template_data)
        modifications: List[str] = []
        
        def sanitize_value(value: Any, path: str) -> Any:
            if isinstance(value, str):
                original = value
                
                # Remove null bytes
                value = value.replace('\x00', '')
                
                # Remove control characters
                value = ''.join(c for c in value if ord(c) >= 32 or c in '\n\r\t')
                
                # Escape YAML special characters in restricted fields
                if path in self.RESTRICTED_FIELDS:
                    value = value.replace('{{', '{ {').replace('}}', '} }')
                    value = value.replace('${', '$ {')
                
                if value != original:
                    modifications.append(f"Sanitized value at {path}")
                
                return value
            
            elif isinstance(value, dict):
                return {k: sanitize_value(v, f"{path}.{k}") for k, v in value.items()}
            
            elif isinstance(value, list):
                return [sanitize_value(item, f"{path}[{i}]") for i, item in enumerate(value)]
            
            return value
        
        for key, value in sanitized.items():
            sanitized[key] = sanitize_value(value, key)
        
        return sanitized, modifications


def validate_template_security(
    template_data: Union[Dict[str, Any], str, Path],
    strict: bool = True,
) -> SecurityValidationResult:
    """Convenience function to validate template security.
    
    Args:
        template_data: Template as dict, YAML string, or file path
        strict: Use strict validation mode
        
    Returns:
        SecurityValidationResult with all findings
    """
    validator = TemplateSecurityValidator(strict_mode=strict)
    return validator.validate_template(template_data)
