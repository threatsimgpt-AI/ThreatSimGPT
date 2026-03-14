"""
Core validation engine extracted from TemplateSecurityValidator.

Handles the actual security validation logic without
caching, audit logging, or other concerns.
"""

import hashlib
import re
import secrets
import yaml
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional

from .config import SecurityValidatorConfig
from .template_validator import (
    SecurityFinding, SecuritySeverity, SecurityCategory
)


class ValidationEngine:
    """Core validation engine for template security."""
    
    def __init__(self, config: SecurityValidatorConfig):
        """
        Initialize validation engine.
        
        Args:
            config: Security validator configuration
        """
        self.config = config
        self.patterns = self._compile_patterns()
    
    def validate_template_content(
        self,
        template_data: Dict[str, Any]
    ) -> Tuple[Optional[Dict[str, Any]], List[SecurityFinding]]:
        """
        Validate template content for security issues.
        
        Args:
            template_data: Template data to validate
            
        Returns:
            Tuple of (parsed_data, findings)
        """
        findings = []
        
        # Parse YAML
        try:
            parsed_data = yaml.safe_load(yaml.dump(template_data))
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
        
        # Validate template size
        content_size = len(str(template_data))
        if content_size > self.config.max_template_size:
            findings.append(SecurityFinding(
                severity=SecuritySeverity.MEDIUM,
                category=SecurityCategory.RESOURCE_ABUSE,
                title="Template size exceeds limit",
                description=f"Template size {content_size} exceeds limit {self.config.max_template_size}",
                location="root",
                value_preview=f"Size: {content_size}",
                remediation="Reduce template size or increase limit",
            ))
        
        # Perform security checks
        findings.extend(self._check_injection_attacks(parsed_data))
        findings.extend(self._check_path_traversal(parsed_data))
        findings.extend(self._check_credential_exposure(parsed_data))
        findings.extend(self._check_malicious_urls(parsed_data))
        findings.extend(self._check_pii_exposure(parsed_data))
        findings.extend(self._check_resource_abuse(parsed_data))
        findings.extend(self._check_yaml_security(parsed_data))
        findings.extend(self._check_content_policy(parsed_data))
        findings.extend(self._check_encoding_attacks(parsed_data))
        
        return parsed_data, findings
    
    def _compile_patterns(self) -> Dict[str, List[Tuple[re.Pattern, str]]]:
        """Compile all security patterns."""
        patterns = {}
        
        # YAML/Command Injection patterns
        patterns['yaml_injection'] = [
            (re.compile(r'!!python/', re.IGNORECASE), "Python object deserialization"),
            (re.compile(r'!!ruby/', re.IGNORECASE), "Ruby object deserialization"),
            (re.compile(r'!!java/', re.IGNORECASE), "Java object deserialization"),
            (re.compile(r'\$\{.*\}', re.IGNORECASE), "Variable substitution"),
            (re.compile(r'\&.*\*', re.IGNORECASE), "YAML anchor reference"),
            (re.compile(r'<<:\s*\w+', re.IGNORECASE), "YAML merge key"),
        ]
        
        # Path Traversal patterns
        patterns['path_traversal'] = [
            (re.compile(r'\.\.[\\/]', re.IGNORECASE), "Directory traversal"),
            (re.compile(r'[\\/]\.\.[\\/]', re.IGNORECASE), "Directory traversal"),
            (re.compile(r'[a-zA-Z]:[\\/]', re.IGNORECASE), "Windows drive path"),
            (re.compile(r'/etc/passwd', re.IGNORECASE), "Unix password file"),
            (re.compile(r'/proc/', re.IGNORECASE), "Linux proc filesystem"),
            (re.compile(r'~/', re.IGNORECASE), "Home directory reference"),
        ]
        
        # Credential patterns
        patterns['credentials'] = [
            (re.compile(r'password\s*[:=]\s*["\']?[\w\-@#$%^&*+]+["\']?', re.IGNORECASE), "Password field"),
            (re.compile(r'api[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?', re.IGNORECASE), "API key"),
            (re.compile(r'secret[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?', re.IGNORECASE), "Secret key"),
            (re.compile(r'access[_-]?token\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?', re.IGNORECASE), "Access token"),
            (re.compile(r'private[_-]?key\s*[:=]\s*-----BEGIN', re.IGNORECASE), "Private key"),
            (re.compile(r'authorization\s*[:=]\s*["\']?bearer\s+[a-zA-Z0-9]{20,}', re.IGNORECASE), "Bearer token"),
        ]
        
        # Malicious URL patterns
        patterns['malicious_urls'] = [
            (re.compile(r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', re.IGNORECASE), "IP address URL"),
            (re.compile(r'https?://.*\.tk/', re.IGNORECASE), "Suspicious TLD"),
            (re.compile(r'https?://.*\.ml/', re.IGNORECASE), "Suspicious TLD"),
            (re.compile(r'https?://.*\.ga/', re.IGNORECASE), "Suspicious TLD"),
            (re.compile(r'https?://bit\.ly/', re.IGNORECASE), "URL shortener"),
            (re.compile(r'https?://tinyurl\.com/', re.IGNORECASE), "URL shortener"),
        ]
        
        # PII patterns
        patterns['pii'] = [
            (re.compile(r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b', re.IGNORECASE), "SSN pattern"),
            (re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', re.IGNORECASE), "Credit card pattern"),
            (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.IGNORECASE), "Email address"),
            (re.compile(r'\b\d{3}-\d{3}-\d{4}\b', re.IGNORECASE), "Phone number pattern"),
        ]
        
        # Resource abuse patterns
        patterns['resource_abuse'] = [
            (re.compile(r'for\s+.*\s+in\s+range\([0-9]+,\s*[0-9]+\)') or re.compile(r'while\s+.*\s*<\s*[0-9]+', re.IGNORECASE), "Potential infinite loop"),
            (re.compile(r'system\s*\(\s*["\'].*rm\s+-rf', re.IGNORECASE), "Dangerous system command"),
            (re.compile(r'subprocess\.call\s*\(\s*["\'].*rm', re.IGNORECASE), "Dangerous subprocess call"),
            (re.compile(r'os\.system\s*\(\s*["\'].*rm', re.IGNORECASE), "Dangerous OS command"),
        ]
        
        # YAML security patterns
        patterns['yaml_security'] = [
            (re.compile(r'!!omap', re.IGNORECASE), "Ordered map vulnerability"),
            (re.compile(r'!!set', re.IGNORECASE), "Set type vulnerability"),
            (re.compile(r'!!binary', re.IGNORECASE), "Binary data type"),
            (re.compile(r'tag:.*!python/object', re.IGNORECASE), "Python object tag"),
        ]
        
        # Content policy patterns
        patterns['content_policy'] = [
            (re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL), "Script tag"),
            (re.compile(r'javascript:', re.IGNORECASE), "JavaScript protocol"),
            (re.compile(r'vbscript:', re.IGNORECASE), "VBScript protocol"),
            (re.compile(r'data:text/html', re.IGNORECASE), "Data URI HTML"),
        ]
        
        # Encoding attack patterns
        patterns['encoding_attacks'] = [
            (re.compile(r'%[0-9A-Fa-f]{2}', re.IGNORECASE), "URL encoding"),
            (re.compile(r'&#\d+;', re.IGNORECASE), "HTML entity encoding"),
            (re.compile(r'&#x[0-9A-Fa-f]+;', re.IGNORECASE), "Hex HTML encoding"),
            (re.compile(r'\\u[0-9A-Fa-f]{4}', re.IGNORECASE), "Unicode escape"),
        ]
        
        return patterns
    
    def _check_value_against_patterns(
        self,
        value: str,
        patterns: List[Tuple[re.Pattern, str]],
        location: str,
        category: SecurityCategory,
        severity: SecuritySeverity,
    ) -> List[SecurityFinding]:
        """Check a value against a list of patterns."""
        findings = []
        
        for pattern, description in patterns:
            try:
                matches = pattern.findall(str(value))
                if matches:
                    findings.append(SecurityFinding(
                        severity=severity,
                        category=category,
                        title=f"{category.value.replace('_', ' ').title()} detected",
                        description=f"Detected {description} at {location}",
                        location=location,
                        evidence=str(matches[0])[:100] if matches else None,
                        pattern_matched=pattern.pattern,
                        value_preview=str(value)[:100],
                        remediation=f"Remove or sanitize {description}",
                        cwe_id=self._get_cwe_id(category),
                    ))
            except re.error:
                # Skip invalid patterns
                continue
            except Exception:
                # Skip patterns that cause errors
                continue
        
        return findings
    
    def _get_cwe_id(self, category: SecurityCategory) -> str:
        """Get CWE ID for security category."""
        cwe_mapping = {
            SecurityCategory.INJECTION: "CWE-74",
            SecurityCategory.PATH_TRAVERSAL: "CWE-22",
            SecurityCategory.CREDENTIAL_EXPOSURE: "CWE-522",
            SecurityCategory.MALICIOUS_URL: "CWE-200",
            SecurityCategory.PII_EXPOSURE: "CWE-359",
            SecurityCategory.RESOURCE_ABUSE: "CWE-400",
            SecurityCategory.YAML_SECURITY: "CWE-20",
            SecurityCategory.CONTENT_POLICY: "CWE-79",
            SecurityCategory.ENCODING_ATTACK: "CWE-172",
            SecurityCategory.SCHEMA_VIOLATION: "CWE-20",
        }
        return cwe_mapping.get(category, "CWE-16")
    
    def _check_injection_attacks(self, data: Dict[str, Any]) -> List[SecurityFinding]:
        """Check for injection attacks."""
        findings = []
        
        def check_recursive(obj, path="root"):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    findings.extend(self._check_value_against_patterns(
                        value, self.patterns['yaml_injection'],
                        f"{path}.{key}",
                        SecurityCategory.INJECTION,
                        SecuritySeverity.HIGH
                    ))
                    check_recursive(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_recursive(item, f"{path}[{i}]")
        
        check_recursive(data)
        return findings
    
    def _check_path_traversal(self, data: Dict[str, Any]) -> List[SecurityFinding]:
        """Check for path traversal attacks."""
        findings = []
        
        def check_recursive(obj, path="root"):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    findings.extend(self._check_value_against_patterns(
                        value, self.patterns['path_traversal'],
                        f"{path}.{key}",
                        SecurityCategory.PATH_TRAVERSAL,
                        SecuritySeverity.HIGH
                    ))
                    check_recursive(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_recursive(item, f"{path}[{i}]")
        
        check_recursive(data)
        return findings
    
    def _check_credential_exposure(self, data: Dict[str, Any]) -> List[SecurityFinding]:
        """Check for credential exposure."""
        findings = []
        
        def check_recursive(obj, path="root"):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    findings.extend(self._check_value_against_patterns(
                        value, self.patterns['credentials'],
                        f"{path}.{key}",
                        SecurityCategory.CREDENTIAL_EXPOSURE,
                        SecuritySeverity.CRITICAL
                    ))
                    check_recursive(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_recursive(item, f"{path}[{i}]")
        
        check_recursive(data)
        return findings
    
    def _check_malicious_urls(self, data: Dict[str, Any]) -> List[SecurityFinding]:
        """Check for malicious URLs."""
        findings = []
        
        def check_recursive(obj, path="root"):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    findings.extend(self._check_value_against_patterns(
                        value, self.patterns['malicious_urls'],
                        f"{path}.{key}",
                        SecurityCategory.MALICIOUS_URL,
                        SecuritySeverity.HIGH
                    ))
                    check_recursive(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_recursive(item, f"{path}[{i}]")
        
        check_recursive(data)
        return findings
    
    def _check_pii_exposure(self, data: Dict[str, Any]) -> List[SecurityFinding]:
        """Check for PII exposure."""
        findings = []
        
        def check_recursive(obj, path="root"):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    findings.extend(self._check_value_against_patterns(
                        value, self.patterns['pii'],
                        f"{path}.{key}",
                        SecurityCategory.PII_EXPOSURE,
                        SecuritySeverity.MEDIUM
                    ))
                    check_recursive(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_recursive(item, f"{path}[{i}]")
        
        check_recursive(data)
        return findings
    
    def _check_resource_abuse(self, data: Dict[str, Any]) -> List[SecurityFinding]:
        """Check for resource abuse."""
        findings = []
        
        def check_recursive(obj, path="root"):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    findings.extend(self._check_value_against_patterns(
                        value, self.patterns['resource_abuse'],
                        f"{path}.{key}",
                        SecurityCategory.RESOURCE_ABUSE,
                        SecuritySeverity.MEDIUM
                    ))
                    check_recursive(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_recursive(item, f"{path}[{i}]")
        
        check_recursive(data)
        return findings
    
    def _check_yaml_security(self, data: Dict[str, Any]) -> List[SecurityFinding]:
        """Check for YAML security issues."""
        findings = []
        
        def check_recursive(obj, path="root"):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    findings.extend(self._check_value_against_patterns(
                        value, self.patterns['yaml_security'],
                        f"{path}.{key}",
                        SecurityCategory.YAML_SECURITY,
                        SecuritySeverity.HIGH
                    ))
                    check_recursive(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_recursive(item, f"{path}[{i}]")
        
        check_recursive(data)
        return findings
    
    def _check_content_policy(self, data: Dict[str, Any]) -> List[SecurityFinding]:
        """Check for content policy violations."""
        findings = []
        
        def check_recursive(obj, path="root"):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    findings.extend(self._check_value_against_patterns(
                        value, self.patterns['content_policy'],
                        f"{path}.{key}",
                        SecurityCategory.CONTENT_POLICY,
                        SecuritySeverity.MEDIUM
                    ))
                    check_recursive(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_recursive(item, f"{path}[{i}]")
        
        check_recursive(data)
        return findings
    
    def _check_encoding_attacks(self, data: Dict[str, Any]) -> List[SecurityFinding]:
        """Check for encoding attacks."""
        findings = []
        
        def check_recursive(obj, path="root"):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    findings.extend(self._check_value_against_patterns(
                        value, self.patterns['encoding_attacks'],
                        f"{path}.{key}",
                        SecurityCategory.ENCODING_ATTACK,
                        SecuritySeverity.MEDIUM
                    ))
                    check_recursive(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_recursive(item, f"{path}[{i}]")
        
        check_recursive(data)
        return findings
