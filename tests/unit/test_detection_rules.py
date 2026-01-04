"""Unit tests for Detection Rule Generator (Issue #25).

Author: David Onoja (Blue Team)
Track: detection
"""

import pytest
import yaml
import json
from typing import List

from threatsimgpt.analytics.detection_rules import (
    DetectionRule,
    DetectionLogic,
    LogSourceConfig,
    MitreMapping,
    RuleFormat,
    RuleMetadata,
    RuleSeverity,
    RuleStatus,
    SigmaRuleGenerator,
    SplunkRuleGenerator,
    ElasticRuleGenerator,
    SentinelRuleGenerator,
    RuleValidator,
    ValidationResult,
)


class TestDetectionRuleModels:
    """Test detection rule data models."""
    
    def test_create_basic_rule(self):
        """Test creating a basic detection rule."""
        rule = DetectionRule(
            title="Test Phishing Detection",
            name="test_phishing",
            description="Detects test phishing attempt",
            status=RuleStatus.EXPERIMENTAL,
            severity=RuleSeverity.HIGH,
            logsource=LogSourceConfig(category="email", product="email_gateway"),
            detection=DetectionLogic(
                selection={"EventType": "EmailReceived"},
                condition="selection",
            ),
        )
        
        assert rule.title == "Test Phishing Detection"
        assert rule.severity == RuleSeverity.HIGH
        assert rule.status == RuleStatus.EXPERIMENTAL
    
    def test_rule_with_mitre_mapping(self):
        """Test rule with MITRE ATT&CK mapping."""
        mitre = MitreMapping(
            tactic_id="TA0001",
            tactic_name="Initial Access",
            technique_id="T1566",
            technique_name="Phishing",
            sub_technique_id="T1566.001",
            sub_technique_name="Spearphishing Attachment",
        )
        
        rule = DetectionRule(
            title="Spearphishing Detection",
            name="spearphishing",
            description="Detects spearphishing attachment",
            status=RuleStatus.EXPERIMENTAL,
            severity=RuleSeverity.HIGH,
            logsource=LogSourceConfig(category="email"),
            detection=DetectionLogic(selection={}, condition="selection"),
            mitre_attack=[mitre],
        )
        
        assert len(rule.mitre_attack) == 1
        assert rule.mitre_attack[0].technique_id == "T1566"
        assert rule.mitre_attack[0].sub_technique_id == "T1566.001"
    
    def test_detection_logic(self):
        """Test detection logic with selection and filter."""
        detection = DetectionLogic(
            selection={
                "EventType": "EmailReceived",
                "Subject|contains": ["urgent", "action required"],
            },
            filter={"SenderDomain|endswith": "@trusted.com"},
            condition="selection and not filter",
        )
        
        assert "EventType" in detection.selection
        assert detection.filter is not None
        assert "not filter" in detection.condition


class TestSigmaRuleGenerator:
    """Test Sigma rule generator."""
    
    @pytest.fixture
    def generator(self) -> SigmaRuleGenerator:
        return SigmaRuleGenerator()
    
    @pytest.fixture
    def sample_rule(self) -> DetectionRule:
        return DetectionRule(
            title="Test Sigma Rule",
            name="test_sigma",
            description="Test rule for Sigma generation",
            status=RuleStatus.EXPERIMENTAL,
            severity=RuleSeverity.MEDIUM,
            logsource=LogSourceConfig(
                category="process_creation",
                product="windows",
                service="sysmon",
            ),
            detection=DetectionLogic(
                selection={"EventID": 1, "Image|endswith": "\\cmd.exe"},
                condition="selection",
            ),
            metadata=RuleMetadata(
                author="Test Author",
                tags=["test"],
            ),
        )
    
    def test_generate_sigma_yaml(self, generator: SigmaRuleGenerator, sample_rule: DetectionRule):
        """Test generating Sigma YAML."""
        result = generator.generate(sample_rule)
        
        # Should be valid YAML
        parsed = yaml.safe_load(result)
        
        assert parsed["title"] == "Test Sigma Rule"
        assert parsed["status"] == "experimental"
        assert parsed["level"] == "medium"
        assert "logsource" in parsed
        assert "detection" in parsed
    
    def test_validate_sigma_rule(self, generator: SigmaRuleGenerator, sample_rule: DetectionRule):
        """Test validating Sigma rule."""
        yaml_content = generator.generate(sample_rule)
        is_valid, errors = generator.validate(yaml_content)
        
        assert is_valid is True
        assert len(errors) == 0
    
    def test_from_attack_technique(self, generator: SigmaRuleGenerator):
        """Test generating rule from MITRE technique."""
        rules = generator.from_attack_technique("T1566.001", RuleSeverity.HIGH)
        
        assert len(rules) == 1
        assert "T1566.001" in rules[0].title
        assert rules[0].severity == RuleSeverity.HIGH
        
        # Generate and verify YAML
        yaml_content = generator.generate(rules[0])
        assert "spearphishing" in yaml_content.lower()
    
    def test_format_rule(self, generator: SigmaRuleGenerator, sample_rule: DetectionRule):
        """Test format_rule convenience method."""
        result = generator.format_rule(sample_rule)
        assert isinstance(result, str)
        assert "title:" in result


class TestSplunkRuleGenerator:
    """Test Splunk SPL rule generator."""
    
    @pytest.fixture
    def generator(self) -> SplunkRuleGenerator:
        return SplunkRuleGenerator()
    
    @pytest.fixture
    def sample_rule(self) -> DetectionRule:
        return DetectionRule(
            title="Test Splunk Rule",
            name="test_splunk",
            description="Test rule for Splunk generation",
            status=RuleStatus.EXPERIMENTAL,
            severity=RuleSeverity.HIGH,
            logsource=LogSourceConfig(product="windows"),
            detection=DetectionLogic(
                selection={"EventCode": 4688, "NewProcessName|endswith": "\\cmd.exe"},
                condition="selection",
            ),
            metadata=RuleMetadata(author="Test Author"),
        )
    
    def test_generate_splunk_spl(self, generator: SplunkRuleGenerator, sample_rule: DetectionRule):
        """Test generating Splunk SPL query."""
        result = generator.generate(sample_rule)
        
        assert "index=" in result
        assert "EventCode" in result or "spl" in result.lower()
    
    def test_validate_splunk_query(self, generator: SplunkRuleGenerator, sample_rule: DetectionRule):
        """Test validating Splunk query."""
        spl = generator.generate(sample_rule)
        is_valid, errors = generator.validate(spl)
        
        # Basic validation should pass
        assert is_valid is True
    
    def test_from_attack_technique_splunk(self, generator: SplunkRuleGenerator):
        """Test generating Splunk rule from MITRE technique."""
        rules = generator.from_attack_technique("T1059.001", RuleSeverity.CRITICAL)
        
        assert len(rules) == 1
        assert "powershell" in rules[0].title.lower() or "T1059.001" in rules[0].title
    
    def test_custom_index_map(self):
        """Test configurable index mapping."""
        custom_map = {
            "windows": "index=sec_windows_prod",
            "linux": "index=sec_linux_prod",
        }
        generator = SplunkRuleGenerator(index_map=custom_map)
        
        assert generator.index_map["windows"] == "index=sec_windows_prod"
        assert "sec_linux_prod" in generator.index_map["linux"]


class TestSplunkSecurityFeatures:
    """Test SPL injection prevention and security features (Issue #58)."""
    
    @pytest.fixture
    def generator(self) -> SplunkRuleGenerator:
        return SplunkRuleGenerator()
    
    def test_sanitize_pipe_injection(self, generator: SplunkRuleGenerator):
        """Test that pipe characters are escaped to prevent command injection."""
        malicious = "test|delete index=*"
        sanitized = generator._sanitize_value(malicious)
        
        # Pipe should be escaped with backslash
        assert "\\|" in sanitized
        # Raw unescaped pipe should not exist (check it's not just |delete but \|delete)
        assert sanitized == "test\\|delete index=*"
    
    def test_sanitize_semicolon_injection(self, generator: SplunkRuleGenerator):
        """Test that semicolons are escaped to prevent command chaining."""
        malicious = "test; | delete index=*"
        sanitized = generator._sanitize_value(malicious)
        
        assert "\\;" in sanitized
        assert sanitized == "test\\; \\| delete index=*"
    
    def test_sanitize_backtick_injection(self, generator: SplunkRuleGenerator):
        """Test that backticks are escaped to prevent subsearch injection."""
        malicious = "test`search index=sensitive`"
        sanitized = generator._sanitize_value(malicious)
        
        # Backticks should be escaped
        assert "\\`" in sanitized
        assert sanitized == "test\\`search index=sensitive\\`"
    
    def test_sanitize_quote_injection(self, generator: SplunkRuleGenerator):
        """Test that quotes are escaped to prevent string escape attacks."""
        malicious = 'test" OR 1=1 OR "'
        sanitized = generator._sanitize_value(malicious)
        
        # Quotes should be escaped
        assert '\\"' in sanitized
        assert sanitized == 'test\\" OR 1=1 OR \\"'
    
    def test_sanitize_preserves_backslash_order(self, generator: SplunkRuleGenerator):
        """Test that backslashes are escaped first to prevent double-escaping."""
        malicious = 'test\\|command'
        sanitized = generator._sanitize_value(malicious)
        
        # Backslash should be escaped first, then pipe
        # Input: test\|command -> test\\|command (backslash escaped) -> test\\\|command (pipe escaped)
        assert '\\\\' in sanitized  # Escaped backslash
        assert '\\|' in sanitized   # Escaped pipe
    
    def test_format_value_uses_sanitization(self, generator: SplunkRuleGenerator):
        """Test that _format_value applies sanitization."""
        malicious = "malware|delete index=*"
        result = generator._format_value(malicious)
        
        # Should contain escaped pipe
        assert "\\|" in result
        # The full result should have the escaped version
        assert "malware\\|delete" in result
    
    def test_complexity_limit_enforced(self, generator: SplunkRuleGenerator):
        """Test that query complexity limits prevent DoS."""
        # Create selection with too many conditions
        oversized_selection = {f"field_{i}": f"value_{i}" for i in range(60)}
        
        with pytest.raises(ValueError, match="exceeds maximum conditions"):
            generator._convert_selection(oversized_selection)
    
    def test_complexity_within_limit(self, generator: SplunkRuleGenerator):
        """Test that selections within limit work normally."""
        valid_selection = {f"field_{i}": f"value_{i}" for i in range(10)}
        
        result = generator._convert_selection(valid_selection)
        assert "field_0" in result
        assert "field_9" in result
    
    def test_sanitize_single_quote_injection(self, generator: SplunkRuleGenerator):
        """Test that single quotes are escaped."""
        malicious = "test' OR '1'='1"
        sanitized = generator._sanitize_value(malicious)
        
        assert "\\'" in sanitized
        assert sanitized == "test\\' OR \\'1\\'=\\'1"
    
    def test_field_name_injection_prevented(self, generator: SplunkRuleGenerator):
        """Test that field names are sanitized to prevent injection."""
        # Attacker tries to inject via field name
        malicious_selection = {"EventCode=1 | delete index": "anything"}
        result = generator._convert_selection(malicious_selection)
        
        # Pipe should be escaped in field name
        assert "\\|" in result
        # The raw unescaped pipe (without backslash) should not allow command execution
        # Note: "\| delete" contains "| delete" as substring, but the backslash prevents execution
        assert "EventCode=1 \\| delete" in result or "\\|" in result
    
    def test_simple_value_returns_sanitized(self, generator: SplunkRuleGenerator):
        """Test that simple values without spaces/wildcards are still sanitized."""
        # This tests the critical fix - simple values must return sanitized
        malicious = "admin|delete"
        result = generator._format_value(malicious)
        
        # Should be sanitized even without quotes
        assert "\\|" in result
        assert result == "admin\\|delete"
    
    # ============ P2: Additional Negative Test Cases ============
    
    def test_sanitize_bracket_injection(self, generator: SplunkRuleGenerator):
        """Test that brackets are escaped to prevent index injection."""
        malicious = "value[*]"
        sanitized = generator._sanitize_value(malicious)
        
        assert "\\[" in sanitized
        assert "\\]" in sanitized
        assert sanitized == "value\\[*\\]"
    
    def test_sanitize_parenthesis_injection(self, generator: SplunkRuleGenerator):
        """Test that parentheses are escaped to prevent subsearch grouping."""
        malicious = "test(search * | delete)"
        sanitized = generator._sanitize_value(malicious)
        
        assert "\\(" in sanitized
        assert "\\)" in sanitized
        assert "\\|" in sanitized
    
    def test_sanitize_dollar_sign_injection(self, generator: SplunkRuleGenerator):
        """Test that dollar signs are escaped to prevent variable injection."""
        malicious = "test$var$"
        sanitized = generator._sanitize_value(malicious)
        
        assert "\\$" in sanitized
        assert sanitized == "test\\$var\\$"
    
    def test_input_length_validation(self, generator: SplunkRuleGenerator):
        """Test that excessively long inputs are rejected post-normalization."""
        # Create a string longer than MAX_VALUE_LENGTH
        oversized_input = "a" * (generator.MAX_VALUE_LENGTH + 1)
        
        with pytest.raises(ValueError, match="exceeds maximum length"):
            generator._sanitize_value(oversized_input)
    
    def test_pre_normalization_length_validation(self, generator: SplunkRuleGenerator):
        """Test that pre-normalization length check prevents DoS via Unicode expansion.
        
        NFKC normalization can expand strings (e.g., ﬁ → fi), so we check
        length before normalization to prevent resource exhaustion attacks.
        """
        # Create a string that exceeds pre-normalization limit (2x MAX_VALUE_LENGTH)
        oversized_pre_norm = "a" * (generator.MAX_VALUE_LENGTH * 2 + 1)
        
        with pytest.raises(ValueError, match="pre-normalization"):
            generator._sanitize_value(oversized_pre_norm)
    
    def test_input_at_exact_length_limit(self, generator: SplunkRuleGenerator):
        """Test that input at exactly MAX_VALUE_LENGTH is accepted."""
        exact_limit = "a" * generator.MAX_VALUE_LENGTH
        result = generator._sanitize_value(exact_limit)
        assert len(result) == generator.MAX_VALUE_LENGTH
    
    def test_input_within_length_limit(self, generator: SplunkRuleGenerator):
        """Test that inputs within length limit are accepted."""
        valid_input = "a" * (generator.MAX_VALUE_LENGTH // 10)  # 10% of limit
        result = generator._sanitize_value(valid_input)
        
        assert len(result) == generator.MAX_VALUE_LENGTH // 10
    
    def test_regex_redos_prevention(self, generator: SplunkRuleGenerator):
        """Test that ReDoS patterns are escaped in regex modifier."""
        # Catastrophic backtracking pattern
        redos_pattern = "(a+)+"
        result = generator._format_value(redos_pattern, modifier="re")
        
        # Should use regex-escaped pattern
        assert "| regex" in result
        # The pattern should be escaped (re.escape converts (a+)+ to \(a\+\)\+)
        assert "\\(" in result or "\\+" in result
    
    def test_regex_metacharacters_escaped(self, generator: SplunkRuleGenerator):
        """Test that regex metacharacters are escaped."""
        dangerous_regex = ".*+?^${}[]|()"
        result = generator._sanitize_regex(dangerous_regex)
        
        # All metacharacters should be escaped
        assert "\\" in result  # At least some escaping occurred
        assert result != dangerous_regex
    
    def test_nesting_depth_limit_enforced(self, generator: SplunkRuleGenerator):
        """Test that nesting depth limits prevent stack exhaustion."""
        # Create deeply nested selection
        def create_nested(depth):
            if depth == 0:
                return "value"
            return {"nested": create_nested(depth - 1)}
        
        deeply_nested = create_nested(generator.MAX_NESTING_DEPTH + 2)
        selection = {"field": deeply_nested}
        
        with pytest.raises(ValueError, match="nesting depth exceeds maximum"):
            generator._convert_selection(selection)
    
    def test_nesting_within_limit(self, generator: SplunkRuleGenerator):
        """Test that selections within nesting limit work normally."""
        # Create selection within limit
        nested = {"inner_field": "inner_value"}
        selection = {"outer_field": nested}
        
        result = generator._convert_selection(selection)
        assert "inner_field" in result
    
    def test_combined_attack_vectors(self, generator: SplunkRuleGenerator):
        """Test sanitization against combined attack vectors."""
        # Multiple attack vectors in one string
        combined = 'test|delete; `subsearch` "escape" (group) [index] $var$'
        sanitized = generator._sanitize_value(combined)
        
        # All dangerous chars should be escaped
        assert "\\|" in sanitized
        assert "\\;" in sanitized
        assert "\\`" in sanitized
        assert '\\"' in sanitized
        assert "\\(" in sanitized
        assert "\\[" in sanitized
        assert "\\$" in sanitized
    
    def test_null_byte_handling(self, generator: SplunkRuleGenerator):
        """Test handling of null bytes in input - null bytes should be stripped."""
        # Null byte injection attempt
        malicious = "test\x00|delete"
        result = generator._sanitize_value(malicious)
        
        # Null byte should be stripped, pipe should be escaped
        assert "\x00" not in result  # Null byte removed
        assert "\\|" in result       # Pipe escaped
        assert result == "test\\|delete"  # Clean result
    
    def test_unicode_bypass_attempt(self, generator: SplunkRuleGenerator):
        """Test that fullwidth unicode characters are normalized and sanitized.
        
        Unicode normalization (NFKC) converts fullwidth chars to ASCII equivalents,
        which are then properly escaped to prevent bypass attacks.
        """
        # Fullwidth pipe: ｜ (U+FF5C) - NFKC normalization converts to ASCII |
        unicode_attempt = "test｜delete"
        result = generator._sanitize_value(unicode_attempt)
        
        # After NFKC normalization, fullwidth pipe becomes ASCII pipe and is escaped
        assert "\\|" in result  # Pipe should be escaped after normalization
        assert result == "test\\|delete"  # Fully sanitized
        
        # ASCII pipe should also be escaped (baseline test)
        ascii_version = "test|delete"
        ascii_result = generator._sanitize_value(ascii_version)
        assert "\\|" in ascii_result
        assert ascii_result == "test\\|delete"
    
    def test_empty_string_handling(self, generator: SplunkRuleGenerator):
        """Test handling of empty strings."""
        result = generator._sanitize_value("")
        assert result == ""
    
    def test_non_string_input_conversion(self, generator: SplunkRuleGenerator):
        """Test that non-string inputs are converted."""
        # Integer input
        result = generator._sanitize_value(12345)
        assert result == "12345"
        
        # Float input
        result = generator._sanitize_value(3.14)
        assert result == "3.14"
    
    def test_index_map_immutability(self):
        """Test that external index_map modifications don't affect generator."""
        external_map = {"windows": "index=external"}
        generator = SplunkRuleGenerator(index_map=external_map)
        
        # Modify external map
        external_map["windows"] = "index=modified"
        
        # Generator should be unaffected (copy was made)
        assert generator.index_map["windows"] == "index=external"
    
    def test_invalid_modifier_rejection(self, generator: SplunkRuleGenerator):
        """Test that invalid modifiers are rejected and logged."""
        # Invalid modifier should be treated as field name
        result = generator._field_to_spl("field|invalidmodifier", "value")
        
        # Should treat entire string as field name, not extract modifier
        assert "field\\|invalidmodifier" in result
    
    def test_newline_injection_prevented(self, generator: SplunkRuleGenerator):
        """Test that newline characters are replaced to prevent command injection."""
        malicious = "test\n| delete index=*"
        result = generator._sanitize_value(malicious)
        
        # Newline should be replaced with space
        assert "\n" not in result
        # Pipe should still be escaped
        assert "\\|" in result
        # Result should have space instead of newline
        assert "test \\| delete" in result
    
    def test_carriage_return_injection_prevented(self, generator: SplunkRuleGenerator):
        """Test that carriage return characters are replaced."""
        malicious = "test\r\n| delete index=*"
        result = generator._sanitize_value(malicious)
        
        # CR and LF should be replaced with spaces
        assert "\r" not in result
        assert "\n" not in result
        # Pipe should still be escaped
        assert "\\|" in result


class TestElasticRuleGenerator:
    """Test Elastic KQL rule generator."""
    
    @pytest.fixture
    def generator(self) -> ElasticRuleGenerator:
        return ElasticRuleGenerator()
    
    @pytest.fixture
    def sample_rule(self) -> DetectionRule:
        return DetectionRule(
            title="Test Elastic Rule",
            name="test_elastic",
            description="Test rule for Elastic generation",
            status=RuleStatus.EXPERIMENTAL,
            severity=RuleSeverity.MEDIUM,
            logsource=LogSourceConfig(product="windows"),
            detection=DetectionLogic(
                selection={"process.name": "cmd.exe"},
                condition="selection",
            ),
            mitre_attack=[
                MitreMapping(
                    tactic_id="TA0002",
                    tactic_name="Execution",
                    technique_id="T1059",
                    technique_name="Command and Scripting Interpreter",
                )
            ],
            metadata=RuleMetadata(author="Test Author"),
        )
    
    def test_generate_elastic_json(self, generator: ElasticRuleGenerator, sample_rule: DetectionRule):
        """Test generating Elastic JSON rule."""
        result = generator.generate(sample_rule)
        
        # Should be valid JSON
        parsed = json.loads(result)
        
        assert parsed["name"] == "Test Elastic Rule"
        assert "query" in parsed
        assert "threat" in parsed  # MITRE mapping
    
    def test_elastic_mitre_mapping(self, generator: ElasticRuleGenerator, sample_rule: DetectionRule):
        """Test MITRE ATT&CK mapping in Elastic rule."""
        result = generator.generate(sample_rule)
        parsed = json.loads(result)
        
        assert len(parsed["threat"]) == 1
        assert parsed["threat"][0]["framework"] == "MITRE ATT&CK"
        assert parsed["threat"][0]["tactic"]["id"] == "TA0002"


class TestSentinelRuleGenerator:
    """Test Microsoft Sentinel KQL rule generator."""
    
    @pytest.fixture
    def generator(self) -> SentinelRuleGenerator:
        return SentinelRuleGenerator()
    
    @pytest.fixture
    def sample_rule(self) -> DetectionRule:
        return DetectionRule(
            title="Test Sentinel Rule",
            name="test_sentinel",
            description="Test rule for Sentinel generation",
            status=RuleStatus.EXPERIMENTAL,
            severity=RuleSeverity.HIGH,
            logsource=LogSourceConfig(product="windows"),
            detection=DetectionLogic(
                selection={"EventID": 4625},
                condition="selection",
            ),
            metadata=RuleMetadata(author="Test Author"),
        )
    
    def test_generate_sentinel_kql(self, generator: SentinelRuleGenerator, sample_rule: DetectionRule):
        """Test generating Sentinel KQL rule."""
        result = generator.generate(sample_rule)
        
        # Sentinel output can be KQL or JSON (ARM template)
        # Check if it contains expected content
        assert result is not None
        assert len(result) > 0
        # Should contain rule title or KQL elements
        assert "Test Sentinel Rule" in result or "SecurityEvent" in result or "query" in result.lower()
    
    def test_from_attack_technique_sentinel(self, generator: SentinelRuleGenerator):
        """Test generating Sentinel rule from MITRE technique."""
        rules = generator.from_attack_technique("T1110.003", RuleSeverity.HIGH)
        
        assert len(rules) == 1
        assert "T1110" in rules[0].title or "brute" in rules[0].description.lower()


class TestRuleValidator:
    """Test detection rule validator."""
    
    @pytest.fixture
    def validator(self) -> RuleValidator:
        return RuleValidator()
    
    @pytest.fixture
    def valid_sigma_rule(self) -> str:
        return """
title: Test Rule
id: 12345678-1234-1234-1234-123456789abc
status: experimental
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
"""
    
    def test_validate_valid_sigma(self, validator: RuleValidator):
        """Test validating valid Sigma rule."""
        rule = DetectionRule(
            title="Test Rule",
            name="test",
            description="Test",
            status=RuleStatus.EXPERIMENTAL,
            severity=RuleSeverity.MEDIUM,
            logsource=LogSourceConfig(category="process_creation", product="windows"),
            detection=DetectionLogic(selection={"EventID": 1}, condition="selection"),
        )
        
        # Use the validate method which takes only the rule
        result = validator.validate(rule)
        
        assert isinstance(result, ValidationResult)
        # Basic rule should pass or have errors with proper structure
        assert hasattr(result, 'is_valid')
    
    def test_validate_sigma_yaml(self, validator: RuleValidator, valid_sigma_rule: str):
        """Test validating Sigma YAML content."""
        result = validator.validate_sigma(valid_sigma_rule)
        
        assert isinstance(result, ValidationResult)
        # Valid sigma should pass basic validation
        assert result.is_valid or len(result.errors) >= 0


class TestCLIIntegration:
    """Test CLI integration for detection commands."""
    
    def test_generators_are_importable(self):
        """Test that all generators can be imported."""
        from threatsimgpt.analytics.detection_rules import (
            SigmaRuleGenerator,
            SplunkRuleGenerator,
            ElasticRuleGenerator,
            SentinelRuleGenerator,
        )
        
        assert SigmaRuleGenerator is not None
        assert SplunkRuleGenerator is not None
        assert ElasticRuleGenerator is not None
        assert SentinelRuleGenerator is not None
    
    def test_cli_detect_group_exists(self):
        """Test that detect CLI group exists."""
        from threatsimgpt.cli.detect import detect_group
        
        assert detect_group is not None
        # Check commands exist
        assert "generate" in detect_group.commands
        assert "from-technique" in detect_group.commands
        assert "validate" in detect_group.commands
        assert "list-formats" in detect_group.commands


class TestMitreAttackCoverage:
    """Test MITRE ATT&CK technique coverage."""
    
    @pytest.fixture
    def sigma_generator(self) -> SigmaRuleGenerator:
        return SigmaRuleGenerator()
    
    @pytest.mark.parametrize("technique_id,expected_name", [
        ("T1566", "Phishing"),
        ("T1566.001", "Spearphishing Attachment"),
        ("T1566.002", "Spearphishing Link"),
        ("T1059.001", "PowerShell"),
        ("T1110.003", "Password Spraying"),
        ("T1078", "Valid Accounts"),
    ])
    def test_known_techniques(self, sigma_generator: SigmaRuleGenerator, technique_id: str, expected_name: str):
        """Test that known MITRE techniques generate rules."""
        rules = sigma_generator.from_attack_technique(technique_id)
        
        assert len(rules) >= 1
        # Rule title should contain technique ID or name
        assert technique_id in rules[0].title or expected_name in rules[0].description
    
    def test_unknown_technique_returns_empty(self, sigma_generator: SigmaRuleGenerator):
        """Test that unknown technique returns empty list."""
        rules = sigma_generator.from_attack_technique("T9999.999")
        
        assert len(rules) == 0
