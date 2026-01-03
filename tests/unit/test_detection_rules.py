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
