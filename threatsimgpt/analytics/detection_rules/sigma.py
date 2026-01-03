"""Sigma Rule Generator.

Generates Sigma YAML detection rules - the industry standard format
that can be converted to any SIEM platform.

Reference: https://github.com/SigmaHQ/sigma

Author: David Onoja (Blue Team)
"""

import re
from typing import Any, Dict, List, Optional
import yaml

from .generator import BaseRuleGenerator, MITRE_TECHNIQUES, ATTACK_LOG_SOURCES
from .models import (
    DetectionRule,
    DetectionLogic,
    LogSourceConfig,
    MitreMapping,
    RuleFormat,
    RuleMetadata,
    RuleSeverity,
    RuleStatus,
)


class SigmaRuleGenerator(BaseRuleGenerator):
    """Generator for Sigma YAML detection rules."""
    
    format = RuleFormat.SIGMA
    
    def generate(self, rule: DetectionRule) -> str:
        """Generate Sigma YAML from DetectionRule.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            Sigma YAML string
        """
        sigma_rule = self._build_sigma_structure(rule)
        
        # Use custom YAML dumper for proper formatting
        return self._dump_yaml(sigma_rule)
    
    def validate(self, rule_content: str) -> tuple[bool, List[str]]:
        """Validate Sigma rule syntax.
        
        Args:
            rule_content: Sigma YAML string
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        try:
            # Parse YAML
            rule = yaml.safe_load(rule_content)
            
            if not isinstance(rule, dict):
                errors.append("Rule must be a YAML dictionary")
                return False, errors
            
            # Required fields
            required_fields = ["title", "logsource", "detection"]
            for field in required_fields:
                if field not in rule:
                    errors.append(f"Missing required field: {field}")
            
            # Validate logsource
            if "logsource" in rule:
                logsource = rule["logsource"]
                if not isinstance(logsource, dict):
                    errors.append("logsource must be a dictionary")
                elif not any(k in logsource for k in ["category", "product", "service"]):
                    errors.append("logsource must have at least one of: category, product, service")
            
            # Validate detection
            if "detection" in rule:
                detection = rule["detection"]
                if not isinstance(detection, dict):
                    errors.append("detection must be a dictionary")
                elif "condition" not in detection:
                    errors.append("detection must have a 'condition' field")
            
            # Validate status if present
            valid_statuses = ["experimental", "test", "stable", "deprecated"]
            if "status" in rule and rule["status"] not in valid_statuses:
                errors.append(f"Invalid status. Must be one of: {valid_statuses}")
            
            # Validate level if present
            valid_levels = ["informational", "low", "medium", "high", "critical"]
            if "level" in rule and rule["level"] not in valid_levels:
                errors.append(f"Invalid level. Must be one of: {valid_levels}")
            
            return len(errors) == 0, errors
            
        except yaml.YAMLError as e:
            errors.append(f"Invalid YAML syntax: {str(e)}")
            return False, errors
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
            return False, errors
    
    def _build_sigma_structure(self, rule: DetectionRule) -> Dict[str, Any]:
        """Build Sigma rule structure from DetectionRule.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            Dictionary ready for YAML serialization
        """
        sigma = {}
        
        # Title and identification
        sigma["title"] = rule.title
        sigma["id"] = rule.rule_id
        sigma["status"] = rule.status
        sigma["level"] = rule.severity
        
        # Description
        sigma["description"] = rule.description
        
        # Author and date
        sigma["author"] = rule.metadata.author
        sigma["date"] = rule.metadata.date
        if rule.metadata.modified:
            sigma["modified"] = rule.metadata.modified
        
        # References
        if rule.metadata.references:
            sigma["references"] = rule.metadata.references
        
        # Tags (including MITRE ATT&CK)
        tags = rule.get_sigma_tags()
        if tags:
            sigma["tags"] = tags
        
        # Log source
        sigma["logsource"] = self._build_logsource(rule)
        
        # Detection logic
        sigma["detection"] = rule.detection.to_sigma_detection()
        
        # False positives
        if rule.metadata.false_positives:
            sigma["falsepositives"] = rule.metadata.false_positives
        
        return sigma
    
    def _build_logsource(self, rule: DetectionRule) -> Dict[str, str]:
        """Build logsource section.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            Logsource dictionary
        """
        logsource = {}
        
        if rule.logsource.category:
            logsource["category"] = rule.logsource.category
        if rule.logsource.product:
            logsource["product"] = rule.logsource.product
        if rule.logsource.service:
            logsource["service"] = rule.logsource.service
        if rule.logsource.definition:
            logsource["definition"] = rule.logsource.definition
        
        # Default if empty
        if not logsource:
            logsource["category"] = "process_creation"
            logsource["product"] = "windows"
        
        return logsource
    
    def _dump_yaml(self, data: Dict[str, Any]) -> str:
        """Dump dictionary to properly formatted YAML.
        
        Args:
            data: Dictionary to serialize
            
        Returns:
            YAML string
        """
        # Custom representer for multiline strings
        def str_representer(dumper, data):
            if '\n' in data:
                return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
            return dumper.represent_scalar('tag:yaml.org,2002:str', data)
        
        yaml.add_representer(str, str_representer)
        
        return yaml.dump(
            data,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            width=120,
        )
    
    def from_attack_technique(
        self,
        technique_id: str,
        severity: RuleSeverity = RuleSeverity.HIGH
    ) -> List[DetectionRule]:
        """Generate Sigma rules from MITRE ATT&CK technique.
        
        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1566.001)
            severity: Severity level for the generated rule
            
        Returns:
            List of DetectionRule objects
        """
        base_id = technique_id.split(".")[0]
        
        if base_id not in MITRE_TECHNIQUES:
            return []
        
        tech_info = MITRE_TECHNIQUES[base_id]
        
        # Get technique name
        if "." in technique_id:
            sub_techniques = tech_info.get("sub_techniques", {})
            technique_name = sub_techniques.get(technique_id, tech_info["technique_name"])
        else:
            technique_name = tech_info["technique_name"]
        
        # Determine attack type from tactic
        tactic_to_attack_type = {
            "TA0001": "phishing",
            "TA0002": "malware",
            "TA0006": "credential_theft",
            "TA0008": "phishing",
            "TA0011": "malware",
            "TA0043": "phishing",
        }
        attack_type = tactic_to_attack_type.get(tech_info["tactic_id"], "phishing")
        
        # Get appropriate log source
        logsource = ATTACK_LOG_SOURCES.get(attack_type, LogSourceConfig())
        
        # Build detection logic based on technique
        detection = self._build_detection_for_technique(technique_id, attack_type)
        
        # Create MITRE mapping
        mitre_mapping = MitreMapping(
            tactic_id=tech_info["tactic_id"],
            tactic_name=tech_info["tactic_name"],
            technique_id=base_id,
            technique_name=tech_info["technique_name"],
            sub_technique_id=technique_id if "." in technique_id else None,
            sub_technique_name=technique_name if "." in technique_id else None,
        )
        
        # Create rule
        rule = DetectionRule(
            title=f"MITRE ATT&CK {technique_id} - {technique_name}",
            name=f"mitre_{technique_id.replace('.', '_').lower()}",
            description=f"Detects potential {technique_name} activity ({technique_id}). Tactic: {tech_info['tactic_name']}",
            status=RuleStatus.EXPERIMENTAL,
            severity=severity,
            logsource=logsource,
            detection=detection,
            mitre_attack=[mitre_mapping],
            metadata=RuleMetadata(
                author="ThreatSimGPT Blue Team - David Onoja",
                tags=[f"attack.{tech_info['tactic_id'].lower()}", f"attack.{technique_id.lower()}"],
                false_positives=["Legitimate administrative activity", "Authorized security testing"],
            ),
        )
        
        return [rule]
    
    def _build_detection_for_technique(
        self,
        technique_id: str,
        attack_type: str
    ) -> DetectionLogic:
        """Build detection logic specific to a technique.
        
        Args:
            technique_id: MITRE technique ID
            attack_type: Derived attack type
            
        Returns:
            DetectionLogic object
        """
        # Phishing-related techniques
        if technique_id.startswith("T1566"):
            if technique_id == "T1566.001":  # Spearphishing Attachment
                return DetectionLogic(
                    selection={
                        "EventType": ["EmailReceived", "FileDownloaded"],
                        "AttachmentType|endswith": [".exe", ".dll", ".js", ".vbs", ".hta", ".ps1", ".bat"],
                    },
                    filter={"SenderDomain|endswith": "@trusted-domain.com"},
                    condition="selection and not filter",
                )
            elif technique_id == "T1566.002":  # Spearphishing Link
                return DetectionLogic(
                    selection={
                        "EventType": "EmailReceived",
                        "BodyURL|contains": ["bit.ly", "tinyurl", "goo.gl", "t.co"],
                    },
                    condition="selection",
                )
        
        # Execution techniques
        if technique_id.startswith("T1059"):
            if technique_id == "T1059.001":  # PowerShell
                return DetectionLogic(
                    selection={
                        "EventID": 1,
                        "Image|endswith": "\\powershell.exe",
                        "CommandLine|contains": ["-enc", "-nop", "bypass", "downloadstring", "iex"],
                    },
                    condition="selection",
                )
        
        # Credential techniques
        if technique_id.startswith("T1110"):
            return DetectionLogic(
                selection={
                    "EventID": 4625,
                    "LogonType": [3, 10],
                },
                condition="selection | count() by TargetUserName > 10",
            )
        
        # Valid Accounts
        if technique_id.startswith("T1078"):
            return DetectionLogic(
                selection={
                    "EventID": [4624, 4648],
                    "LogonType": [10, 3],
                },
                filter={"TargetUserName|endswith": "$"},
                condition="selection and not filter",
            )
        
        # Default generic detection
        return DetectionLogic(
            selection={"EventType": attack_type},
            condition="selection",
        )
    
    def format_rule(self, rule: DetectionRule) -> str:
        """Format DetectionRule as Sigma YAML string.
        
        Args:
            rule: DetectionRule to format
            
        Returns:
            Formatted Sigma YAML string
        """
        return self.generate(rule)


class SigmaRuleParser:
    """Parser for existing Sigma rules."""
    
    @staticmethod
    def parse(yaml_content: str) -> Optional[DetectionRule]:
        """Parse Sigma YAML into DetectionRule.
        
        Args:
            yaml_content: Sigma YAML string
            
        Returns:
            DetectionRule object or None if parsing fails
        """
        try:
            data = yaml.safe_load(yaml_content)
            
            if not isinstance(data, dict):
                return None
            
            # Extract detection logic
            detection_data = data.get("detection", {})
            detection = DetectionRule.detection.type_(
                selection=detection_data.get("selection", {}),
                filter=detection_data.get("filter"),
                condition=detection_data.get("condition", "selection"),
                timeframe=detection_data.get("timeframe"),
            )
            
            # Build rule
            from .models import (
                DetectionLogic,
                LogSourceConfig,
                RuleMetadata,
                RuleSeverity,
                RuleStatus,
            )
            
            logsource_data = data.get("logsource", {})
            logsource = LogSourceConfig(
                category=logsource_data.get("category"),
                product=logsource_data.get("product"),
                service=logsource_data.get("service"),
            )
            
            rule = DetectionRule(
                rule_id=data.get("id", ""),
                title=data.get("title", "Imported Rule"),
                description=data.get("description", ""),
                status=RuleStatus(data.get("status", "experimental")),
                severity=RuleSeverity(data.get("level", "medium")),
                logsource=logsource,
                detection=DetectionLogic(
                    selection=detection_data.get("selection", {}),
                    filter=detection_data.get("filter"),
                    condition=detection_data.get("condition", "selection"),
                ),
                metadata=RuleMetadata(
                    author=data.get("author", "Unknown"),
                    date=data.get("date", ""),
                    references=data.get("references", []),
                    false_positives=data.get("falsepositives", []),
                    tags=data.get("tags", []),
                ),
            )
            
            return rule
            
        except Exception:
            return None
