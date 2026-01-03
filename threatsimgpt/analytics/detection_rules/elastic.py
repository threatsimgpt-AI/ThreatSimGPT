"""Elastic KQL Rule Generator.

Generates Elasticsearch Kibana Query Language (KQL) detection rules.

Author: David Onoja (Blue Team)
"""

import json
import re
from typing import Any, Dict, List, Optional

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


class ElasticRuleGenerator(BaseRuleGenerator):
    """Generator for Elasticsearch KQL detection rules."""
    
    format = RuleFormat.ELASTIC
    
    # Severity mapping to Elastic's severity levels
    SEVERITY_MAP = {
        RuleSeverity.INFORMATIONAL: 1,
        RuleSeverity.LOW: 21,
        RuleSeverity.MEDIUM: 47,
        RuleSeverity.HIGH: 73,
        RuleSeverity.CRITICAL: 99,
    }
    
    # Log source to Elastic index pattern mapping
    INDEX_PATTERN_MAP = {
        "windows": "winlogbeat-*",
        "linux": "filebeat-*",
        "sysmon": "winlogbeat-*",
        "email": "mail-*",
        "firewall": "firewall-*",
        "network": "packetbeat-*",
        "cloud_aws": "filebeat-aws-*",
        "cloud_azure": "filebeat-azure-*",
    }
    
    def generate(self, rule: DetectionRule) -> str:
        """Generate Elastic detection rule JSON.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            Elastic detection rule as JSON string
        """
        elastic_rule = self._build_elastic_rule(rule)
        return json.dumps(elastic_rule, indent=2)
    
    def generate_kql_query(self, rule: DetectionRule) -> str:
        """Generate just the KQL query string.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            KQL query string
        """
        return self._build_kql_query(rule)
    
    def validate(self, rule_content: str) -> tuple[bool, List[str]]:
        """Validate Elastic rule JSON.
        
        Args:
            rule_content: Elastic rule JSON string
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        try:
            rule = json.loads(rule_content)
            
            # Required fields for Elastic detection rules
            required_fields = ["name", "description", "risk_score", "severity", "query"]
            for field in required_fields:
                if field not in rule:
                    errors.append(f"Missing required field: {field}")
            
            # Validate risk_score range
            if "risk_score" in rule:
                score = rule["risk_score"]
                if not isinstance(score, (int, float)) or score < 0 or score > 100:
                    errors.append("risk_score must be between 0 and 100")
            
            # Validate severity
            valid_severities = ["low", "medium", "high", "critical"]
            if "severity" in rule and rule["severity"] not in valid_severities:
                errors.append(f"severity must be one of: {valid_severities}")
            
            # Validate type
            valid_types = ["query", "threshold", "eql", "machine_learning"]
            if "type" in rule and rule["type"] not in valid_types:
                errors.append(f"type must be one of: {valid_types}")
            
            # Validate query field exists and is non-empty
            if "query" in rule:
                if not rule["query"] or not rule["query"].strip():
                    errors.append("query cannot be empty")
            
            return len(errors) == 0, errors
            
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON: {str(e)}")
            return False, errors
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
            return False, errors
    
    def _build_elastic_rule(self, rule: DetectionRule) -> Dict[str, Any]:
        """Build complete Elastic detection rule.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            Elastic rule dictionary
        """
        # Map severity
        severity_str = str(rule.severity).lower()
        if severity_str == "informational":
            severity_str = "low"
        
        # Build the rule structure
        elastic_rule = {
            "name": rule.title,
            "description": rule.description,
            "risk_score": self.SEVERITY_MAP.get(rule.severity, 50),
            "severity": severity_str,
            "type": "query",
            "query": self._build_kql_query(rule),
            "language": "kuery",
            "index": self._get_index_patterns(rule),
            "tags": self._build_tags(rule),
            "author": [rule.metadata.author],
            "from": "now-6m",
            "to": "now",
            "enabled": True,
            "interval": "5m",
            "max_signals": 100,
        }
        
        # Add MITRE ATT&CK threat mapping
        if rule.mitre_attack:
            elastic_rule["threat"] = self._build_threat_mapping(rule)
        
        # Add references
        if rule.metadata.references:
            elastic_rule["references"] = rule.metadata.references
        
        # Add false positives
        if rule.metadata.false_positives:
            elastic_rule["false_positives"] = rule.metadata.false_positives
        
        # Add rule_id for updates
        elastic_rule["rule_id"] = rule.rule_id
        
        return elastic_rule
    
    def _build_kql_query(self, rule: DetectionRule) -> str:
        """Build KQL query string from detection logic.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            KQL query string
        """
        parts = []
        
        # Build selection conditions
        selection_kql = self._convert_selection_to_kql(rule.detection.selection)
        if selection_kql:
            parts.append(f"({selection_kql})")
        
        # Build filter conditions (exclusions)
        if rule.detection.filter:
            filter_kql = self._convert_selection_to_kql(rule.detection.filter)
            if filter_kql:
                parts.append(f"NOT ({filter_kql})")
        
        if not parts:
            return "*"
        
        return " AND ".join(parts)
    
    def _convert_selection_to_kql(self, selection: Dict[str, Any]) -> str:
        """Convert Sigma-style selection to KQL.
        
        Args:
            selection: Selection dictionary
            
        Returns:
            KQL query string
        """
        conditions = []
        
        for field, value in selection.items():
            kql_condition = self._field_to_kql(field, value)
            if kql_condition:
                conditions.append(kql_condition)
        
        if not conditions:
            return ""
        
        return " AND ".join(conditions)
    
    def _field_to_kql(self, field: str, value: Any) -> str:
        """Convert a field condition to KQL.
        
        Args:
            field: Field name (possibly with modifier)
            value: Field value(s)
            
        Returns:
            KQL condition string
        """
        # Parse field and modifier
        parts = field.split("|")
        field_name = self._map_field_name(parts[0])
        modifier = parts[1] if len(parts) > 1 else None
        
        # Handle list values
        if isinstance(value, list):
            kql_values = []
            for v in value:
                kql_values.append(self._format_kql_condition(field_name, v, modifier))
            return f"({' OR '.join(kql_values)})"
        
        # Single value
        return self._format_kql_condition(field_name, value, modifier)
    
    def _format_kql_condition(
        self,
        field: str,
        value: Any,
        modifier: Optional[str] = None
    ) -> str:
        """Format a single KQL condition.
        
        Args:
            field: Field name
            value: Field value
            modifier: Sigma modifier
            
        Returns:
            KQL condition string
        """
        str_value = str(value)
        
        if modifier == "contains":
            return f'{field}: "*{str_value}*"'
        elif modifier == "startswith":
            return f'{field}: "{str_value}*"'
        elif modifier == "endswith":
            return f'{field}: "*{str_value}"'
        elif modifier == "re":
            # KQL doesn't directly support regex, use wildcards
            return f'{field}: "{str_value}"'
        
        # Exact match
        return f'{field}: "{str_value}"'
    
    def _map_field_name(self, field: str) -> str:
        """Map Sigma field names to Elastic field names.
        
        Args:
            field: Sigma field name
            
        Returns:
            Elastic field name
        """
        # Common field mappings
        field_map = {
            "EventID": "event.code",
            "EventType": "event.action",
            "Image": "process.executable",
            "CommandLine": "process.command_line",
            "ParentImage": "process.parent.executable",
            "ParentCommandLine": "process.parent.command_line",
            "User": "user.name",
            "TargetUserName": "user.target.name",
            "SourceIP": "source.ip",
            "DestinationIP": "destination.ip",
            "DestinationPort": "destination.port",
            "Subject": "email.subject",
            "SenderDomain": "email.sender.domain",
        }
        
        return field_map.get(field, field.lower())
    
    def _get_index_patterns(self, rule: DetectionRule) -> List[str]:
        """Get Elastic index patterns from rule log source.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            List of index patterns
        """
        product = rule.logsource.product or "windows"
        
        if product in self.INDEX_PATTERN_MAP:
            return [self.INDEX_PATTERN_MAP[product]]
        
        return ["logs-*"]
    
    def _build_tags(self, rule: DetectionRule) -> List[str]:
        """Build Elastic tags from rule.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            List of tags
        """
        tags = ["ThreatSimGPT"]
        
        # Add custom tags
        tags.extend(rule.metadata.tags)
        
        # Add MITRE tags
        for mapping in rule.mitre_attack:
            tags.append(f"MITRE-{mapping.technique_id}")
        
        return list(set(tags))
    
    def _build_threat_mapping(self, rule: DetectionRule) -> List[Dict[str, Any]]:
        """Build MITRE ATT&CK threat mapping for Elastic.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            Elastic threat mapping list
        """
        threats = []
        
        for mapping in rule.mitre_attack:
            threat = {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": mapping.tactic_id,
                    "name": mapping.tactic_name,
                    "reference": f"https://attack.mitre.org/tactics/{mapping.tactic_id}/",
                },
                "technique": [
                    {
                        "id": mapping.technique_id,
                        "name": mapping.technique_name,
                        "reference": f"https://attack.mitre.org/techniques/{mapping.technique_id}/",
                    }
                ],
            }
            
            # Add sub-technique if present
            if mapping.sub_technique_id:
                threat["technique"][0]["subtechnique"] = [
                    {
                        "id": mapping.sub_technique_id,
                        "name": mapping.sub_technique_name or "",
                        "reference": f"https://attack.mitre.org/techniques/{mapping.sub_technique_id.replace('.', '/')}/",
                    }
                ]
            
            threats.append(threat)
        
        return threats
    
    def from_attack_technique(
        self,
        technique_id: str,
        severity: RuleSeverity = RuleSeverity.HIGH
    ) -> List[DetectionRule]:
        """Generate Elastic KQL rules from MITRE ATT&CK technique.
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            severity: Severity level for the rule
            
        Returns:
            List of DetectionRule objects
        """
        base_id = technique_id.split(".")[0]
        
        if base_id not in MITRE_TECHNIQUES:
            return []
        
        tech_info = MITRE_TECHNIQUES[base_id]
        
        if "." in technique_id:
            sub_techniques = tech_info.get("sub_techniques", {})
            technique_name = sub_techniques.get(technique_id, tech_info["technique_name"])
        else:
            technique_name = tech_info["technique_name"]
        
        tactic_to_attack_type = {
            "TA0001": "phishing",
            "TA0002": "malware",
            "TA0006": "credential_theft",
            "TA0008": "phishing",
            "TA0011": "malware",
            "TA0043": "phishing",
        }
        attack_type = tactic_to_attack_type.get(tech_info["tactic_id"], "phishing")
        
        logsource = ATTACK_LOG_SOURCES.get(attack_type, LogSourceConfig(product="windows"))
        detection = self._build_detection_for_technique(technique_id, attack_type)
        
        mitre_mapping = MitreMapping(
            tactic_id=tech_info["tactic_id"],
            tactic_name=tech_info["tactic_name"],
            technique_id=base_id,
            technique_name=tech_info["technique_name"],
            sub_technique_id=technique_id if "." in technique_id else None,
            sub_technique_name=technique_name if "." in technique_id else None,
        )
        
        rule = DetectionRule(
            title=f"Elastic - MITRE {technique_id} - {technique_name}",
            name=f"elastic_mitre_{technique_id.replace('.', '_').lower()}",
            description=f"Elastic KQL query to detect {technique_name} ({technique_id})",
            status=RuleStatus.EXPERIMENTAL,
            severity=severity,
            logsource=logsource,
            detection=detection,
            mitre_attack=[mitre_mapping],
            metadata=RuleMetadata(
                author="ThreatSimGPT Blue Team - David Onoja",
                tags=[f"attack.{technique_id.lower()}"],
            ),
        )
        
        return [rule]
    
    def _build_detection_for_technique(
        self,
        technique_id: str,
        attack_type: str
    ) -> DetectionLogic:
        """Build Elastic-optimized detection for technique."""
        if technique_id.startswith("T1566"):
            if technique_id == "T1566.001":
                return DetectionLogic(
                    selection={
                        "event.category": "email",
                        "email.attachments.file.extension": ["exe", "dll", "js", "ps1"],
                    },
                    condition="selection",
                )
        
        if technique_id == "T1059.001":
            return DetectionLogic(
                selection={
                    "process.name": "powershell.exe",
                    "process.command_line|contains": ["downloadstring", "-enc", "bypass"],
                },
                condition="selection",
            )
        
        if technique_id.startswith("T1110"):
            return DetectionLogic(
                selection={
                    "event.category": "authentication",
                    "event.outcome": "failure",
                },
                condition="selection | threshold count > 10 by user.name",
            )
        
        return DetectionLogic(
            selection={"event.type": attack_type},
            condition="selection",
        )
    
    def format_rule(self, rule: DetectionRule) -> str:
        """Format DetectionRule as Elastic JSON.
        
        Args:
            rule: DetectionRule to format
            
        Returns:
            Formatted JSON string
        """
        return self.generate(rule)
