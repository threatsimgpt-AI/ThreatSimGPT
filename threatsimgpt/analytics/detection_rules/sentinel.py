"""Microsoft Sentinel KQL Rule Generator.

Generates Microsoft Sentinel/Azure Monitor KQL detection rules.

Author: David Onoja (Blue Team)
"""

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

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


class SentinelRuleGenerator(BaseRuleGenerator):
    """Generator for Microsoft Sentinel KQL detection rules."""
    
    format = RuleFormat.SENTINEL
    
    # Severity mapping to Sentinel's severity levels
    SEVERITY_MAP = {
        RuleSeverity.INFORMATIONAL: "Informational",
        RuleSeverity.LOW: "Low",
        RuleSeverity.MEDIUM: "Medium",
        RuleSeverity.HIGH: "High",
        RuleSeverity.CRITICAL: "High",  # Sentinel max is High
    }
    
    # Log source to Sentinel table mapping
    TABLE_MAP = {
        "windows": "SecurityEvent",
        "windows_security": "SecurityEvent",
        "windows_sysmon": "Sysmon",
        "linux": "Syslog",
        "linux_auditd": "AuditLog",
        "email": "EmailEvents",
        "email_gateway": "EmailEvents",
        "firewall": "AzureNetworkAnalytics_CL",
        "network": "AzureNetworkAnalytics_CL",
        "cloud_azure": "AzureActivity",
        "cloud_aws": "AWSCloudTrail",
        "endpoint": "DeviceEvents",
        "office365": "OfficeActivity",
    }
    
    def generate(self, rule: DetectionRule) -> str:
        """Generate Microsoft Sentinel analytics rule.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            Sentinel rule as ARM template JSON
        """
        # Generate both KQL query and full ARM template
        kql_query = self._build_kql_query(rule)
        arm_template = self._build_arm_template(rule, kql_query)
        
        output = []
        output.append("// === Microsoft Sentinel Analytics Rule ===")
        output.append(f"// Rule: {rule.title}")
        output.append(f"// ID: {rule.rule_id}")
        output.append(f"// Severity: {rule.severity}")
        output.append("")
        output.append("// === KQL Query ===")
        output.append(kql_query)
        output.append("")
        output.append("// === ARM Template ===")
        output.append(json.dumps(arm_template, indent=2))
        
        return "\n".join(output)
    
    def generate_kql_only(self, rule: DetectionRule) -> str:
        """Generate just the KQL query string.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            KQL query string
        """
        return self._build_kql_query(rule)
    
    def validate(self, rule_content: str) -> tuple[bool, List[str]]:
        """Validate Sentinel rule content.
        
        Args:
            rule_content: Sentinel rule string
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Extract KQL section
        kql_match = re.search(r'// === KQL Query ===\n(.*?)\n\n// === ARM Template ===', 
                             rule_content, re.DOTALL)
        
        if kql_match:
            kql_query = kql_match.group(1).strip()
            kql_errors = self._validate_kql(kql_query)
            errors.extend(kql_errors)
        else:
            # Try validating as pure KQL
            if not rule_content.startswith("//"):
                kql_errors = self._validate_kql(rule_content)
                errors.extend(kql_errors)
        
        # Extract and validate ARM template if present
        arm_match = re.search(r'// === ARM Template ===\n(.*)', rule_content, re.DOTALL)
        if arm_match:
            try:
                arm_template = json.loads(arm_match.group(1).strip())
                arm_errors = self._validate_arm_template(arm_template)
                errors.extend(arm_errors)
            except json.JSONDecodeError as e:
                errors.append(f"Invalid ARM template JSON: {str(e)}")
        
        return len(errors) == 0, errors
    
    def _validate_kql(self, kql: str) -> List[str]:
        """Validate KQL query syntax.
        
        Args:
            kql: KQL query string
            
        Returns:
            List of validation errors
        """
        errors = []
        
        if not kql or not kql.strip():
            errors.append("Empty KQL query")
            return errors
        
        # Check for table name at start
        if not re.match(r'^[A-Za-z_]\w*', kql.strip()):
            errors.append("KQL query should start with a table name")
        
        # Check for unbalanced parentheses
        open_parens = kql.count('(')
        close_parens = kql.count(')')
        if open_parens != close_parens:
            errors.append(f"Unbalanced parentheses: {open_parens} open, {close_parens} close")
        
        # Check for unbalanced quotes
        double_quotes = kql.count('"')
        if double_quotes % 2 != 0:
            errors.append("Unbalanced double quotes")
        
        single_quotes = kql.count("'")
        if single_quotes % 2 != 0:
            errors.append("Unbalanced single quotes")
        
        # Check for common KQL syntax patterns
        if re.search(r'\|\s*\|', kql):
            errors.append("Double pipe (||) is invalid in KQL")
        
        return errors
    
    def _validate_arm_template(self, template: Dict[str, Any]) -> List[str]:
        """Validate ARM template structure.
        
        Args:
            template: ARM template dictionary
            
        Returns:
            List of validation errors
        """
        errors = []
        
        # Check for required fields
        if "properties" not in template:
            errors.append("ARM template missing 'properties' field")
            return errors
        
        props = template["properties"]
        required = ["displayName", "severity", "query"]
        for field in required:
            if field not in props:
                errors.append(f"ARM template missing required field: {field}")
        
        # Validate severity
        valid_severities = ["Informational", "Low", "Medium", "High"]
        if "severity" in props and props["severity"] not in valid_severities:
            errors.append(f"Invalid severity. Must be one of: {valid_severities}")
        
        return errors
    
    def _build_kql_query(self, rule: DetectionRule) -> str:
        """Build KQL query from detection logic.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            KQL query string
        """
        lines = []
        
        # Determine the table
        table = self._get_table(rule)
        lines.append(table)
        
        # Add time filter
        if rule.detection.timeframe:
            timeframe = self._parse_timeframe(rule.detection.timeframe)
            lines.append(f"| where TimeGenerated >= ago({timeframe})")
        else:
            lines.append("| where TimeGenerated >= ago(1h)")
        
        # Build where clause from selection
        where_clauses = self._build_where_clauses(rule.detection.selection)
        for clause in where_clauses:
            lines.append(f"| where {clause}")
        
        # Build filter (exclusions)
        if rule.detection.filter:
            filter_clauses = self._build_where_clauses(rule.detection.filter)
            for clause in filter_clauses:
                lines.append(f"| where not({clause})")
        
        # Handle aggregation in condition
        condition = rule.detection.condition.lower()
        if "count()" in condition or rule.detection.aggregation:
            lines.extend(self._build_aggregation(rule))
        
        # Add project for relevant fields
        lines.append("| project TimeGenerated, Computer, Account, EventID, Activity")
        
        return "\n".join(lines)
    
    def _get_table(self, rule: DetectionRule) -> str:
        """Get Sentinel table from rule log source.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            Table name
        """
        # Try product first
        if rule.logsource.product:
            product = rule.logsource.product.lower()
            if product in self.TABLE_MAP:
                return self.TABLE_MAP[product]
        
        # Try service
        if rule.logsource.service:
            service = rule.logsource.service.lower()
            if service in self.TABLE_MAP:
                return self.TABLE_MAP[service]
        
        # Try category
        if rule.logsource.category:
            category = rule.logsource.category.lower()
            category_map = {
                "process_creation": "SecurityEvent",
                "authentication": "SecurityEvent",
                "firewall": "AzureNetworkAnalytics_CL",
                "email": "EmailEvents",
            }
            if category in category_map:
                return category_map[category]
        
        # Default to SecurityEvent
        return "SecurityEvent"
    
    def _parse_timeframe(self, timeframe: str) -> str:
        """Parse Sigma timeframe to KQL format.
        
        Args:
            timeframe: Sigma timeframe (e.g., "5m", "1h", "24h")
            
        Returns:
            KQL timespan format
        """
        # Already in correct format for KQL
        if re.match(r'\d+[smhd]', timeframe):
            return timeframe
        
        # Try to parse other formats
        match = re.match(r'(\d+)\s*(second|minute|hour|day)s?', timeframe, re.IGNORECASE)
        if match:
            value = match.group(1)
            unit = match.group(2).lower()[0]  # s, m, h, d
            return f"{value}{unit}"
        
        return "1h"  # Default
    
    def _build_where_clauses(self, selection: Dict[str, Any]) -> List[str]:
        """Build KQL where clauses from selection.
        
        Args:
            selection: Selection dictionary
            
        Returns:
            List of where clause strings
        """
        clauses = []
        
        for field, value in selection.items():
            clause = self._field_to_kql(field, value)
            if clause:
                clauses.append(clause)
        
        return clauses
    
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
            if modifier == "contains":
                # Use has_any for contains with list
                values_str = ", ".join(f'"{v}"' for v in value)
                return f'{field_name} has_any ({values_str})'
            elif modifier in ("startswith", "endswith"):
                conditions = [self._format_kql_condition(field_name, v, modifier) for v in value]
                return f"({' or '.join(conditions)})"
            else:
                # Use in for exact match with list
                values_str = ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in value)
                return f'{field_name} in ({values_str})'
        
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
            return f'{field} contains "{str_value}"'
        elif modifier == "startswith":
            return f'{field} startswith "{str_value}"'
        elif modifier == "endswith":
            return f'{field} endswith "{str_value}"'
        elif modifier == "re":
            return f'{field} matches regex "{str_value}"'
        
        # Exact match
        if isinstance(value, str):
            return f'{field} == "{str_value}"'
        return f'{field} == {value}'
    
    def _map_field_name(self, field: str) -> str:
        """Map Sigma field names to Sentinel field names.
        
        Args:
            field: Sigma field name
            
        Returns:
            Sentinel field name
        """
        field_map = {
            "EventID": "EventID",
            "EventType": "Activity",
            "Image": "NewProcessName",
            "CommandLine": "CommandLine",
            "ParentImage": "ParentProcessName",
            "User": "Account",
            "TargetUserName": "TargetAccount",
            "SourceIP": "IpAddress",
            "DestinationIP": "DestinationIP",
            "DestinationPort": "DestinationPort",
            "LogonType": "LogonType",
            "Status": "Status",
            "Subject": "Subject",
            "SenderDomain": "SenderFromDomain",
        }
        
        return field_map.get(field, field)
    
    def _build_aggregation(self, rule: DetectionRule) -> List[str]:
        """Build KQL aggregation statements.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            List of KQL lines for aggregation
        """
        lines = []
        
        agg = rule.detection.aggregation or {}
        condition = rule.detection.condition.lower()
        
        # Parse threshold from condition
        threshold = 1
        threshold_match = re.search(r'>\s*(\d+)', condition)
        if threshold_match:
            threshold = int(threshold_match.group(1))
        
        # Determine grouping
        group_by = agg.get("groupby", ["Account", "Computer"])
        if isinstance(group_by, str):
            group_by = [group_by]
        
        group_fields = ", ".join(group_by)
        lines.append(f"| summarize Count = count() by {group_fields}")
        lines.append(f"| where Count > {threshold}")
        
        return lines
    
    def _build_arm_template(self, rule: DetectionRule, kql_query: str) -> Dict[str, Any]:
        """Build ARM template for Sentinel analytics rule.
        
        Args:
            rule: DetectionRule object
            kql_query: KQL query string
            
        Returns:
            ARM template dictionary
        """
        # Build tactics and techniques
        tactics = []
        techniques = []
        
        for mapping in rule.mitre_attack:
            tactics.append(mapping.tactic_name.replace(" ", ""))
            techniques.append(mapping.full_technique_id)
        
        return {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [
                {
                    "type": "Microsoft.SecurityInsights/alertRules",
                    "apiVersion": "2022-11-01",
                    "name": rule.rule_id,
                    "kind": "Scheduled",
                    "properties": {
                        "displayName": rule.title,
                        "description": rule.description,
                        "severity": self.SEVERITY_MAP.get(rule.severity, "Medium"),
                        "enabled": True,
                        "query": kql_query,
                        "queryFrequency": "PT5M",
                        "queryPeriod": "PT1H",
                        "triggerOperator": "GreaterThan",
                        "triggerThreshold": 0,
                        "suppressionDuration": "PT1H",
                        "suppressionEnabled": False,
                        "tactics": list(set(tactics)) if tactics else ["InitialAccess"],
                        "techniques": list(set(techniques)) if techniques else [],
                        "alertRuleTemplateName": None,
                        "incidentConfiguration": {
                            "createIncident": True,
                            "groupingConfiguration": {
                                "enabled": True,
                                "reopenClosedIncident": False,
                                "lookbackDuration": "PT5H",
                                "matchingMethod": "AllEntities",
                            }
                        },
                        "eventGroupingSettings": {
                            "aggregationKind": "SingleAlert"
                        }
                    }
                }
            ]
        }
    
    def from_attack_technique(
        self,
        technique_id: str,
        severity: RuleSeverity = RuleSeverity.HIGH
    ) -> List[DetectionRule]:
        """Generate Sentinel KQL rules from MITRE ATT&CK technique.
        
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
            title=f"Sentinel - MITRE {technique_id} - {technique_name}",
            name=f"sentinel_mitre_{technique_id.replace('.', '_').lower()}",
            description=f"Microsoft Sentinel KQL query to detect {technique_name} ({technique_id})",
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
        """Build Sentinel-optimized detection for technique."""
        if technique_id.startswith("T1566"):
            if technique_id == "T1566.001":
                return DetectionLogic(
                    selection={
                        "Table": "EmailEvents",
                        "AttachmentExtension": ["exe", "dll", "js", "ps1", "vbs"],
                    },
                    condition="selection",
                )
        
        if technique_id == "T1059.001":
            return DetectionLogic(
                selection={
                    "Table": "DeviceProcessEvents",
                    "ProcessCommandLine|contains": ["downloadstring", "-enc", "bypass"],
                    "FileName": "powershell.exe",
                },
                condition="selection",
            )
        
        if technique_id.startswith("T1110"):
            return DetectionLogic(
                selection={
                    "Table": "SecurityEvent",
                    "EventID": 4625,
                },
                condition="selection | summarize count() by TargetAccount | where count_ > 10",
            )
        
        return DetectionLogic(
            selection={"EventType": attack_type},
            condition="selection",
        )
    
    def format_rule(self, rule: DetectionRule) -> str:
        """Format DetectionRule as Sentinel KQL.
        
        Args:
            rule: DetectionRule to format
            
        Returns:
            Formatted KQL string with metadata
        """
        return self.generate(rule)
