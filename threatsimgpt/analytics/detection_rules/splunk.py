"""Splunk SPL Rule Generator.

Generates Splunk Search Processing Language (SPL) queries from detection rules.

Author: David Onoja (Blue Team)
"""

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


class SplunkRuleGenerator(BaseRuleGenerator):
    """Generator for Splunk SPL detection queries.
    
    Security Features:
        - Input sanitization to prevent SPL injection
        - Configurable index mapping for enterprise deployments
        - Query complexity limits to prevent DoS
    """
    
    format = RuleFormat.SPLUNK
    
    # Sigma modifier to SPL function mapping
    MODIFIER_MAP = {
        "contains": "*{}*",
        "startswith": "{}*",
        "endswith": "*{}",
        "re": "| regex {}",
        "base64": "| base64 decode",
        "all": "AND",
    }
    
    # Default log source to Splunk index mapping (configurable via constructor)
    DEFAULT_INDEX_MAP = {
        "windows": "index=windows",
        "linux": "index=linux",
        "sysmon": "index=sysmon",
        "email": "index=email",
        "firewall": "index=firewall",
        "proxy": "index=proxy",
        "dns": "index=dns",
        "cloud_aws": "index=aws",
        "cloud_azure": "index=azure",
    }
    
    # Characters that need escaping in SPL values (security - prevents injection)
    SPL_DANGEROUS_CHARS = {
        '\\': '\\\\',  # Backslash - escape char (must be first)
        '"': '\\"',    # Double quote - string delimiter
        "'": "\\'",    # Single quote - alternate string delimiter
        '|': '\\|',    # Pipe - command separator
        ';': '\\;',    # Semicolon - command terminator
        '`': '\\`',    # Backtick - subsearch delimiter
    }
    
    # Query complexity limits to prevent DoS attacks
    MAX_CONDITIONS = 50
    MAX_NESTING_DEPTH = 5
    
    def __init__(self, index_map: Optional[Dict[str, str]] = None):
        """Initialize Splunk rule generator.
        
        Args:
            index_map: Custom index mapping for enterprise deployments.
                       If None, uses DEFAULT_INDEX_MAP.
                       
        Example:
            # Custom index mapping for your environment
            generator = SplunkRuleGenerator(index_map={
                "windows": "index=sec_windows",
                "linux": "index=sec_linux",
            })
        """
        super().__init__()
        self.index_map = index_map if index_map is not None else self.DEFAULT_INDEX_MAP.copy()
    
    def _sanitize_value(self, value: str) -> str:
        """Sanitize user input to prevent SPL injection attacks.
        
        This method escapes dangerous characters that could be used
        for SPL injection. Must be called on all user-provided values
        before interpolation into SPL queries.
        
        Args:
            value: User-provided value to sanitize
            
        Returns:
            Sanitized value safe for SPL interpolation
            
        Security:
            Escapes: \\, ", |, ;, `
            
        Example:
            >>> gen._sanitize_value('test|delete index=*')
            'test\\|delete index=*'
        """
        if not isinstance(value, str):
            value = str(value)
        
        result = value
        # Escape in order - backslash first to avoid double-escaping
        for char, escaped in self.SPL_DANGEROUS_CHARS.items():
            result = result.replace(char, escaped)
        
        return result
    
    def generate(self, rule: DetectionRule) -> str:
        """Generate Splunk SPL query from DetectionRule.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            Splunk SPL query string
        """
        lines = []
        
        # Add header comment
        lines.append(f"```spl")
        lines.append(f"| # ThreatSimGPT Detection Rule: {rule.title}")
        lines.append(f"| # ID: {rule.rule_id}")
        lines.append(f"| # Severity: {rule.severity}")
        lines.append(f"| # Description: {rule.description[:100]}...")
        lines.append("")
        
        # Build the main search
        spl_query = self._build_spl_query(rule)
        lines.append(spl_query)
        
        # Add aggregation if present
        if rule.detection.aggregation:
            agg = self._build_aggregation(rule.detection.aggregation)
            lines.append(agg)
        
        # Add alert configuration comment
        lines.append("")
        lines.append(f"| # Alert Configuration:")
        lines.append(f"| # - Trigger: Per-Result")
        lines.append(f"| # - Severity: {rule.severity}")
        lines.append(f"```")
        
        return "\n".join(lines)
    
    def validate(self, rule_content: str) -> tuple[bool, List[str]]:
        """Validate Splunk SPL syntax.
        
        Args:
            rule_content: SPL query string
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Remove comments and code blocks
        clean_content = re.sub(r'\| #.*', '', rule_content)
        clean_content = re.sub(r'```\w*', '', clean_content)
        clean_content = clean_content.strip()
        
        if not clean_content:
            errors.append("Empty SPL query")
            return False, errors
        
        # Check for basic SPL structure
        if not re.search(r'(index\s*=|source\s*=|\| search)', clean_content, re.IGNORECASE):
            errors.append("SPL query should start with index=, source=, or | search")
        
        # Check for unbalanced parentheses
        open_parens = clean_content.count('(')
        close_parens = clean_content.count(')')
        if open_parens != close_parens:
            errors.append(f"Unbalanced parentheses: {open_parens} open, {close_parens} close")
        
        # Check for unbalanced quotes
        double_quotes = clean_content.count('"')
        if double_quotes % 2 != 0:
            errors.append("Unbalanced double quotes")
        
        # Check for common SPL syntax errors
        if re.search(r'\|\s*\|', clean_content):
            errors.append("Double pipe (||) is invalid in SPL")
        
        return len(errors) == 0, errors
    
    def _build_spl_query(self, rule: DetectionRule) -> str:
        """Build the main SPL query.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            SPL query string
        """
        parts = []
        
        # Determine index from log source
        index = self._get_index(rule)
        parts.append(index)
        
        # Build selection criteria
        selection_spl = self._convert_selection(rule.detection.selection)
        if selection_spl:
            parts.append(selection_spl)
        
        # Build filter criteria (NOT conditions)
        if rule.detection.filter:
            filter_spl = self._convert_selection(rule.detection.filter)
            if filter_spl:
                parts.append(f"NOT ({filter_spl})")
        
        # Join with appropriate operators based on condition
        condition = rule.detection.condition.lower()
        
        if " or " in condition:
            query = " OR ".join(parts[1:]) if len(parts) > 1 else parts[0]
            return f"{parts[0]} ({query})"
        else:
            return " ".join(parts)
    
    def _get_index(self, rule: DetectionRule) -> str:
        """Get Splunk index from rule log source.
        
        Args:
            rule: DetectionRule object
            
        Returns:
            Index specification string
        """
        product = rule.logsource.product or "windows"
        
        if product in self.index_map:
            return self.index_map[product]
        
        # Default to windows
        return self.index_map.get("windows", "index=windows")
    
    def _convert_selection(self, selection: Dict[str, Any]) -> str:
        """Convert Sigma selection to SPL with complexity limits.
        
        Args:
            selection: Sigma selection dictionary
            
        Returns:
            SPL filter string
            
        Raises:
            ValueError: If selection exceeds MAX_CONDITIONS limit
        """
        # SECURITY: Enforce complexity limits to prevent DoS
        if len(selection) > self.MAX_CONDITIONS:
            raise ValueError(
                f"Selection exceeds maximum conditions ({len(selection)} > {self.MAX_CONDITIONS}). "
                "This limit prevents query complexity attacks."
            )
        
        conditions = []
        
        for field, value in selection.items():
            spl_condition = self._field_to_spl(field, value)
            if spl_condition:
                conditions.append(spl_condition)
        
        if not conditions:
            return ""
        
        return " ".join(conditions)
    
    def _field_to_spl(self, field: str, value: Any) -> str:
        """Convert a single field condition to SPL.
        
        Args:
            field: Field name (possibly with modifier like 'field|contains')
            value: Field value(s)
            
        Returns:
            SPL condition string
        """
        # Parse field and modifier - only split on first pipe for valid Sigma syntax
        # Valid: "CommandLine|contains" -> field="CommandLine", modifier="contains"
        # Invalid/attack: "EventCode=1 | delete" should be sanitized
        parts = field.split("|", 1)  # Only split on first pipe
        field_name = parts[0]
        modifier = parts[1] if len(parts) > 1 else None
        
        # SECURITY: Validate modifier is a known safe value
        valid_modifiers = {"contains", "startswith", "endswith", "re", "base64", "all", None}
        if modifier and modifier not in valid_modifiers:
            # Unknown modifier - treat entire string as field name and sanitize
            field_name = field
            modifier = None
        
        # SECURITY: Sanitize field name to prevent injection via field names
        sanitized_field = self._sanitize_value(field_name)
        
        # Handle list values
        if isinstance(value, list):
            spl_values = []
            for v in value:
                spl_values.append(self._format_value(v, modifier))
            
            return f'({sanitized_field}=' + f' OR {sanitized_field}='.join(spl_values) + ')'
        
        # Single value
        formatted_value = self._format_value(value, modifier)
        return f'{sanitized_field}={formatted_value}'
    
    def _format_value(self, value: Any, modifier: Optional[str] = None) -> str:
        """Format a value for SPL with injection protection.
        
        Args:
            value: Value to format
            modifier: Sigma modifier
            
        Returns:
            Formatted and sanitized SPL value
            
        Security:
            All values are sanitized via _sanitize_value() before interpolation.
        """
        str_value = str(value)
        
        # SECURITY: Sanitize user input to prevent SPL injection
        sanitized_value = self._sanitize_value(str_value)
        
        # Apply modifier
        if modifier == "contains":
            return f'"*{sanitized_value}*"'
        elif modifier == "startswith":
            return f'"{sanitized_value}*"'
        elif modifier == "endswith":
            return f'"*{sanitized_value}"'
        elif modifier == "re":
            return f'| regex "{sanitized_value}"'
        
        # Quote strings with spaces or wildcards
        if " " in sanitized_value or "*" in sanitized_value:
            return f'"{sanitized_value}"'
        
        # SECURITY FIX: Return sanitized value, not original
        return sanitized_value
    
    def _build_aggregation(self, aggregation: Dict[str, Any]) -> str:
        """Build SPL aggregation commands.
        
        Args:
            aggregation: Aggregation configuration
            
        Returns:
            SPL aggregation string
        """
        parts = []
        
        if "count" in aggregation:
            group_by = aggregation.get("groupby", [])
            threshold = aggregation.get("threshold", 1)
            
            if group_by:
                if isinstance(group_by, str):
                    group_by = [group_by]
                parts.append(f"| stats count by {', '.join(group_by)}")
                parts.append(f"| where count > {threshold}")
            else:
                parts.append(f"| stats count")
                parts.append(f"| where count > {threshold}")
        
        if "timeframe" in aggregation:
            timeframe = aggregation["timeframe"]
            parts.insert(0, f"| bin _time span={timeframe}")
        
        return "\n".join(parts)
    
    def from_attack_technique(
        self,
        technique_id: str,
        severity: RuleSeverity = RuleSeverity.HIGH
    ) -> List[DetectionRule]:
        """Generate Splunk SPL rules from MITRE ATT&CK technique.
        
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
        
        # Determine attack type
        tactic_to_attack_type = {
            "TA0001": "phishing",
            "TA0002": "malware",
            "TA0006": "credential_theft",
            "TA0008": "phishing",
            "TA0011": "malware",
            "TA0043": "phishing",
        }
        attack_type = tactic_to_attack_type.get(tech_info["tactic_id"], "phishing")
        
        # Get log source
        logsource = ATTACK_LOG_SOURCES.get(attack_type, LogSourceConfig(product="windows"))
        
        # Build detection
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
        
        rule = DetectionRule(
            title=f"Splunk - MITRE {technique_id} - {technique_name}",
            name=f"splunk_mitre_{technique_id.replace('.', '_').lower()}",
            description=f"Splunk SPL query to detect {technique_name} ({technique_id})",
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
        """Build Splunk-optimized detection for technique."""
        # Phishing
        if technique_id.startswith("T1566"):
            if technique_id == "T1566.001":
                return DetectionLogic(
                    selection={
                        "sourcetype": "mail",
                        "attachment_type": ["exe", "dll", "js", "vbs", "ps1"],
                    },
                    condition="selection",
                )
            elif technique_id == "T1566.002":
                return DetectionLogic(
                    selection={
                        "sourcetype": "mail",
                        "url|contains": ["bit.ly", "tinyurl", "t.co"],
                    },
                    condition="selection",
                )
        
        # PowerShell
        if technique_id == "T1059.001":
            return DetectionLogic(
                selection={
                    "EventCode": 4104,
                    "ScriptBlockText|contains": ["downloadstring", "invoke-expression", "-enc"],
                },
                condition="selection",
            )
        
        # Brute Force
        if technique_id.startswith("T1110"):
            return DetectionLogic(
                selection={"EventCode": 4625},
                condition="selection | stats count by src_user | where count > 10",
            )
        
        # Default
        return DetectionLogic(
            selection={"EventType": attack_type},
            condition="selection",
        )
    
    def format_rule(self, rule: DetectionRule) -> str:
        """Format DetectionRule as Splunk SPL.
        
        Args:
            rule: DetectionRule to format
            
        Returns:
            Formatted SPL query with comments
        """
        spl = self.generate(rule)
        
        # Add header comments
        header = f"""```spl
# Rule: {rule.title}
# Description: {rule.description}
# Severity: {rule.severity}
# Author: {rule.metadata.author}
# MITRE ATT&CK: {', '.join(m.technique_id for m in rule.mitre_attack) if rule.mitre_attack else 'N/A'}

{spl}
```"""
        return header


def sigma_to_splunk(sigma_yaml: str) -> str:
    """Convert Sigma YAML directly to Splunk SPL.
    
    This is a convenience function for quick conversions.
    
    Args:
        sigma_yaml: Sigma rule in YAML format
        
    Returns:
        Splunk SPL query
    """
    from .sigma import SigmaRuleParser
    
    rule = SigmaRuleParser.parse(sigma_yaml)
    if not rule:
        raise ValueError("Failed to parse Sigma rule")
    
    generator = SplunkRuleGenerator()
    return generator.generate(rule)
