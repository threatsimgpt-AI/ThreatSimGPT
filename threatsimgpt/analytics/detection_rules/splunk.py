"""Splunk SPL Rule Generator.

Generates Splunk Search Processing Language (SPL) queries from detection rules.

Author: David Onoja (Blue Team)
"""

import logging
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

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

# Security event logging for SIEM ingestion
logger = logging.getLogger(__name__)


class SplunkRuleGenerator(BaseRuleGenerator):
    """Generator for Splunk SPL detection queries.
    
    Security Features:
        - Input sanitization to prevent SPL injection
        - Regex sanitization to prevent ReDoS attacks
        - Configurable index mapping for enterprise deployments
        - Query complexity limits to prevent DoS
        - Input length validation
        - Security event logging
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
    
    # Valid Sigma modifiers for validation (class constant for maintainability)
    VALID_MODIFIERS = frozenset({"contains", "startswith", "endswith", "re", "base64", "all"})
    
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
    # Expanded coverage for comprehensive protection
    SPL_DANGEROUS_CHARS = {
        '\\': '\\\\',  # Backslash - escape char (must be first)
        '"': '\\"',    # Double quote - string delimiter
        "'": "\\'",    # Single quote - alternate string delimiter
        '|': '\\|',    # Pipe - command separator
        ';': '\\;',    # Semicolon - command terminator
        '`': '\\`',    # Backtick - subsearch delimiter
        '[': '\\[',    # Open bracket - index injection
        ']': '\\]',    # Close bracket - index injection
        '(': '\\(',    # Open paren - subsearch grouping
        ')': '\\)',    # Close paren - subsearch grouping
        '$': '\\$',    # Dollar sign - variable injection
        '\n': ' ',     # Newline - command injection (replace with space)
        '\r': ' ',     # Carriage return - command injection (replace with space)
    }
    
    # Explicit escape order to avoid dict ordering dependency
    # Backslash MUST be first to prevent double-escaping
    # Newline/CR at end since they're replaced, not escaped
    ESCAPE_ORDER = ('\\', '"', "'", '|', ';', '`', '[', ']', '(', ')', '$', '\n', '\r')
    
    # Regex metacharacters that need escaping for ReDoS prevention
    REGEX_METACHARACTERS = frozenset({'.', '*', '+', '?', '^', '$', '{', '}', '[', ']', '|', '(', ')'})
    
    # Query complexity limits to prevent DoS attacks
    MAX_CONDITIONS = 50
    MAX_NESTING_DEPTH = 5
    MAX_VALUE_LENGTH = 10000  # Maximum input length to prevent memory exhaustion
    
    # Sigma field separator limit - only split on first pipe for valid Sigma syntax
    SIGMA_FIELD_SEPARATOR_LIMIT = 1
    
    def __init__(self, index_map: Optional[Dict[str, str]] = None) -> None:
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
        # SECURITY: Copy index_map to prevent external mutation
        if index_map is not None:
            self.index_map = index_map.copy()
        else:
            self.index_map = self.DEFAULT_INDEX_MAP.copy()
    
    def _sanitize_value(self, value: str) -> str:
        """Sanitize user input to prevent SPL injection attacks.
        
        This method escapes dangerous characters that could be used
        for SPL injection. Must be called on all user-provided values
        before interpolation into SPL queries.
        
        Args:
            value: User-provided value to sanitize
            
        Returns:
            Sanitized value safe for SPL interpolation
            
        Raises:
            ValueError: If value exceeds MAX_VALUE_LENGTH
            
        Security:
            - Unicode normalization (NFKC) to prevent bypass via fullwidth chars
            - Null byte stripping to prevent string termination attacks
            - Escapes: \\, ", ', |, ;, `, [, ], (, ), $, \\n, \\r
            - Validates input length before AND after normalization
            - Logs sanitization events for security monitoring
            
        Example:
            >>> gen._sanitize_value('test|delete index=*')
            'test\\|delete index=*'
        """
        if not isinstance(value, str):
            value = str(value)
        
        # SECURITY: Pre-normalization length check to prevent DoS from normalization itself
        # NFKC normalization can EXPAND strings (e.g., ﬁ → fi), so check before processing
        # Allow 2x headroom for expansion, but reject obviously malicious inputs
        if len(value) > self.MAX_VALUE_LENGTH * 2:
            logger.warning(
                f"SPL injection attempt blocked: pre-normalization value too long "
                f"({len(value)} > {self.MAX_VALUE_LENGTH * 2})"
            )
            raise ValueError(
                f"Value exceeds maximum pre-normalization length ({len(value)} > {self.MAX_VALUE_LENGTH * 2}). "
                "This limit prevents DoS attacks via Unicode expansion."
            )
        
        # SECURITY: Normalize Unicode to prevent bypass via fullwidth/alternate chars
        # NFKC normalization converts fullwidth pipe ｜ (U+FF5C) to ASCII pipe |
        value = unicodedata.normalize('NFKC', value)
        
        # SECURITY: Strip null bytes to prevent string termination attacks
        # Null bytes can cause downstream systems to truncate strings
        value = value.replace('\x00', '')
        
        # SECURITY: Post-normalization length check to enforce final limit
        if len(value) > self.MAX_VALUE_LENGTH:
            logger.warning(
                f"SPL injection attempt blocked: normalized value exceeds max length "
                f"({len(value)} > {self.MAX_VALUE_LENGTH})"
            )
            raise ValueError(
                f"Value exceeds maximum length ({len(value)} > {self.MAX_VALUE_LENGTH}). "
                "This limit prevents memory exhaustion attacks."
            )
        
        result = value
        original = value
        
        # Escape using explicit order - backslash first to avoid double-escaping
        for char in self.ESCAPE_ORDER:
            escaped = self.SPL_DANGEROUS_CHARS[char]
            result = result.replace(char, escaped)
        
        # SECURITY: Log sanitization events for SIEM monitoring
        if result != original:
            logger.info(
                f"SPL value sanitized: {len(original)} chars, "
                f"{sum(1 for c in original if c in self.SPL_DANGEROUS_CHARS)} dangerous chars escaped"
            )
        
        return result
    
    def _sanitize_regex(self, value: str) -> str:
        """Sanitize regex patterns to prevent ReDoS attacks.
        
        This method escapes regex metacharacters that could cause
        catastrophic backtracking (ReDoS - Regular Expression Denial of Service).
        
        Args:
            value: User-provided regex pattern to sanitize
            
        Returns:
            Sanitized regex pattern safe from ReDoS
            
        Security:
            - Escapes regex metacharacters: . * + ? ^ $ { } [ ] | ( )
            - Prevents catastrophic backtracking patterns like (a+)+
            - Should be used for all regex modifier values
            
        Note:
            This is a defense-in-depth measure. The regex modifier should be used
            with caution as Splunk's regex engine may still have performance
            implications with complex patterns. Consider restricting regex usage
            to trusted sources only.
            
        Known Limitations:
            - URL-encoded bypass (e.g., %7C for pipe) is out of scope and should
              be handled at the HTTP/input validation layer before reaching this code.
            
        Example:
            >>> gen._sanitize_regex('(a+)+')
            '\\(a\\+\\)\\+'
        """
        if not isinstance(value, str):
            value = str(value)
        
        # SECURITY: Validate input length
        if len(value) > self.MAX_VALUE_LENGTH:
            logger.warning(
                f"Regex value rejected: exceeds max length ({len(value)} > {self.MAX_VALUE_LENGTH})"
            )
            raise ValueError(
                f"Regex value exceeds maximum length ({len(value)} > {self.MAX_VALUE_LENGTH}). "
                "This limit prevents memory exhaustion attacks."
            )
        
        # Escape regex metacharacters to prevent ReDoS
        result = re.escape(value)
        
        # SECURITY: Log sanitization without exposing sensitive pattern content
        logger.debug(f"Regex pattern sanitized: {len(value)} chars input")
        
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
    
    def validate(self, rule_content: str) -> Tuple[bool, List[str]]:
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
    
    def _convert_selection(self, selection: Dict[str, Any], depth: int = 0) -> str:
        """Convert Sigma selection to SPL with complexity limits.
        
        Args:
            selection: Sigma selection dictionary
            depth: Current nesting depth for recursive calls
            
        Returns:
            SPL filter string
            
        Raises:
            ValueError: If selection exceeds MAX_CONDITIONS or MAX_NESTING_DEPTH limit
        """
        # SECURITY: Enforce nesting depth limit to prevent stack exhaustion
        if depth > self.MAX_NESTING_DEPTH:
            logger.warning(
                f"SPL complexity attack blocked: nesting depth {depth} exceeds limit {self.MAX_NESTING_DEPTH}"
            )
            raise ValueError(
                f"Selection nesting depth exceeds maximum ({depth} > {self.MAX_NESTING_DEPTH}). "
                "This limit prevents query complexity attacks."
            )
        
        # SECURITY: Enforce complexity limits to prevent DoS
        if len(selection) > self.MAX_CONDITIONS:
            logger.warning(
                f"SPL complexity attack blocked: {len(selection)} conditions exceeds limit {self.MAX_CONDITIONS}"
            )
            raise ValueError(
                f"Selection exceeds maximum conditions ({len(selection)} > {self.MAX_CONDITIONS}). "
                "This limit prevents query complexity attacks."
            )
        
        conditions = []
        
        for field, value in selection.items():
            # Handle nested selections (recursively)
            if isinstance(value, dict):
                nested_spl = self._convert_selection(value, depth + 1)
                if nested_spl:
                    conditions.append(f"({nested_spl})")
            else:
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
        parts = field.split("|", self.SIGMA_FIELD_SEPARATOR_LIMIT)
        field_name = parts[0]
        modifier = parts[1] if len(parts) > 1 else None
        
        # SECURITY: Validate modifier is a known safe value (using class constant)
        if modifier and modifier not in self.VALID_MODIFIERS:
            # Unknown modifier - treat entire string as field name and sanitize
            # Truncate modifier in log to prevent log injection with long payloads
            logger.warning(f"Invalid Sigma modifier rejected: '{modifier[:20]}{'...' if len(modifier) > 20 else ''}'")
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
            - All values are sanitized via _sanitize_value() before interpolation
            - Regex values use _sanitize_regex() to prevent ReDoS attacks
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
            # SECURITY: Use regex-specific sanitization to prevent ReDoS
            regex_safe_value = self._sanitize_regex(str_value)
            return f'| regex "{regex_safe_value}"'
        
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
