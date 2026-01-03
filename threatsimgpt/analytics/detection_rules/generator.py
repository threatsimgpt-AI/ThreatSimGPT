"""Base Detection Rule Generator.

Provides the foundation for generating SIEM detection rules from attack scenarios.

Author: David Onoja (Blue Team)
"""

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type

from .models import (
    DetectionRule,
    DetectionLogic,
    LogSourceConfig,
    MitreMapping,
    RuleFormat,
    RuleGenerationRequest,
    RuleGenerationResult,
    RuleMetadata,
    RuleSeverity,
    RuleStatus,
)


# MITRE ATT&CK technique database (subset for common phishing/social engineering)
MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1566": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_name": "Phishing",
        "sub_techniques": {
            "T1566.001": "Spearphishing Attachment",
            "T1566.002": "Spearphishing Link",
            "T1566.003": "Spearphishing via Service",
        }
    },
    "T1204": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_name": "User Execution",
        "sub_techniques": {
            "T1204.001": "Malicious Link",
            "T1204.002": "Malicious File",
        }
    },
    "T1078": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_name": "Valid Accounts",
        "sub_techniques": {
            "T1078.001": "Default Accounts",
            "T1078.002": "Domain Accounts",
            "T1078.003": "Local Accounts",
            "T1078.004": "Cloud Accounts",
        }
    },
    "T1110": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_name": "Brute Force",
        "sub_techniques": {
            "T1110.001": "Password Guessing",
            "T1110.002": "Password Cracking",
            "T1110.003": "Password Spraying",
            "T1110.004": "Credential Stuffing",
        }
    },
    "T1534": {
        "tactic_id": "TA0008",
        "tactic_name": "Lateral Movement",
        "technique_name": "Internal Spearphishing",
        "sub_techniques": {}
    },
    "T1598": {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_name": "Phishing for Information",
        "sub_techniques": {
            "T1598.001": "Spearphishing Service",
            "T1598.002": "Spearphishing Attachment",
            "T1598.003": "Spearphishing Link",
        }
    },
    "T1059": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_name": "Command and Scripting Interpreter",
        "sub_techniques": {
            "T1059.001": "PowerShell",
            "T1059.003": "Windows Command Shell",
            "T1059.005": "Visual Basic",
            "T1059.007": "JavaScript",
        }
    },
    "T1071": {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_name": "Application Layer Protocol",
        "sub_techniques": {
            "T1071.001": "Web Protocols",
            "T1071.002": "File Transfer Protocols",
            "T1071.003": "Mail Protocols",
        }
    },
}

# Attack type to log source mapping
ATTACK_LOG_SOURCES: Dict[str, LogSourceConfig] = {
    "phishing": LogSourceConfig(
        category="email",
        product="email_gateway",
        service="mail"
    ),
    "malware": LogSourceConfig(
        category="process_creation",
        product="windows",
        service="sysmon"
    ),
    "credential_theft": LogSourceConfig(
        category="authentication",
        product="windows",
        service="security"
    ),
    "network_intrusion": LogSourceConfig(
        category="firewall",
        product="firewall",
        service="network"
    ),
    "data_exfiltration": LogSourceConfig(
        category="proxy",
        product="proxy",
        service="web"
    ),
}


class BaseRuleGenerator(ABC):
    """Abstract base class for detection rule generators."""
    
    format: RuleFormat
    
    @abstractmethod
    def generate(self, rule: DetectionRule) -> str:
        """Generate rule in the specific format.
        
        Args:
            rule: DetectionRule object to convert
            
        Returns:
            String representation of the rule in target format
        """
        pass
    
    @abstractmethod
    def validate(self, rule_content: str) -> tuple[bool, List[str]]:
        """Validate the generated rule syntax.
        
        Args:
            rule_content: Generated rule string
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        pass


class DetectionRuleGenerator:
    """Main detection rule generator that orchestrates format-specific generators."""
    
    def __init__(self):
        """Initialize the generator with format-specific handlers."""
        self._generators: Dict[RuleFormat, BaseRuleGenerator] = {}
    
    def register_generator(self, format: RuleFormat, generator: BaseRuleGenerator):
        """Register a format-specific generator.
        
        Args:
            format: The rule format this generator handles
            generator: Generator instance
        """
        self._generators[format] = generator
    
    def generate_from_scenario(
        self,
        request: RuleGenerationRequest
    ) -> RuleGenerationResult:
        """Generate detection rules from an attack scenario.
        
        Args:
            request: Rule generation request with scenario details
            
        Returns:
            RuleGenerationResult with generated rules
        """
        start_time = time.time()
        
        try:
            # Build detection rule from scenario
            rule = self._build_rule_from_scenario(request)
            
            # Generate in requested formats
            result = RuleGenerationResult(
                success=True,
                rule=rule,
                validation_passed=True,
            )
            
            for format in request.formats:
                if format in self._generators:
                    generator = self._generators[format]
                    content = generator.generate(rule)
                    
                    # Validate generated content
                    is_valid, errors = generator.validate(content)
                    if not is_valid:
                        result.validation_passed = False
                        result.validation_errors.extend(errors)
                    
                    # Store generated content
                    if format == RuleFormat.SIGMA:
                        result.sigma_yaml = content
                    elif format == RuleFormat.SPLUNK:
                        result.splunk_spl = content
                    elif format == RuleFormat.ELASTIC:
                        result.elastic_kql = content
                    elif format == RuleFormat.SENTINEL:
                        result.sentinel_kql = content
                    
                    rule.formats_generated.append(format)
            
            result.generation_time_ms = (time.time() - start_time) * 1000
            return result
            
        except Exception as e:
            return RuleGenerationResult(
                success=False,
                validation_passed=False,
                validation_errors=[str(e)],
                generation_time_ms=(time.time() - start_time) * 1000,
            )
    
    def _build_rule_from_scenario(
        self,
        request: RuleGenerationRequest
    ) -> DetectionRule:
        """Build a DetectionRule from scenario request.
        
        Args:
            request: The generation request
            
        Returns:
            DetectionRule object
        """
        # Determine MITRE mappings
        mitre_mappings = self._get_mitre_mappings(
            request.mitre_techniques,
            request.attack_type
        )
        
        # Determine severity
        severity = request.severity_override or self._detect_severity(
            request.attack_type,
            request.attack_vectors
        )
        
        # Build detection logic
        detection = self._build_detection_logic(request)
        
        # Get appropriate log source
        logsource = ATTACK_LOG_SOURCES.get(
            request.attack_type.lower(),
            LogSourceConfig()
        )
        
        # Create rule
        rule = DetectionRule(
            title=f"ThreatSimGPT - {request.scenario_name}",
            name=self._slugify(request.scenario_name),
            description=request.scenario_description,
            status=RuleStatus.EXPERIMENTAL,
            severity=severity,
            logsource=logsource,
            detection=detection,
            mitre_attack=mitre_mappings,
            metadata=RuleMetadata(
                author="ThreatSimGPT Blue Team",
                source_scenario_id=request.scenario_id,
                tags=[f"attack.{request.attack_type.lower()}"],
                false_positives=[
                    "Legitimate business communications may trigger this rule",
                    "Review context before escalating",
                ],
            ),
        )
        
        return rule
    
    def _get_mitre_mappings(
        self,
        technique_ids: List[str],
        attack_type: str
    ) -> List[MitreMapping]:
        """Get MITRE ATT&CK mappings for techniques.
        
        Args:
            technique_ids: List of MITRE technique IDs
            attack_type: Type of attack for auto-detection
            
        Returns:
            List of MitreMapping objects
        """
        mappings = []
        
        # If no techniques provided, auto-detect based on attack type
        if not technique_ids:
            technique_ids = self._auto_detect_techniques(attack_type)
        
        for tech_id in technique_ids:
            # Handle sub-techniques (e.g., T1566.001)
            base_id = tech_id.split(".")[0]
            
            if base_id in MITRE_TECHNIQUES:
                tech_info = MITRE_TECHNIQUES[base_id]
                
                sub_tech_id = None
                sub_tech_name = None
                if "." in tech_id and tech_id in tech_info.get("sub_techniques", {}):
                    sub_tech_id = tech_id
                    sub_tech_name = tech_info["sub_techniques"][tech_id]
                
                mapping = MitreMapping(
                    tactic_id=tech_info["tactic_id"],
                    tactic_name=tech_info["tactic_name"],
                    technique_id=base_id,
                    technique_name=tech_info["technique_name"],
                    sub_technique_id=sub_tech_id,
                    sub_technique_name=sub_tech_name,
                )
                mappings.append(mapping)
        
        return mappings
    
    def _auto_detect_techniques(self, attack_type: str) -> List[str]:
        """Auto-detect MITRE techniques based on attack type.
        
        Args:
            attack_type: Type of attack
            
        Returns:
            List of technique IDs
        """
        attack_type_lower = attack_type.lower()
        
        technique_map = {
            "phishing": ["T1566.001", "T1566.002", "T1204.001"],
            "spearphishing": ["T1566.001", "T1566.002"],
            "credential_theft": ["T1078", "T1110.003"],
            "malware": ["T1204.002", "T1059.001"],
            "social_engineering": ["T1566", "T1598"],
            "bec": ["T1566.002", "T1534"],  # Business Email Compromise
            "ransomware": ["T1204.002", "T1059.001", "T1071.001"],
        }
        
        return technique_map.get(attack_type_lower, ["T1566"])
    
    def _detect_severity(
        self,
        attack_type: str,
        attack_vectors: List[str]
    ) -> RuleSeverity:
        """Detect appropriate severity based on attack characteristics.
        
        Args:
            attack_type: Type of attack
            attack_vectors: Attack vectors used
            
        Returns:
            Appropriate severity level
        """
        high_severity_types = {"ransomware", "data_exfiltration", "credential_theft"}
        critical_indicators = {"executive", "c-suite", "ceo", "cfo", "wire_transfer"}
        
        attack_type_lower = attack_type.lower()
        vectors_lower = [v.lower() for v in attack_vectors]
        
        # Check for critical indicators
        for indicator in critical_indicators:
            if indicator in attack_type_lower or any(indicator in v for v in vectors_lower):
                return RuleSeverity.CRITICAL
        
        # Check for high severity attack types
        if attack_type_lower in high_severity_types:
            return RuleSeverity.HIGH
        
        # Default based on attack type
        if "phishing" in attack_type_lower:
            return RuleSeverity.MEDIUM
        
        return RuleSeverity.MEDIUM
    
    def _build_detection_logic(
        self,
        request: RuleGenerationRequest
    ) -> DetectionLogic:
        """Build detection logic from request.
        
        Args:
            request: Generation request
            
        Returns:
            DetectionLogic object
        """
        attack_type = request.attack_type.lower()
        
        # Build selection criteria based on attack type
        if "phishing" in attack_type or "email" in attack_type:
            selection = {
                "EventType": "EmailReceived",
                "Subject|contains": [
                    "urgent",
                    "action required",
                    "verify",
                    "account",
                    "password",
                    "suspended",
                ],
                "SenderDomain|endswith": [
                    ".xyz",
                    ".top",
                    ".work",
                    ".click",
                ],
            }
            filter_criteria = {
                "SenderDomain|endswith": [
                    "@company.com",  # Internal domain
                ],
            }
            condition = "selection and not filter"
            
        elif "credential" in attack_type or "login" in attack_type:
            selection = {
                "EventID": [4625, 4624],  # Failed/successful login
                "LogonType": [3, 10],  # Network/Remote
                "Status": "0xC000006D",  # Bad password
            }
            filter_criteria = {
                "TargetUserName|endswith": "$",  # Machine accounts
            }
            condition = "selection and not filter | count() by TargetUserName > 5"
            
        elif "malware" in attack_type or "execution" in attack_type:
            selection = {
                "EventID": 1,  # Sysmon Process Creation
                "Image|endswith": [
                    "\\powershell.exe",
                    "\\cmd.exe",
                    "\\wscript.exe",
                    "\\cscript.exe",
                ],
                "CommandLine|contains": [
                    "downloadstring",
                    "invoke-expression",
                    "bypass",
                    "-enc",
                    "-encodedcommand",
                ],
            }
            filter_criteria = None
            condition = "selection"
            
        else:
            # Generic detection
            selection = {
                "EventType": request.attack_type,
            }
            filter_criteria = None
            condition = "selection"
        
        return DetectionLogic(
            selection=selection,
            filter=filter_criteria,
            condition=condition,
        )
    
    def _slugify(self, text: str) -> str:
        """Convert text to slug format.
        
        Args:
            text: Text to slugify
            
        Returns:
            Slugified string
        """
        import re
        text = text.lower()
        text = re.sub(r'[^\w\s-]', '', text)
        text = re.sub(r'[-\s]+', '_', text)
        return text.strip('_')
    
    def from_attack_technique(
        self,
        technique_id: str,
        formats: Optional[List[RuleFormat]] = None
    ) -> RuleGenerationResult:
        """Generate detection rules directly from a MITRE ATT&CK technique ID.
        
        This is a convenience method for blue team analysts who want to quickly
        generate detection rules based on MITRE ATT&CK framework.
        
        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1566.001)
            formats: List of formats to generate (defaults to all registered)
            
        Returns:
            RuleGenerationResult with generated rules
        """
        # Parse technique ID
        base_id = technique_id.split(".")[0]
        
        if base_id not in MITRE_TECHNIQUES:
            return RuleGenerationResult(
                success=False,
                validation_passed=False,
                validation_errors=[f"Unknown MITRE technique: {technique_id}"],
                generation_time_ms=0,
            )
        
        tech_info = MITRE_TECHNIQUES[base_id]
        
        # Get technique name
        if "." in technique_id:
            sub_techniques = tech_info.get("sub_techniques", {})
            technique_name = sub_techniques.get(technique_id, tech_info["technique_name"])
        else:
            technique_name = tech_info["technique_name"]
        
        # Determine attack type from tactic
        tactic_to_attack_type = {
            "TA0001": "phishing",  # Initial Access
            "TA0002": "malware",   # Execution
            "TA0006": "credential_theft",  # Credential Access
            "TA0008": "phishing",  # Lateral Movement (internal)
            "TA0011": "malware",   # Command and Control
            "TA0043": "phishing",  # Reconnaissance
        }
        attack_type = tactic_to_attack_type.get(tech_info["tactic_id"], "phishing")
        
        # Build request
        request = RuleGenerationRequest(
            scenario_name=f"MITRE {technique_id} - {technique_name}",
            scenario_description=f"Detection rule for MITRE ATT&CK technique {technique_id}: {technique_name}. Tactic: {tech_info['tactic_name']}",
            scenario_id=f"mitre_{technique_id.replace('.', '_').lower()}",
            attack_type=attack_type,
            attack_vectors=[technique_name],
            mitre_techniques=[technique_id],
            formats=formats or list(self._generators.keys()),
        )
        
        return self.generate_from_scenario(request)
