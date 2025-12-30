"""Mitigation Playbook Generator for ThreatSimGPT.

This module generates defense/mitigation playbooks that accompany threat simulations,
providing actionable security guidance for each threat scenario.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MitigationPlaybook:
    """Structured mitigation playbook for a threat scenario."""
    scenario_name: str
    threat_type: str
    mitre_techniques: List[str]

    # Detection strategies
    detection_indicators: List[str]
    detection_tools: List[str]

    # Prevention strategies
    prevention_controls: List[str]
    security_policies: List[str]

    # Response procedures
    immediate_actions: List[str]
    escalation_procedures: List[str]
    recovery_steps: List[str]

    # Training recommendations
    awareness_topics: List[str]
    skill_development: List[str]

    # Metrics
    risk_level: str  # low, medium, high, critical
    complexity: int  # 1-10

    generated_at: str = None

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now().isoformat()


# Comprehensive mitigation database mapped by threat type and MITRE techniques
MITIGATION_DATABASE = {
    "spear_phishing": {
        "detection_indicators": [
            "Unexpected emails from executives or authority figures requesting urgent action",
            "Email sender domain slightly misspelled (homoglyph attacks)",
            "Requests for sensitive information or credentials via email",
            "Pressure tactics: deadlines, consequences, confidentiality requests",
            "Links to unfamiliar or slightly misspelled domains",
            "Attachments with unusual file extensions or macros enabled",
            "Email headers showing mismatched sender information",
            "Grammar or formatting inconsistencies unusual for the claimed sender",
        ],
        "detection_tools": [
            "Email Security Gateway (Proofpoint, Mimecast, Microsoft Defender)",
            "DMARC/DKIM/SPF email authentication verification",
            "URL reputation scanning and sandboxing",
            "Attachment detonation and behavioral analysis",
            "User and Entity Behavior Analytics (UEBA)",
            "Security Awareness Training platforms with phishing simulations",
        ],
        "prevention_controls": [
            "Implement strict email authentication (DMARC reject policy)",
            "Deploy email security gateway with advanced threat protection",
            "Enable external email banners/warnings",
            "Block macro execution in Office documents from external sources",
            "Implement URL rewriting and time-of-click protection",
            "Configure SPF, DKIM, and DMARC for all sending domains",
            "Use multi-factor authentication for all email accounts",
            "Implement data loss prevention (DLP) policies",
        ],
        "security_policies": [
            "Verification policy: Always verify unusual requests via separate communication channel",
            "Financial transaction policy: Require dual approval for wire transfers",
            "Credential policy: IT will never ask for passwords via email",
            "Attachment policy: Report suspicious attachments to security team",
            "External email policy: Exercise extra caution with external senders",
        ],
        "immediate_actions": [
            "Do NOT click any links or download attachments",
            "Do NOT reply to the suspicious email",
            "Report to security team using phishing report button",
            "If clicked, disconnect from network immediately",
            "Change passwords if credentials may have been compromised",
            "Document the incident with screenshots",
        ],
        "escalation_procedures": [
            "Security team receives report within 15 minutes",
            "Analyze email headers and payload within 1 hour",
            "Block sender domain/IP at email gateway",
            "Search for similar emails across organization",
            "Notify affected users and reset compromised credentials",
            "Escalate to incident response if compromise confirmed",
        ],
        "recovery_steps": [
            "Quarantine affected systems for forensic analysis",
            "Reset all potentially compromised credentials",
            "Review access logs for unauthorized activity",
            "Restore systems from known-good backups if needed",
            "Conduct post-incident review and update defenses",
            "Provide targeted training for affected users",
        ],
        "awareness_topics": [
            "Recognizing spear-phishing red flags",
            "Verifying sender identity through out-of-band methods",
            "Understanding social engineering psychology",
            "Safe handling of email attachments and links",
            "Reporting procedures for suspicious emails",
        ],
        "skill_development": [
            "Email header analysis basics",
            "Hover-before-click URL verification",
            "Recognizing urgency manipulation tactics",
            "Understanding domain spoofing techniques",
            "Building healthy skepticism for unexpected requests",
        ],
    },

    "phishing": {
        "detection_indicators": [
            "Generic greeting instead of personalized salutation",
            "Suspicious sender address not matching claimed organization",
            "Urgent language demanding immediate action",
            "Requests to click links or provide login credentials",
            "Poor grammar, spelling, or formatting",
            "Mismatched URLs (hover shows different destination)",
            "Threats of account suspension or legal action",
        ],
        "detection_tools": [
            "Email Security Gateway with anti-phishing capabilities",
            "Browser-based phishing protection",
            "URL filtering and reputation services",
            "Endpoint Detection and Response (EDR)",
            "Security Awareness Training platforms",
        ],
        "prevention_controls": [
            "Enable email authentication (SPF, DKIM, DMARC)",
            "Deploy web filtering to block known phishing domains",
            "Implement password managers to prevent credential entry on fake sites",
            "Enable MFA for all accounts",
            "Configure browser security settings",
        ],
        "security_policies": [
            "Never enter credentials from email links - navigate directly to sites",
            "Report all suspicious emails to IT security",
            "Verify requests involving money or sensitive data",
            "Use company password manager for all logins",
        ],
        "immediate_actions": [
            "Do not click links or enter credentials",
            "Report the email using phishing report button",
            "If credentials entered, change password immediately",
            "Enable MFA if not already active",
        ],
        "escalation_procedures": [
            "Security team analyzes reported phishing within 30 minutes",
            "Block malicious URLs at web proxy",
            "Alert all users if widespread campaign detected",
            "Coordinate with email security vendor for updated signatures",
        ],
        "recovery_steps": [
            "Reset compromised credentials",
            "Review account activity for unauthorized access",
            "Update email filtering rules",
            "Send awareness reminder to organization",
        ],
        "awareness_topics": [
            "Identifying phishing email characteristics",
            "Safe browsing and credential hygiene",
            "Reporting procedures",
            "Understanding attacker motivations",
        ],
        "skill_development": [
            "URL inspection techniques",
            "Sender verification methods",
            "Critical thinking for unsolicited requests",
        ],
    },

    "business_email_compromise": {
        "detection_indicators": [
            "Executive impersonation requesting wire transfers",
            "Urgency combined with secrecy requests",
            "Changes to payment instructions or bank accounts",
            "Emails sent outside normal business hours",
            "Requests to bypass normal approval processes",
            "Lookalike domains (ceo@company-inc.com vs ceo@company.com)",
            "Reply-to address different from sender address",
        ],
        "detection_tools": [
            "Email Security Gateway with BEC detection",
            "UEBA for executive account monitoring",
            "Payment verification systems",
            "Domain monitoring for lookalike registration",
            "Email authentication enforcement",
        ],
        "prevention_controls": [
            "Implement dual-approval for financial transactions",
            "Establish verbal verification for payment changes",
            "Monitor for lookalike domain registrations",
            "Configure VIP/executive account protection",
            "Implement invoice verification procedures",
        ],
        "security_policies": [
            "All wire transfers require verbal confirmation via known phone number",
            "Payment detail changes require in-person or video verification",
            "Finance team must verify vendor bank changes through established contacts",
            "No financial transactions based solely on email instructions",
        ],
        "immediate_actions": [
            "STOP any pending financial transactions",
            "Call the apparent sender using known contact information",
            "Report to security and finance leadership",
            "Preserve all email evidence",
        ],
        "escalation_procedures": [
            "Immediate escalation to CFO/Finance leadership",
            "Contact bank to halt/recall fraudulent transfers",
            "Engage legal counsel if funds transferred",
            "Report to FBI IC3 for BEC incidents",
            "Conduct forensic investigation of email compromise",
        ],
        "recovery_steps": [
            "Work with bank on fund recovery",
            "Reset all executive email credentials",
            "Review all recent financial transactions",
            "Implement additional financial controls",
            "File insurance claim if applicable",
        ],
        "awareness_topics": [
            "BEC attack patterns and techniques",
            "Executive impersonation tactics",
            "Financial verification procedures",
            "Recognizing urgency manipulation",
        ],
        "skill_development": [
            "Verbal verification protocols",
            "Recognizing authority-based manipulation",
            "Financial transaction security",
        ],
    },

    "vishing": {
        "detection_indicators": [
            "Unexpected calls claiming to be from IT, HR, or executives",
            "Caller ID spoofing showing internal numbers",
            "Requests for passwords, tokens, or remote access",
            "Pressure to act immediately without verification",
            "Threats of consequences for non-compliance",
            "Requests to bypass security procedures",
        ],
        "detection_tools": [
            "Call recording and analysis systems",
            "Caller ID verification services",
            "Voice authentication systems",
            "Security awareness training with vishing simulations",
        ],
        "prevention_controls": [
            "Establish callback verification procedures",
            "Implement voice authentication for sensitive requests",
            "Create verbal challenge phrases for IT support",
            "Document all legitimate IT contact procedures",
        ],
        "security_policies": [
            "Never provide passwords or credentials over phone",
            "Always callback to verified numbers for sensitive requests",
            "IT will never ask for passwords or MFA codes",
            "Use established helpdesk ticket system for support",
        ],
        "immediate_actions": [
            "Hang up on suspicious calls",
            "Do not provide any information",
            "Report to security team immediately",
            "Document caller ID and conversation details",
        ],
        "escalation_procedures": [
            "Security team logs and analyzes vishing attempts",
            "Alert organization if pattern detected",
            "Trace phone numbers through carrier",
            "Update voice mail and phone system warnings",
        ],
        "recovery_steps": [
            "Reset any disclosed credentials",
            "Review account activity for compromise",
            "Update training materials with new tactics",
        ],
        "awareness_topics": [
            "Recognizing vishing tactics",
            "Callback verification procedures",
            "Understanding caller ID spoofing",
        ],
        "skill_development": [
            "Assertive call termination techniques",
            "Verification questioning strategies",
            "Recognizing manipulation in conversations",
        ],
    },

    "smishing": {
        "detection_indicators": [
            "SMS from unknown numbers claiming to be banks/services",
            "Links in text messages to unfamiliar URLs",
            "Urgent messages about account problems",
            "Requests to call phone numbers or reply with codes",
            "Package delivery notifications with suspicious links",
        ],
        "detection_tools": [
            "Mobile Device Management (MDM) with web filtering",
            "SMS filtering applications",
            "Mobile Threat Defense (MTD) solutions",
        ],
        "prevention_controls": [
            "Enable spam filtering on mobile devices",
            "Deploy MDM with URL filtering",
            "Disable auto-download of MMS content",
            "Use official apps instead of SMS links",
        ],
        "security_policies": [
            "Never click links in unexpected text messages",
            "Verify messages by logging into accounts directly",
            "Report suspicious SMS to carrier (forward to 7726)",
        ],
        "immediate_actions": [
            "Do not click links or call numbers in suspicious SMS",
            "Block the sender",
            "Report to carrier and security team",
            "If clicked, scan device for malware",
        ],
        "escalation_procedures": [
            "Security team analyzes reported smishing",
            "Block malicious URLs at corporate proxy",
            "Alert employees of ongoing campaign",
        ],
        "recovery_steps": [
            "Factory reset device if compromised",
            "Reset credentials for any accessed accounts",
            "Monitor accounts for unauthorized activity",
        ],
        "awareness_topics": [
            "SMS phishing tactics",
            "Safe mobile device practices",
            "Recognizing urgency in text messages",
        ],
        "skill_development": [
            "URL verification on mobile devices",
            "Recognizing legitimate vs. fraudulent notifications",
        ],
    },
}

# MITRE ATT&CK technique mappings
MITRE_MITIGATIONS = {
    "T1566.001": {  # Spear-Phishing Attachment
        "name": "Spear-Phishing Attachment",
        "mitigations": [
            "M1049 - Antivirus/Antimalware",
            "M1031 - Network Intrusion Prevention",
            "M1017 - User Training",
            "M1021 - Restrict Web-Based Content",
        ],
        "detections": [
            "DS0015 - Application Log",
            "DS0022 - File",
            "DS0029 - Network Traffic",
        ],
    },
    "T1566.002": {  # Spear-Phishing Link
        "name": "Spear-Phishing Link",
        "mitigations": [
            "M1017 - User Training",
            "M1021 - Restrict Web-Based Content",
            "M1054 - Software Configuration",
        ],
        "detections": [
            "DS0015 - Application Log",
            "DS0029 - Network Traffic",
        ],
    },
    "T1598": {  # Phishing for Information
        "name": "Phishing for Information",
        "mitigations": [
            "M1017 - User Training",
            "M1054 - Software Configuration",
        ],
        "detections": [
            "DS0015 - Application Log",
            "DS0029 - Network Traffic",
        ],
    },
}


class MitigationGenerator:
    """Generate mitigation playbooks for threat scenarios."""

    def __init__(self):
        self.mitigation_db = MITIGATION_DATABASE
        self.mitre_db = MITRE_MITIGATIONS
        logger.info("MitigationGenerator initialized")

    def generate_playbook(
        self,
        scenario_name: str,
        threat_type: str,
        mitre_techniques: List[str] = None,
        target_profile: Dict[str, Any] = None,
        difficulty_level: int = 5,
    ) -> MitigationPlaybook:
        """Generate a comprehensive mitigation playbook for a threat scenario.

        Args:
            scenario_name: Name of the threat scenario
            threat_type: Type of threat (phishing, bec, vishing, etc.)
            mitre_techniques: List of MITRE ATT&CK technique IDs
            target_profile: Target profile information
            difficulty_level: Scenario difficulty (1-10)

        Returns:
            MitigationPlaybook with comprehensive defense strategies
        """
        # Normalize threat type
        threat_key = threat_type.lower().replace("-", "_").replace(" ", "_")

        # Get base mitigations for threat type
        base_mitigations = self.mitigation_db.get(
            threat_key,
            self.mitigation_db.get("phishing", {})  # Default to phishing
        )

        # Enhance with MITRE-specific mitigations
        mitre_mitigations = []
        mitre_detections = []
        if mitre_techniques:
            for technique in mitre_techniques:
                if technique in self.mitre_db:
                    mitre_info = self.mitre_db[technique]
                    mitre_mitigations.extend(mitre_info.get("mitigations", []))
                    mitre_detections.extend(mitre_info.get("detections", []))

        # Determine risk level based on difficulty
        risk_level = self._calculate_risk_level(difficulty_level, threat_type)

        # Create playbook
        playbook = MitigationPlaybook(
            scenario_name=scenario_name,
            threat_type=threat_type,
            mitre_techniques=mitre_techniques or [],
            detection_indicators=base_mitigations.get("detection_indicators", []),
            detection_tools=base_mitigations.get("detection_tools", []),
            prevention_controls=base_mitigations.get("prevention_controls", []),
            security_policies=base_mitigations.get("security_policies", []),
            immediate_actions=base_mitigations.get("immediate_actions", []),
            escalation_procedures=base_mitigations.get("escalation_procedures", []),
            recovery_steps=base_mitigations.get("recovery_steps", []),
            awareness_topics=base_mitigations.get("awareness_topics", []),
            skill_development=base_mitigations.get("skill_development", []),
            risk_level=risk_level,
            complexity=difficulty_level,
        )

        logger.info(f"Generated mitigation playbook for: {scenario_name}")
        return playbook

    def _calculate_risk_level(self, difficulty: int, threat_type: str) -> str:
        """Calculate risk level based on difficulty and threat type."""
        high_risk_threats = ["business_email_compromise", "bec", "spear_phishing"]

        if threat_type.lower() in high_risk_threats:
            difficulty += 2  # BEC/spear-phishing are inherently higher risk

        if difficulty >= 8:
            return "critical"
        elif difficulty >= 6:
            return "high"
        elif difficulty >= 4:
            return "medium"
        else:
            return "low"

    def format_playbook_markdown(self, playbook: MitigationPlaybook) -> str:
        """Format playbook as markdown for storage/display.

        Args:
            playbook: MitigationPlaybook to format

        Returns:
            Formatted markdown string
        """
        mitre_str = ", ".join(playbook.mitre_techniques) if playbook.mitre_techniques else "N/A"

        md = f"""# Mitigation Playbook: {playbook.scenario_name}

## Overview
- **Threat Type**: {playbook.threat_type}
- **Risk Level**: {playbook.risk_level.upper()}
- **Complexity**: {playbook.complexity}/10
- **MITRE ATT&CK**: {mitre_str}
- **Generated**: {playbook.generated_at}

---

## Detection

### Indicators of Compromise (IoCs)
{self._format_list(playbook.detection_indicators)}

### Detection Tools & Technologies
{self._format_list(playbook.detection_tools)}

---

## Prevention

### Security Controls
{self._format_list(playbook.prevention_controls)}

### Security Policies
{self._format_list(playbook.security_policies)}

---

## Response Procedures

### Immediate Actions (First 15 Minutes)
{self._format_numbered_list(playbook.immediate_actions)}

### Escalation Procedures
{self._format_numbered_list(playbook.escalation_procedures)}

### Recovery Steps
{self._format_numbered_list(playbook.recovery_steps)}

---

## Training & Awareness

### Key Awareness Topics
{self._format_list(playbook.awareness_topics)}

### Skill Development Areas
{self._format_list(playbook.skill_development)}

---

## Quick Reference Card

| Category | Key Action |
|----------|------------|
| **If you receive this** | Do NOT click, reply, or act |
| **First step** | Report to security team |
| **Verify via** | Separate communication channel |
| **If compromised** | Disconnect, report, change credentials |

---

*This playbook was automatically generated by ThreatSimGPT for security training purposes.*
*Review and customize for your organization's specific policies and procedures.*
"""
        return md

    def _format_list(self, items: List[str]) -> str:
        """Format items as bullet list."""
        if not items:
            return "- No specific items identified\n"
        return "\n".join(f"- {item}" for item in items)

    def _format_numbered_list(self, items: List[str]) -> str:
        """Format items as numbered list."""
        if not items:
            return "1. No specific steps identified\n"
        return "\n".join(f"{i+1}. {item}" for i, item in enumerate(items))


# Global instance
mitigation_generator = MitigationGenerator()


def generate_mitigation_playbook(
    scenario_name: str,
    threat_type: str,
    mitre_techniques: List[str] = None,
    target_profile: Dict[str, Any] = None,
    difficulty_level: int = 5,
) -> str:
    """Convenience function to generate a formatted mitigation playbook.

    Args:
        scenario_name: Name of the threat scenario
        threat_type: Type of threat
        mitre_techniques: MITRE ATT&CK technique IDs
        target_profile: Target profile information
        difficulty_level: Scenario difficulty (1-10)

    Returns:
        Formatted markdown playbook
    """
    playbook = mitigation_generator.generate_playbook(
        scenario_name=scenario_name,
        threat_type=threat_type,
        mitre_techniques=mitre_techniques,
        target_profile=target_profile,
        difficulty_level=difficulty_level,
    )
    return mitigation_generator.format_playbook_markdown(playbook)
