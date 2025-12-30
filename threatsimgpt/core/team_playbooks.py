"""Team-Specific Playbook Generator for ThreatSimGPT.

Generates customized security playbooks for different cybersecurity teams:
- Blue Team (Defense/Detection)
- Red Team (Offensive Security)
- Purple Team (Collaborative Testing)
- SOC (Security Operations Center)
- Threat Intelligence
- GRC (Governance, Risk, Compliance)
- Incident Response
- Security Awareness Training
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class SecurityTeam(Enum):
    """Security team types."""
    BLUE_TEAM = "blue_team"
    RED_TEAM = "red_team"
    PURPLE_TEAM = "purple_team"
    SOC = "soc"
    THREAT_INTEL = "threat_intel"
    GRC = "grc"
    INCIDENT_RESPONSE = "incident_response"
    SECURITY_AWARENESS = "security_awareness"


@dataclass
class TeamPlaybook:
    """Team-specific playbook output."""
    team: SecurityTeam
    scenario_name: str
    threat_type: str
    mitre_techniques: List[str]
    content: Dict[str, Any]
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())


# =============================================================================
# TEAM-SPECIFIC CONTENT DATABASES
# =============================================================================

BLUE_TEAM_CONTENT = {
    "spear_phishing": {
        "detection_rules": [
            {
                "name": "Spear-Phishing Email Detection",
                "type": "SIEM Rule",
                "logic": "email_external=true AND (subject CONTAINS 'urgent' OR 'confidential' OR 'wire transfer') AND sender_domain NOT IN whitelist",
                "severity": "HIGH",
                "mitre": "T1566.001"
            },
            {
                "name": "Executive Impersonation Detection",
                "type": "Email Security",
                "logic": "display_name MATCHES executive_list AND sender_domain != corporate_domain",
                "severity": "CRITICAL",
                "mitre": "T1566.002"
            },
            {
                "name": "Lookalike Domain Detection",
                "type": "DNS/Proxy",
                "logic": "domain_similarity_score > 0.85 AND domain NOT IN whitelist AND domain_age < 30_days",
                "severity": "HIGH",
                "mitre": "T1566.002"
            },
        ],
        "monitoring_queries": [
            {
                "name": "Suspicious Email Link Clicks",
                "platform": "Splunk/Elastic",
                "query": 'index=proxy sourcetype=web_proxy url_category="uncategorized" OR url_reputation="unknown" | stats count by user, url, timestamp',
            },
            {
                "name": "Credential Submission to External Sites",
                "platform": "Splunk/Elastic",
                "query": 'index=proxy method=POST uri_path IN ("*login*", "*signin*", "*auth*") dest_domain NOT IN corporate_domains | table user, dest_domain, uri_path',
            },
        ],
        "hardening_measures": [
            "Configure DMARC with reject policy (p=reject)",
            "Enable external email warning banners",
            "Implement URL rewriting and time-of-click analysis",
            "Deploy email attachment sandboxing",
            "Configure macro blocking for external documents",
            "Enable Safe Links and Safe Attachments (M365)",
        ],
        "ioc_types": [
            "Sender email addresses",
            "Sender domains (including lookalikes)",
            "Embedded URLs and redirect chains",
            "Attachment hashes (MD5, SHA256)",
            "Email header anomalies (X-Originating-IP, Reply-To mismatches)",
        ],
    },
    "business_email_compromise": {
        "detection_rules": [
            {
                "name": "Wire Transfer Request Detection",
                "type": "Email DLP",
                "logic": "body CONTAINS ('wire transfer' OR 'bank account' OR 'routing number') AND sender_external=true",
                "severity": "CRITICAL",
                "mitre": "T1566.002"
            },
            {
                "name": "Payment Detail Change Request",
                "type": "Email Security",
                "logic": "body CONTAINS ('update payment' OR 'new bank' OR 'change account') AND attachment_count > 0",
                "severity": "HIGH",
                "mitre": "T1534"
            },
        ],
        "monitoring_queries": [
            {
                "name": "Financial Keywords in External Emails",
                "platform": "Splunk/Elastic",
                "query": 'index=email direction=inbound | regex body="(?i)(wire|transfer|routing|swift|iban|bank account)" | stats count by sender, recipient, subject',
            },
        ],
        "hardening_measures": [
            "Implement dual-approval workflows for wire transfers",
            "Configure VIP/executive email protection",
            "Enable impersonation protection in email gateway",
            "Require out-of-band verification for payment changes",
        ],
        "ioc_types": [
            "Spoofed executive email addresses",
            "Lookalike domains",
            "Fraudulent bank account details",
            "Reply-to address mismatches",
        ],
    },
    "vishing": {
        "detection_rules": [
            {
                "name": "Unusual Helpdesk Access Patterns",
                "type": "UEBA",
                "logic": "password_reset_count > threshold AND time_window < 1hour AND caller_verified=false",
                "severity": "HIGH",
                "mitre": "T1598.001"
            },
        ],
        "monitoring_queries": [
            {
                "name": "Password Reset Anomalies",
                "platform": "Splunk/Elastic",
                "query": 'index=iam action="password_reset" | stats count by target_user, requestor, method | where count > 2',
            },
        ],
        "hardening_measures": [
            "Implement callback verification for sensitive requests",
            "Deploy voice authentication for helpdesk",
            "Require ticket creation before credential changes",
            "Log all helpdesk interactions with caller details",
        ],
        "ioc_types": [
            "Spoofed caller IDs",
            "Call patterns and timing",
            "Social engineering scripts/pretexts",
        ],
    },
}

RED_TEAM_CONTENT = {
    "spear_phishing": {
        "attack_techniques": [
            {
                "name": "Executive Impersonation via Display Name Spoofing",
                "description": "Craft emails with executive display names using external domains",
                "mitre": "T1566.002",
                "difficulty": "Low",
                "detection_risk": "Medium"
            },
            {
                "name": "Lookalike Domain Registration",
                "description": "Register domains with visual similarity (homoglyphs, typosquatting)",
                "mitre": "T1583.001",
                "difficulty": "Low",
                "detection_risk": "Low"
            },
            {
                "name": "HTML Smuggling Payload Delivery",
                "description": "Embed payloads in HTML attachments to bypass email security",
                "mitre": "T1027.006",
                "difficulty": "Medium",
                "detection_risk": "Medium"
            },
            {
                "name": "OAuth Consent Phishing",
                "description": "Trick users into granting permissions to malicious OAuth apps",
                "mitre": "T1566.002",
                "difficulty": "Medium",
                "detection_risk": "Low"
            },
        ],
        "payload_options": [
            {
                "type": "Credential Harvesting",
                "tools": ["Evilginx2", "Gophish", "Modlishka"],
                "description": "Real-time credential interception with MFA bypass capability"
            },
            {
                "type": "Macro-enabled Document",
                "tools": ["Office Macro", "VBA Stomping"],
                "description": "Document with embedded macro for initial access"
            },
            {
                "type": "Link to Malicious Site",
                "tools": ["Custom landing page", "Redirect chain"],
                "description": "Phishing link with evasion techniques"
            },
        ],
        "evasion_techniques": [
            "Use legitimate email services (SendGrid, Mailchimp) for delivery",
            "Implement CAPTCHA on phishing pages to evade automated scanning",
            "Use URL shorteners with preview disabled",
            "Deploy pages on compromised legitimate domains",
            "Implement geofencing to avoid security researcher access",
            "Use time-delayed payload activation",
        ],
        "success_metrics": [
            "Email delivery rate (bypassed spam filters)",
            "Open rate (tracking pixel)",
            "Click-through rate (link engagement)",
            "Credential capture rate",
            "MFA bypass success rate",
            "Time to detection by SOC",
        ],
        "opsec_considerations": [
            "Use dedicated infrastructure separate from production",
            "Register domains 30+ days before campaign",
            "Use privacy-protected WHOIS registration",
            "Implement proper SSL certificates",
            "Avoid reusing infrastructure across engagements",
        ],
    },
    "business_email_compromise": {
        "attack_techniques": [
            {
                "name": "CEO Fraud (Wire Transfer)",
                "description": "Impersonate CEO to request urgent wire transfers",
                "mitre": "T1534",
                "difficulty": "Medium",
                "detection_risk": "High"
            },
            {
                "name": "Vendor Email Compromise",
                "description": "Compromise vendor email to redirect payments",
                "mitre": "T1586.002",
                "difficulty": "High",
                "detection_risk": "Low"
            },
            {
                "name": "Invoice Manipulation",
                "description": "Intercept and modify legitimate invoices",
                "mitre": "T1565.001",
                "difficulty": "Medium",
                "detection_risk": "Medium"
            },
        ],
        "payload_options": [
            {
                "type": "Fraudulent Wire Instructions",
                "tools": ["Forged PDF", "Email thread hijacking"],
                "description": "Modified payment details in convincing format"
            },
        ],
        "evasion_techniques": [
            "Study target's email format and signature style",
            "Time attacks during travel/vacation periods",
            "Use urgency and confidentiality pretexts",
            "Request secrecy to prevent verification",
        ],
        "success_metrics": [
            "Email believability score",
            "Finance team response rate",
            "Wire transfer initiation rate",
            "Time to internal detection",
        ],
        "opsec_considerations": [
            "Research target organization's hierarchy thoroughly",
            "Understand internal approval processes",
            "Map out communication patterns",
        ],
    },
    "vishing": {
        "attack_techniques": [
            {
                "name": "IT Helpdesk Impersonation",
                "description": "Call employees posing as IT support",
                "mitre": "T1598.001",
                "difficulty": "Medium",
                "detection_risk": "Low"
            },
            {
                "name": "Callback Phishing",
                "description": "Leave voicemail requesting callback to attacker line",
                "mitre": "T1598.001",
                "difficulty": "Low",
                "detection_risk": "Low"
            },
        ],
        "payload_options": [
            {
                "type": "Credential Harvesting via Phone",
                "tools": ["Pretexting script", "Caller ID spoofing"],
                "description": "Extract credentials through social engineering"
            },
            {
                "type": "Remote Access Installation",
                "tools": ["TeamViewer", "AnyDesk", "Quick Assist"],
                "description": "Guide user to install remote access for 'support'"
            },
        ],
        "evasion_techniques": [
            "Use caller ID spoofing to show internal numbers",
            "Research target before calling (LinkedIn, org chart)",
            "Call during busy periods for reduced scrutiny",
            "Have convincing background noise (office sounds)",
        ],
        "success_metrics": [
            "Call answer rate",
            "Credential disclosure rate",
            "Remote access installation rate",
            "Average call duration before detection",
        ],
        "opsec_considerations": [
            "Use burner phones or VoIP with disposable numbers",
            "Prepare for callback verification attempts",
            "Have consistent backstory and knowledge",
        ],
    },
}

PURPLE_TEAM_CONTENT = {
    "spear_phishing": {
        "test_scenarios": [
            {
                "name": "Baseline Phishing Detection Test",
                "objective": "Measure current detection capabilities",
                "red_action": "Send test phishing email with tracking",
                "blue_expectation": "Email blocked or flagged within 5 minutes",
                "metrics": ["Detection time", "Alert accuracy", "User report rate"]
            },
            {
                "name": "Evasion Technique Testing",
                "objective": "Test detection of advanced techniques",
                "red_action": "Use HTML smuggling, homoglyph domains",
                "blue_expectation": "Behavioral analysis triggers on execution",
                "metrics": ["Evasion success rate", "Secondary detection rate"]
            },
            {
                "name": "User Response Testing",
                "objective": "Assess user security awareness",
                "red_action": "Send realistic spear-phishing to sample users",
                "blue_expectation": "Users report via proper channels",
                "metrics": ["Click rate", "Report rate", "Credential entry rate"]
            },
        ],
        "detection_gaps": [
            "Display name spoofing without email authentication check",
            "Delayed payload activation bypassing sandbox",
            "Legitimate service abuse (Google Docs, OneDrive)",
            "QR code phishing (quishing) bypassing URL scanning",
        ],
        "improvement_recommendations": [
            {
                "gap": "No lookalike domain detection",
                "recommendation": "Implement domain similarity monitoring",
                "priority": "HIGH",
                "effort": "Medium"
            },
            {
                "gap": "Slow user reporting",
                "recommendation": "Deploy one-click phishing report button",
                "priority": "MEDIUM",
                "effort": "Low"
            },
            {
                "gap": "Macro execution not blocked",
                "recommendation": "Enable ASR rules for macro blocking",
                "priority": "HIGH",
                "effort": "Low"
            },
        ],
        "collaborative_exercises": [
            {
                "name": "Tabletop Exercise: Executive Targeting",
                "duration": "2 hours",
                "participants": ["Red Team", "Blue Team", "SOC", "Executive Sponsors"],
                "scenario": "Simulated spear-phishing campaign targeting C-suite"
            },
            {
                "name": "Live Fire Exercise",
                "duration": "1 week",
                "participants": ["Red Team", "Blue Team", "SOC"],
                "scenario": "Controlled phishing campaign with real-time defense"
            },
        ],
    },
}

SOC_CONTENT = {
    "spear_phishing": {
        "alert_triage": [
            {
                "alert_name": "Phishing Email Detected",
                "priority": "P2 - High",
                "initial_actions": [
                    "Verify alert is not false positive",
                    "Check if email was delivered or quarantined",
                    "Identify all recipients",
                    "Check for user interaction (clicks, replies)"
                ],
                "escalation_criteria": [
                    "User clicked link and entered credentials",
                    "Multiple users targeted",
                    "Executive/VIP targeted",
                    "Payload executed on endpoint"
                ],
                "sla": "15 minutes initial triage"
            },
        ],
        "investigation_steps": [
            "1. Extract and analyze email headers (X-Originating-IP, SPF/DKIM/DMARC results)",
            "2. Identify sender domain reputation and registration date",
            "3. Extract and detonate URLs in sandbox (URLscan, Any.Run)",
            "4. Extract and analyze attachments (VirusTotal, sandbox)",
            "5. Query SIEM for all emails from sender domain",
            "6. Check proxy logs for user clicks on malicious URLs",
            "7. Review endpoint telemetry for payload execution",
            "8. Document IOCs and update blocklists",
        ],
        "response_playbook": [
            {
                "phase": "Containment",
                "actions": [
                    "Quarantine email from all mailboxes",
                    "Block sender domain at email gateway",
                    "Block malicious URLs at proxy",
                    "Disable compromised user accounts (if credentials stolen)"
                ],
                "timeframe": "30 minutes"
            },
            {
                "phase": "Eradication",
                "actions": [
                    "Force password reset for affected users",
                    "Revoke active sessions",
                    "Scan endpoints for indicators",
                    "Remove any downloaded payloads"
                ],
                "timeframe": "2 hours"
            },
            {
                "phase": "Recovery",
                "actions": [
                    "Re-enable accounts with MFA verification",
                    "Monitor for follow-up attacks",
                    "Update detection rules based on TTPs",
                    "Send user awareness notification"
                ],
                "timeframe": "24 hours"
            },
        ],
        "communication_templates": {
            "internal_notification": "Security Alert: Phishing campaign detected targeting [DEPARTMENT]. Do not interact with emails from [SENDER]. Report suspicious emails to security@company.com.",
            "management_update": "Incident Update: [X] users targeted, [Y] clicked, [Z] credentials potentially compromised. Containment in progress. ETA for resolution: [TIME].",
        },
    },
}

THREAT_INTEL_CONTENT = {
    "spear_phishing": {
        "threat_profile": {
            "threat_actors": [
                "APT groups targeting specific industries",
                "Financially motivated cybercriminals (BEC groups)",
                "Nation-state actors for espionage",
            ],
            "campaign_indicators": [
                "Theme consistency across emails",
                "Infrastructure patterns (hosting, registration)",
                "Target selection methodology",
                "Timing patterns (business hours, events)",
            ],
            "ttps_observed": [
                "T1566.001 - Spear-Phishing Attachment",
                "T1566.002 - Spear-Phishing Link",
                "T1598 - Phishing for Information",
                "T1583.001 - Acquire Infrastructure: Domains",
            ],
        },
        "ioc_collection": {
            "email_iocs": [
                "Sender addresses and domains",
                "Reply-to addresses",
                "Email header fingerprints",
                "Subject line patterns",
            ],
            "network_iocs": [
                "Phishing domain and IP addresses",
                "SSL certificate fingerprints",
                "URL patterns and redirect chains",
                "Command and control infrastructure",
            ],
            "file_iocs": [
                "Attachment hashes (MD5, SHA1, SHA256)",
                "File names and extensions",
                "Macro signatures",
                "Payload characteristics",
            ],
        },
        "intelligence_products": [
            {
                "name": "Tactical Alert",
                "audience": "SOC, IR Team",
                "content": "IOCs, detection rules, immediate actions",
                "frequency": "As needed (active campaigns)"
            },
            {
                "name": "Threat Advisory",
                "audience": "Security Leadership, IT",
                "content": "Campaign summary, risk assessment, recommendations",
                "frequency": "Weekly or per significant campaign"
            },
            {
                "name": "Strategic Brief",
                "audience": "Executive Leadership",
                "content": "Threat landscape, business impact, investment needs",
                "frequency": "Monthly/Quarterly"
            },
        ],
        "sharing_frameworks": [
            "STIX/TAXII for structured IOC sharing",
            "MISP for threat intelligence platform integration",
            "ISACs for industry-specific sharing",
            "TLP protocol for classification",
        ],
    },
}

GRC_CONTENT = {
    "spear_phishing": {
        "risk_assessment": {
            "inherent_risk": "HIGH",
            "likelihood": "Very Likely (5/5)",
            "impact": "Significant (4/5)",
            "risk_score": 20,
            "risk_rating": "Critical",
            "business_impact": [
                "Financial loss from fraudulent transactions",
                "Data breach and regulatory penalties",
                "Reputational damage",
                "Operational disruption",
                "Legal liability",
            ],
        },
        "control_assessment": [
            {
                "control": "Email Security Gateway",
                "status": "Implemented",
                "effectiveness": "Partially Effective",
                "gaps": "Does not detect all lookalike domains"
            },
            {
                "control": "Security Awareness Training",
                "status": "Implemented",
                "effectiveness": "Partially Effective",
                "gaps": "Annual training only, no continuous reinforcement"
            },
            {
                "control": "Multi-Factor Authentication",
                "status": "Implemented",
                "effectiveness": "Effective",
                "gaps": "Some legacy applications excluded"
            },
            {
                "control": "Incident Response Plan",
                "status": "Implemented",
                "effectiveness": "Effective",
                "gaps": "Not tested in 12 months"
            },
        ],
        "compliance_mapping": {
            "NIST CSF": ["PR.AT-1", "DE.CM-1", "DE.CM-4", "RS.RP-1"],
            "ISO 27001": ["A.7.2.2", "A.12.2.1", "A.13.2.3", "A.16.1.1"],
            "SOC 2": ["CC6.1", "CC6.8", "CC7.2"],
            "PCI DSS": ["6.5.4", "12.6.1", "12.10.1"],
            "HIPAA": ["164.308(a)(5)", "164.308(a)(6)"],
            "GDPR": ["Article 32", "Article 33"],
        },
        "policy_requirements": [
            {
                "policy": "Acceptable Use Policy",
                "requirement": "Users must report suspicious emails within 24 hours",
                "status": "Compliant"
            },
            {
                "policy": "Information Security Policy",
                "requirement": "Email authentication (SPF/DKIM/DMARC) required",
                "status": "Compliant"
            },
            {
                "policy": "Incident Response Policy",
                "requirement": "Phishing incidents classified as P2 minimum",
                "status": "Compliant"
            },
        ],
        "audit_evidence": [
            "Email gateway configuration exports",
            "Training completion records",
            "Phishing simulation results",
            "Incident response logs",
            "Penetration test reports",
        ],
    },
}

INCIDENT_RESPONSE_CONTENT = {
    "spear_phishing": {
        "classification": {
            "category": "Social Engineering - Phishing",
            "severity_matrix": {
                "low": "Email blocked, no user interaction",
                "medium": "Email delivered, user clicked but no credential entry",
                "high": "Credentials entered or payload executed",
                "critical": "Executive targeted, data exfiltration, or active compromise"
            },
        },
        "response_phases": {
            "preparation": [
                "Maintain updated contact lists for key stakeholders",
                "Ensure forensic tools are ready (email extraction, sandbox)",
                "Document email gateway administrative access",
                "Prepare communication templates",
            ],
            "identification": [
                "Determine scope: How many users received the email?",
                "Identify user interactions: clicks, credential entry, downloads",
                "Extract and preserve email evidence (headers, body, attachments)",
                "Determine if campaign is targeted or widespread",
            ],
            "containment": [
                "Quarantine/delete phishing emails from all mailboxes",
                "Block sender domain and IPs at perimeter",
                "Block malicious URLs at proxy/firewall",
                "Disable potentially compromised accounts",
                "Isolate affected endpoints if payload executed",
            ],
            "eradication": [
                "Force password reset for all affected users",
                "Revoke OAuth tokens and active sessions",
                "Remove malicious files from endpoints",
                "Update email filtering rules",
                "Add IOCs to blocklists",
            ],
            "recovery": [
                "Re-enable accounts with verified MFA",
                "Restore any affected systems from backup",
                "Monitor for signs of persistent access",
                "Validate no lateral movement occurred",
            ],
            "lessons_learned": [
                "Document timeline and actions taken",
                "Identify detection and response gaps",
                "Update playbooks and detection rules",
                "Conduct targeted user training",
                "Present findings to security leadership",
            ],
        },
        "evidence_collection": [
            "Original email with full headers (.eml format)",
            "Email gateway logs showing delivery path",
            "Proxy/firewall logs for any URL clicks",
            "Endpoint telemetry for payload execution",
            "Screenshots of phishing page (if applicable)",
            "User statements about actions taken",
        ],
        "legal_considerations": [
            "Preserve evidence for potential law enforcement",
            "Document chain of custody",
            "Consider breach notification requirements",
            "Engage legal counsel if PII involved",
            "Prepare regulatory notification if required",
        ],
    },
}

SECURITY_AWARENESS_CONTENT = {
    "spear_phishing": {
        "training_modules": [
            {
                "name": "Recognizing Spear-Phishing Attacks",
                "duration": "15 minutes",
                "format": "Interactive video + quiz",
                "topics": [
                    "What makes spear-phishing different",
                    "Common pretexts and lures",
                    "Red flags to watch for",
                    "Real-world examples"
                ],
                "audience": "All employees"
            },
            {
                "name": "Executive Targeting Awareness",
                "duration": "20 minutes",
                "format": "Scenario-based training",
                "topics": [
                    "Why executives are targeted",
                    "BEC and wire fraud tactics",
                    "Verification procedures",
                    "Escalation protocols"
                ],
                "audience": "Executives, Finance, HR"
            },
            {
                "name": "Safe Email Handling",
                "duration": "10 minutes",
                "format": "Quick reference guide + tips",
                "topics": [
                    "Hover before clicking",
                    "Verifying sender identity",
                    "Reporting suspicious emails",
                    "What to do if you clicked"
                ],
                "audience": "All employees"
            },
        ],
        "simulation_campaigns": [
            {
                "name": "Baseline Assessment",
                "difficulty": "Easy",
                "pretext": "IT password reset notification",
                "success_criteria": "< 15% click rate",
                "frequency": "Quarterly"
            },
            {
                "name": "Intermediate Challenge",
                "difficulty": "Medium",
                "pretext": "Executive request for document review",
                "success_criteria": "< 10% click rate",
                "frequency": "Quarterly"
            },
            {
                "name": "Advanced Scenario",
                "difficulty": "Hard",
                "pretext": "Personalized message using OSINT",
                "success_criteria": "< 5% click rate",
                "frequency": "Semi-annually"
            },
        ],
        "awareness_materials": [
            {
                "type": "Poster",
                "title": "STOP - THINK - VERIFY",
                "placement": "Break rooms, elevators, common areas",
                "key_messages": [
                    "Unexpected? Verify the sender",
                    "Urgent? Take a breath",
                    "Suspicious? Report it"
                ]
            },
            {
                "type": "Email Tips",
                "title": "Weekly Security Tips",
                "delivery": "Email newsletter",
                "topics": [
                    "Phishing red flags of the week",
                    "Success stories (caught phishing)",
                    "Quick security wins"
                ]
            },
            {
                "type": "Quick Reference Card",
                "title": "Phishing Response Checklist",
                "format": "Wallet card / desk reference",
                "content": [
                    "Don't click, don't reply",
                    "Report using phishing button",
                    "Call security if you clicked",
                    "Change password if compromised"
                ]
            },
        ],
        "metrics_and_reporting": [
            "Click rate by department",
            "Report rate (users reporting phishing)",
            "Time to report",
            "Repeat clickers identification",
            "Training completion rates",
            "Improvement trends over time",
        ],
    },
}


class TeamPlaybookGenerator:
    """Generate team-specific security playbooks."""

    def __init__(self):
        self.content_databases = {
            SecurityTeam.BLUE_TEAM: BLUE_TEAM_CONTENT,
            SecurityTeam.RED_TEAM: RED_TEAM_CONTENT,
            SecurityTeam.PURPLE_TEAM: PURPLE_TEAM_CONTENT,
            SecurityTeam.SOC: SOC_CONTENT,
            SecurityTeam.THREAT_INTEL: THREAT_INTEL_CONTENT,
            SecurityTeam.GRC: GRC_CONTENT,
            SecurityTeam.INCIDENT_RESPONSE: INCIDENT_RESPONSE_CONTENT,
            SecurityTeam.SECURITY_AWARENESS: SECURITY_AWARENESS_CONTENT,
        }
        logger.info("TeamPlaybookGenerator initialized")

    def generate_team_playbook(
        self,
        team: SecurityTeam,
        scenario_name: str,
        threat_type: str,
        mitre_techniques: List[str] = None,
        difficulty_level: int = 5,
    ) -> TeamPlaybook:
        """Generate a playbook for a specific security team.

        Args:
            team: Target security team
            scenario_name: Name of the threat scenario
            threat_type: Type of threat
            mitre_techniques: MITRE ATT&CK technique IDs
            difficulty_level: Scenario difficulty (1-10)

        Returns:
            TeamPlaybook with team-specific content
        """
        # Normalize threat type
        threat_key = threat_type.lower().replace("-", "_").replace(" ", "_")

        # Get team-specific content database
        team_db = self.content_databases.get(team, {})

        # Get content for this threat type (fall back to spear_phishing as default)
        content = team_db.get(threat_key, team_db.get("spear_phishing", {}))

        playbook = TeamPlaybook(
            team=team,
            scenario_name=scenario_name,
            threat_type=threat_type,
            mitre_techniques=mitre_techniques or [],
            content=content,
        )

        logger.info(f"Generated {team.value} playbook for: {scenario_name}")
        return playbook

    def generate_all_team_playbooks(
        self,
        scenario_name: str,
        threat_type: str,
        mitre_techniques: List[str] = None,
        difficulty_level: int = 5,
    ) -> Dict[SecurityTeam, TeamPlaybook]:
        """Generate playbooks for all security teams.

        Args:
            scenario_name: Name of the threat scenario
            threat_type: Type of threat
            mitre_techniques: MITRE ATT&CK technique IDs
            difficulty_level: Scenario difficulty

        Returns:
            Dictionary of team -> playbook mappings
        """
        playbooks = {}
        for team in SecurityTeam:
            playbooks[team] = self.generate_team_playbook(
                team=team,
                scenario_name=scenario_name,
                threat_type=threat_type,
                mitre_techniques=mitre_techniques,
                difficulty_level=difficulty_level,
            )
        return playbooks

    def format_playbook_markdown(self, playbook: TeamPlaybook) -> str:
        """Format a team playbook as markdown.

        Args:
            playbook: TeamPlaybook to format

        Returns:
            Formatted markdown string
        """
        formatters = {
            SecurityTeam.BLUE_TEAM: self._format_blue_team,
            SecurityTeam.RED_TEAM: self._format_red_team,
            SecurityTeam.PURPLE_TEAM: self._format_purple_team,
            SecurityTeam.SOC: self._format_soc,
            SecurityTeam.THREAT_INTEL: self._format_threat_intel,
            SecurityTeam.GRC: self._format_grc,
            SecurityTeam.INCIDENT_RESPONSE: self._format_incident_response,
            SecurityTeam.SECURITY_AWARENESS: self._format_security_awareness,
        }

        formatter = formatters.get(playbook.team, self._format_generic)
        return formatter(playbook)

    def _format_blue_team(self, playbook: TeamPlaybook) -> str:
        """Format Blue Team playbook."""
        content = playbook.content
        mitre_str = ", ".join(playbook.mitre_techniques) if playbook.mitre_techniques else "N/A"

        # Format detection rules
        rules_md = ""
        for rule in content.get("detection_rules", []):
            rules_md += f"""
#### {rule['name']}
- **Type**: {rule['type']}
- **Severity**: {rule['severity']}
- **MITRE**: {rule['mitre']}
- **Logic**: `{rule['logic']}`
"""

        # Format monitoring queries
        queries_md = ""
        for query in content.get("monitoring_queries", []):
            queries_md += f"""
#### {query['name']}
- **Platform**: {query['platform']}
```
{query['query']}
```
"""

        # Format hardening measures
        hardening_md = "\n".join(f"- {item}" for item in content.get("hardening_measures", []))

        # Format IOC types
        ioc_md = "\n".join(f"- {item}" for item in content.get("ioc_types", []))

        return f"""# [BLUE] Blue Team Playbook: {playbook.scenario_name}

## Overview
| Field | Value |
|-------|-------|
| **Team** | Blue Team (Defense) |
| **Threat Type** | {playbook.threat_type} |
| **MITRE ATT&CK** | {mitre_str} |
| **Generated** | {playbook.generated_at} |

---

## Detection Rules
{rules_md}

---

## Monitoring Queries
{queries_md}

---

## Hardening Measures
{hardening_md}

---

## IOC Types to Collect
{ioc_md}

---

## Quick Actions

| Priority | Action |
|----------|--------|
| **Immediate** | Block sender domain at email gateway |
| **Short-term** | Update detection rules with new IOCs |
| **Long-term** | Implement additional email authentication |

---

*Blue Team Playbook generated by ThreatSimGPT for defensive operations.*
"""

    def _format_red_team(self, playbook: TeamPlaybook) -> str:
        """Format Red Team playbook."""
        content = playbook.content
        mitre_str = ", ".join(playbook.mitre_techniques) if playbook.mitre_techniques else "N/A"

        # Format attack techniques
        techniques_md = ""
        for tech in content.get("attack_techniques", []):
            techniques_md += f"""
#### {tech['name']}
- **Description**: {tech['description']}
- **MITRE**: {tech['mitre']}
- **Difficulty**: {tech['difficulty']}
- **Detection Risk**: {tech['detection_risk']}
"""

        # Format payload options
        payloads_md = ""
        for payload in content.get("payload_options", []):
            tools_str = ", ".join(payload.get('tools', []))
            payloads_md += f"""
#### {payload['type']}
- **Tools**: {tools_str}
- **Description**: {payload['description']}
"""

        # Format evasion techniques
        evasion_md = "\n".join(f"- {item}" for item in content.get("evasion_techniques", []))

        # Format success metrics
        metrics_md = "\n".join(f"- {item}" for item in content.get("success_metrics", []))

        # Format OPSEC
        opsec_md = "\n".join(f"- {item}" for item in content.get("opsec_considerations", []))

        return f"""# [RED] Red Team Playbook: {playbook.scenario_name}

## Overview
| Field | Value |
|-------|-------|
| **Team** | Red Team (Offensive) |
| **Threat Type** | {playbook.threat_type} |
| **MITRE ATT&CK** | {mitre_str} |
| **Generated** | {playbook.generated_at} |

---

## Attack Techniques
{techniques_md}

---

## Payload Options
{payloads_md}

---

## Evasion Techniques
{evasion_md}

---

## Success Metrics
{metrics_md}

---

## OPSEC Considerations
{opsec_md}

---

## Engagement Checklist

- [ ] Infrastructure prepared and aged
- [ ] Pretext developed and tested
- [ ] Payloads tested in sandbox
- [ ] Success metrics defined
- [ ] Communication plan with Blue Team (if Purple)
- [ ] Deconfliction with SOC established

---

*Red Team Playbook generated by ThreatSimGPT for authorized security testing only.*
*Always obtain proper authorization before conducting offensive security operations.*
"""

    def _format_purple_team(self, playbook: TeamPlaybook) -> str:
        """Format Purple Team playbook."""
        content = playbook.content
        mitre_str = ", ".join(playbook.mitre_techniques) if playbook.mitre_techniques else "N/A"

        # Format test scenarios
        scenarios_md = ""
        for scenario in content.get("test_scenarios", []):
            metrics_str = ", ".join(scenario.get('metrics', []))
            scenarios_md += f"""
#### {scenario['name']}
- **Objective**: {scenario['objective']}
- **Red Action**: {scenario['red_action']}
- **Blue Expectation**: {scenario['blue_expectation']}
- **Metrics**: {metrics_str}
"""

        # Format detection gaps
        gaps_md = "\n".join(f"- {item}" for item in content.get("detection_gaps", []))

        # Format improvement recommendations
        recs_md = ""
        for rec in content.get("improvement_recommendations", []):
            recs_md += f"""
| Gap | {rec['gap']} |
| Recommendation | {rec['recommendation']} |
| Priority | {rec['priority']} |
| Effort | {rec['effort']} |

"""

        # Format collaborative exercises
        exercises_md = ""
        for ex in content.get("collaborative_exercises", []):
            participants_str = ", ".join(ex.get('participants', []))
            exercises_md += f"""
#### {ex['name']}
- **Duration**: {ex['duration']}
- **Participants**: {participants_str}
- **Scenario**: {ex['scenario']}
"""

        return f"""# [PURPLE] Purple Team Playbook: {playbook.scenario_name}

## Overview
| Field | Value |
|-------|-------|
| **Team** | Purple Team (Collaborative) |
| **Threat Type** | {playbook.threat_type} |
| **MITRE ATT&CK** | {mitre_str} |
| **Generated** | {playbook.generated_at} |

---

## Test Scenarios
{scenarios_md}

---

## Detection Gaps Identified
{gaps_md}

---

## Improvement Recommendations
{recs_md}

---

## Collaborative Exercises
{exercises_md}

---

## Purple Team Workflow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Planning   │───▶│  Execution  │───▶│  Analysis   │
│             │    │             │    │             │
│ - Scope     │    │ - Red ops   │    │ - Gaps      │
│ - Metrics   │    │ - Blue mon  │    │ - Metrics   │
│ - Timeline  │    │ - Real-time │    │ - Report    │
└─────────────┘    └─────────────┘    └─────────────┘
```

---

*Purple Team Playbook generated by ThreatSimGPT for collaborative security improvement.*
"""

    def _format_soc(self, playbook: TeamPlaybook) -> str:
        """Format SOC playbook."""
        content = playbook.content
        mitre_str = ", ".join(playbook.mitre_techniques) if playbook.mitre_techniques else "N/A"

        # Format alert triage
        triage_md = ""
        for alert in content.get("alert_triage", []):
            initial_actions = "\n".join(f"   - {a}" for a in alert.get('initial_actions', []))
            escalation = "\n".join(f"   - {e}" for e in alert.get('escalation_criteria', []))
            triage_md += f"""
#### {alert['alert_name']}
- **Priority**: {alert['priority']}
- **SLA**: {alert['sla']}
- **Initial Actions**:
{initial_actions}
- **Escalation Criteria**:
{escalation}
"""

        # Format investigation steps
        investigation_md = "\n".join(content.get("investigation_steps", []))

        # Format response playbook
        response_md = ""
        for phase in content.get("response_playbook", []):
            actions = "\n".join(f"   - {a}" for a in phase.get('actions', []))
            response_md += f"""
### {phase['phase']} (Target: {phase['timeframe']})
{actions}
"""

        # Format communication templates
        comms = content.get("communication_templates", {})

        return f"""# [SOC] SOC Playbook: {playbook.scenario_name}

## Overview
| Field | Value |
|-------|-------|
| **Team** | Security Operations Center |
| **Threat Type** | {playbook.threat_type} |
| **MITRE ATT&CK** | {mitre_str} |
| **Generated** | {playbook.generated_at} |

---

## Alert Triage
{triage_md}

---

## Investigation Steps
{investigation_md}

---

## Response Playbook
{response_md}

---

## Communication Templates

### Internal Notification
> {comms.get('internal_notification', 'N/A')}

### Management Update
> {comms.get('management_update', 'N/A')}

---

## SOC Analyst Quick Reference

| Stage | Key Action | Tool |
|-------|------------|------|
| Triage | Verify alert validity | SIEM |
| Scope | Find all affected users | Email Gateway |
| Contain | Quarantine emails | Email Admin |
| Investigate | Analyze headers/URLs | Sandbox |
| Document | Log all findings | Ticketing System |

---

*SOC Playbook generated by ThreatSimGPT for security operations.*
"""

    def _format_threat_intel(self, playbook: TeamPlaybook) -> str:
        """Format Threat Intelligence playbook."""
        content = playbook.content
        mitre_str = ", ".join(playbook.mitre_techniques) if playbook.mitre_techniques else "N/A"

        profile = content.get("threat_profile", {})

        # Format threat actors
        actors_md = "\n".join(f"- {a}" for a in profile.get("threat_actors", []))

        # Format campaign indicators
        indicators_md = "\n".join(f"- {i}" for i in profile.get("campaign_indicators", []))

        # Format TTPs
        ttps_md = "\n".join(f"- {t}" for t in profile.get("ttps_observed", []))

        # Format IOC collection
        ioc_collection = content.get("ioc_collection", {})
        email_iocs = "\n".join(f"- {i}" for i in ioc_collection.get("email_iocs", []))
        network_iocs = "\n".join(f"- {i}" for i in ioc_collection.get("network_iocs", []))
        file_iocs = "\n".join(f"- {i}" for i in ioc_collection.get("file_iocs", []))

        # Format intelligence products
        products_md = ""
        for prod in content.get("intelligence_products", []):
            products_md += f"""
#### {prod['name']}
- **Audience**: {prod['audience']}
- **Content**: {prod['content']}
- **Frequency**: {prod['frequency']}
"""

        # Format sharing frameworks
        sharing_md = "\n".join(f"- {s}" for s in content.get("sharing_frameworks", []))

        return f"""# [INTEL] Threat Intelligence Playbook: {playbook.scenario_name}

## Overview
| Field | Value |
|-------|-------|
| **Team** | Threat Intelligence |
| **Threat Type** | {playbook.threat_type} |
| **MITRE ATT&CK** | {mitre_str} |
| **Generated** | {playbook.generated_at} |

---

## Threat Profile

### Threat Actors
{actors_md}

### Campaign Indicators
{indicators_md}

### TTPs Observed
{ttps_md}

---

## IOC Collection

### Email IOCs
{email_iocs}

### Network IOCs
{network_iocs}

### File IOCs
{file_iocs}

---

## Intelligence Products
{products_md}

---

## Sharing Frameworks
{sharing_md}

---

## Intelligence Workflow

```
Collection ──▶ Processing ──▶ Analysis ──▶ Dissemination
    │              │             │              │
    ▼              ▼             ▼              ▼
  IOCs         Normalize      Assess        Products
  Logs         Correlate      Attribute     Alerts
  OSINT        Enrich         Predict       Briefs
```

---

*Threat Intelligence Playbook generated by ThreatSimGPT for intelligence operations.*
"""

    def _format_grc(self, playbook: TeamPlaybook) -> str:
        """Format GRC playbook."""
        content = playbook.content
        mitre_str = ", ".join(playbook.mitre_techniques) if playbook.mitre_techniques else "N/A"

        # Format risk assessment
        risk = content.get("risk_assessment", {})
        business_impact = "\n".join(f"- {i}" for i in risk.get("business_impact", []))

        # Format control assessment
        controls_md = ""
        for ctrl in content.get("control_assessment", []):
            controls_md += f"""
| **{ctrl['control']}** |
| Status: {ctrl['status']} | Effectiveness: {ctrl['effectiveness']} |
| Gaps: {ctrl['gaps']} |

"""

        # Format compliance mapping
        compliance = content.get("compliance_mapping", {})
        compliance_md = ""
        for framework, controls in compliance.items():
            controls_str = ", ".join(controls)
            compliance_md += f"| {framework} | {controls_str} |\n"

        # Format policy requirements
        policies_md = ""
        for policy in content.get("policy_requirements", []):
            policies_md += f"| {policy['policy']} | {policy['requirement']} | {policy['status']} |\n"

        # Format audit evidence
        evidence_md = "\n".join(f"- {e}" for e in content.get("audit_evidence", []))

        return f"""# [GRC] GRC Playbook: {playbook.scenario_name}

## Overview
| Field | Value |
|-------|-------|
| **Team** | Governance, Risk & Compliance |
| **Threat Type** | {playbook.threat_type} |
| **MITRE ATT&CK** | {mitre_str} |
| **Generated** | {playbook.generated_at} |

---

## Risk Assessment

| Metric | Value |
|--------|-------|
| **Inherent Risk** | {risk.get('inherent_risk', 'N/A')} |
| **Likelihood** | {risk.get('likelihood', 'N/A')} |
| **Impact** | {risk.get('impact', 'N/A')} |
| **Risk Score** | {risk.get('risk_score', 'N/A')} |
| **Risk Rating** | {risk.get('risk_rating', 'N/A')} |

### Business Impact
{business_impact}

---

## Control Assessment
{controls_md}

---

## Compliance Mapping

| Framework | Relevant Controls |
|-----------|-------------------|
{compliance_md}

---

## Policy Requirements

| Policy | Requirement | Status |
|--------|-------------|--------|
{policies_md}

---

## Audit Evidence Required
{evidence_md}

---

## Risk Treatment Options

| Option | Description | Residual Risk |
|--------|-------------|---------------|
| **Accept** | Document and monitor | HIGH |
| **Mitigate** | Implement additional controls | MEDIUM |
| **Transfer** | Cyber insurance | MEDIUM |
| **Avoid** | Restrict high-risk activities | LOW |

---

*GRC Playbook generated by ThreatSimGPT for governance and compliance operations.*
"""

    def _format_incident_response(self, playbook: TeamPlaybook) -> str:
        """Format Incident Response playbook."""
        content = playbook.content
        mitre_str = ", ".join(playbook.mitre_techniques) if playbook.mitre_techniques else "N/A"

        # Format classification
        classification = content.get("classification", {})
        severity_matrix = classification.get("severity_matrix", {})
        severity_md = "\n".join(f"| **{k.upper()}** | {v} |" for k, v in severity_matrix.items())

        # Format response phases
        phases = content.get("response_phases", {})
        phases_md = ""
        for phase_name, actions in phases.items():
            actions_md = "\n".join(f"- {a}" for a in actions)
            phases_md += f"""
### {phase_name.replace('_', ' ').title()}
{actions_md}
"""

        # Format evidence collection
        evidence_md = "\n".join(f"- {e}" for e in content.get("evidence_collection", []))

        # Format legal considerations
        legal_md = "\n".join(f"- {l}" for l in content.get("legal_considerations", []))

        return f"""# [IR] Incident Response Playbook: {playbook.scenario_name}

## Overview
| Field | Value |
|-------|-------|
| **Team** | Incident Response |
| **Threat Type** | {playbook.threat_type} |
| **MITRE ATT&CK** | {mitre_str} |
| **Generated** | {playbook.generated_at} |

---

## Classification

**Category**: {classification.get('category', 'N/A')}

### Severity Matrix
| Level | Criteria |
|-------|----------|
{severity_md}

---

## Response Phases
{phases_md}

---

## Evidence Collection
{evidence_md}

---

## Legal Considerations
{legal_md}

---

## IR Timeline Template

| Time | Action | Owner | Status |
|------|--------|-------|--------|
| T+0 | Alert received | SOC | [ ] |
| T+15m | Initial triage | SOC | [ ] |
| T+30m | Containment initiated | IR Team | [ ] |
| T+1h | Scope determined | IR Team | [ ] |
| T+2h | Eradication complete | IR Team | [ ] |
| T+4h | Recovery initiated | IT Ops | [ ] |
| T+24h | Post-incident review | IR Lead | [ ] |

---

*Incident Response Playbook generated by ThreatSimGPT for incident management.*
"""

    def _format_security_awareness(self, playbook: TeamPlaybook) -> str:
        """Format Security Awareness playbook."""
        content = playbook.content
        mitre_str = ", ".join(playbook.mitre_techniques) if playbook.mitre_techniques else "N/A"

        # Format training modules
        modules_md = ""
        for mod in content.get("training_modules", []):
            topics = "\n".join(f"   - {t}" for t in mod.get('topics', []))
            modules_md += f"""
#### {mod['name']}
- **Duration**: {mod['duration']}
- **Format**: {mod['format']}
- **Audience**: {mod['audience']}
- **Topics**:
{topics}
"""

        # Format simulation campaigns
        campaigns_md = ""
        for camp in content.get("simulation_campaigns", []):
            campaigns_md += f"""
| **{camp['name']}** | {camp['difficulty']} | {camp['pretext']} | {camp['success_criteria']} | {camp['frequency']} |
"""

        # Format awareness materials
        materials_md = ""
        for mat in content.get("awareness_materials", []):
            if 'key_messages' in mat:
                messages = "\n".join(f"   - {m}" for m in mat['key_messages'])
                materials_md += f"""
#### {mat['title']} ({mat['type']})
- **Placement**: {mat.get('placement', mat.get('delivery', 'N/A'))}
- **Key Messages**:
{messages}
"""
            elif 'content' in mat:
                content_list = "\n".join(f"   - {c}" for c in mat['content'])
                materials_md += f"""
#### {mat['title']} ({mat['type']})
- **Format**: {mat.get('format', 'N/A')}
- **Content**:
{content_list}
"""

        # Format metrics
        metrics_md = "\n".join(f"- {m}" for m in content.get("metrics_and_reporting", []))

        return f"""# [AWARENESS] Security Awareness Playbook: {playbook.scenario_name}

## Overview
| Field | Value |
|-------|-------|
| **Team** | Security Awareness & Training |
| **Threat Type** | {playbook.threat_type} |
| **MITRE ATT&CK** | {mitre_str} |
| **Generated** | {playbook.generated_at} |

---

## Training Modules
{modules_md}

---

## Phishing Simulation Campaigns

| Campaign | Difficulty | Pretext | Success Criteria | Frequency |
|----------|------------|---------|------------------|-----------|
{campaigns_md}

---

## Awareness Materials
{materials_md}

---

## Metrics & Reporting
{metrics_md}

---

## Training Calendar Template

| Month | Activity | Target Audience |
|-------|----------|-----------------|
| Q1 | Baseline phishing simulation | All employees |
| Q1 | Executive targeting training | C-suite, Finance |
| Q2 | Safe email handling refresher | All employees |
| Q2 | Intermediate simulation | All employees |
| Q3 | BEC awareness training | Finance, HR |
| Q3 | Advanced simulation | High-risk roles |
| Q4 | Annual security awareness | All employees |
| Q4 | Metrics review & planning | Security team |

---

*Security Awareness Playbook generated by ThreatSimGPT for training operations.*
"""

    def _format_generic(self, playbook: TeamPlaybook) -> str:
        """Format generic playbook for unknown team types."""
        return f"""# Security Playbook: {playbook.scenario_name}

## Overview
- **Team**: {playbook.team.value}
- **Threat Type**: {playbook.threat_type}
- **MITRE ATT&CK**: {', '.join(playbook.mitre_techniques) if playbook.mitre_techniques else 'N/A'}
- **Generated**: {playbook.generated_at}

## Content
{playbook.content}

---

*Playbook generated by ThreatSimGPT.*
"""


# Global instance
team_playbook_generator = TeamPlaybookGenerator()


def generate_team_playbook(
    team: str,
    scenario_name: str,
    threat_type: str,
    mitre_techniques: List[str] = None,
    difficulty_level: int = 5,
) -> str:
    """Convenience function to generate a formatted team playbook.

    Args:
        team: Team name (blue_team, red_team, purple_team, soc, threat_intel, grc, incident_response, security_awareness)
        scenario_name: Name of the threat scenario
        threat_type: Type of threat
        mitre_techniques: MITRE ATT&CK technique IDs
        difficulty_level: Scenario difficulty (1-10)

    Returns:
        Formatted markdown playbook
    """
    # Convert string to enum
    team_enum = SecurityTeam(team.lower().replace(" ", "_").replace("-", "_"))

    playbook = team_playbook_generator.generate_team_playbook(
        team=team_enum,
        scenario_name=scenario_name,
        threat_type=threat_type,
        mitre_techniques=mitre_techniques,
        difficulty_level=difficulty_level,
    )
    return team_playbook_generator.format_playbook_markdown(playbook)


def generate_all_team_playbooks(
    scenario_name: str,
    threat_type: str,
    mitre_techniques: List[str] = None,
    difficulty_level: int = 5,
) -> Dict[str, str]:
    """Generate formatted playbooks for all security teams.

    Args:
        scenario_name: Name of the threat scenario
        threat_type: Type of threat
        mitre_techniques: MITRE ATT&CK technique IDs
        difficulty_level: Scenario difficulty

    Returns:
        Dictionary of team_name -> formatted markdown playbook
    """
    playbooks = team_playbook_generator.generate_all_team_playbooks(
        scenario_name=scenario_name,
        threat_type=threat_type,
        mitre_techniques=mitre_techniques,
        difficulty_level=difficulty_level,
    )

    return {
        team.value: team_playbook_generator.format_playbook_markdown(playbook)
        for team, playbook in playbooks.items()
    }
