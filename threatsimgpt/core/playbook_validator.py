"""Playbook Validation Framework for ThreatSimGPT.

This module provides comprehensive validation of field manuals and playbooks
to ensure they meet industry standards and provide actionable, high-quality content.

Validation Categories:
1. Structure Validation - Required sections, formatting, organization
2. Content Quality - Actionability, specificity, completeness
3. Industry Standards - NIST, ISO 27001, MITRE ATT&CK alignment
4. Compliance Alignment - SOC2, PCI-DSS, HIPAA, GDPR mapping
5. Technical Accuracy - Tool commands, detection rules, IOC formats
6. Usefulness Score - Real-world applicability and value
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# VALIDATION ENUMS AND DATA CLASSES
# =============================================================================

class ValidationSeverity(Enum):
    """Severity levels for validation findings."""
    CRITICAL = "critical"    # Must fix - playbook is not usable
    HIGH = "high"           # Should fix - significantly reduces value
    MEDIUM = "medium"       # Recommended - improves quality
    LOW = "low"            # Optional - nice to have
    INFO = "info"          # Informational - suggestions


class ValidationCategory(Enum):
    """Categories of validation checks."""
    STRUCTURE = "structure"
    CONTENT_QUALITY = "content_quality"
    INDUSTRY_STANDARDS = "industry_standards"
    COMPLIANCE = "compliance"
    TECHNICAL_ACCURACY = "technical_accuracy"
    USEFULNESS = "usefulness"


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    NIST_CSF = "NIST Cybersecurity Framework"
    NIST_800_53 = "NIST SP 800-53"
    ISO_27001 = "ISO 27001"
    SOC2 = "SOC 2"
    PCI_DSS = "PCI DSS"
    HIPAA = "HIPAA"
    GDPR = "GDPR"
    MITRE_ATTACK = "MITRE ATT&CK"
    CIS_CONTROLS = "CIS Controls"


@dataclass
class ValidationFinding:
    """A single validation finding."""
    category: ValidationCategory
    severity: ValidationSeverity
    title: str
    description: str
    recommendation: str
    location: Optional[str] = None  # Section or line where issue found
    compliance_impact: List[str] = field(default_factory=list)
    auto_fixable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "location": self.location,
            "compliance_impact": self.compliance_impact,
            "auto_fixable": self.auto_fixable,
        }


@dataclass
class ValidationScore:
    """Validation score for a specific category."""
    category: ValidationCategory
    score: float  # 0-100
    max_score: float = 100.0
    findings_count: int = 0
    critical_count: int = 0
    details: str = ""

    @property
    def percentage(self) -> float:
        return (self.score / self.max_score) * 100 if self.max_score > 0 else 0


@dataclass
class ValidationReport:
    """Complete validation report for a playbook."""
    playbook_path: str
    playbook_team: str
    validated_at: datetime
    overall_score: float  # 0-100
    grade: str  # A, B, C, D, F
    category_scores: Dict[ValidationCategory, ValidationScore]
    findings: List[ValidationFinding]
    compliance_status: Dict[ComplianceFramework, bool]
    recommendations: List[str]
    is_production_ready: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook_path": self.playbook_path,
            "playbook_team": self.playbook_team,
            "validated_at": self.validated_at.isoformat(),
            "overall_score": self.overall_score,
            "grade": self.grade,
            "category_scores": {
                k.value: {
                    "score": v.score,
                    "percentage": v.percentage,
                    "findings_count": v.findings_count,
                }
                for k, v in self.category_scores.items()
            },
            "findings": [f.to_dict() for f in self.findings],
            "compliance_status": {k.value: v for k, v in self.compliance_status.items()},
            "recommendations": self.recommendations,
            "is_production_ready": self.is_production_ready,
        }

    def to_markdown(self) -> str:
        """Generate a markdown validation report."""
        lines = [
            "# Playbook Validation Report",
            "",
            f"> **Generated**: {self.validated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"> **Playbook**: `{self.playbook_path}`",
            f"> **Team**: {self.playbook_team}",
            "",
            "---",
            "",
            "## Overall Assessment",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| **Overall Score** | {self.overall_score:.1f}/100 |",
            f"| **Grade** | {self.grade} |",
            f"| **Production Ready** | {'[YES]' if self.is_production_ready else '[NO]'} |",
            f"| **Total Findings** | {len(self.findings)} |",
            f"| **Critical Issues** | {sum(1 for f in self.findings if f.severity == ValidationSeverity.CRITICAL)} |",
            "",
            "---",
            "",
            "## Category Scores",
            "",
            "| Category | Score | Status |",
            "|----------|-------|--------|",
        ]

        for cat, score in self.category_scores.items():
            status = "[PASS]" if score.percentage >= 80 else "[WARN]" if score.percentage >= 60 else "[FAIL]"
            lines.append(f"| {cat.value.replace('_', ' ').title()} | {score.percentage:.0f}% | {status} |")

        lines.extend([
            "",
            "---",
            "",
            "## Compliance Status",
            "",
            "| Framework | Status |",
            "|-----------|--------|",
        ])

        for framework, compliant in self.compliance_status.items():
            status = "[ALIGNED]" if compliant else "[GAPS]"
            lines.append(f"| {framework.value} | {status} |")

        if self.findings:
            lines.extend([
                "",
                "---",
                "",
                "## Validation Findings",
                "",
            ])

            # Group by severity
            for severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH,
                           ValidationSeverity.MEDIUM, ValidationSeverity.LOW]:
                severity_findings = [f for f in self.findings if f.severity == severity]
                if severity_findings:
                    prefix = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]"}
                    lines.append(f"### {prefix.get(severity.value, '•')} {severity.value.upper()} ({len(severity_findings)})")
                    lines.append("")
                    for finding in severity_findings:
                        lines.append(f"**{finding.title}**")
                        lines.append(f"- {finding.description}")
                        lines.append(f"- *Recommendation*: {finding.recommendation}")
                        if finding.location:
                            lines.append(f"- *Location*: {finding.location}")
                        lines.append("")

        if self.recommendations:
            lines.extend([
                "---",
                "",
                "## Top Recommendations",
                "",
            ])
            for i, rec in enumerate(self.recommendations[:10], 1):
                lines.append(f"{i}. {rec}")

        return "\n".join(lines)


# =============================================================================
# VALIDATION RULE DEFINITIONS
# =============================================================================

# Required sections for each team type
REQUIRED_SECTIONS = {
    "blue_team": [
        "threat overview",
        "detection",
        "monitoring",
        "hardening",
        "ioc",
    ],
    "red_team": [
        "reconnaissance",
        "attack",
        "payload",
        "execution",
        "evasion",
    ],
    "purple_team": [
        "test cases",
        "detection validation",
        "gap analysis",
        "improvement",
    ],
    "soc": [
        "triage",
        "severity",
        "escalation",
        "response",
        "playbook",
    ],
    "threat_intel": [
        "threat actor",
        "campaign",
        "ioc",
        "ttp",
        "intelligence",
    ],
    "grc": [
        "risk",
        "compliance",
        "control",
        "policy",
        "audit",
    ],
    "incident_response": [
        "preparation",
        "identification",
        "containment",
        "eradication",
        "recovery",
        "lessons learned",
    ],
    "security_awareness": [
        "indicator",
        "training",
        "example",
        "report",
        "quiz",
    ],
}

# Technical content patterns that indicate quality
QUALITY_INDICATORS = {
    "detection_rules": [
        r"index\s*=",  # Splunk
        r"event\.category",  # Elastic
        r"SELECT\s+\*\s+FROM",  # SQL-based SIEM
        r"rule\s+\w+\s*{",  # YARA
        r"title:\s*",  # Sigma
        r"alert\s+(tcp|udp|icmp)",  # Snort/Suricata
    ],
    "commands": [
        r"^\$\s",  # PowerShell
        r"^#\s",  # Bash comment
        r"^\s*\w+\s+-\w+",  # CLI commands with flags
        r"curl\s+",
        r"grep\s+",
        r"awk\s+",
        r"Get-\w+",  # PowerShell cmdlets
    ],
    "ioc_patterns": [
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # IP address
        r"\b[a-f0-9]{32}\b",  # MD5
        r"\b[a-f0-9]{40}\b",  # SHA1
        r"\b[a-f0-9]{64}\b",  # SHA256
        r"https?://[^\s]+",  # URL
        r"\b[\w.-]+\.(com|net|org|io|ru|cn)\b",  # Domain
    ],
    "mitre_references": [
        r"T\d{4}(\.\d{3})?",  # MITRE technique ID
        r"TA\d{4}",  # MITRE tactic ID
        r"ATT&CK",
        r"MITRE",
    ],
    "metrics": [
        r"\d+%",  # Percentages
        r"\d+\s*(second|minute|hour|day)s?",  # Time metrics
        r"SLA",
        r"KPI",
        r"mean\s+time",
        r"MTTD|MTTR",
    ],
}

# Compliance framework requirements
COMPLIANCE_REQUIREMENTS = {
    ComplianceFramework.NIST_CSF: {
        "required_concepts": [
            "identify", "protect", "detect", "respond", "recover"
        ],
        "recommended_sections": [
            "risk assessment", "access control", "monitoring", "incident response"
        ],
    },
    ComplianceFramework.ISO_27001: {
        "required_concepts": [
            "information security", "risk", "control", "audit", "policy"
        ],
        "recommended_sections": [
            "access control", "cryptography", "operations security"
        ],
    },
    ComplianceFramework.SOC2: {
        "required_concepts": [
            "security", "availability", "confidentiality", "privacy"
        ],
        "recommended_sections": [
            "access control", "change management", "incident response"
        ],
    },
    ComplianceFramework.PCI_DSS: {
        "required_concepts": [
            "cardholder data", "network security", "access control", "monitoring"
        ],
        "recommended_sections": [
            "encryption", "vulnerability management", "logging"
        ],
    },
    ComplianceFramework.HIPAA: {
        "required_concepts": [
            "phi", "protected health information", "privacy", "security rule"
        ],
        "recommended_sections": [
            "access control", "audit controls", "transmission security"
        ],
    },
    ComplianceFramework.GDPR: {
        "required_concepts": [
            "personal data", "data subject", "consent", "breach notification"
        ],
        "recommended_sections": [
            "data protection", "privacy by design", "incident response"
        ],
    },
    ComplianceFramework.MITRE_ATTACK: {
        "required_concepts": [
            "technique", "tactic", "procedure", "detection"
        ],
        "recommended_sections": [
            "initial access", "execution", "persistence", "defense evasion"
        ],
    },
}

# Actionability keywords that indicate practical content
ACTIONABILITY_KEYWORDS = [
    "step", "procedure", "command", "execute", "run", "deploy",
    "configure", "enable", "disable", "create", "implement",
    "verify", "validate", "check", "monitor", "alert",
    "investigate", "analyze", "respond", "contain", "eradicate",
    "document", "report", "escalate", "notify",
]


# =============================================================================
# PLAYBOOK VALIDATOR CLASS
# =============================================================================

class PlaybookValidator:
    """Comprehensive playbook validation engine."""

    def __init__(
        self,
        compliance_frameworks: Optional[List[ComplianceFramework]] = None,
        strict_mode: bool = False,
    ):
        """Initialize the validator.

        Args:
            compliance_frameworks: List of frameworks to validate against
            strict_mode: If True, applies stricter validation rules
        """
        self.compliance_frameworks = compliance_frameworks or [
            ComplianceFramework.NIST_CSF,
            ComplianceFramework.MITRE_ATTACK,
        ]
        self.strict_mode = strict_mode
        self.findings: List[ValidationFinding] = []

    def validate(
        self,
        content: str,
        team: str,
        playbook_path: str = "unknown",
    ) -> ValidationReport:
        """Validate a playbook and generate a comprehensive report.

        Args:
            content: The playbook markdown content
            team: The team type (blue_team, red_team, etc.)
            playbook_path: Path to the playbook file

        Returns:
            ValidationReport with scores and findings
        """
        self.findings = []
        content_lower = content.lower()

        # Run all validation checks
        structure_score = self._validate_structure(content, content_lower, team)
        quality_score = self._validate_content_quality(content, content_lower, team)
        standards_score = self._validate_industry_standards(content, content_lower, team)
        compliance_status = self._validate_compliance(content, content_lower)
        technical_score = self._validate_technical_accuracy(content, content_lower, team)
        usefulness_score = self._validate_usefulness(content, content_lower, team)

        # Calculate overall score (weighted average)
        weights = {
            ValidationCategory.STRUCTURE: 0.15,
            ValidationCategory.CONTENT_QUALITY: 0.25,
            ValidationCategory.INDUSTRY_STANDARDS: 0.20,
            ValidationCategory.TECHNICAL_ACCURACY: 0.20,
            ValidationCategory.USEFULNESS: 0.20,
        }

        category_scores = {
            ValidationCategory.STRUCTURE: structure_score,
            ValidationCategory.CONTENT_QUALITY: quality_score,
            ValidationCategory.INDUSTRY_STANDARDS: standards_score,
            ValidationCategory.TECHNICAL_ACCURACY: technical_score,
            ValidationCategory.USEFULNESS: usefulness_score,
        }

        overall_score = sum(
            score.score * weights.get(cat, 0.2)
            for cat, score in category_scores.items()
        )

        # Determine grade
        grade = self._calculate_grade(overall_score)

        # Check if production ready
        critical_count = sum(1 for f in self.findings if f.severity == ValidationSeverity.CRITICAL)
        high_count = sum(1 for f in self.findings if f.severity == ValidationSeverity.HIGH)
        is_production_ready = (
            overall_score >= 70 and
            critical_count == 0 and
            high_count <= 2
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(category_scores)

        return ValidationReport(
            playbook_path=playbook_path,
            playbook_team=team,
            validated_at=datetime.now(),
            overall_score=overall_score,
            grade=grade,
            category_scores=category_scores,
            findings=self.findings,
            compliance_status=compliance_status,
            recommendations=recommendations,
            is_production_ready=is_production_ready,
        )

    def _validate_structure(
        self,
        content: str,
        content_lower: str,
        team: str,
    ) -> ValidationScore:
        """Validate playbook structure and organization."""
        score = 100.0
        findings_count = 0

        # Check for required sections
        required = REQUIRED_SECTIONS.get(team, [])
        missing_sections = []

        for section in required:
            if section not in content_lower:
                missing_sections.append(section)
                score -= 10
                findings_count += 1

        if missing_sections:
            self.findings.append(ValidationFinding(
                category=ValidationCategory.STRUCTURE,
                severity=ValidationSeverity.HIGH if len(missing_sections) > 2 else ValidationSeverity.MEDIUM,
                title="Missing Required Sections",
                description=f"The following required sections are missing: {', '.join(missing_sections)}",
                recommendation=f"Add sections covering: {', '.join(missing_sections)}",
                compliance_impact=["NIST CSF", "ISO 27001"],
            ))

        # Check for proper markdown structure
        if not re.search(r'^# ', content, re.MULTILINE):
            score -= 10
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.STRUCTURE,
                severity=ValidationSeverity.MEDIUM,
                title="Missing Main Title",
                description="Playbook should have a main title (H1 heading)",
                recommendation="Add a descriptive H1 title at the beginning",
            ))

        # Check for section headers
        h2_count = len(re.findall(r'^## ', content, re.MULTILINE))
        if h2_count < 3:
            score -= 15
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.STRUCTURE,
                severity=ValidationSeverity.MEDIUM,
                title="Insufficient Section Structure",
                description=f"Only {h2_count} major sections found. Well-organized playbooks have 5+ sections.",
                recommendation="Break content into logical sections with H2 headings",
            ))

        # Check for tables (professional formatting)
        if '|' not in content or '---' not in content:
            score -= 5
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.STRUCTURE,
                severity=ValidationSeverity.LOW,
                title="No Tables Found",
                description="Tables improve readability for structured information",
                recommendation="Add tables for severity matrices, timelines, or checklists",
            ))

        # Check document length
        word_count = len(content.split())
        if word_count < 500:
            score -= 20
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.STRUCTURE,
                severity=ValidationSeverity.HIGH,
                title="Insufficient Content",
                description=f"Playbook has only {word_count} words. Comprehensive playbooks need 1000+ words.",
                recommendation="Expand content with more detailed procedures, examples, and context",
            ))

        return ValidationScore(
            category=ValidationCategory.STRUCTURE,
            score=max(0, score),
            findings_count=findings_count,
            details=f"Found {h2_count} sections, {word_count} words",
        )

    def _validate_content_quality(
        self,
        content: str,
        content_lower: str,
        team: str,
    ) -> ValidationScore:
        """Validate content quality and actionability."""
        score = 100.0
        findings_count = 0

        # Check for actionable language
        actionable_count = sum(
            1 for keyword in ACTIONABILITY_KEYWORDS
            if keyword in content_lower
        )

        if actionable_count < 5:
            score -= 20
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.CONTENT_QUALITY,
                severity=ValidationSeverity.HIGH,
                title="Low Actionability",
                description=f"Only {actionable_count} actionable keywords found. Content may be too theoretical.",
                recommendation="Add specific steps, commands, and procedures that readers can execute",
            ))
        elif actionable_count < 10:
            score -= 10
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.CONTENT_QUALITY,
                severity=ValidationSeverity.MEDIUM,
                title="Moderate Actionability",
                description="Content could be more action-oriented",
                recommendation="Include more step-by-step procedures and executable commands",
            ))

        # Check for code blocks (practical examples)
        code_blocks = len(re.findall(r'```', content))
        if code_blocks < 2:
            score -= 15
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.CONTENT_QUALITY,
                severity=ValidationSeverity.MEDIUM,
                title="Insufficient Code Examples",
                description=f"Only {code_blocks // 2} code blocks found. Technical playbooks need examples.",
                recommendation="Add code examples for commands, queries, and configurations",
            ))

        # Check for specific examples
        example_patterns = [
            r'example[:\s]',
            r'for instance',
            r'such as',
            r'e\.g\.',
            r'sample',
        ]
        example_count = sum(
            len(re.findall(pattern, content_lower))
            for pattern in example_patterns
        )

        if example_count < 3:
            score -= 10
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.CONTENT_QUALITY,
                severity=ValidationSeverity.MEDIUM,
                title="Few Concrete Examples",
                description="Playbook lacks concrete examples to illustrate concepts",
                recommendation="Add real-world examples, sample scenarios, and case studies",
            ))

        # Check for numbered lists (procedures)
        numbered_lists = len(re.findall(r'^\d+\.', content, re.MULTILINE))
        if numbered_lists < 3:
            score -= 5
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.CONTENT_QUALITY,
                severity=ValidationSeverity.LOW,
                title="Few Numbered Procedures",
                description="Numbered lists help readers follow procedures sequentially",
                recommendation="Use numbered lists for step-by-step procedures",
            ))

        # Check for specificity (avoid vague language)
        vague_phrases = [
            "as needed", "if necessary", "when appropriate",
            "as required", "may vary", "depends on",
        ]
        vague_count = sum(
            1 for phrase in vague_phrases
            if phrase in content_lower
        )

        if vague_count > 5:
            score -= 10
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.CONTENT_QUALITY,
                severity=ValidationSeverity.MEDIUM,
                title="Vague Language Detected",
                description=f"Found {vague_count} vague phrases. Content should be more specific.",
                recommendation="Replace vague language with specific thresholds, criteria, or conditions",
            ))

        return ValidationScore(
            category=ValidationCategory.CONTENT_QUALITY,
            score=max(0, score),
            findings_count=findings_count,
            details=f"Actionability: {actionable_count}, Examples: {example_count}",
        )

    def _validate_industry_standards(
        self,
        content: str,
        content_lower: str,
        team: str,
    ) -> ValidationScore:
        """Validate alignment with industry standards."""
        score = 100.0
        findings_count = 0

        # Check for MITRE ATT&CK references
        mitre_refs = re.findall(r'T\d{4}(\.\d{3})?', content)
        if not mitre_refs:
            score -= 20
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.INDUSTRY_STANDARDS,
                severity=ValidationSeverity.HIGH,
                title="No MITRE ATT&CK References",
                description="Playbook should reference MITRE ATT&CK techniques",
                recommendation="Add MITRE technique IDs (e.g., T1566.001) for threat mapping",
                compliance_impact=["MITRE ATT&CK", "NIST CSF"],
            ))
        elif len(mitre_refs) < 3:
            score -= 10
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.INDUSTRY_STANDARDS,
                severity=ValidationSeverity.MEDIUM,
                title="Limited MITRE ATT&CK Coverage",
                description=f"Only {len(mitre_refs)} MITRE techniques referenced",
                recommendation="Map all relevant attack techniques to MITRE framework",
            ))

        # Check for severity classification
        severity_patterns = [
            r'(critical|high|medium|low)\s*(severity|priority|risk)',
            r'severity\s*[:\-]\s*(critical|high|medium|low)',
            r'(p1|p2|p3|p4)',
        ]
        has_severity = any(
            re.search(pattern, content_lower)
            for pattern in severity_patterns
        )

        if not has_severity:
            score -= 15
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.INDUSTRY_STANDARDS,
                severity=ValidationSeverity.MEDIUM,
                title="No Severity Classification",
                description="Playbook should include severity/priority classification",
                recommendation="Add a severity matrix (Critical/High/Medium/Low) with criteria",
            ))

        # Check for timeline/SLA references
        time_patterns = [
            r'\d+\s*(minute|hour|day)s?',
            r'SLA',
            r'response time',
            r'T\+\d+',
        ]
        has_timeline = any(
            re.search(pattern, content_lower if 'SLA' not in pattern else content)
            for pattern in time_patterns
        )

        if not has_timeline:
            score -= 10
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.INDUSTRY_STANDARDS,
                severity=ValidationSeverity.MEDIUM,
                title="No Timeline/SLA Information",
                description="Playbook should include response time expectations",
                recommendation="Add SLA targets and response time guidelines",
            ))

        # Check for escalation procedures
        if 'escalat' not in content_lower:
            score -= 10
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.INDUSTRY_STANDARDS,
                severity=ValidationSeverity.MEDIUM,
                title="No Escalation Procedures",
                description="Playbook should define when and how to escalate",
                recommendation="Add escalation criteria, paths, and contact information",
            ))

        # Check for reference to standards
        standards_mentioned = []
        for standard in ['nist', 'iso 27001', 'cis', 'sans', 'owasp']:
            if standard in content_lower:
                standards_mentioned.append(standard.upper())

        if not standards_mentioned:
            score -= 5
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.INDUSTRY_STANDARDS,
                severity=ValidationSeverity.LOW,
                title="No Standards References",
                description="Consider referencing industry standards",
                recommendation="Reference applicable standards (NIST, ISO 27001, CIS, etc.)",
            ))

        return ValidationScore(
            category=ValidationCategory.INDUSTRY_STANDARDS,
            score=max(0, score),
            findings_count=findings_count,
            details=f"MITRE refs: {len(mitre_refs)}, Standards: {', '.join(standards_mentioned) or 'None'}",
        )

    def _validate_compliance(
        self,
        content: str,
        content_lower: str,
    ) -> Dict[ComplianceFramework, bool]:
        """Validate compliance with selected frameworks."""
        compliance_status = {}

        for framework in self.compliance_frameworks:
            requirements = COMPLIANCE_REQUIREMENTS.get(framework, {})
            required_concepts = requirements.get("required_concepts", [])

            # Check if required concepts are present
            found_concepts = sum(
                1 for concept in required_concepts
                if concept in content_lower
            )

            # Framework is considered aligned if >50% of concepts are covered
            is_compliant = found_concepts >= len(required_concepts) * 0.5 if required_concepts else True
            compliance_status[framework] = is_compliant

            if not is_compliant and required_concepts:
                missing = [c for c in required_concepts if c not in content_lower]
                self.findings.append(ValidationFinding(
                    category=ValidationCategory.COMPLIANCE,
                    severity=ValidationSeverity.MEDIUM,
                    title=f"{framework.value} Alignment Gap",
                    description=f"Missing coverage of: {', '.join(missing[:3])}",
                    recommendation=f"Add content addressing {framework.value} requirements",
                    compliance_impact=[framework.value],
                ))

        return compliance_status

    def _validate_technical_accuracy(
        self,
        content: str,
        content_lower: str,
        team: str,
    ) -> ValidationScore:
        """Validate technical accuracy of content."""
        score = 100.0
        findings_count = 0

        # Check for detection rules (for defensive teams)
        if team in ['blue_team', 'soc', 'purple_team']:
            detection_patterns = QUALITY_INDICATORS['detection_rules']
            detection_found = sum(
                1 for pattern in detection_patterns
                if re.search(pattern, content, re.IGNORECASE)
            )

            if detection_found == 0:
                score -= 25
                findings_count += 1
                self.findings.append(ValidationFinding(
                    category=ValidationCategory.TECHNICAL_ACCURACY,
                    severity=ValidationSeverity.HIGH,
                    title="No Detection Rules",
                    description="Defensive playbooks should include detection rules",
                    recommendation="Add SIEM queries, Sigma rules, or YARA signatures",
                ))
            elif detection_found < 2:
                score -= 10
                findings_count += 1
                self.findings.append(ValidationFinding(
                    category=ValidationCategory.TECHNICAL_ACCURACY,
                    severity=ValidationSeverity.MEDIUM,
                    title="Limited Detection Coverage",
                    description="Add more detection rule formats for broader coverage",
                    recommendation="Include Splunk, Elastic, Sigma, and/or YARA rules",
                ))

        # Check for IOC examples
        ioc_patterns = QUALITY_INDICATORS['ioc_patterns']
        ioc_found = sum(
            1 for pattern in ioc_patterns
            if re.search(pattern, content, re.IGNORECASE)
        )

        if team in ['blue_team', 'soc', 'threat_intel', 'incident_response']:
            if ioc_found == 0:
                score -= 15
                findings_count += 1
                self.findings.append(ValidationFinding(
                    category=ValidationCategory.TECHNICAL_ACCURACY,
                    severity=ValidationSeverity.MEDIUM,
                    title="No IOC Examples",
                    description="Include example IOC formats (IPs, hashes, domains)",
                    recommendation="Add sample IOCs with proper formatting guidance",
                ))

        # Check for command examples
        command_patterns = QUALITY_INDICATORS['commands']
        command_found = sum(
            1 for pattern in command_patterns
            if re.search(pattern, content, re.MULTILINE)
        )

        if command_found < 3:
            score -= 10
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.TECHNICAL_ACCURACY,
                severity=ValidationSeverity.MEDIUM,
                title="Few Command Examples",
                description=f"Only {command_found} command patterns found",
                recommendation="Add executable commands for investigation and response",
            ))

        # Check for tool references
        common_tools = [
            'splunk', 'elastic', 'sentinel', 'crowdstrike', 'carbon black',
            'wireshark', 'volatility', 'autopsy', 'burp', 'nmap',
            'powershell', 'python', 'bash', 'yara', 'sigma',
        ]
        tools_mentioned = [t for t in common_tools if t in content_lower]

        if len(tools_mentioned) < 2:
            score -= 10
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.TECHNICAL_ACCURACY,
                severity=ValidationSeverity.LOW,
                title="Limited Tool Coverage",
                description="Mention specific tools for implementation",
                recommendation="Reference common security tools (SIEM, EDR, forensic tools)",
            ))

        return ValidationScore(
            category=ValidationCategory.TECHNICAL_ACCURACY,
            score=max(0, score),
            findings_count=findings_count,
            details=f"Tools: {', '.join(tools_mentioned[:5]) or 'None'}",
        )

    def _validate_usefulness(
        self,
        content: str,
        content_lower: str,
        team: str,
    ) -> ValidationScore:
        """Validate real-world usefulness and applicability."""
        score = 100.0
        findings_count = 0

        # Check for decision criteria
        decision_patterns = [
            r'if\s+.*then',
            r'when\s+.*:',
            r'criteria',
            r'threshold',
            r'decision\s*(tree|matrix|point)',
        ]
        decision_found = sum(
            1 for pattern in decision_patterns
            if re.search(pattern, content_lower)
        )

        if decision_found == 0:
            score -= 15
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.USEFULNESS,
                severity=ValidationSeverity.MEDIUM,
                title="No Decision Criteria",
                description="Playbook lacks clear decision points or criteria",
                recommendation="Add decision trees, thresholds, or criteria for actions",
            ))

        # Check for checklists
        checklist_patterns = [
            r'\[\s*\]|\[x\]|\[X\]',  # Standard checkbox syntax
            r'\[-\]|\[o\]|\[\*\]',  # Alternative checkbox syntax
            r'checklist',
        ]
        has_checklist = any(
            re.search(pattern, content_lower if 'checklist' in pattern else content)
            for pattern in checklist_patterns
        )

        if not has_checklist:
            score -= 10
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.USEFULNESS,
                severity=ValidationSeverity.LOW,
                title="No Checklists",
                description="Checklists help ensure completeness during incidents",
                recommendation="Add actionable checklists for response procedures",
            ))

        # Check for contact information placeholder
        contact_patterns = [
            r'contact',
            r'notify',
            r'email',
            r'phone',
            r'slack',
            r'pager',
        ]
        has_contact = any(
            pattern in content_lower
            for pattern in contact_patterns
        )

        if not has_contact:
            score -= 10
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.USEFULNESS,
                severity=ValidationSeverity.MEDIUM,
                title="No Contact Information",
                description="Include escalation contacts or notification guidance",
                recommendation="Add contact roles/channels for escalation",
            ))

        # Check for automation potential
        automation_patterns = [
            r'automat',
            r'script',
            r'playbook',
            r'runbook',
            r'soar',
            r'orchestrat',
        ]
        automation_found = sum(
            1 for pattern in automation_patterns
            if pattern in content_lower
        )

        if automation_found == 0:
            score -= 5
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.USEFULNESS,
                severity=ValidationSeverity.LOW,
                title="No Automation Guidance",
                description="Consider automation opportunities",
                recommendation="Identify steps that can be automated via SOAR/scripts",
            ))

        # Check for metrics/KPIs
        metrics_found = sum(
            1 for pattern in QUALITY_INDICATORS['metrics']
            if re.search(pattern, content, re.IGNORECASE)
        )

        if metrics_found == 0:
            score -= 10
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.USEFULNESS,
                severity=ValidationSeverity.MEDIUM,
                title="No Success Metrics",
                description="Include metrics to measure effectiveness",
                recommendation="Add KPIs, SLAs, or success criteria",
            ))

        # Check for common pitfalls/warnings
        warning_patterns = [
            r'warning|caution|note:',
            r'common mistake',
            r'do not|don\'t|avoid',
            r'important:',
        ]
        has_warnings = any(
            re.search(pattern, content_lower)
            for pattern in warning_patterns
        )

        if not has_warnings:
            score -= 5
            findings_count += 1
            self.findings.append(ValidationFinding(
                category=ValidationCategory.USEFULNESS,
                severity=ValidationSeverity.LOW,
                title="No Warnings or Pitfalls",
                description="Include common mistakes to avoid",
                recommendation="Add warnings, cautions, and common pitfalls",
            ))

        return ValidationScore(
            category=ValidationCategory.USEFULNESS,
            score=max(0, score),
            findings_count=findings_count,
            details=f"Decision criteria: {decision_found}, Metrics: {metrics_found}",
        )

    def _calculate_grade(self, score: float) -> str:
        """Calculate letter grade from score."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def _generate_recommendations(
        self,
        category_scores: Dict[ValidationCategory, ValidationScore],
    ) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        # Sort categories by score (lowest first)
        sorted_categories = sorted(
            category_scores.items(),
            key=lambda x: x[1].score
        )

        for category, score in sorted_categories:
            if score.percentage < 80:
                if category == ValidationCategory.STRUCTURE:
                    recommendations.append(
                        "Improve document structure with clear sections, tables, and proper headings"
                    )
                elif category == ValidationCategory.CONTENT_QUALITY:
                    recommendations.append(
                        "Add more actionable content with specific steps, commands, and examples"
                    )
                elif category == ValidationCategory.INDUSTRY_STANDARDS:
                    recommendations.append(
                        "Align content with MITRE ATT&CK and add severity classifications"
                    )
                elif category == ValidationCategory.TECHNICAL_ACCURACY:
                    recommendations.append(
                        "Include detection rules, IOC formats, and tool-specific commands"
                    )
                elif category == ValidationCategory.USEFULNESS:
                    recommendations.append(
                        "Add decision criteria, checklists, and measurable success metrics"
                    )

        # Add recommendations from critical/high findings
        for finding in self.findings:
            if finding.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]:
                if finding.recommendation not in recommendations:
                    recommendations.append(finding.recommendation)

        return recommendations[:10]  # Top 10 recommendations

    def validate_file(self, file_path: str) -> ValidationReport:
        """Validate a playbook file.

        Args:
            file_path: Path to the playbook markdown file

        Returns:
            ValidationReport
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Playbook not found: {file_path}")

        content = path.read_text()

        # Try to determine team from path or content
        team = "unknown"
        for team_name in REQUIRED_SECTIONS.keys():
            if team_name in str(path).lower() or team_name in content.lower():
                team = team_name
                break

        return self.validate(content, team, str(path))

    def validate_all_playbooks(
        self,
        playbook_dir: str,
    ) -> List[ValidationReport]:
        """Validate all playbooks in a directory.

        Args:
            playbook_dir: Path to directory containing playbooks

        Returns:
            List of ValidationReports
        """
        reports = []
        playbook_path = Path(playbook_dir)

        if not playbook_path.exists():
            logger.warning(f"Playbook directory not found: {playbook_dir}")
            return reports

        for md_file in playbook_path.rglob("*.md"):
            try:
                report = self.validate_file(str(md_file))
                reports.append(report)
            except Exception as e:
                logger.error(f"Error validating {md_file}: {e}")

        return reports


# =============================================================================
# VALIDATION UTILITIES
# =============================================================================

def validate_playbook(
    content: str,
    team: str,
    frameworks: Optional[List[str]] = None,
) -> ValidationReport:
    """Convenience function to validate a playbook.

    Args:
        content: Playbook markdown content
        team: Team type
        frameworks: List of compliance framework names

    Returns:
        ValidationReport
    """
    compliance_frameworks = []
    if frameworks:
        for name in frameworks:
            for framework in ComplianceFramework:
                if name.lower() in framework.value.lower():
                    compliance_frameworks.append(framework)
                    break

    validator = PlaybookValidator(
        compliance_frameworks=compliance_frameworks or None
    )

    return validator.validate(content, team)


def get_validation_summary(reports: List[ValidationReport]) -> Dict[str, Any]:
    """Generate a summary of multiple validation reports.

    Args:
        reports: List of ValidationReports

    Returns:
        Summary dictionary
    """
    if not reports:
        return {"error": "No reports to summarize"}

    avg_score = sum(r.overall_score for r in reports) / len(reports)
    production_ready = sum(1 for r in reports if r.is_production_ready)

    grade_counts = {}
    for report in reports:
        grade_counts[report.grade] = grade_counts.get(report.grade, 0) + 1

    return {
        "total_playbooks": len(reports),
        "average_score": round(avg_score, 1),
        "production_ready": production_ready,
        "production_ready_percentage": round(production_ready / len(reports) * 100, 1),
        "grade_distribution": grade_counts,
        "total_findings": sum(len(r.findings) for r in reports),
        "critical_findings": sum(
            sum(1 for f in r.findings if f.severity == ValidationSeverity.CRITICAL)
            for r in reports
        ),
    }
