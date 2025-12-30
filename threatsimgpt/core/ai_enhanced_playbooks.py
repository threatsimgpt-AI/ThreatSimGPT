"""AI-Enhanced Playbook Generator for ThreatSimGPT.

This module uses LLM models to generate comprehensive, research-backed field manuals
for each security team. The system continuously improves playbooks by:

1. Incorporating latest threat intelligence from simulations
2. Learning from organizational context and industry specifics
3. Generating detailed, enterprise-grade documentation
4. Adapting content based on feedback and new attack patterns

Each playbook is designed as a professional field manual suitable for:
- Enterprise security operations
- Industry compliance requirements
- Professional training and certification
- Incident response procedures
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PlaybookQuality(Enum):
    """Quality level for generated playbooks."""
    BASIC = "basic"           # Rule-based, no AI
    ENHANCED = "enhanced"     # AI-enhanced with context
    COMPREHENSIVE = "comprehensive"  # Full AI research mode
    EXPERT = "expert"         # Maximum detail, citations, examples


@dataclass
class PlaybookContext:
    """Context for AI playbook generation."""
    scenario_name: str
    threat_type: str
    mitre_techniques: List[str]
    difficulty_level: int
    industry: str = "general"
    organization_size: str = "enterprise"  # startup, smb, enterprise, government
    compliance_frameworks: List[str] = field(default_factory=list)
    previous_incidents: List[Dict] = field(default_factory=list)
    custom_requirements: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# AI PROMPT TEMPLATES FOR EACH SECURITY TEAM
# =============================================================================

FIELD_MANUAL_SYSTEM_PROMPT = """You are a world-class cybersecurity expert with extensive experience in {team_name} operations. You are writing a comprehensive field manual that will be used by security professionals in enterprise environments.

Your manual must be:
1. ACTIONABLE - Every section must include specific steps, commands, and procedures
2. COMPREHENSIVE - Cover all aspects thoroughly with real-world examples
3. CURRENT - Reference latest threat intelligence, CVEs, and attack patterns
4. PROFESSIONAL - Written for experienced security practitioners
5. COMPLIANT - Align with industry frameworks (NIST, ISO 27001, MITRE ATT&CK)

Write in a professional technical documentation style. Include:
- Specific tool commands and configurations
- Detection rule syntax (SIEM, YARA, Sigma)
- Code snippets where applicable
- Decision trees for triage
- Metrics and KPIs for measurement
- References to authoritative sources
"""

BLUE_TEAM_MANUAL_PROMPT = """# Blue Team Field Manual Generation

## Scenario Context
- **Threat Scenario**: {scenario_name}
- **Threat Type**: {threat_type}
- **MITRE ATT&CK**: {mitre_techniques}
- **Difficulty Level**: {difficulty}/10
- **Industry**: {industry}
- **Organization Size**: {org_size}
- **Compliance Requirements**: {compliance}

## Generate a Comprehensive Blue Team Field Manual

Create a detailed operational manual covering:

### 1. THREAT OVERVIEW & INTELLIGENCE
- Threat actor profiles and motivations
- Attack chain analysis (Cyber Kill Chain mapping)
- Historical campaign data and trends
- Industry-specific targeting patterns

### 2. DETECTION ENGINEERING
Provide specific, deployable detection rules:

#### SIEM Detection Rules (Splunk/Elastic format)
```
[Provide actual query syntax]
```

#### Sigma Rules
```yaml
[Provide Sigma rule YAML]
```

#### YARA Rules (if applicable)
```
[Provide YARA signatures]
```

#### Network Detection (Suricata/Snort)
```
[Provide IDS signatures]
```

### 3. MONITORING & VISIBILITY
- Critical log sources required
- Dashboard specifications
- Alert thresholds and tuning
- Baseline establishment procedures

### 4. HARDENING PROCEDURES
- System hardening checklists
- Configuration baselines (CIS Benchmarks)
- Email security configurations
- Network segmentation recommendations

### 5. IOC MANAGEMENT
- IOC collection procedures
- Enrichment workflows
- Blocklist management
- Threat feed integration

### 6. METRICS & REPORTING
- Detection coverage metrics
- Mean Time to Detect (MTTD)
- False positive rates
- Executive reporting templates

### 7. TOOL CONFIGURATIONS
Provide specific configurations for:
- Microsoft Defender / Sentinel
- CrowdStrike / Carbon Black
- Proofpoint / Mimecast
- Splunk / Elastic SIEM

### 8. CONTINUOUS IMPROVEMENT
- Detection gap analysis procedures
- Purple team exercise recommendations
- Training requirements

Generate the complete manual with all sections filled in with specific, actionable content.
"""

RED_TEAM_MANUAL_PROMPT = """# Red Team Field Manual Generation

## Scenario Context
- **Threat Scenario**: {scenario_name}
- **Threat Type**: {threat_type}
- **MITRE ATT&CK**: {mitre_techniques}
- **Difficulty Level**: {difficulty}/10
- **Industry**: {industry}
- **Organization Size**: {org_size}

## Generate a Comprehensive Red Team Field Manual

Create a detailed offensive operations manual covering:

### 1. RECONNAISSANCE & OSINT
- Target profiling methodology
- OSINT collection techniques
- Social media intelligence gathering
- Technical footprinting procedures
- Tools: Maltego, Shodan, theHarvester, LinkedIn

### 2. INFRASTRUCTURE SETUP
- Domain acquisition and aging
- Email infrastructure configuration
- Phishing platform deployment (Gophish, King Phisher)
- Payload hosting considerations
- OPSEC requirements

### 3. ATTACK TECHNIQUES
For each technique, provide:
- Step-by-step execution procedures
- Tool configurations and commands
- Sample payloads (educational)
- Expected outcomes
- Detection signatures to evade

#### Primary Attack Vector
```
[Detailed attack procedure]
```

#### Secondary Attack Vectors
```
[Alternative approaches]
```

### 4. PAYLOAD DEVELOPMENT
- Payload types and selection criteria
- Obfuscation techniques
- Delivery mechanisms
- C2 considerations (if applicable)

### 5. EVASION TECHNIQUES
- Email security bypass methods
- Sandbox evasion
- EDR evasion considerations
- Network detection evasion
- Time-based evasion

### 6. SUCCESS METRICS
- Engagement success criteria
- Data collection requirements
- Evidence preservation
- Reporting metrics

### 7. CAMPAIGN MANAGEMENT
- Phishing campaign scheduling
- Target list management
- Real-time monitoring
- Abort criteria and procedures

### 8. POST-ENGAGEMENT
- Debrief procedures
- Finding documentation
- Remediation recommendations
- Executive presentation format

### 9. LEGAL & ETHICAL CONSIDERATIONS
- Rules of Engagement template
- Scope documentation
- Authorization requirements
- Data handling procedures

Generate the complete manual with specific, actionable content for authorized security testing.
"""

SOC_MANUAL_PROMPT = """# SOC Analyst Field Manual Generation

## Scenario Context
- **Threat Scenario**: {scenario_name}
- **Threat Type**: {threat_type}
- **MITRE ATT&CK**: {mitre_techniques}
- **Difficulty Level**: {difficulty}/10
- **Industry**: {industry}

## Generate a Comprehensive SOC Operations Manual

Create a detailed SOC analyst manual covering:

### 1. ALERT CLASSIFICATION
- Alert categorization matrix
- Severity classification criteria
- Priority assignment guidelines
- SLA requirements by severity

| Severity | Response Time | Escalation | Example |
|----------|---------------|------------|---------|
| Critical | 15 minutes | Immediate | ... |
| High | 1 hour | ... | ... |
| Medium | 4 hours | ... | ... |
| Low | 24 hours | ... | ... |

### 2. TRIAGE PROCEDURES
Step-by-step triage workflow:

```
[Decision tree for alert triage]
```

#### Initial Assessment Checklist
- [ ] Verify alert is not false positive
- [ ] Identify affected assets
- [ ] Determine blast radius
- [ ] Check for related alerts
- [ ] Document initial findings

### 3. INVESTIGATION PLAYBOOK
Detailed investigation steps:

#### Email Header Analysis
```
[Commands and procedures]
```

#### URL/Domain Analysis
```
[Analysis procedures with tool commands]
```

#### Attachment Analysis
```
[Sandbox submission procedures]
```

#### User Activity Review
```
[SIEM queries for user behavior]
```

### 4. ESCALATION PROCEDURES
- Escalation matrix
- Contact procedures
- Information handoff template
- Management notification criteria

### 5. CONTAINMENT ACTIONS
Immediate response actions with specific commands:

#### Email Containment
```powershell
[Exchange/M365 commands for email quarantine]
```

#### Network Containment
```
[Firewall/proxy blocking procedures]
```

#### Endpoint Containment
```
[EDR isolation commands]
```

### 6. DOCUMENTATION REQUIREMENTS
- Ticket documentation standards
- Evidence collection procedures
- Chain of custody requirements
- Timeline documentation format

### 7. COMMUNICATION TEMPLATES
- Internal stakeholder notifications
- Management updates
- User communications
- External party notifications

### 8. SHIFT HANDOFF
- Handoff documentation template
- Open investigation summary
- Pending actions tracker
- Known issues log

### 9. METRICS TRACKING
- Alerts processed
- MTTD / MTTR
- False positive rate
- Escalation rate

Generate the complete manual with specific procedures and commands.
"""

PURPLE_TEAM_MANUAL_PROMPT = """# Purple Team Field Manual Generation

## Scenario Context
- **Threat Scenario**: {scenario_name}
- **Threat Type**: {threat_type}
- **MITRE ATT&CK**: {mitre_techniques}
- **Difficulty Level**: {difficulty}/10
- **Industry**: {industry}

## Generate a Comprehensive Purple Team Operations Manual

Create a collaborative security testing manual covering:

### 1. EXERCISE PLANNING
- Scope definition template
- Success criteria establishment
- Timeline and milestones
- Resource requirements
- Communication plan

### 2. THREAT EMULATION FRAMEWORK
Map attacks to MITRE ATT&CK:

| Technique ID | Name | Red Team Action | Blue Team Detection | Gap |
|--------------|------|-----------------|---------------------|-----|
| {mitre_techniques} | ... | ... | ... | ... |

### 3. TEST CASES
Detailed test cases with:
- Objective
- Red team procedure
- Expected blue team response
- Pass/fail criteria
- Evidence requirements

#### Test Case Template
```
Test ID: TC-001
Objective: [What we're testing]
Red Action: [Specific attack steps]
Blue Expectation: [Expected detection/response]
Actual Result: [To be filled]
Gap Identified: [To be filled]
Recommendation: [To be filled]
```

### 4. DETECTION VALIDATION
- Detection rule testing procedures
- Coverage mapping methodology
- Gap identification process
- Prioritization framework

### 5. REAL-TIME COLLABORATION
- Communication channels
- Attack notification procedures
- Detection confirmation process
- Immediate feedback loops

### 6. GAP ANALYSIS
- Gap documentation template
- Risk scoring methodology
- Remediation prioritization
- Tracking and verification

### 7. IMPROVEMENT RECOMMENDATIONS
- Detection enhancement proposals
- Process improvement suggestions
- Tool/capability requirements
- Training needs assessment

### 8. REPORTING
- Technical findings report template
- Executive summary format
- Metrics dashboard
- Trend analysis

### 9. CONTINUOUS IMPROVEMENT
- Lessons learned documentation
- Knowledge base updates
- Playbook refinements
- Training material updates

Generate the complete manual with actionable templates and procedures.
"""

THREAT_INTEL_MANUAL_PROMPT = """# Threat Intelligence Field Manual Generation

## Scenario Context
- **Threat Scenario**: {scenario_name}
- **Threat Type**: {threat_type}
- **MITRE ATT&CK**: {mitre_techniques}
- **Difficulty Level**: {difficulty}/10
- **Industry**: {industry}

## Generate a Comprehensive Threat Intelligence Manual

Create a detailed CTI operations manual covering:

### 1. INTELLIGENCE REQUIREMENTS
- Priority Intelligence Requirements (PIRs)
- Standing Intelligence Requirements
- Ad-hoc collection requirements
- Stakeholder mapping

### 2. COLLECTION MANAGEMENT
#### Open Source Intelligence (OSINT)
- Sources and feeds
- Collection automation
- Validation procedures

#### Technical Intelligence
- Malware analysis procedures
- Network traffic analysis
- Artifact collection

#### Human Intelligence
- Industry sharing groups
- Law enforcement liaison
- Vendor relationships

### 3. THREAT ACTOR PROFILING
Template for threat actor documentation:

```
Actor Name: [Name/Designation]
Aliases: [Known aliases]
Attribution Confidence: [Low/Medium/High]
Motivation: [Financial/Espionage/Hacktivism]
Capabilities: [Sophistication level]
Target Industries: [Sectors targeted]
Geographic Focus: [Regions]
TTPs: [MITRE ATT&CK mapping]
Infrastructure: [Known infrastructure]
Tools: [Malware/tools used]
Historical Campaigns: [Previous operations]
```

### 4. IOC MANAGEMENT
- IOC types and confidence levels
- Enrichment workflows
- Aging and expiration policies
- Distribution procedures

#### IOC Quality Framework
| Confidence | Definition | Action | Retention |
|------------|------------|--------|-----------|
| High | Confirmed malicious | Block immediately | 90 days |
| Medium | Likely malicious | Monitor/alert | 30 days |
| Low | Suspicious | Watchlist only | 7 days |

### 5. ANALYSIS FRAMEWORKS
- Diamond Model application
- Kill Chain analysis
- MITRE ATT&CK mapping
- F3EAD cycle

### 6. INTELLIGENCE PRODUCTS
Templates for each product type:

#### Tactical Alert (Immediate)
```
[Template with required fields]
```

#### Weekly Threat Brief
```
[Template with required sections]
```

#### Strategic Assessment
```
[Template for leadership]
```

### 7. SHARING & COLLABORATION
- STIX/TAXII implementation
- TLP classification guide
- ISAC participation
- Information sharing agreements

### 8. METRICS & EFFECTIVENESS
- Intelligence accuracy metrics
- Timeliness measurements
- Stakeholder satisfaction
- Operational impact tracking

Generate the complete manual with specific procedures and templates.
"""

GRC_MANUAL_PROMPT = """# GRC Field Manual Generation

## Scenario Context
- **Threat Scenario**: {scenario_name}
- **Threat Type**: {threat_type}
- **MITRE ATT&CK**: {mitre_techniques}
- **Difficulty Level**: {difficulty}/10
- **Industry**: {industry}
- **Compliance Frameworks**: {compliance}

## Generate a Comprehensive GRC Operations Manual

Create a detailed governance, risk, and compliance manual covering:

### 1. RISK ASSESSMENT METHODOLOGY
- Risk identification procedures
- Likelihood assessment criteria
- Impact assessment matrix
- Risk scoring methodology

#### Risk Matrix
| Likelihood/Impact | Negligible | Minor | Moderate | Significant | Severe |
|-------------------|------------|-------|----------|-------------|--------|
| Almost Certain | ... | ... | ... | ... | Critical |
| Likely | ... | ... | ... | ... | ... |
| Possible | ... | ... | ... | ... | ... |
| Unlikely | ... | ... | ... | ... | ... |
| Rare | Low | ... | ... | ... | ... |

### 2. CONTROL FRAMEWORK MAPPING
Map controls across frameworks:

| Control | NIST CSF | ISO 27001 | CIS Controls | SOC 2 | PCI DSS |
|---------|----------|-----------|--------------|-------|---------|
| Email Security | PR.PT-4 | A.13.2.3 | 9.2 | CC6.1 | 1.1.4 |
| ... | ... | ... | ... | ... | ... |

### 3. CONTROL ASSESSMENT
- Control effectiveness criteria
- Testing procedures
- Evidence requirements
- Gap remediation tracking

#### Control Assessment Template
```
Control ID: [ID]
Control Name: [Name]
Control Objective: [What it achieves]
Implementation Status: [Implemented/Partial/Not Implemented]
Effectiveness: [Effective/Partially Effective/Ineffective]
Evidence: [Required documentation]
Gaps: [Identified deficiencies]
Remediation: [Required actions]
Owner: [Responsible party]
Due Date: [Timeline]
```

### 4. COMPLIANCE MONITORING
- Continuous monitoring procedures
- Compliance dashboard specifications
- Exception management process
- Audit preparation checklist

### 5. POLICY FRAMEWORK
Required policies for this threat type:
- Policy requirements
- Procedure documentation
- Standard specifications
- Guidelines

#### Policy Template
```
Policy: [Name]
Version: [X.X]
Effective Date: [Date]
Owner: [Role]
Purpose: [Why this policy exists]
Scope: [Who/what it applies to]
Policy Statement: [The actual policy]
Compliance: [How compliance is measured]
Exceptions: [Exception process]
References: [Related documents]
```

### 6. THIRD-PARTY RISK
- Vendor assessment procedures
- Due diligence requirements
- Ongoing monitoring
- Contract requirements

### 7. INCIDENT COMPLIANCE
- Regulatory notification requirements
- Breach notification timelines
- Documentation requirements
- Regulatory communication templates

| Regulation | Notification Deadline | Authority | Requirements |
|------------|----------------------|-----------|--------------|
| GDPR | 72 hours | DPA | ... |
| HIPAA | 60 days | HHS | ... |
| PCI DSS | Immediate | Card brands | ... |

### 8. AUDIT MANAGEMENT
- Audit preparation procedures
- Evidence collection guide
- Finding remediation tracking
- Audit response templates

### 9. METRICS & REPORTING
- Risk posture metrics
- Compliance scorecards
- Board reporting templates
- Trend analysis

Generate the complete manual with specific procedures and templates.
"""

IR_MANUAL_PROMPT = """# Incident Response Field Manual Generation

## Scenario Context
- **Threat Scenario**: {scenario_name}
- **Threat Type**: {threat_type}
- **MITRE ATT&CK**: {mitre_techniques}
- **Difficulty Level**: {difficulty}/10
- **Industry**: {industry}

## Generate a Comprehensive Incident Response Manual

Create a detailed IR operations manual following NIST/SANS methodology:

### 1. PREPARATION
- IR team structure and roles
- Contact lists and escalation paths
- Tool readiness checklist
- Runbook inventory
- Training requirements

#### IR Team RACI Matrix
| Activity | IR Lead | Analyst | IT Ops | Legal | Comms | Exec |
|----------|---------|---------|--------|-------|-------|------|
| Detection | I | R | I | I | I | I |
| Triage | A | R | C | I | I | I |
| Containment | A | R | R | C | I | I |
| ... | ... | ... | ... | ... | ... | ... |

### 2. IDENTIFICATION
- Alert validation procedures
- Scoping methodology
- Initial classification criteria
- Evidence preservation (first steps)

#### Identification Checklist
- [ ] Alert source and confidence
- [ ] Affected systems identified
- [ ] User impact assessment
- [ ] Initial IOCs collected
- [ ] Timeline started
- [ ] Stakeholders notified

### 3. CONTAINMENT
#### Short-term Containment
```
[Immediate actions with commands]
```

#### Long-term Containment
```
[Sustained containment procedures]
```

#### Containment Decision Tree
```
[Decision flowchart for containment options]
```

### 4. ERADICATION
- Malware removal procedures
- Account remediation
- System hardening post-incident
- Verification procedures

### 5. RECOVERY
- System restoration procedures
- Validation testing
- Monitoring enhancement
- Phased return to production

### 6. LESSONS LEARNED
- Post-incident review template
- Root cause analysis methodology
- Improvement tracking
- Knowledge base updates

### 7. EVIDENCE HANDLING
- Evidence collection procedures
- Chain of custody documentation
- Forensic imaging procedures
- Legal hold processes

#### Evidence Log Template
| Item | Description | Collected By | Date/Time | Hash | Storage |
|------|-------------|--------------|-----------|------|---------|
| ... | ... | ... | ... | ... | ... |

### 8. COMMUNICATION
- Internal communication templates
- External notification templates
- Media response guidelines
- Regulatory notification procedures

### 9. LEGAL CONSIDERATIONS
- Law enforcement engagement criteria
- Legal privilege considerations
- Regulatory obligations
- Insurance notification

### 10. METRICS
- Incident metrics tracking
- MTTD/MTTC/MTTR measurement
- Trend analysis
- Reporting templates

Generate the complete manual with specific procedures and templates.
"""

SECURITY_AWARENESS_MANUAL_PROMPT = """# Security Awareness Field Manual Generation

## Scenario Context
- **Threat Scenario**: {scenario_name}
- **Threat Type**: {threat_type}
- **MITRE ATT&CK**: {mitre_techniques}
- **Difficulty Level**: {difficulty}/10
- **Industry**: {industry}
- **Organization Size**: {org_size}

## Generate a Comprehensive Security Awareness Program Manual

Create a detailed training and awareness manual covering:

### 1. PROGRAM FRAMEWORK
- Program objectives and goals
- Target audience segmentation
- Training frequency requirements
- Success metrics definition

#### Audience Segmentation
| Group | Risk Level | Training Frequency | Content Focus |
|-------|------------|-------------------|---------------|
| Executives | Critical | Quarterly | BEC, Whaling |
| Finance | High | Monthly | Wire fraud, Invoice scams |
| All Staff | Medium | Quarterly | General phishing |
| IT Staff | High | Monthly | Technical threats |

### 2. CURRICULUM DESIGN
#### Core Modules
- Module 1: Recognizing Phishing
  - Learning objectives
  - Content outline
  - Interactive elements
  - Assessment questions

- Module 2: Safe Email Practices
  - [Similar structure]

- Module 3: Reporting Procedures
  - [Similar structure]

#### Role-Based Training
- Executive-specific content
- Finance-specific content
- IT-specific content
- New hire onboarding

### 3. PHISHING SIMULATION PROGRAM
- Campaign design methodology
- Difficulty progression framework
- Template library requirements
- Landing page specifications

#### Simulation Campaign Template
```
Campaign Name: [Name]
Difficulty: [1-10]
Target Group: [Audience]
Pretext: [Social engineering angle]
Indicators: [Red flags included]
Success Criteria: [Click rate target]
Follow-up Training: [Required for clickers]
```

### 4. CONTENT DEVELOPMENT
- Writing guidelines for awareness content
- Visual design standards
- Accessibility requirements
- Localization procedures

#### Content Types
- Email newsletters
- Posters and infographics
- Video scripts
- Interactive modules
- Quick reference cards

### 5. DELIVERY MECHANISMS
- LMS integration requirements
- Email delivery specifications
- Physical material distribution
- Event-based training (lunch & learns)

### 6. MEASUREMENT & REPORTING
- Phishing simulation metrics
- Training completion rates
- Knowledge assessment scores
- Behavior change indicators

#### Metrics Dashboard
| Metric | Target | Current | Trend |
|--------|--------|---------|-------|
| Click Rate | <5% | X% | ↓ |
| Report Rate | >60% | X% | ↑ |
| Training Completion | 100% | X% | → |
| Repeat Clickers | <2% | X% | ↓ |

### 7. GAMIFICATION & ENGAGEMENT
- Recognition programs
- Incentive structures
- Competition frameworks
- Badge/achievement systems

### 8. REMEDIAL TRAINING
- Clicker follow-up procedures
- Repeat offender escalation
- Manager notification process
- Additional training requirements

### 9. PROGRAM MANAGEMENT
- Annual planning calendar
- Budget requirements
- Vendor management
- Tool administration

### 10. CONTINUOUS IMPROVEMENT
- Program review procedures
- Industry benchmarking
- Feedback collection
- Content refresh cycles

Generate the complete manual with specific procedures and templates.
"""

# Map teams to their prompts
TEAM_PROMPTS = {
    "blue_team": ("Blue Team Defense Operations", BLUE_TEAM_MANUAL_PROMPT),
    "red_team": ("Red Team Offensive Operations", RED_TEAM_MANUAL_PROMPT),
    "purple_team": ("Purple Team Collaborative Testing", PURPLE_TEAM_MANUAL_PROMPT),
    "soc": ("Security Operations Center", SOC_MANUAL_PROMPT),
    "threat_intel": ("Threat Intelligence Operations", THREAT_INTEL_MANUAL_PROMPT),
    "grc": ("Governance, Risk & Compliance", GRC_MANUAL_PROMPT),
    "incident_response": ("Incident Response Operations", IR_MANUAL_PROMPT),
    "security_awareness": ("Security Awareness & Training", SECURITY_AWARENESS_MANUAL_PROMPT),
}


class AIEnhancedPlaybookGenerator:
    """Generate AI-enhanced, comprehensive field manuals for security teams."""

    def __init__(self, llm_manager=None):
        """Initialize the AI-enhanced playbook generator.

        Args:
            llm_manager: LLM manager instance for AI generation.
                        If None, will attempt to import from threatsimgpt.llm
        """
        self.llm_manager = llm_manager
        self.playbook_cache_dir = Path("generated_content/field_manuals")
        self.knowledge_base_dir = Path("generated_content/knowledge_base")
        self._ensure_directories()

        logger.info("AIEnhancedPlaybookGenerator initialized")

    def _ensure_directories(self):
        """Ensure required directories exist."""
        self.playbook_cache_dir.mkdir(parents=True, exist_ok=True)
        self.knowledge_base_dir.mkdir(parents=True, exist_ok=True)

        # Create team-specific directories
        for team in TEAM_PROMPTS.keys():
            (self.playbook_cache_dir / team).mkdir(parents=True, exist_ok=True)

    def _get_llm_manager(self):
        """Get or initialize LLM manager with auto-configuration."""
        if self.llm_manager is None:
            try:
                from threatsimgpt.llm import LLMProviderManager, LLMProviderConfig, LLMProvider, LLMModel
                import os

                manager = LLMProviderManager()

                # Try to auto-configure a provider from environment variables
                # Try OpenAI first
                openai_key = os.environ.get("OPENAI_API_KEY")
                if openai_key:
                    config = LLMProviderConfig(
                        provider=LLMProvider.OPENAI,
                        api_key=openai_key,
                        default_model=LLMModel.GPT_4,
                    )
                    manager.add_provider(config, set_as_default=True)
                    logger.info("LLM configured with OpenAI provider")
                    self.llm_manager = manager
                    return self.llm_manager

                # Try Anthropic
                anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
                if anthropic_key:
                    config = LLMProviderConfig(
                        provider=LLMProvider.ANTHROPIC,
                        api_key=anthropic_key,
                        default_model=LLMModel.CLAUDE_3_SONNET,
                    )
                    manager.add_provider(config, set_as_default=True)
                    logger.info("LLM configured with Anthropic provider")
                    self.llm_manager = manager
                    return self.llm_manager

                # Try OpenRouter
                openrouter_key = os.environ.get("OPENROUTER_API_KEY")
                if openrouter_key:
                    config = LLMProviderConfig(
                        provider=LLMProvider.OPENROUTER,
                        api_key=openrouter_key,
                        base_url="https://openrouter.ai/api/v1",
                        default_model=LLMModel.GPT_4,  # OpenRouter supports OpenAI models
                    )
                    manager.add_provider(config, set_as_default=True)
                    logger.info("LLM configured with OpenRouter provider")
                    self.llm_manager = manager
                    return self.llm_manager

                # No API key found - manager exists but has no providers
                logger.warning("No LLM API key found. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or OPENROUTER_API_KEY for AI-enhanced playbooks.")
                return None

            except Exception as e:
                logger.warning(f"Could not initialize LLM manager: {e}")
                return None
        return self.llm_manager

    async def generate_field_manual(
        self,
        team: str,
        context: PlaybookContext,
        quality: PlaybookQuality = PlaybookQuality.COMPREHENSIVE,
        use_cache: bool = True,
    ) -> str:
        """Generate a comprehensive field manual for a security team.

        Args:
            team: Target team (blue_team, red_team, etc.)
            context: PlaybookContext with scenario details
            quality: Quality level for generation
            use_cache: Whether to use cached versions if available

        Returns:
            Formatted markdown field manual
        """
        # Check cache first
        if use_cache:
            cached = self._get_cached_manual(team, context)
            if cached:
                logger.info(f"Using cached manual for {team}")
                return cached

        # Get team-specific prompt
        if team not in TEAM_PROMPTS:
            raise ValueError(f"Unknown team: {team}. Valid teams: {list(TEAM_PROMPTS.keys())}")

        team_name, prompt_template = TEAM_PROMPTS[team]

        # Format the prompt with context
        formatted_prompt = prompt_template.format(
            scenario_name=context.scenario_name,
            threat_type=context.threat_type,
            mitre_techniques=", ".join(context.mitre_techniques),
            difficulty=context.difficulty_level,
            industry=context.industry,
            org_size=context.organization_size,
            compliance=", ".join(context.compliance_frameworks) if context.compliance_frameworks else "General best practices",
        )

        # Get LLM manager
        llm = self._get_llm_manager()

        if llm is None or quality == PlaybookQuality.BASIC:
            # Fall back to rule-based generation
            logger.info(f"Using rule-based generation for {team}")
            return self._generate_rule_based_manual(team, context)

        # Generate with AI
        try:
            from threatsimgpt.llm import LLMRequest, LLMProvider, LLMModel, ContentType

            system_prompt = FIELD_MANUAL_SYSTEM_PROMPT.format(team_name=team_name)

            # Build proper LLMRequest - use PRETEXT_SCENARIO as closest match for documentation
            request = LLMRequest(
                provider=LLMProvider.OPENAI,  # Default provider, can be configured
                model=LLMModel.GPT_4,
                content_type=ContentType.PRETEXT_SCENARIO,
                system_prompt=system_prompt,
                user_prompt=formatted_prompt,
                max_tokens=8000,  # Large output for comprehensive manual
                temperature=0.3,  # Lower temperature for consistent, factual output
                scenario_context={
                    "team": team,
                    "threat_type": context.threat_type,
                    "industry": context.industry,
                    "difficulty": context.difficulty_level,
                },
            )

            # Use the LLM to generate the manual
            response = await llm.generate(request)

            manual_content = response.content if hasattr(response, 'content') else str(response)

            # Add header and metadata
            final_manual = self._format_manual_with_metadata(
                team=team,
                team_name=team_name,
                content=manual_content,
                context=context,
                quality=quality,
            )

            # Cache the result
            self._cache_manual(team, context, final_manual)

            # Update knowledge base
            self._update_knowledge_base(team, context, final_manual)

            return final_manual

        except Exception as e:
            logger.error(f"AI generation failed for {team}: {e}")
            return self._generate_rule_based_manual(team, context)

    def generate_field_manual_sync(
        self,
        team: str,
        context: PlaybookContext,
        quality: PlaybookQuality = PlaybookQuality.ENHANCED,
    ) -> str:
        """Synchronous version of field manual generation.

        Falls back to rule-based if async is not available.
        """
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're already in an async context, use rule-based
                return self._generate_rule_based_manual(team, context)
            return loop.run_until_complete(
                self.generate_field_manual(team, context, quality)
            )
        except RuntimeError:
            # No event loop, create one
            return asyncio.run(
                self.generate_field_manual(team, context, quality)
            )
        except Exception as e:
            logger.warning(f"Async generation failed: {e}, using rule-based")
            return self._generate_rule_based_manual(team, context)

    def _generate_rule_based_manual(self, team: str, context: PlaybookContext) -> str:
        """Generate a rule-based manual when AI is not available."""
        from threatsimgpt.core.team_playbooks import (
            team_playbook_generator,
            SecurityTeam,
        )

        # Convert team string to enum
        team_enum = SecurityTeam(team)

        # Generate using existing rule-based system
        playbook = team_playbook_generator.generate_team_playbook(
            team=team_enum,
            scenario_name=context.scenario_name,
            threat_type=context.threat_type,
            mitre_techniques=context.mitre_techniques,
            difficulty_level=context.difficulty_level,
        )

        base_content = team_playbook_generator.format_playbook_markdown(playbook)

        # Add field manual wrapper
        team_name = TEAM_PROMPTS.get(team, (team, ""))[0]

        return f"""# 📖 {team_name} Field Manual

> **Document Type**: Operational Field Manual
> **Classification**: Internal Use Only
> **Version**: 1.0 (Rule-Based Generation)
> **Generated**: {datetime.now().isoformat()}

---

## Document Information

| Field | Value |
|-------|-------|
| **Scenario** | {context.scenario_name} |
| **Threat Type** | {context.threat_type} |
| **MITRE ATT&CK** | {', '.join(context.mitre_techniques)} |
| **Industry** | {context.industry} |
| **Difficulty** | {context.difficulty_level}/10 |

---

{base_content}

---

## Appendix A: References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- CIS Controls: https://www.cisecurity.org/controls

---

## Appendix B: Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | {datetime.now().strftime('%Y-%m-%d')} | ThreatSimGPT | Initial generation |

---

*This field manual was generated by ThreatSimGPT using rule-based templates.*
*For AI-enhanced comprehensive manuals, configure an LLM provider.*
"""

    def _format_manual_with_metadata(
        self,
        team: str,
        team_name: str,
        content: str,
        context: PlaybookContext,
        quality: PlaybookQuality,
    ) -> str:
        """Add professional metadata and formatting to the manual."""

        label_map = {
            "blue_team": "[BLUE]",
            "red_team": "[RED]",
            "purple_team": "[PURPLE]",
            "soc": "[SOC]",
            "threat_intel": "[INTEL]",
            "grc": "[GRC]",
            "incident_response": "[IR]",
            "security_awareness": "[AWARENESS]",
        }

        label = label_map.get(team, "[TEAM]")

        return f"""# {label} {team_name} Field Manual

> **Document Type**: Comprehensive Operational Field Manual
> **Classification**: Internal Use Only - Security Sensitive
> **Version**: 2.0 (AI-Enhanced)
> **Quality Level**: {quality.value.title()}
> **Generated**: {datetime.now().isoformat()}
> **Generator**: ThreatSimGPT AI-Enhanced Playbook System

---

## Executive Summary

This field manual provides comprehensive operational guidance for {team_name}
operations in response to **{context.scenario_name}** ({context.threat_type}).

**Key Details:**
- **MITRE ATT&CK Coverage**: {', '.join(context.mitre_techniques)}
- **Industry Context**: {context.industry}
- **Organization Size**: {context.organization_size}
- **Threat Difficulty**: {context.difficulty_level}/10

---

## Document Information

| Field | Value |
|-------|-------|
| **Target Team** | {team_name} |
| **Scenario** | {context.scenario_name} |
| **Threat Type** | {context.threat_type} |
| **MITRE Techniques** | {', '.join(context.mitre_techniques)} |
| **Industry** | {context.industry} |
| **Organization Size** | {context.organization_size} |
| **Compliance Frameworks** | {', '.join(context.compliance_frameworks) if context.compliance_frameworks else 'General'} |
| **Difficulty Level** | {context.difficulty_level}/10 |

---

{content}

---

## Appendix A: MITRE ATT&CK Reference

| Technique ID | Description | Mitigation |
|--------------|-------------|------------|
{self._generate_mitre_table(context.mitre_techniques)}

---

## Appendix B: Related Resources

### Industry Frameworks
- MITRE ATT&CK Framework: https://attack.mitre.org/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- CIS Controls v8: https://www.cisecurity.org/controls
- ISO 27001:2022: https://www.iso.org/standard/27001

### Threat Intelligence
- CISA Alerts: https://www.cisa.gov/news-events/cybersecurity-advisories
- US-CERT: https://www.us-cert.gov/
- MITRE CVE: https://cve.mitre.org/

### Tools & Resources
- Sigma Rules: https://github.com/SigmaHQ/sigma
- YARA Rules: https://github.com/Yara-Rules/rules
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team

---

## Appendix C: Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 2.0 | {datetime.now().strftime('%Y-%m-%d')} | ThreatSimGPT AI | AI-enhanced generation |
| 1.0 | {datetime.now().strftime('%Y-%m-%d')} | ThreatSimGPT | Initial template |

---

## Appendix D: Feedback & Improvement

This manual is continuously improved through:
1. Simulation feedback integration
2. Incident lessons learned
3. Industry threat intelligence updates
4. Team operational feedback

To contribute improvements, document findings in the knowledge base.

---

*This field manual was generated by ThreatSimGPT's AI-Enhanced Playbook System.*
*Content is based on current threat intelligence and industry best practices.*
*Review and customize for your organization's specific requirements.*
"""

    def _generate_mitre_table(self, techniques: List[str]) -> str:
        """Generate MITRE ATT&CK reference table."""
        mitre_data = {
            "T1566": ("Phishing", "User Training, Email Filtering"),
            "T1566.001": ("Spearphishing Attachment", "Antivirus, User Training, Sandboxing"),
            "T1566.002": ("Spearphishing Link", "URL Filtering, User Training, Web Proxy"),
            "T1598": ("Phishing for Information", "User Training, MFA"),
            "T1598.001": ("Spearphishing Service", "User Training, Verification Procedures"),
            "T1534": ("Internal Spearphishing", "Network Segmentation, Email Security"),
            "T1583.001": ("Acquire Infrastructure: Domains", "Domain Monitoring, Threat Intel"),
        }

        rows = []
        for tech in techniques:
            if tech in mitre_data:
                name, mitigation = mitre_data[tech]
                rows.append(f"| {tech} | {name} | {mitigation} |")
            else:
                rows.append(f"| {tech} | See attack.mitre.org | Review framework |")

        return "\n".join(rows) if rows else "| N/A | No techniques specified | N/A |"

    def _get_cached_manual(self, team: str, context: PlaybookContext) -> Optional[str]:
        """Check for cached manual."""
        cache_key = f"{context.threat_type}_{context.difficulty_level}"
        cache_file = self.playbook_cache_dir / team / f"{cache_key}.md"

        if cache_file.exists():
            # Check if cache is recent (within 7 days)
            age = datetime.now().timestamp() - cache_file.stat().st_mtime
            if age < 7 * 24 * 60 * 60:  # 7 days in seconds
                return cache_file.read_text()

        return None

    def _cache_manual(self, team: str, context: PlaybookContext, content: str):
        """Cache generated manual."""
        cache_key = f"{context.threat_type}_{context.difficulty_level}"
        cache_file = self.playbook_cache_dir / team / f"{cache_key}.md"
        cache_file.write_text(content)

    def _update_knowledge_base(self, team: str, context: PlaybookContext, content: str):
        """Update the knowledge base with new insights."""
        kb_file = self.knowledge_base_dir / f"{team}_knowledge.json"

        # Load existing knowledge base
        if kb_file.exists():
            kb = json.loads(kb_file.read_text())
        else:
            kb = {"entries": [], "last_updated": None}

        # Add new entry
        kb["entries"].append({
            "scenario": context.scenario_name,
            "threat_type": context.threat_type,
            "mitre_techniques": context.mitre_techniques,
            "timestamp": datetime.now().isoformat(),
            "content_hash": hash(content),
        })

        # Keep only last 100 entries
        kb["entries"] = kb["entries"][-100:]
        kb["last_updated"] = datetime.now().isoformat()

        # Save
        kb_file.write_text(json.dumps(kb, indent=2))

    def get_improvement_suggestions(self, team: str) -> List[str]:
        """Get suggestions for improving team playbooks based on knowledge base."""
        kb_file = self.knowledge_base_dir / f"{team}_knowledge.json"

        if not kb_file.exists():
            return ["No historical data available. Run more simulations to gather insights."]

        kb = json.loads(kb_file.read_text())

        # Analyze patterns
        threat_types = {}
        for entry in kb["entries"]:
            tt = entry["threat_type"]
            threat_types[tt] = threat_types.get(tt, 0) + 1

        suggestions = []

        # Suggest based on frequency
        if threat_types:
            most_common = max(threat_types, key=threat_types.get)
            suggestions.append(
                f"Consider enhancing {most_common} coverage - it's your most frequent threat type "
                f"({threat_types[most_common]} simulations)"
            )

        # Suggest based on recency
        if kb["entries"]:
            latest = kb["entries"][-1]
            suggestions.append(
                f"Latest simulation: {latest['scenario']} - Review for new insights"
            )

        return suggestions


# Global instance
ai_playbook_generator = AIEnhancedPlaybookGenerator()


def generate_ai_enhanced_manual(
    team: str,
    scenario_name: str,
    threat_type: str,
    mitre_techniques: List[str] = None,
    difficulty_level: int = 5,
    industry: str = "general",
    organization_size: str = "enterprise",
    compliance_frameworks: List[str] = None,
) -> str:
    """Convenience function to generate an AI-enhanced field manual.

    Args:
        team: Target team (blue_team, red_team, etc.)
        scenario_name: Name of the threat scenario
        threat_type: Type of threat
        mitre_techniques: MITRE ATT&CK technique IDs
        difficulty_level: Scenario difficulty (1-10)
        industry: Target industry
        organization_size: Organization size category
        compliance_frameworks: Applicable compliance frameworks

    Returns:
        Comprehensive field manual as markdown
    """
    context = PlaybookContext(
        scenario_name=scenario_name,
        threat_type=threat_type,
        mitre_techniques=mitre_techniques or [],
        difficulty_level=difficulty_level,
        industry=industry,
        organization_size=organization_size,
        compliance_frameworks=compliance_frameworks or [],
    )

    return ai_playbook_generator.generate_field_manual_sync(team, context)


def generate_all_ai_enhanced_manuals(
    scenario_name: str,
    threat_type: str,
    mitre_techniques: List[str] = None,
    difficulty_level: int = 5,
    industry: str = "general",
    organization_size: str = "enterprise",
    compliance_frameworks: List[str] = None,
) -> Dict[str, str]:
    """Generate AI-enhanced field manuals for all security teams.

    Returns:
        Dictionary of team -> field manual content
    """
    context = PlaybookContext(
        scenario_name=scenario_name,
        threat_type=threat_type,
        mitre_techniques=mitre_techniques or [],
        difficulty_level=difficulty_level,
        industry=industry,
        organization_size=organization_size,
        compliance_frameworks=compliance_frameworks or [],
    )

    manuals = {}
    for team in TEAM_PROMPTS.keys():
        manuals[team] = ai_playbook_generator.generate_field_manual_sync(team, context)

    return manuals
