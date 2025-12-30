"""Enhanced Prompt Engineering System for ThreatSimGPT.

This module implements production-grade prompt templates for all content types,
following industry best practices from OpenAI, Anthropic, and Google research.

Key Features:
- Chain-of-Thought (CoT) reasoning
- Few-shot learning with dynamic examples
- Role-based system prompts
- Constraint-based generation
- Quality metrics and validation
- Content-type specific optimization
"""

import logging
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class ContentType(str, Enum):
    """Content types for threat simulation."""
    EMAIL = "email"
    SMS = "sms"
    PHONE_SCRIPT = "phone_script"
    DOCUMENT = "document"
    WEB_PAGE = "web_page"
    SOCIAL_POST = "social_post"
    MALWARE_SAMPLE = "malware_sample"
    OTHER = "other"


class ThreatType(str, Enum):
    """Threat scenario types."""
    PHISHING = "phishing"
    SPEAR_PHISHING = "spear_phishing"
    SMS_PHISHING = "sms_phishing"
    VISHING = "vishing"
    BEC = "business_email_compromise"
    SOCIAL_ENGINEERING = "social_engineering"
    PRETEXTING = "pretexting"
    WATERING_HOLE = "watering_hole"
    GENERIC = "generic"


@dataclass
class PromptContext:
    """Context information for prompt generation."""
    # Target profile
    target_role: str
    target_department: str
    seniority_level: str
    technical_level: str
    security_awareness: int  # 1-10
    industry: str

    # Scenario details
    threat_type: str
    attack_vector: str
    difficulty_level: int  # 1-10
    urgency_level: int  # 1-10
    scenario_name: str
    scenario_description: str

    # Content specifications
    content_type: str
    tone: str = "professional"
    max_length: int = 500
    language: str = "English"

    # Optional context
    company_name: Optional[str] = None
    mitre_techniques: Optional[List[str]] = None
    additional_context: Optional[Dict[str, Any]] = None


class EnhancedPromptEngine:
    """Production-grade prompt engineering system."""

    def __init__(self):
        """Initialize the enhanced prompt engine."""
        self.system_prompts = self._initialize_system_prompts()
        self.few_shot_examples = self._initialize_examples()
        logger.info("Enhanced Prompt Engine initialized")

    def generate_prompt(self, context: PromptContext) -> str:
        """Generate optimized prompt for given context.

        Args:
            context: Prompt context with target and scenario details

        Returns:
            Fully constructed prompt with CoT, few-shot, and constraints
        """
        # Select appropriate system prompt
        system_prompt = self._get_system_prompt(context.content_type)

        # Build context section
        context_section = self._build_context_section(context)

        # Add Chain-of-Thought guidance
        cot_section = self._build_cot_section(context)

        # Add few-shot examples
        examples_section = self._build_examples_section(context)

        # Add requirements and constraints
        requirements_section = self._build_requirements_section(context)

        # Add output specification
        output_section = self._build_output_specification(context)

        # Combine all sections
        full_prompt = f"""{system_prompt}

{context_section}

{cot_section}

{examples_section}

{requirements_section}

{output_section}
"""

        logger.debug(f"Generated prompt for {context.content_type} ({len(full_prompt)} chars)")
        return full_prompt

    def _initialize_system_prompts(self) -> Dict[str, str]:
        """Initialize expert system prompts for each content type."""
        return {
            ContentType.EMAIL: """You are an expert cybersecurity researcher specializing in email-based threat scenarios with 15+ years of experience in red team operations and security awareness training for Fortune 500 companies.

Your expertise includes:
- Advanced phishing and spear-phishing tactics
- Business Email Compromise (BEC) techniques
- Email social engineering psychology
- Industry-specific communication patterns
- MITRE ATT&CK techniques (T1566.001, T1566.002)

You create realistic training materials that help security professionals recognize and respond to email-based threats while maintaining strict safety and ethical guidelines.""",

            ContentType.SMS: """You are a mobile security specialist focusing on SMS-based social engineering attacks (smishing) with deep expertise in:
- Mobile threat vectors and attack patterns
- SMS phishing psychology and urgency tactics
- Mobile device user behavior and vulnerabilities
- Telecommunication security awareness training
- MITRE ATT&CK mobile techniques

You craft realistic SMS scenarios for security training and awareness testing.""",

            ContentType.PHONE_SCRIPT: """You are a social engineering expert specializing in voice-based attacks (vishing) and pretexting with extensive experience in:
- Voice-based social engineering tactics
- Real-time conversation manipulation
- Authority and trust-building techniques
- Call center impersonation methods
- Objection handling and persuasion
- MITRE ATT&CK techniques (T1598)

You design comprehensive phone scripts that teach security teams to recognize and defend against voice-based threats through realistic training scenarios.""",

            ContentType.DOCUMENT: """You are a document-based threat analyst specializing in malicious attachments and weaponized files with expertise in:
- Macro-based attacks and document exploits
- PDF and Office document threats
- Form-based credential harvesting
- File metadata manipulation
- Document-based social engineering
- MITRE ATT&CK techniques (T1566.001, T1204)

You create detailed document-based attack scenarios that demonstrate realistic threats while providing clear educational value for security training.""",

            ContentType.WEB_PAGE: """You are a web-based threat specialist focusing on phishing sites, fake portals, and malicious web pages with deep knowledge of:
- Phishing site design and hosting
- Brand impersonation techniques
- Credential harvesting pages
- Drive-by download scenarios
- Web-based social engineering
- MITRE ATT&CK techniques (T1566.002, T1189)

You design realistic fake web page scenarios that help train users to identify spoofed sites and credential theft attempts.""",

            ContentType.SOCIAL_POST: """You are a social media threat analyst specializing in social engineering through social platforms with expertise in:
- Social media reconnaissance (OSINT)
- Fake profile creation and trust-building
- Social platform-specific attack vectors
- Viral spreading and influence campaigns
- Personal information exploitation
- MITRE ATT&CK techniques (T1593, T1598.001)

You create realistic social media-based threat scenarios for security awareness training.""",
        }

    def _get_system_prompt(self, content_type: str) -> str:
        """Get appropriate system prompt for content type."""
        return self.system_prompts.get(
            content_type,
            "You are a cybersecurity expert creating realistic threat simulation training materials."
        )

    def _build_context_section(self, context: PromptContext) -> str:
        """Build the context section of the prompt."""
        return f"""### MISSION
Generate a realistic {context.content_type} demonstrating {context.threat_type} tactics for security awareness training.

### TARGET PROFILE
- **Role**: {context.target_role}
- **Department**: {context.target_department}
- **Seniority**: {context.seniority_level}
- **Technical Level**: {context.technical_level}
- **Security Awareness**: {context.security_awareness}/10
- **Industry**: {context.industry}

### SCENARIO CONTEXT
- **Threat Type**: {context.threat_type}
- **Attack Vector**: {context.attack_vector}
- **Difficulty Level**: {context.difficulty_level}/10
- **Urgency Level**: {context.urgency_level}/10
- **Scenario**: {context.scenario_name}
- **Description**: {context.scenario_description}
{self._format_mitre_techniques(context.mitre_techniques) if context.mitre_techniques else ""}"""

    def _format_mitre_techniques(self, techniques: List[str]) -> str:
        """Format MITRE ATT&CK techniques."""
        if not techniques:
            return ""
        return f"- **MITRE ATT&CK**: {', '.join(techniques)}"

    def _build_cot_section(self, context: PromptContext) -> str:
        """Build Chain-of-Thought reasoning section."""
        return f"""### CHAIN-OF-THOUGHT ANALYSIS

Before generating the final content, think step-by-step through this scenario:

**Step 1: Target Psychology Analysis**
- What does a {context.target_role} in {context.target_department} worry about daily?
- What requests seem legitimate in their typical workflow?
- What consequences motivate immediate action for this role?
- How does technical level {context.technical_level} affect their security behavior?
- Given security awareness {context.security_awareness}/10, what sophistication is needed?

**Step 2: Attack Strategy Selection**
- For {context.threat_type}, what social engineering tactics are most effective?
- What authority figures does a {context.target_role} trust?
- How can we create urgency level {context.urgency_level}/10 believably?
- What pretext makes sense in the {context.industry} industry?
- What timing and context create natural pressure?

**Step 3: Realism Engineering**
- What terminology is standard in {context.industry}?
- What communication patterns does {context.target_department} use?
- What processes would {context.target_role} find familiar?
- What technical details add authenticity without over-complexity?
- How can we match the sophistication of difficulty level {context.difficulty_level}/10?

**Step 4: Red Flag Calibration**
- For difficulty {context.difficulty_level}/10, how subtle should warnings be?
- What would someone with security awareness {context.security_awareness}/10 notice?
- Where should detection points be placed for training value?
- How can we balance realism with detectability?
- What indicators should trained security professionals recognize?

**Step 5: Educational Value Optimization**
- What specific security concepts does this scenario teach?
- How can we make the learning objectives clear?
- What detection skills should trainees develop?
- Which MITRE ATT&CK techniques does this demonstrate?
- What real-world threat does this represent?

Now, based on this systematic analysis, generate the {context.content_type}:"""

    def _build_examples_section(self, context: PromptContext) -> str:
        """Build few-shot examples section."""
        examples = self._get_relevant_examples(context)

        if not examples:
            return ""

        examples_text = "### FEW-SHOT EXAMPLES\n\n"
        examples_text += "Here are examples of high-quality outputs for similar scenarios:\n\n"

        for i, example in enumerate(examples, 1):
            examples_text += f"**Example {i}:** {example['title']}\n"
            examples_text += f"```\n{example['content']}\n```\n"
            examples_text += f"*Quality Metrics: Realism {example['realism']}/10, "
            examples_text += f"Effectiveness {example['effectiveness']}/10*\n\n"

        return examples_text

    def _get_relevant_examples(self, context: PromptContext) -> List[Dict[str, Any]]:
        """Get relevant few-shot examples for context."""
        # Return curated example based on content type
        # (Database query implementation pending)

        if context.content_type == ContentType.EMAIL:
            return [{
                'title': f"Professional Email for {context.target_role}",
                'content': self._get_email_example(context),
                'realism': 9,
                'effectiveness': 8
            }]
        elif context.content_type == ContentType.SMS:
            return [{
                'title': f"Mobile SMS for {context.target_role}",
                'content': self._get_sms_example(context),
                'realism': 8,
                'effectiveness': 9
            }]

        return []

    def _get_email_example(self, context: PromptContext) -> str:
        """Get email example based on context."""
        if "executive" in context.target_role.lower() or "ceo" in context.target_role.lower():
            return """Subject: URGENT: Q4 Board Meeting Materials - Review Required

From: Board Secretary <board.secretary@boardportal.example.com>
To: ceo@company.example.com

Dear [CEO Name],

The Board of Directors has finalized the Q4 strategic review materials for tomorrow's executive session. Per governance protocols, all C-suite executives must review and digitally acknowledge receipt by 5:00 PM today.

Access your board packet: https://secure-boardportal.example.com/q4-materials

This link expires in 4 hours for security compliance.

Best regards,
Eleanor Vance
Board Secretary"""
        else:
            return """Subject: IT Security Update Required - Action Needed Today

From: IT Security <security@company-it.example.com>
To: employee@company.example.com

Dear Team Member,

We've detected unusual activity on your account and need you to verify your credentials as part of our enhanced security protocol.

Please complete verification within 2 hours:
https://secure-verify.example.com/auth

Failure to verify may result in temporary account suspension.

IT Security Team"""

    def _get_sms_example(self, context: PromptContext) -> str:
        """Get SMS example based on context."""
        return """[IT-Security]
URGENT: Your account shows suspicious login from unknown location at 3:42 AM.
If this wasn't you, verify immediately:
secure-verify.example.com/IT-8472
Action required within 1 hour."""

    def _build_requirements_section(self, context: PromptContext) -> str:
        """Build requirements and constraints section."""
        content_reqs = self._get_content_specific_requirements(context)

        return f"""### REQUIREMENTS

**Content Specifications:**
{content_reqs}

**Realism Requirements:**
- Match communication patterns typical in {context.industry}
- Use terminology familiar to {context.target_department}
- Reflect sophistication appropriate for difficulty level {context.difficulty_level}/10
- Include psychological triggers effective for {context.target_role}
- Maintain {context.tone} tone throughout
- Keep length within {context.max_length} words

**Educational Requirements:**
- Include detectable red flags calibrated to difficulty level
- Provide clear training value
- Demonstrate real-world attack patterns
- Enable skill development for security awareness
- Support learning objectives for threat recognition

### SAFETY CONSTRAINTS (MANDATORY)
-  NO actual malicious code, exploits, or malware
-  NO real company names, domains, or identifiable information
-  ALL URLs must use example.com domains
-  ALL data must be fictional but realistic
-  ALL content must include educational markers
-  Content must serve legitimate security training purposes"""

    def _get_content_specific_requirements(self, context: PromptContext) -> str:
        """Get requirements specific to content type."""
        requirements_map = {
            ContentType.EMAIL: """- Subject line with appropriate urgency
- From/To headers with realistic addresses
- Email body with proper formatting and structure
- Professional signature block
- Relevant call-to-action
- Fake but realistic URLs (example.com)""",

            ContentType.SMS: """- Sender ID or phone number display
- Message length: 120-250 characters
- Mobile-appropriate language and formatting
- Clear call-to-action
- Shortened URL format (bit.example.com style)
- Mobile urgency tactics""",

            ContentType.PHONE_SCRIPT: """- Complete conversation script with caller and target lines
- Opening, rapport-building, and closing sections
- Objection handling branches
- Background context for caller
- Success metrics and objectives
- Realistic conversation flow""",

            ContentType.DOCUMENT: """- Document type and file format
- Visual content description
- Metadata (filename, author, date)
- Malicious element description (educational, not implemented)
- Attack flow explanation
- Professional document formatting"""
        }

        return requirements_map.get(
            context.content_type,
            "- Content appropriate for threat type\n- Clear structure and formatting\n- Realistic details"
        )

    def _build_output_specification(self, context: PromptContext) -> str:
        """Build output format specification."""
        format_spec = self._get_output_format(context.content_type)

        return f"""### OUTPUT SPECIFICATION

Generate the content in this exact format:

{format_spec}

### QUALITY CHECKLIST

Before finalizing, verify your output includes:
- [ ] Realistic for {context.industry} and {context.target_role}
- [ ] Appropriate sophistication for difficulty {context.difficulty_level}/10
- [ ] Urgency matches level {context.urgency_level}/10
- [ ] Psychological triggers suit target profile
- [ ] Grammar/style matches difficulty and target
- [ ] All URLs use example.com domains
- [ ] Red flags present and calibrated correctly
- [ ] Professional formatting maintained
- [ ] Educational analysis provides training value
- [ ] Safety constraints followed completely"""

    def _get_output_format(self, content_type: str) -> str:
        """Get output format specification for content type."""
        formats = {
            ContentType.EMAIL: """```
---
METADATA:
- Content Type: Email ({threat_type})
- Difficulty: {difficulty}/10
- Target: {target_role}
---

Subject: [Specific subject line]

From: [Sender Name] <[sender@example.com]>
To: {target_role} <[target@company.example.com]>
Date: [Realistic date/time]

[Email body with proper formatting and paragraphs]

[Professional signature]

---
TRAINING ANALYSIS:

Red Flags Present:
1. [Flag 1] - Detection Difficulty: [1-10]
2. [Flag 2] - Detection Difficulty: [1-10]
3. [Flag 3] - Detection Difficulty: [1-10]

Social Engineering Tactics:
- [Tactic 1]: [How it's employed]
- [Tactic 2]: [How it's employed]

Learning Objectives:
- [What trainees should learn]
- [Detection skills to develop]

Real-World Context:
- [Similar real attacks]
- [Industry-specific relevance]
```""",

            ContentType.SMS: """```
---
METADATA:
- Content Type: SMS Phishing (Smishing)
- Sender: [Display name or number]
- Characters: [Count]
- Difficulty: {difficulty}/10
---

FROM: [Sender Name/Number]
TIME: [Timestamp]

[SMS message content]
[120-250 characters]
[URL: short-url.example.com]

---
TRAINING ANALYSIS:

Red Flags:
1. [Mobile-specific indicator]
2. [Domain/URL issue]
3. [Context/timing issue]

Mobile Attack Techniques:
- [Technique 1 with explanation]
- [Technique 2 with explanation]

Detection Tips:
- [How to verify on mobile]
- [What to check]
```""",

            ContentType.PHONE_SCRIPT: """```
---
METADATA:
- Content Type: Phone Script (Vishing)
- Caller Pretext: [Role]
- Duration: [Minutes]
- Difficulty: {difficulty}/10
---

SCENARIO: [Brief setup]

CALLER PREP:
- Spoofed Caller ID: [Number]
- Background: [Office/Call center]
- Insider Knowledge: [What caller knows]

--- SCRIPT ---

[Complete conversation with caller and target lines]
[Include multiple exchanges]
[Show objection handling branches]

---
TRAINING ANALYSIS:

Red Flags:
1. [Vocal/behavioral flag]
2. [Process violation]
3. [Information request flag]

Social Engineering:
- Authority: [How established]
- Urgency: [How created]
- Trust: [How built]

Proper Response:
1. [What target should do]
2. [Verification method]
3. [Escalation procedure]
```"""
        }

        return formats.get(content_type, "Generate appropriate content based on requirements.")

    def _initialize_examples(self) -> Dict[str, List[Dict]]:
        """Initialize few-shot example library."""
        # Return empty dict; examples are generated dynamically
        # (Database loading to be implemented)
        return {}


# Convenience function for quick prompt generation
def generate_threat_prompt(
    target_role: str,
    threat_type: str,
    content_type: str,
    difficulty: int = 5,
    **kwargs
) -> str:
    """Quick prompt generation with sensible defaults.

    Args:
        target_role: Role of the target (e.g., "CEO", "Accountant")
        threat_type: Type of threat (e.g., "phishing", "vishing")
        content_type: Content to generate (e.g., "email", "sms")
        difficulty: Difficulty level 1-10
        **kwargs: Additional context parameters

    Returns:
        Generated prompt ready for LLM
    """
    context = PromptContext(
        target_role=target_role,
        target_department=kwargs.get('department', 'general'),
        seniority_level=kwargs.get('seniority', 'mid'),
        technical_level=kwargs.get('technical_level', 'moderate'),
        security_awareness=kwargs.get('security_awareness', 5),
        industry=kwargs.get('industry', 'technology'),
        threat_type=threat_type,
        attack_vector=kwargs.get('attack_vector', 'email'),
        difficulty_level=difficulty,
        urgency_level=kwargs.get('urgency', 5),
        scenario_name=kwargs.get('scenario_name', f'{threat_type.title()} Attack'),
        scenario_description=kwargs.get('description', f'Simulated {threat_type} attack scenario'),
        content_type=content_type,
        tone=kwargs.get('tone', 'professional'),
        company_name=kwargs.get('company_name'),
        mitre_techniques=kwargs.get('mitre_techniques')
    )

    engine = EnhancedPromptEngine()
    return engine.generate_prompt(context)


if __name__ == "__main__":
    # Test the prompt engine
    logging.basicConfig(level=logging.INFO)

    test_context = PromptContext(
        target_role="Chief Financial Officer",
        target_department="executive",
        seniority_level="senior",
        technical_level="moderate",
        security_awareness=6,
        industry="finance",
        threat_type="business_email_compromise",
        attack_vector="email",
        difficulty_level=8,
        urgency_level=7,
        scenario_name="Executive Wire Transfer Fraud",
        scenario_description="BEC attack targeting CFO with urgent wire transfer request",
        content_type="email",
        tone="professional",
        company_name="Example Financial Corp",
        mitre_techniques=["T1566.001", "T1534"]
    )

    engine = EnhancedPromptEngine()
    prompt = engine.generate_prompt(test_context)

    print("="*80)
    print("GENERATED PROMPT:")
    print("="*80)
    print(prompt)
    print("="*80)
    print(f"Prompt length: {len(prompt)} characters")
