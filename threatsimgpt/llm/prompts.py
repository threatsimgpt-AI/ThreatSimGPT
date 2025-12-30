"""Advanced prompt engineering framework for ThreatSimGPT.

This module provides sophisticated prompt templates, context injection,
and content generation strategies for various threat simulation scenarios.
"""

import json
import re
from typing import Any, Dict, List, Optional

from .models import ContentType, PromptContext, PromptTemplate


class PromptTemplateLibrary:
    """Library of prompt templates for different threat scenarios."""

    EMAIL_PHISHING_TEMPLATE = PromptTemplate(
        name="email_phishing_v1",
        content_type=ContentType.EMAIL_PHISHING,
        system_prompt="""You are a cybersecurity professional creating realistic phishing email content for authorized security awareness training and penetration testing. This content will be used in controlled environments to educate employees about social engineering tactics.

Your goal is to create convincing but educational phishing emails that demonstrate real-world attack patterns while maintaining ethical boundaries. The content should be realistic enough to serve as effective training material but clearly marked for educational purposes.

Key principles:
1. Create realistic social engineering content for training purposes
2. Include subtle indicators that trained security professionals would recognize
3. Focus on psychological triggers and urgency tactics used by real attackers
4. Ensure content is appropriate for corporate security training environments
5. Include educational elements that help recipients learn to identify threats

Remember: This is for authorized security training only. All content will be clearly marked as simulated and used in controlled educational environments.""",
        user_prompt_template="""Create a phishing email for security training with the following parameters:

Target Profile:
- Role: {target_role}
- Department: {target_department}
- Seniority: {target_seniority}
- Technical Level: {target_technical_level}
- Security Awareness: {security_awareness_level}/10

Scenario Context:
- Threat Type: {threat_type}
- Delivery Vector: {delivery_vector}
- Difficulty Level: {difficulty_level}/10
- Urgency Level: {urgency_level}/10
- Tone: {tone}

Psychological Triggers: {psychological_triggers}
Social Engineering Tactics: {social_engineering_tactics}

Company Context: {company_name}
Additional Context: {custom_context}

Create a realistic phishing email that includes:
1. Appropriate subject line
2. Sender information (realistic but fictitious)
3. Email body with social engineering elements
4. Call-to-action (link, attachment, or reply request)
5. Professional formatting appropriate for the target's level

The email should demonstrate common phishing techniques while being appropriate for corporate security training. Include subtle red flags that security-aware employees might notice.

Format your response as:
Subject: [subject line]
From: [sender name and email]
To: [target placeholder]

[Email body content]

---
Training Notes: [Brief explanation of techniques used]""",
        variables=[
            "target_role", "target_department", "target_seniority", "target_technical_level",
            "security_awareness_level", "threat_type", "delivery_vector", "difficulty_level",
            "urgency_level", "tone", "psychological_triggers", "social_engineering_tactics",
            "company_name", "custom_context"
        ],
        constraints=[
            "Content must be appropriate for corporate security training",
            "Include educational elements and red flags",
            "Avoid harmful or offensive content",
            "Maintain realistic but ethical approach",
            "Include clear training context markers"
        ]
    )

    SMS_PHISHING_TEMPLATE = PromptTemplate(
        name="sms_phishing_v1",
        content_type=ContentType.SMS_PHISHING,
        system_prompt="""You are a cybersecurity professional creating realistic SMS phishing content for authorized security awareness training. This content will be used to educate employees about mobile-based social engineering attacks.

Create convincing SMS phishing messages that demonstrate real attack patterns while maintaining educational value. The messages should be realistic enough for effective training but appropriate for corporate security programs.

Focus on:
1. Common SMS phishing tactics (urgency, authority, fear)
2. Mobile-specific attack vectors (links, apps, verification codes)
3. Psychological manipulation techniques used by attackers
4. Realistic but safe content for training environments
5. Educational red flags that recipients should recognize

All content is for authorized security training in controlled environments.""",
        user_prompt_template="""Create an SMS phishing message for security training:

Target Profile:
- Role: {target_role}
- Technical Level: {target_technical_level}
- Security Awareness: {security_awareness_level}/10

Scenario:
- Threat Type: {threat_type}
- Difficulty: {difficulty_level}/10
- Urgency: {urgency_level}/10

Tactics: {social_engineering_tactics}
Triggers: {psychological_triggers}
Company: {company_name}

Create a realistic SMS that includes:
1. Appropriate sender (number or name)
2. Compelling message content
3. Call-to-action (link, reply, call)
4. Urgency or authority elements

Keep it concise (under 160 characters for realism) and include common SMS phishing patterns.

Format:
From: [sender]
Message: [SMS content]

Training Notes: [Brief explanation of techniques]""",
        variables=[
            "target_role", "target_technical_level", "security_awareness_level",
            "threat_type", "difficulty_level", "urgency_level", "social_engineering_tactics",
            "psychological_triggers", "company_name"
        ],
        constraints=[
            "Keep message under 160 characters when possible",
            "Include realistic mobile attack patterns",
            "Appropriate for corporate training",
            "Educational red flags included"
        ]
    )

    VOICE_SCRIPT_TEMPLATE = PromptTemplate(
        name="voice_script_v1",
        content_type=ContentType.VOICE_SCRIPT,
        system_prompt="""You are creating voice-based social engineering scripts for authorized security training. These scripts will be used by security professionals to conduct controlled vishing (voice phishing) simulations.

Create realistic conversation scripts that demonstrate how attackers use voice communication to manipulate targets. The scripts should be educational, showing common vishing techniques while maintaining ethical boundaries.

Focus on:
1. Realistic conversation flow and dialogue
2. Social engineering tactics specific to voice calls
3. Psychological manipulation through tone and urgency
4. Common pretext scenarios used by attackers
5. Educational elements for security awareness training

All scripts are for authorized security training purposes in controlled environments.""",
        user_prompt_template="""Create a vishing script for security training:

Target Profile:
- Role: {target_role}
- Department: {target_department}
- Seniority: {target_seniority}
- Technical Level: {target_technical_level}

Scenario:
- Threat Type: {threat_type}
- Pretext: {custom_context}
- Difficulty: {difficulty_level}/10
- Urgency: {urgency_level}/10

Tactics: {social_engineering_tactics}
Triggers: {psychological_triggers}

Create a realistic vishing script including:
1. Opening/introduction
2. Pretext establishment
3. Information gathering questions
4. Urgency/pressure tactics
5. Closing/next steps

Format as a conversation script with caller directions.

Script:
[Detailed conversation flow]

Training Notes: [Techniques and red flags to discuss]""",
        variables=[
            "target_role", "target_department", "target_seniority", "target_technical_level",
            "threat_type", "custom_context", "difficulty_level", "urgency_level",
            "social_engineering_tactics", "psychological_triggers"
        ],
        constraints=[
            "Realistic conversation flow",
            "Educational and ethical content",
            "Include training discussion points",
            "Appropriate for corporate security training"
        ]
    )

    PRETEXT_SCENARIO_TEMPLATE = PromptTemplate(
        name="pretext_scenario_v1",
        content_type=ContentType.PRETEXT_SCENARIO,
        system_prompt="""You are developing pretext scenarios for authorized social engineering training. These scenarios provide realistic backgrounds and storylines that security professionals can use during controlled penetration testing exercises.

Create detailed pretext scenarios that demonstrate how attackers build convincing backstories to manipulate targets. Focus on realistic business contexts, authority relationships, and urgent situations that attackers commonly exploit.

The scenarios should be:
1. Believable and well-researched
2. Appropriate for corporate environments
3. Educational about common attack patterns
4. Usable in controlled security testing
5. Include realistic details and supporting elements

All scenarios are for authorized security training and testing purposes.""",
        user_prompt_template="""Create a pretext scenario for security training:

Target Profile:
- Role: {target_role}
- Department: {target_department}
- Company: {company_name}
- Industry: {target_industry}

Scenario Parameters:
- Threat Type: {threat_type}
- Delivery Vector: {delivery_vector}
- Difficulty: {difficulty_level}/10
- Context: {custom_context}

Social Engineering Elements:
- Tactics: {social_engineering_tactics}
- Psychological Triggers: {psychological_triggers}
- MITRE Techniques: {mitre_techniques}

Create a detailed pretext scenario including:

1. Background Story:
   - Who the attacker is pretending to be
   - Relationship to target/organization
   - Reason for contact

2. Supporting Details:
   - Specific information to make story believable
   - Authority/urgency elements
   - Technical or business context

3. Execution Plan:
   - Contact method and timing
   - Information to gather
   - Escalation strategies

4. Props/Resources Needed:
   - Documentation or credentials
   - Technical setup requirements
   - Supporting materials

Training Value: Explain what security concepts this scenario teaches and what red flags defenders should watch for.""",
        variables=[
            "target_role", "target_department", "company_name", "target_industry",
            "threat_type", "delivery_vector", "difficulty_level", "custom_context",
            "social_engineering_tactics", "psychological_triggers", "mitre_techniques"
        ],
        constraints=[
            "Detailed and realistic scenarios",
            "Include supporting materials list",
            "Educational value clearly explained",
            "Appropriate for professional security training"
        ]
    )


class PromptContextBuilder:
    """Builder class for creating rich prompt contexts from scenario data."""

    @staticmethod
    def from_scenario(scenario_data: Dict[str, Any]) -> PromptContext:
        """Build prompt context from threat scenario data."""

        # Extract core scenario information
        metadata = scenario_data.get("metadata", {})
        target = scenario_data.get("target_profile", {})
        behavioral = scenario_data.get("behavioral_patterns", {})

        # Map psychological triggers to human-readable format
        triggers = behavioral.get("psychological_triggers", [])
        trigger_descriptions = []
        for trigger in triggers:
            if hasattr(trigger, 'value'):
                trigger_descriptions.append(trigger.value)
            else:
                trigger_descriptions.append(str(trigger))

        # Map social engineering tactics
        tactics = behavioral.get("social_engineering_tactics", [])
        tactic_descriptions = []
        for tactic in tactics:
            if hasattr(tactic, 'value'):
                tactic_descriptions.append(tactic.value)
            else:
                tactic_descriptions.append(str(tactic))

        # Map MITRE techniques
        mitre_techniques = behavioral.get("mitre_attack_techniques", [])
        mitre_descriptions = []
        for technique in mitre_techniques:
            if hasattr(technique, 'value'):
                mitre_descriptions.append(technique.value)
            else:
                mitre_descriptions.append(str(technique))

        return PromptContext(
            threat_type=str(metadata.get("threat_type", "unknown")),
            delivery_vector=str(metadata.get("delivery_vector", "email")),
            difficulty_level=metadata.get("difficulty_level", 5),
            target_role=target.get("role", "employee"),
            target_department=target.get("department", "general"),
            target_seniority=str(target.get("seniority_level", "mid")),
            target_technical_level=str(target.get("technical_sophistication", "moderate")),
            target_industry=target.get("industry", "technology"),
            security_awareness_level=target.get("security_awareness_level", 5),
            psychological_triggers=trigger_descriptions,
            social_engineering_tactics=tactic_descriptions,
            mitre_techniques=mitre_descriptions,
            urgency_level=behavioral.get("urgency_level", 5),
            tone=behavioral.get("communication_tone", "professional"),
            company_name=target.get("organization", "TechCorp Inc."),
            custom_context=scenario_data.get("custom_context", {})
        )


class PromptEngine:
    """Advanced prompt engineering engine with template management and context injection."""

    def __init__(self):
        self.templates: Dict[str, PromptTemplate] = {}
        self.library = PromptTemplateLibrary()
        self._load_default_templates()

    def _load_default_templates(self):
        """Load default prompt templates."""
        templates = [
            self.library.EMAIL_PHISHING_TEMPLATE,
            self.library.SMS_PHISHING_TEMPLATE,
            self.library.VOICE_SCRIPT_TEMPLATE,
            self.library.PRETEXT_SCENARIO_TEMPLATE,
        ]

        for template in templates:
            self.templates[template.name] = template

    def add_template(self, template: PromptTemplate):
        """Add a custom prompt template."""
        self.templates[template.name] = template

    def get_template(self, content_type: ContentType) -> Optional[PromptTemplate]:
        """Get the best template for a content type."""
        for template in self.templates.values():
            if template.content_type == content_type:
                return template
        return None

    def render_prompt(self, template: PromptTemplate, context: PromptContext) -> Dict[str, str]:
        """Render a prompt template with context variables."""

        # Prepare context variables
        variables = {
            "target_role": context.target_role,
            "target_department": context.target_department,
            "target_seniority": context.target_seniority,
            "target_technical_level": context.target_technical_level,
            "target_industry": context.target_industry or "technology",
            "security_awareness_level": str(context.security_awareness_level),
            "threat_type": context.threat_type,
            "delivery_vector": context.delivery_vector,
            "difficulty_level": str(context.difficulty_level),
            "urgency_level": str(context.urgency_level),
            "tone": context.tone,
            "psychological_triggers": ", ".join(context.psychological_triggers),
            "social_engineering_tactics": ", ".join(context.social_engineering_tactics),
            "mitre_techniques": ", ".join(context.mitre_techniques),
            "company_name": context.company_name or "TechCorp Inc.",
            "custom_context": json.dumps(context.custom_context, indent=2) if context.custom_context else "None specified"
        }

        # Render the user prompt template
        user_prompt = template.user_prompt_template
        for var, value in variables.items():
            placeholder = f"{{{var}}}"
            user_prompt = user_prompt.replace(placeholder, str(value))

        return {
            "system_prompt": template.system_prompt,
            "user_prompt": user_prompt
        }

    def generate_prompts(self, content_type: ContentType, context: PromptContext) -> Dict[str, str]:
        """Generate prompts for a specific content type and context."""
        template = self.get_template(content_type)
        if not template:
            raise ValueError(f"No template found for content type: {content_type}")

        return self.render_prompt(template, context)

    def validate_template(self, template: PromptTemplate) -> List[str]:
        """Validate a prompt template for completeness and correctness."""
        issues = []

        # Check required fields
        if not template.name:
            issues.append("Template name is required")

        if not template.system_prompt:
            issues.append("System prompt is required")

        if not template.user_prompt_template:
            issues.append("User prompt template is required")

        # Check variable consistency
        template_variables = set(re.findall(r'\{(\w+)\}', template.user_prompt_template))
        declared_variables = set(template.variables)

        missing_vars = template_variables - declared_variables
        if missing_vars:
            issues.append(f"Undeclared variables in template: {missing_vars}")

        unused_vars = declared_variables - template_variables
        if unused_vars:
            issues.append(f"Declared but unused variables: {unused_vars}")

        return issues

    def list_templates(self) -> List[Dict[str, Any]]:
        """List all available templates with metadata."""
        return [
            {
                "name": template.name,
                "content_type": template.content_type.value,
                "variable_count": len(template.variables),
                "constraint_count": len(template.constraints),
                "has_examples": len(template.examples) > 0
            }
            for template in self.templates.values()
        ]
