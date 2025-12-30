"""Core threat simulation engine for ThreatSimGPT.

This module provides the main simulation engine that orchestrates threat scenario
execution using LLM providers and validation systems.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional, Any, List, Dict
from uuid import uuid4

from threatsimgpt.core.models import (
    ThreatScenario,
    SimulationResult,
    SimulationStage,
    SimulationStatus
)
from threatsimgpt.llm.enhanced_prompts import generate_threat_prompt, ContentType

logger = logging.getLogger(__name__)


class ThreatSimulator:
    """Core threat simulation engine."""

    def __init__(self, llm_provider: Optional[Any] = None, max_stages: int = 10) -> None:
        """Initialize the threat simulator.

        Args:
            llm_provider: LLM provider instance for content generation
            max_stages: Maximum number of simulation stages to execute
        """
        from threatsimgpt.llm.manager import LLMManager

        self.llm_provider = llm_provider or LLMManager()
        self.max_stages = max_stages
        self._active_simulations: Dict[str, SimulationResult] = {}

    async def execute_simulation(self, scenario: ThreatScenario) -> SimulationResult:
        """Execute a threat simulation scenario.

        Args:
            scenario: The threat scenario to execute

        Returns:
            SimulationResult containing the execution results

        Raises:
            ValueError: If scenario is invalid or missing required data
            RuntimeError: If simulation execution fails
        """
        if not scenario.name:
            raise ValueError("Scenario must have a valid name")

        logger.info(f"Starting simulation for scenario: {scenario.name}")

        # Create simulation result
        result = SimulationResult(
            status=SimulationStatus.RUNNING,
            scenario_id=scenario.scenario_id,
            start_time=datetime.utcnow()
        )

        # Track active simulation
        self._active_simulations[result.result_id] = result

        try:
            # Execute simulation stages
            await self._execute_stages(scenario, result)

            # Mark as completed
            result.mark_completed(success=True)
            logger.info(f"Simulation completed successfully: {scenario.name}")

        except Exception as e:
            logger.error(f"Simulation failed for scenario {scenario.name}: {str(e)}")
            result.mark_completed(success=False, error_message=str(e))

        finally:
            # Remove from active simulations
            self._active_simulations.pop(result.result_id, None)

        return result

    async def _execute_stages(self, scenario: ThreatScenario, result: SimulationResult) -> None:
        """Execute the individual stages of a simulation.

        Args:
            scenario: The threat scenario being executed
            result: The simulation result to update
        """
        # Define basic simulation stages
        stages_config = [
            {"type": "reconnaissance", "description": "Initial target reconnaissance"},
            {"type": "attack_planning", "description": "Plan attack methodology"},
            {"type": "execution", "description": "Execute the threat scenario"},
            {"type": "persistence", "description": "Establish persistence mechanisms"},
            {"type": "data_collection", "description": "Collect target information"},
            {"type": "exfiltration", "description": "Data exfiltration simulation"},
            {"type": "cleanup", "description": "Clean up simulation artifacts"}
        ]

        for i, stage_config in enumerate(stages_config[:self.max_stages]):
            stage_start = datetime.utcnow()

            try:
                # Generate stage content using LLM
                stage_content = await self._generate_stage_content(
                    scenario,
                    stage_config["type"],
                    stage_config["description"]
                )

                # Create simulation stage
                stage = SimulationStage(
                    stage_type=stage_config["type"],
                    content=stage_content,
                    timestamp=stage_start,
                    success=True,
                    metadata={
                        "stage_number": i + 1,
                        "total_stages": len(stages_config),
                        "scenario_name": scenario.name
                    }
                )

                # Calculate duration
                stage_end = datetime.utcnow()
                stage.duration_seconds = (stage_end - stage_start).total_seconds()

                # Add stage to result
                result.add_stage(stage)

                logger.debug(f"Completed stage {i+1}: {stage_config['type']}")

                # Small delay between stages for realism
                await asyncio.sleep(0.1)

            except Exception as e:
                # Create failed stage
                stage = SimulationStage(
                    stage_type=stage_config["type"],
                    content="Stage execution failed",
                    timestamp=stage_start,
                    success=False,
                    error_message=str(e),
                    metadata={"stage_number": i + 1, "error": str(e)}
                )

                result.add_stage(stage)
                logger.warning(f"Stage {i+1} failed: {str(e)}")

                # Continue with next stage unless critical failure
                if "critical" in str(e).lower():
                    break

    async def _generate_stage_content(self, scenario: ThreatScenario, stage_type: str, description: str) -> str:
        """Generate content for a simulation stage using LLM.

        Args:
            scenario: The threat scenario
            stage_type: Type of stage being executed
            description: Description of the stage

        Returns:
            Generated content for the stage
        """
        try:
            # Check if LLM provider is available
            if not self.llm_provider or not self.llm_provider.is_available():
                logger.warning("No LLM provider available, using fallback content")
                return self._generate_fallback_content(scenario, stage_type, description)

            # Create detailed prompt for actual scenario sample generation
            prompt = self._create_scenario_generation_prompt(scenario, stage_type, description)

            # Determine appropriate max_tokens based on content type
            # This prevents truncated content and ensures completeness
            max_tokens_by_type = {
                "email_phishing": 2000,      # Full email with headers and signature
                "sms_phishing": 500,         # Short text messages
                "voice_script": 2000,        # Complete phone conversation script
                "document_lure": 3000,       # Full document content
                "web_page": 2000,            # HTML page content
                "social_media_post": 500,    # Brief social posts
                "chat_message": 500,         # Chat/instant messages
                "pretext_scenario": 1500,    # Scenario descriptions
            }

            # Infer content type from scenario metadata or threat type
            content_type = scenario.metadata.get("content_type", "")
            if not content_type:
                # Infer from threat_type
                threat_str = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)
                if "phishing" in threat_str.lower():
                    content_type = "email_phishing"
                elif "sms" in threat_str.lower():
                    content_type = "sms_phishing"
                elif "social" in threat_str.lower():
                    content_type = "social_media_post"
                elif "vishing" in threat_str.lower() or "voice" in threat_str.lower():
                    content_type = "voice_script"

            # Get appropriate max_tokens (default 1000 if not specified)
            max_tokens = max_tokens_by_type.get(content_type, 1000)

            logger.debug(f"Using max_tokens={max_tokens} for content_type={content_type}")

            # Generate content using LLM manager
            response = await self.llm_provider.generate_content(
                prompt=prompt,
                scenario_type=f"threat_simulation_{stage_type}",
                max_tokens=max_tokens,
                temperature=0.7
            )

            if response and response.content:
                # Check for truncation (finish_reason = 'length')
                finish_reason = getattr(response, 'finish_reason', None)
                if finish_reason == 'length':
                    logger.warning(f"Content truncated for {stage_type} (hit max_tokens={max_tokens})")
                    logger.info(f"Retrying with 50% more tokens ({int(max_tokens * 1.5)})")

                    # Retry with increased max_tokens
                    retry_response = await self.llm_provider.generate_content(
                        prompt=prompt,
                        scenario_type=f"threat_simulation_{stage_type}",
                        max_tokens=int(max_tokens * 1.5),
                        temperature=0.7
                    )

                    if retry_response and retry_response.content:
                        retry_finish = getattr(retry_response, 'finish_reason', None)
                        if retry_finish == 'length':
                            logger.warning("Content still truncated after retry, but using it")
                        else:
                            logger.info("Retry successful - content complete")
                        return retry_response.content
                    else:
                        logger.warning("Retry failed, using original truncated content")
                        return response.content

                logger.debug(f"Generated {len(response.content)} characters for stage {stage_type}")
                return response.content
            else:
                logger.warning(f"Empty response from LLM for stage {stage_type}")
                return self._generate_fallback_content(scenario, stage_type, description)

        except Exception as e:
            logger.error(f"LLM content generation failed for stage {stage_type}: {str(e)}")
            return self._generate_fallback_content(scenario, stage_type, description)

    def _create_scenario_generation_prompt(self, scenario: ThreatScenario, stage_type: str, description: str) -> str:
        """Create stage-specific prompts for generating actual threat scenario samples.

        This method now uses the enhanced prompt system to generate high-quality,
        context-aware prompts with chain-of-thought reasoning and industry best practices.
        """
        try:
            # Map threat type to content type for enhanced prompts
            threat_type = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)
            content_type = self._map_to_enhanced_content_type(threat_type, stage_type)

            # Extract target role and difficulty from scenario
            target_role = scenario.target_profile.get("role", "Employee") if hasattr(scenario, 'target_profile') else "Employee"
            difficulty = getattr(scenario, 'difficulty_level', 7)

            # Generate enhanced prompt using the new system
            enhanced_prompt = generate_threat_prompt(
                target_role=target_role,
                threat_type=threat_type.lower(),
                content_type=content_type,
                difficulty_level=difficulty,
                scenario=scenario
            )

            # Add stage-specific context to the enhanced prompt
            stage_context = f"""

Stage Context: {stage_type} - {description}
Scenario Name: {scenario.name}
Scenario Description: {scenario.description}
"""

            return enhanced_prompt + stage_context

        except Exception as e:
            logger.warning(f"Enhanced prompt generation failed: {e}, falling back to basic prompts")
            # Fallback to basic prompts if enhanced system fails
            return self._create_fallback_prompt(scenario, stage_type, description)

    def _map_to_enhanced_content_type(self, threat_type: str, stage_type: str) -> str:
        """Map threat type and stage to ContentType for enhanced prompts."""
        threat_lower = threat_type.lower()

        if "sms" in threat_lower or "smishing" in threat_lower:
            return "sms"
        elif "phone" in threat_lower or "vishing" in threat_lower or "voice" in stage_type.lower():
            return "phone_script"
        elif "social" in threat_lower and "media" in threat_lower:
            return "social_post"
        elif "document" in threat_lower or "malware" in threat_lower:
            return "document"
        elif "web" in threat_lower or "website" in threat_lower:
            return "web_page"
        else:
            # Default to email for phishing, BEC, and general scenarios
            return "email"

    def _create_fallback_prompt(self, scenario: ThreatScenario, stage_type: str, description: str) -> str:
        """Fallback to basic prompts if enhanced system is unavailable."""
        threat_type = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)

        # Enhanced target profile analysis
        target_context = ""
        if hasattr(scenario, 'target_profile') and scenario.target_profile:
            profile = scenario.target_profile
            target_context = f"""
**TARGET PROFILE:**
- Role: {getattr(profile, 'role', 'Employee')}
- Industry: {getattr(profile, 'industry', 'technology')}
- Department: {getattr(profile, 'department', 'general')}
- Seniority: {getattr(profile, 'seniority', 'mid')}
- Security Awareness: {getattr(profile, 'security_awareness_level', 5)}/10
- Company Size: {getattr(profile, 'company_size', 'medium')}
"""

        # Template parameter analysis for enhanced generation
        template_context = ""
        custom_params = getattr(scenario, 'custom_parameters', {})
        if custom_params:
            template_context = "\n**TEMPLATE PARAMETERS:**\n"

            # Analyze available template resources
            if 'sms_templates' in custom_params:
                sms_data = custom_params['sms_templates']
                template_context += f"SMS Templates: {len(sms_data)} categories available\n"

            if 'impersonated_services' in custom_params:
                services = custom_params['impersonated_services']
                template_context += f"Impersonation Options: {', '.join(services[:5])}{'...' if len(services) > 5 else ''}\n"

            if 'timing_strategies' in custom_params:
                timing = custom_params['timing_strategies']
                template_context += f"Timing Strategies: {', '.join(timing)}\n"

            if 'variable_elements' in custom_params:
                variables = custom_params['variable_elements']
                template_context += "Variable Elements Available:\n"
                for key, value in list(variables.items())[:3]:  # Show first 3
                    if isinstance(value, list):
                        template_context += f"  - {key}: {len(value)} options\n"
                    else:
                        template_context += f"  - {key}: {str(value)[:50]}...\n"

        # Enhanced base context for agent training
        base_context = f"""
**AGENT TRAINING SCENARIO GENERATION**

**SCENARIO DETAILS:**
Name: {scenario.name}
Threat Type: {threat_type}
Description: {scenario.description}
Stage: {stage_type} - {description}
{target_context}
{template_context}

**TRAINING OBJECTIVE:**
Generate realistic attack content that will be used to train AI agents in threat detection, analysis, and response. The content must demonstrate actual attack techniques while providing educational value for machine learning systems.

**GENERATION REQUIREMENTS:**
1. Create authentic attack content (not educational descriptions)
2. Show realistic social engineering techniques
3. Include industry and role-specific targeting
4. Demonstrate various sophistication levels
5. Provide diverse attack variations
6. Include technical indicators for detection training
"""

        # Generate different content based on stage type and threat type with enhanced prompts
        if stage_type == "reconnaissance":
            return self._create_reconnaissance_prompt(scenario, base_context)
        elif stage_type == "attack_planning":
            return self._create_attack_planning_prompt(scenario, base_context)
        elif threat_type in ["phishing", "spear_phishing", "sms_phishing"]:
            return self._create_phishing_sample_prompt(scenario, base_context, stage_type)
        elif threat_type in ["social_engineering", "vishing"]:
            return self._create_social_engineering_prompt(scenario, base_context, stage_type)
        elif threat_type in ["bec", "business_email_compromise"]:
            return self._create_bec_sample_prompt(scenario, base_context, stage_type)
        else:
            return self._create_generic_scenario_prompt(scenario, base_context, stage_type)

    def _create_phishing_sample_prompt(self, scenario: ThreatScenario, base_context: str, stage_type: str) -> str:
        """Generate actual phishing email samples with advanced variation techniques."""
        threat_type = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)

        # Extract target profile details for personalization
        target_role = getattr(scenario.target_profile, 'role', 'Employee')
        target_industry = getattr(scenario.target_profile, 'industry', 'technology')
        target_seniority = getattr(scenario.target_profile, 'seniority', 'mid')
        security_awareness = getattr(scenario.target_profile, 'security_awareness_level', 5)

        # Get custom parameters for variation
        custom_params = getattr(scenario, 'custom_parameters', {})
        sms_templates = custom_params.get('sms_templates', {}) if custom_params else {}

        # Variation techniques based on target characteristics
        sophistication_level = "high" if security_awareness > 7 else "medium" if security_awareness > 4 else "basic"

        if "sms" in threat_type.lower():
            return f"""{base_context}

**AGENT TRAINING SCENARIO GENERATION**

Generate a realistic SMS phishing message sample for training AI agents to recognize and respond to SMS threats.

**Target Profile Analysis:**
- Role: {target_role}
- Industry: {target_industry}
- Seniority: {target_seniority}
- Security Awareness: {security_awareness}/10
- Required Sophistication: {sophistication_level}

**Scenario Generation Requirements:**
1. **Message Authenticity**: Create an actual SMS that could realistically be sent
2. **Industry Context**: Incorporate {target_industry}-specific terminology and concerns
3. **Role-Specific Targeting**: Reference responsibilities and systems relevant to a {target_role}
4. **Psychological Engineering**: Use triggers appropriate for {target_seniority}-level professionals
5. **Variation Elements**: Include multiple variations of:
   - Urgency levels (immediate, hours, end-of-day)
   - Authority sources (IT, security team, executive, vendor)
   - Threat types (account lockout, security breach, system maintenance)
   - Call-to-action styles (click link, reply with info, call number)

**Technical Specifications:**
- Message length: 160-300 characters
- Include shortened URL (use domains like: secure-verify-[company].com)
- Add sender spoofing details (short code or phone number)
- Include timing context (when would this be most effective)

**Agent Training Focus:**
Generate 3 different variations of the same core attack to show how threats adapt:

VARIATION 1 (Direct Authority):
[Generate SMS with authority figure approach]

VARIATION 2 (Peer Request):
[Generate SMS with colleague/peer approach]

VARIATION 3 (System Alert):
[Generate SMS with automated system approach]

For each variation, include:
- The exact SMS message
- Sender identification strategy
- Optimal timing for maximum effectiveness
- Expected target response psychology

Generate realistic scenario samples:"""
        else:
            email_sophistication = {
                "basic": "Simple, obvious phishing with basic social engineering",
                "medium": "Professional-looking email with company branding and moderate social engineering",
                "high": "Highly sophisticated spear-phishing with detailed personalization and advanced evasion"
            }

            return f"""{base_context}

**AGENT TRAINING SCENARIO GENERATION**

Generate realistic phishing email samples for training AI agents to detect and analyze email-based threats.

**Target Profile Analysis:**
- Role: {target_role}
- Industry: {target_industry}
- Seniority: {target_seniority}
- Security Awareness: {security_awareness}/10
- Required Approach: {email_sophistication[sophistication_level]}

**Comprehensive Email Generation Requirements:**

1. **Complete Email Structure**:
   - Realistic From: address with domain spoofing strategy
   - Compelling Subject line with psychological triggers
   - Professional email body with appropriate formatting
   - Believable signature block with contact details
   - Headers that would bypass basic email filters

2. **Industry-Specific Context**:
   - Use {target_industry} terminology and pain points
   - Reference common {target_industry} vendors and services
   - Include {target_industry}-relevant compliance/regulatory concerns
   - Mention {target_industry}-specific systems and processes

3. **Role-Targeted Content**:
   - Address concerns specific to {target_role} responsibilities
   - Use language appropriate for {target_seniority} level
   - Reference systems and processes the {target_role} would interact with
   - Include decision-making scenarios relevant to their authority level

4. **Variation Generation** (Generate 2 distinct approaches):

**APPROACH A - VENDOR IMPERSONATION:**
   - Impersonate a trusted {target_industry} vendor/partner
   - Create urgent business need scenario
   - Include realistic account/invoice references
   - Use professional business language

**APPROACH B - INTERNAL IMPERSONATION:**
   - Impersonate internal colleague or system
   - Create process/policy update scenario
   - Include internal terminology and references
   - Use company communication style

**Technical Implementation Details for Each Approach:**
- Sender spoofing strategy and domain selection
- Email content with exact formatting
- Malicious link implementation (use example.com variants)
- Social engineering psychological pathway
- Optimal delivery timing
- Expected target response behavior
- Potential follow-up attack vectors

**Agent Training Objectives:**
Each generated email should help agents learn to:
- Identify sender authentication issues
- Recognize social engineering tactics
- Analyze urgency and authority manipulation
- Detect domain spoofing and suspicious links
- Understand industry-specific attack vectors
- Recognize personalization vs. generic attacks

Generate the complete email scenarios with all technical details:"""

    def _create_social_engineering_prompt(self, scenario: ThreatScenario, base_context: str, stage_type: str) -> str:
        """Generate comprehensive social engineering script samples for agent training."""

        target_role = getattr(scenario.target_profile, 'role', 'Employee')
        target_industry = getattr(scenario.target_profile, 'industry', 'technology')
        target_department = getattr(scenario.target_profile, 'department', 'general')
        security_awareness = getattr(scenario.target_profile, 'security_awareness_level', 5)

        return f"""{base_context}

**ADVANCED SOCIAL ENGINEERING TRAINING SCENARIOS**

Generate comprehensive phone-based social engineering scenarios for training AI agents to recognize and counter vishing (voice phishing) attacks.

**Target Analysis:**
- Role: {target_role}
- Industry: {target_industry}
- Department: {target_department}
- Security Awareness: {security_awareness}/10

**Multi-Vector Scenario Generation:**

**SCENARIO 1: TECHNICAL SUPPORT IMPERSONATION**
Generate a complete conversation script showing:

*Initial Contact Phase:*
- Caller introduction and pretext establishment
- Technical terminology appropriate for {target_industry}
- Urgency creation without raising suspicion
- Trust building through shared "inside" knowledge

*Information Gathering Phase:*
- Gradual escalation of information requests
- Techniques to extract credentials/access codes
- Methods to bypass security questions
- Social proof and authority establishment

*Execution Phase:*
- Direct requests for sensitive information
- Handling of target resistance or questions
- Alternative approaches if initial method fails
- Cleanup and exit strategies

**SCENARIO 2: EXECUTIVE IMPERSONATION**
Generate a script showing:
- High-pressure executive request scenario
- {target_role}-specific responsibilities exploitation
- Time-sensitive business justification
- Authority gradient manipulation

**SCENARIO 3: VENDOR/PARTNER IMPERSONATION**
Generate a script showing:
- Trusted third-party relationship exploitation
- {target_industry}-specific vendor knowledge
- Business process interruption scenarios
- Compliance and regulatory pressure tactics

**Conversation Structure for Each Scenario:**

```
CALLER: [Opening statement]
TARGET: [Expected response]
CALLER: [Trust building response]
TARGET: [Likely follow-up]
CALLER: [Information request escalation]
[Continue full conversation...]
```

**Advanced Training Elements:**
1. **Psychological Manipulation Techniques:**
   - Reciprocity principles
   - Authority establishment
   - Scarcity and urgency creation
   - Social proof utilization
   - Commitment and consistency exploitation

2. **Technical Social Engineering:**
   - Help desk procedure mimicking
   - System knowledge demonstration
   - Technical jargon appropriate for {target_industry}
   - Process validation techniques

3. **Resistance Handling:**
   - Common objections and responses
   - Escalation techniques when challenged
   - Alternative information gathering methods
   - Graceful exit strategies

4. **Industry-Specific Approaches:**
   - {target_industry} regulatory compliance pressures
   - Common {target_industry} vendors and systems
   - {target_industry} specific pain points and concerns
   - Role-specific responsibilities and authorities

**Agent Training Objectives:**
Each scenario should help agents learn to:
- Identify social engineering tactics in real-time
- Recognize pretext development and trust building
- Detect information gathering techniques
- Understand psychological manipulation methods
- Recognize industry-specific social engineering approaches
- Develop appropriate response and verification procedures

**Generate 3 complete conversation scripts with detailed analysis of psychological techniques used in each phase.**

Generate comprehensive training scenarios:"""

    def _create_bec_sample_prompt(self, scenario: ThreatScenario, base_context: str, stage_type: str) -> str:
        """Generate sophisticated BEC (Business Email Compromise) samples for comprehensive agent training."""

        target_role = getattr(scenario.target_profile, 'role', 'Employee')
        target_industry = getattr(scenario.target_profile, 'industry', 'technology')
        target_seniority = getattr(scenario.target_profile, 'seniority', 'mid')
        company_size = getattr(scenario.target_profile, 'company_size', 'medium')

        return f"""{base_context}

**ADVANCED BEC TRAINING SCENARIO GENERATION**

Generate sophisticated Business Email Compromise scenarios for training AI agents to detect and prevent financial fraud attacks.

**Target Environment Analysis:**
- Role: {target_role}
- Industry: {target_industry}
- Seniority: {target_seniority}
- Company Size: {company_size}

**Multi-Stage BEC Campaign Generation:**

**STAGE 1: RECONNAISSANCE PHASE**
Generate realistic intelligence gathering that would precede the BEC attack:
- Public information sources about target company
- Executive team identification and communication patterns
- Financial processes and approval workflows
- Vendor relationships and payment schedules
- Recent company news and business developments

**STAGE 2: INITIAL COMPROMISE**
Generate the primary BEC attack vectors:

**VECTOR A - CEO IMPERSONATION (W-2 Scam Variant)**
```
From: [CEO Name] <ceo@company-security-update.com>
To: {target_role}@company.com
Subject: [Generate urgent, business-appropriate subject]

[Generate complete email with:]:
- Executive communication style analysis
- Urgent but plausible business justification
- Specific employee data request (W-2s, payroll, etc.)
- Time pressure and confidentiality requirements
- Realistic executive signature and mobile contact
```

**VECTOR B - VENDOR IMPERSONATION (Invoice Redirect)**
```
From: [Vendor Name] <accounts@trusted-vendor-portal.com>
To: {target_role}@company.com
Subject: [Generate payment redirection request]

[Generate complete email with:]:
- Established vendor relationship references
- Banking change notification with urgency
- Realistic invoice references and amounts
- Professional vendor communication style
- Plausible business justification for change
```

**VECTOR C - ATTORNEY IMPERSONATION (Legal Urgency)**
```
From: [Attorney Name] <legal@lawfirm-confidential.com>
To: {target_role}@company.com
Subject: [Generate confidential legal matter]

[Generate complete email with:]:
- Confidential legal matter requiring immediate payment
- Professional legal communication style
- Client-attorney privilege references
- Realistic legal firm branding and contacts
- Time-sensitive compliance or settlement scenario
```

**STAGE 3: FOLLOW-UP AND PRESSURE TACTICS**
For each vector, generate follow-up scenarios:
- Escalation techniques when initial request is questioned
- Alternative contact methods (phone, text, secondary email)
- Social engineering responses to verification attempts
- Pressure tactics to bypass normal approval processes

**STAGE 4: ADVANCED EVASION TECHNIQUES**
Generate examples of:
- Domain spoofing and display name deception
- Email threading and conversation hijacking
- Mobile device targeting for urgent responses
- Off-hours and holiday timing exploitation
- Geographic and timezone manipulation

**Industry-Specific BEC Adaptations for {target_industry}:**
- Common {target_industry} vendor types and payment patterns
- {target_industry} regulatory compliance pressures
- Typical {target_industry} business processes and approval workflows
- {target_industry}-specific terminology and communication styles
- {target_industry} executive hierarchy and decision-making patterns

**Financial Engineering Details:**
For each scenario, include:
- Realistic but fake banking information
- Appropriate transaction amounts for {company_size} companies
- Payment method preferences (wire transfer, ACH, check)
- International banking complications if applicable
- Cryptocurrency payment requests for advanced scenarios

**Agent Training Focus Areas:**
1. **Financial Process Verification:**
   - Normal vs. abnormal payment request patterns
   - Proper approval workflows and verification procedures
   - Red flags in urgent financial communications

2. **Executive Communication Analysis:**
   - Authentic vs. impersonated executive communication styles
   - Timing patterns and communication preferences
   - Authority verification procedures

3. **Vendor Relationship Management:**
   - Legitimate vendor communication channels
   - Banking change verification procedures
   - Invoice validation and authentication methods

4. **Technical Indicators:**
   - Email header analysis and sender verification
   - Domain spoofing detection techniques
   - Display name deception identification

**Risk Assessment Framework:**
For each generated scenario, include:
- Probability of success against different target types
- Potential financial impact and loss scenarios
- Detection difficulty and timeline
- Recommended countermeasures and controls

Generate comprehensive BEC training scenarios with complete technical details and psychological analysis:"""

    def _create_reconnaissance_prompt(self, scenario: ThreatScenario, base_context: str) -> str:
        """Generate reconnaissance activity samples."""
        return f"""{base_context}

Generate realistic reconnaissance activities and information gathering samples for this threat scenario.

Requirements:
- Create actual examples of information that would be gathered about the target
- Show specific OSINT sources and techniques that would be used
- Include realistic but fake target information and company details
- Demonstrate how collected information would be used for the attack
- Show social media, website, and public record research examples
- Include timing and targeting strategies
- Add realistic target profiling and attack preparation steps

Generate the reconnaissance sample:"""

    def _create_attack_planning_prompt(self, scenario: ThreatScenario, base_context: str) -> str:
        """Generate attack planning samples."""
        return f"""{base_context}

Generate a realistic attack execution plan sample for this threat scenario.

Requirements:
- Create an actual step-by-step attack plan that could be followed
- Include specific timing, methods, and resources needed
- Show realistic but fake infrastructure setup (domains, servers, etc.)
- Demonstrate attack flow and decision points
- Include contingency plans and backup methods
- Add realistic success metrics and goals
- Show how to maintain persistence and avoid detection
- Include exit strategies and cleanup procedures

Generate the attack plan sample:"""

    def _create_generic_scenario_prompt(self, scenario: ThreatScenario, base_context: str, stage_type: str) -> str:
        """Generate diverse, comprehensive threat scenario samples for advanced agent training."""

        threat_type = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)
        target_role = getattr(scenario.target_profile, 'role', 'Employee')
        target_industry = getattr(scenario.target_profile, 'industry', 'technology')
        delivery_vector = scenario.delivery_vector.value if hasattr(scenario.delivery_vector, 'value') else str(scenario.delivery_vector)

        return f"""{base_context}

**COMPREHENSIVE THREAT SCENARIO TRAINING GENERATION**

Generate advanced threat scenarios for training AI agents in {threat_type} attack detection and response.

**Scenario Parameters:**
- Threat Type: {threat_type}
- Delivery Vector: {delivery_vector}
- Target Role: {target_role}
- Industry Context: {target_industry}

**Multi-Dimensional Scenario Generation:**

**DIMENSION 1: ATTACK SOPHISTICATION LEVELS**

*Basic Level Scenario:*
- Generate a straightforward {threat_type} attack
- Use obvious social engineering tactics
- Include easily detectable indicators
- Focus on volume-based approach

*Intermediate Level Scenario:*
- Generate a moderately sophisticated {threat_type} attack
- Include targeted reconnaissance elements
- Use industry-specific knowledge
- Implement basic evasion techniques

*Advanced Level Scenario:*
- Generate a highly sophisticated {threat_type} attack
- Include extensive target profiling
- Use advanced social engineering psychology
- Implement sophisticated evasion and persistence

**DIMENSION 2: TEMPORAL VARIATIONS**

*Immediate Threat:*
- High urgency, short timeframe
- Crisis-driven decision making
- Emergency response exploitation

*Slow Burn Campaign:*
- Long-term relationship building
- Gradual trust establishment
- Patient information gathering

*Seasonal/Event-Driven:*
- Holiday/seasonal exploitation
- Industry conference/event timing
- Regulatory deadline pressure

**DIMENSION 3: PSYCHOLOGICAL APPROACH VARIATIONS**

For each scenario, generate versions using different psychological approaches:
- **Authority**: Impersonation of higher-level decision makers
- **Reciprocity**: Offering help or benefits before making requests
- **Social Proof**: Using peer pressure and group conformity
- **Commitment**: Getting target to commit to small actions first
- **Scarcity**: Creating artificial urgency and limited availability
- **Likability**: Building rapport and personal connection

**DIMENSION 4: INDUSTRY-SPECIFIC ADAPTATIONS**

Generate {target_industry}-specific variations that include:
- Industry terminology and jargon
- Common {target_industry} business processes
- Regulatory compliance pressures specific to {target_industry}
- Technology stack and systems common in {target_industry}
- Supply chain and vendor relationships typical of {target_industry}

**DIMENSION 5: ROLE-BASED TARGETING**

Customize scenarios for {target_role} by incorporating:
- Role-specific responsibilities and authorities
- Systems and applications the {target_role} typically uses
- Decision-making patterns and approval processes
- Information access levels and security clearances
- Communication patterns and preferences

**COMPREHENSIVE SCENARIO OUTPUT STRUCTURE:**

For each scenario variation, provide:

1. **Attack Vector Details:**
   - Initial contact method and timing
   - Social engineering pretext and approach
   - Technical implementation details
   - Expected target response psychology

2. **Content Samples:**
   - Exact communication content (emails, messages, scripts)
   - Supporting materials (fake documents, websites, etc.)
   - Follow-up communication sequences
   - Escalation and persistence tactics

3. **Technical Infrastructure:**
   - Domain registration and spoofing strategies
   - Communication platform exploitation
   - Payload delivery mechanisms
   - Data collection and exfiltration methods

4. **Success Metrics and Indicators:**
   - Primary and secondary success criteria
   - Behavioral indicators of compromise
   - Timeline expectations and milestones
   - Potential impact and damage assessment

5. **Detection and Mitigation:**
   - Technical indicators of compromise (IOCs)
   - Behavioral red flags and warning signs
   - Recommended detection tools and techniques
   - Response and mitigation strategies

**Agent Training Objectives:**

Each generated scenario should enable agents to:
- Recognize attack patterns across sophistication levels
- Understand psychological manipulation techniques
- Identify industry and role-specific targeting
- Develop appropriate response strategies
- Learn from realistic attack simulations
- Improve threat detection accuracy and speed

**Variation Requirements:**
Generate at least 3 distinct scenario variations that demonstrate:
- Different attack vectors within the same threat type
- Various psychological approaches and social engineering tactics
- Multiple delivery mechanisms and timing strategies
- Diverse target response scenarios and outcomes
- Range of technical sophistication and evasion techniques

Generate comprehensive, varied threat scenarios for optimal agent training:"""

    def _generate_fallback_content(self, scenario: ThreatScenario, stage_type: str, description: str) -> str:
        """Generate fallback content when LLM is unavailable."""
        threat_type = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)

        fallback_templates = {
            "reconnaissance": f"""
[RECONNAISSANCE STAGE]
Scenario: {scenario.name}
Threat Type: {threat_type}

In this stage, attackers would typically:
• Gather information about the target organization
• Identify potential entry points and vulnerabilities
• Research key personnel and organizational structure
• Collect technical information about systems and infrastructure

Defensive Measures:
• Monitor for unusual reconnaissance activities
• Implement proper information disclosure policies
• Use threat intelligence to identify scanning attempts
• Educate employees about social engineering attempts

Indicators of Compromise:
• Unusual network scanning activities
• Suspicious social media research
• Unexpected information requests
• Anomalous DNS queries
""",
            "attack_planning": f"""
[ATTACK PLANNING STAGE]
Scenario: {scenario.name}
Threat Type: {threat_type}

Attack planning typically involves:
• Analyzing gathered reconnaissance data
• Selecting appropriate attack vectors
• Developing custom tools or adapting existing ones
• Planning timing and sequence of attack phases

Defensive Strategies:
• Implement defense-in-depth architecture
• Regular vulnerability assessments and patching
• Employee security awareness training
• Incident response plan preparation

Key Prevention Points:
• Network segmentation
• Access controls and privilege management
• Security monitoring and alerting
• Regular security audits
""",
            "execution": f"""
[EXECUTION STAGE]
Scenario: {scenario.name}
Threat Type: {threat_type}

Execution phase characteristics:
• Initial access attempts using planned attack vectors
• Exploitation of identified vulnerabilities
• Deployment of malicious payloads or social engineering
• Attempts to establish foothold in target environment

Detection Opportunities:
• Endpoint detection and response (EDR) systems
• Network traffic analysis
• Behavioral analytics
• User activity monitoring

Immediate Response Actions:
• Isolate affected systems
• Preserve evidence for analysis
• Activate incident response team
• Communicate with stakeholders
"""
        }

        # Return specific template or generic content
        return fallback_templates.get(stage_type, f"""
[{stage_type.upper()} STAGE]
Scenario: {scenario.name}
Threat Type: {threat_type}

Stage Description: {description}

This simulation stage would demonstrate key aspects of the {stage_type} phase
in a {threat_type} attack scenario. Educational content and defensive
recommendations would be provided here.

Note: Full content generation requires LLM provider configuration.
""")

    def get_active_simulations(self) -> Dict[str, SimulationResult]:
        """Get currently active simulations.

        Returns:
            Dictionary of active simulation results by ID
        """
        return self._active_simulations.copy()

    def generate_scenario_variations(self, scenario: ThreatScenario, variation_count: int = 5) -> List[str]:
        """Generate multiple scenario variations for comprehensive agent training.

        Args:
            scenario: Base threat scenario to create variations from
            variation_count: Number of variations to generate

        Returns:
            List of generated scenario variation prompts
        """
        variations = []

        # Define variation dimensions
        sophistication_levels = ['basic', 'intermediate', 'advanced']
        psychological_approaches = ['authority', 'urgency', 'reciprocity', 'social_proof', 'scarcity']
        timing_strategies = ['immediate', 'slow_burn', 'event_driven']
        delivery_methods = ['direct', 'chain_referral', 'multi_channel']

        threat_type = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)

        for i in range(variation_count):
            # Select variation parameters
            sophistication = sophistication_levels[i % len(sophistication_levels)]
            psychology = psychological_approaches[i % len(psychological_approaches)]
            timing = timing_strategies[i % len(timing_strategies)]
            delivery = delivery_methods[i % len(delivery_methods)]

            variation_prompt = f"""
**SCENARIO VARIATION {i+1}/{variation_count}**

Base Scenario: {scenario.name}
Threat Type: {threat_type}

Variation Parameters:
- Sophistication: {sophistication}
- Psychology: {psychology}
- Timing: {timing}
- Delivery: {delivery}

Generate a unique {threat_type} scenario that incorporates these specific variation parameters while maintaining realism and training value for AI agents. Ensure this variation teaches different attack patterns and detection methods compared to other variations.

Focus on making this scenario distinctly different in approach while keeping the core threat type consistent.
"""
            variations.append(variation_prompt)

        return variations

    def _create_reconnaissance_prompt(self, scenario: ThreatScenario, base_context: str) -> str:
        """Generate reconnaissance phase content for agent training."""
        target_role = getattr(scenario.target_profile, 'role', 'Employee')
        target_industry = getattr(scenario.target_profile, 'industry', 'technology')

        return f"""{base_context}

**RECONNAISSANCE PHASE TRAINING SCENARIO**

Generate realistic reconnaissance activities and intelligence gathering methods for this threat scenario.

**Target Intelligence Requirements:**
- Role: {target_role}
- Industry: {target_industry}

**Reconnaissance Training Content:**

1. **Open Source Intelligence (OSINT) Collection:**
   - Generate realistic social media research techniques
   - Show company website and employee directory analysis
   - Demonstrate public records and professional network mining
   - Include industry conference and event monitoring

2. **Technical Reconnaissance:**
   - Generate realistic email address harvesting techniques
   - Show domain and subdomain enumeration approaches
   - Demonstrate technology stack identification methods
   - Include network infrastructure analysis

3. **Social Engineering Preparation:**
   - Generate realistic pretext development scenarios
   - Show authority figure identification and impersonation planning
   - Demonstrate communication pattern analysis
   - Include timing and approach optimization

4. **Intelligence Analysis:**
   - Generate realistic target vulnerability assessment
   - Show attack vector prioritization and selection
   - Demonstrate success probability calculations
   - Include risk and detection likelihood analysis

Generate comprehensive reconnaissance scenario content for agent training:"""

    def _create_attack_planning_prompt(self, scenario: ThreatScenario, base_context: str) -> str:
        """Generate attack planning phase content for agent training."""
        threat_type = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)
        delivery_vector = scenario.delivery_vector.value if hasattr(scenario.delivery_vector, 'value') else str(scenario.delivery_vector)

        return f"""{base_context}

**ATTACK PLANNING PHASE TRAINING SCENARIO**

Generate realistic attack planning documentation and methodologies for this {threat_type} scenario.

**Planning Requirements:**
- Threat Type: {threat_type}
- Delivery Vector: {delivery_vector}

**Attack Planning Training Content:**

1. **Attack Vector Development:**
   - Generate realistic attack pathway selection and justification
   - Show alternative approach planning and contingencies
   - Demonstrate timing and sequencing optimization
   - Include resource and tool requirement analysis

2. **Social Engineering Strategy:**
   - Generate realistic pretext and persona development
   - Show psychological manipulation planning and approach
   - Demonstrate authority and trust establishment methods
   - Include resistance handling and objection management

3. **Technical Implementation Planning:**
   - Generate realistic infrastructure setup requirements
   - Show communication channel selection and preparation
   - Demonstrate payload and content development planning
   - Include evasion and persistence strategy design

4. **Operational Security (OPSEC):**
   - Generate realistic detection avoidance strategies
   - Show attribution masking and anonymization planning
   - Demonstrate evidence cleanup and exit strategies
   - Include forensic countermeasure implementation

5. **Success Metrics and Contingencies:**
   - Generate realistic success criteria and measurement methods
   - Show failure point identification and mitigation planning
   - Demonstrate escalation and alternative approach strategies
   - Include timeline optimization and adjustment protocols

Generate comprehensive attack planning scenarios for agent training:"""

    def analyze_scenario_diversity(self, generated_scenarios: List[str]) -> Dict[str, Any]:
        """Analyze the diversity and coverage of generated scenarios for training effectiveness.

        Args:
            generated_scenarios: List of generated scenario content

        Returns:
            Analysis of scenario diversity and training coverage
        """
        analysis = {
            'total_scenarios': len(generated_scenarios),
            'diversity_metrics': {
                'unique_attack_vectors': set(),
                'psychological_tactics': set(),
                'industry_contexts': set(),
                'sophistication_levels': set()
            },
            'training_coverage': {
                'beginner_appropriate': 0,
                'intermediate_appropriate': 0,
                'advanced_appropriate': 0
            },
            'quality_indicators': {
                'realistic_content': 0,
                'educational_value': 0,
                'technical_accuracy': 0
            }
        }

        # Basic analysis - in a real implementation, this would use NLP
        for scenario in generated_scenarios:
            # Simple keyword-based diversity analysis
            if any(word in scenario.lower() for word in ['basic', 'simple', 'obvious']):
                analysis['training_coverage']['beginner_appropriate'] += 1
            if any(word in scenario.lower() for word in ['intermediate', 'moderate', 'targeted']):
                analysis['training_coverage']['intermediate_appropriate'] += 1
            if any(word in scenario.lower() for word in ['advanced', 'sophisticated', 'complex']):
                analysis['training_coverage']['advanced_appropriate'] += 1

        return analysis

    def cancel_simulation(self, result_id: str) -> bool:
        """Cancel an active simulation.

        Args:
            result_id: ID of the simulation result to cancel

        Returns:
            True if simulation was cancelled, False if not found
        """
        if result_id in self._active_simulations:
            result = self._active_simulations[result_id]
            result.status = SimulationStatus.CANCELLED
            result.mark_completed(success=False, error_message="Simulation cancelled by user")
            self._active_simulations.pop(result_id)
            logger.info(f"Simulation cancelled: {result_id}")
            return True
        return False

    def __repr__(self) -> str:
        active_count = len(self._active_simulations)
        return f"ThreatSimulator(provider={type(self.llm_provider).__name__}, active={active_count})"
