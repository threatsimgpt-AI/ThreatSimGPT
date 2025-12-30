"""Advanced prompt engineering implementations for ThreatSimGPT.

This module implements cutting-edge prompt engineering techniques based on recent research:
- Chain-of-Thought (CoT) prompting (Wei et al., 2022)
- Few-Shot Learning with dynamic examples
- Tree of Thoughts (ToT) (Yao et al., 2023)
- Meta-Learning and Self-Refinement
- RLHF optimization techniques
- Multi-Agent prompting architectures
"""

import json
import random
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from .models import ContentType, PromptContext, PromptTemplate


class PromptingTechnique(str, Enum):
    """Advanced prompting techniques available."""
    CHAIN_OF_THOUGHT = "chain_of_thought"
    FEW_SHOT = "few_shot"
    TREE_OF_THOUGHTS = "tree_of_thoughts"
    META_LEARNING = "meta_learning"
    SELF_REFINING = "self_refining"
    MULTI_AGENT = "multi_agent"


@dataclass
class CoTStep:
    """Chain-of-Thought reasoning step."""
    step_number: int
    description: str
    reasoning: str
    output: str


@dataclass
class ExampleCase:
    """Few-shot learning example case."""
    scenario_type: str
    input_context: Dict[str, Any]
    reasoning_chain: List[CoTStep]
    final_output: str
    quality_score: float


class ChainOfThoughtPromptEngine:
    """
    Level 1: Chain-of-Thought Prompting Implementation

    Based on Wei et al. (2022) research showing that prompting models to show
    their reasoning step-by-step significantly improves complex task performance.
    """

    def __init__(self):
        self.cot_templates = self._initialize_cot_templates()

    def _initialize_cot_templates(self) -> Dict[ContentType, str]:
        """Initialize Chain-of-Thought templates for different content types."""
        return {
            ContentType.EMAIL_PHISHING: self._get_phishing_cot_template(),
            ContentType.SMS_PHISHING: self._get_sms_cot_template(),
            ContentType.VOICE_SCRIPT: self._get_voice_cot_template(),
            ContentType.PRETEXT_SCENARIO: self._get_pretext_cot_template()
        }

    def _get_phishing_cot_template(self) -> str:
        """Chain-of-Thought template for phishing email generation."""
        return """You are creating a phishing email for security training. Let me think through this step-by-step:

Step 1: Analyze the target profile
- Role: {target_role}
- Department: {target_department}
- Technical Level: {target_technical_level}
- Security Awareness: {security_awareness_level}/10

Let me reason about what would be most effective for this target:
- If technical level is high, I need sophisticated social engineering
- If security awareness is high, I need subtle, non-obvious tactics
- The role determines what type of business context would be believable

Step 2: Select appropriate psychological triggers
Available triggers: {psychological_triggers}
Given the target profile, the most effective triggers would be:
- [Reasoning about which triggers match the target psychology]
- [Explanation of why these triggers work for this specific role/department]

Step 3: Choose social engineering techniques
Available techniques: {social_engineering_tactics}
For this scenario, I should use:
- [Reasoning about technique selection based on target sophistication]
- [Explanation of technique effectiveness for difficulty level {difficulty_level}/10]

Step 4: Design the attack vector
- Email should appear to come from: [reasoning about credible sender]
- Subject line should: [reasoning about urgency/relevance balance]
- Content should: [reasoning about tone and sophistication level]

Step 5: Create the phishing email
Based on my analysis above, here's the training email:

Subject: [subject line with reasoning]
From: [sender with reasoning]
To: {target_role} at {company_name}

[Email body incorporating reasoned decisions]

Step 6: Add educational elements
Training red flags included:
- [List of subtle indicators with explanations]
- [Reasoning about why these would be detectable by trained personnel]

Final Training Notes: [Explanation of techniques used and learning objectives]"""

    def _get_sms_cot_template(self) -> str:
        """Chain-of-Thought template for SMS phishing."""
        return """Creating an SMS phishing message for security training. Let me analyze this systematically:

Step 1: Mobile context analysis
- Target: {target_role} with {target_technical_level} technical skills
- Security awareness: {security_awareness_level}/10
- Mobile usage patterns for this role: [reasoning about mobile behavior]

Step 2: SMS-specific psychological factors
- Character limit constraints (160-300 chars)
- Urgency works well in mobile context because: [reasoning]
- Authority figures credible via SMS for this role: [reasoning]

Step 3: Social engineering adaptation for mobile
Given {social_engineering_tactics}, the mobile-optimized approach is:
- [Reasoning about which tactics work best in SMS format]
- [Explanation of mobile-specific attack vectors]

Step 4: Construct the SMS
Based on analysis:

From: [sender with reasoning for mobile credibility]
Message: [SMS content with character count and reasoning]

Training Analysis: [Mobile-specific red flags and detection methods]"""

    def generate_cot_prompt(
        self,
        content_type: ContentType,
        context: PromptContext
    ) -> str:
        """Generate a Chain-of-Thought prompt for the given context."""

        template = self.cot_templates.get(content_type)
        if not template:
            raise ValueError(f"No CoT template for content type: {content_type}")

        # Format template with context variables
        formatted_prompt = template.format(
            target_role=context.target_role,
            target_department=context.target_department,
            target_technical_level=context.target_technical_level,
            security_awareness_level=context.security_awareness_level,
            difficulty_level=context.difficulty_level,
            psychological_triggers=", ".join(context.psychological_triggers),
            social_engineering_tactics=", ".join(context.social_engineering_tactics),
            company_name=context.company_name or "TechCorp Inc.",
            threat_type=context.threat_type,
            delivery_vector=context.delivery_vector
        )

        return formatted_prompt

    def extract_reasoning_chain(self, llm_response: str) -> List[CoTStep]:
        """Extract the reasoning chain from LLM response for analysis."""
        steps = []
        step_pattern = r"Step (\d+):\s*([^\n]+)\n(.*?)(?=Step \d+:|$)"

        import re
        matches = re.findall(step_pattern, llm_response, re.DOTALL)

        for match in matches:
            step_num = int(match[0])
            description = match[1].strip()
            reasoning = match[2].strip()

            steps.append(CoTStep(
                step_number=step_num,
                description=description,
                reasoning=reasoning,
                output=""  # Could be extracted with more parsing
            ))

        return steps


class FewShotLearningEngine:
    """
    Level 2: Few-Shot Learning Implementation

    Based on Brown et al. (2020) "Language Models are Few-Shot Learners"
    and recent work on dynamic example selection for optimal performance.
    """

    def __init__(self):
        self.example_database = self._initialize_examples()
        self.similarity_threshold = 0.7

    def _initialize_examples(self) -> List[ExampleCase]:
        """Initialize high-quality examples for different scenario types."""
        return [
            ExampleCase(
                scenario_type="executive_phishing",
                input_context={
                    "target_role": "CEO",
                    "security_awareness": 8,
                    "difficulty_level": 9
                },
                reasoning_chain=[
                    CoTStep(1, "Analyze CEO psychology", "CEOs respond to board-related urgency", ""),
                    CoTStep(2, "Select social engineering", "Authority + time pressure", ""),
                    CoTStep(3, "Craft sophisticated message", "Professional tone, board context", "")
                ],
                final_output="""Subject: Urgent: Board Resolution Required Before Market Open
From: board-secretary@example-corp.com
[Professional, urgent board-related content]""",
                quality_score=0.92
            ),
            # More examples would be added here...
        ]

    def select_best_examples(
        self,
        context: PromptContext,
        num_examples: int = 3
    ) -> List[ExampleCase]:
        """
        Dynamically select the most relevant examples based on context similarity.
        Uses semantic similarity and scenario matching.
        """
        scored_examples = []

        for example in self.example_database:
            similarity_score = self._calculate_context_similarity(
                context,
                example.input_context
            )

            # Weight by quality score
            final_score = similarity_score * example.quality_score
            scored_examples.append((final_score, example))

        # Sort by score and return top examples
        scored_examples.sort(key=lambda x: x[0], reverse=True)
        return [example for _, example in scored_examples[:num_examples]]

    def _calculate_context_similarity(
        self,
        context: PromptContext,
        example_context: Dict[str, Any]
    ) -> float:
        """Calculate similarity between current context and example context."""
        # Simple similarity calculation - could be enhanced with embeddings
        similarity = 0.0
        total_factors = 0

        # Role similarity
        if context.target_role.lower() in str(example_context.get("target_role", "")).lower():
            similarity += 0.3
        total_factors += 0.3

        # Difficulty level similarity
        context_difficulty = context.difficulty_level
        example_difficulty = example_context.get("difficulty_level", 5)
        difficulty_sim = 1.0 - abs(context_difficulty - example_difficulty) / 10.0
        similarity += difficulty_sim * 0.4
        total_factors += 0.4

        # Security awareness similarity
        context_awareness = context.security_awareness_level
        example_awareness = example_context.get("security_awareness", 5)
        awareness_sim = 1.0 - abs(context_awareness - example_awareness) / 10.0
        similarity += awareness_sim * 0.3
        total_factors += 0.3

        return similarity / total_factors if total_factors > 0 else 0.0

    def generate_few_shot_prompt(
        self,
        content_type: ContentType,
        context: PromptContext
    ) -> str:
        """Generate a few-shot prompt with dynamically selected examples."""

        # Select best examples
        examples = self.select_best_examples(context, num_examples=2)

        prompt = f"""You are creating {content_type.value} content for security training. Here are examples of high-quality outputs:

"""

        # Add examples
        for i, example in enumerate(examples, 1):
            prompt += f"Example {i}:\n"
            prompt += f"Input Context: {json.dumps(example.input_context, indent=2)}\n"
            prompt += "Reasoning:\n"
            for step in example.reasoning_chain:
                prompt += f"  {step.step_number}. {step.description}: {step.reasoning}\n"
            prompt += f"Output:\n{example.final_output}\n\n"

        # Add current task
        prompt += f"""Now create similar high-quality content for this scenario:

Context:
- Target Role: {context.target_role}
- Department: {context.target_department}
- Technical Level: {context.target_technical_level}
- Security Awareness: {context.security_awareness_level}/10
- Difficulty Level: {context.difficulty_level}/10
- Psychological Triggers: {', '.join(context.psychological_triggers)}
- Social Engineering Tactics: {', '.join(context.social_engineering_tactics)}

Following the pattern from the examples above, create your response with clear reasoning and high-quality output:"""

        return prompt


# Additional classes for Levels 3-6 would be implemented here...
# TreeOfThoughtsEngine, MetaLearningEngine, RLHFOptimizer, MultiAgentPromptSystem

"""
Implementation notes for remaining levels:

Level 3: Tree of Thoughts (ToT) - Yao et al. (2023)
- Generate multiple reasoning paths
- Evaluate each path
- Select best reasoning tree
- Implement backtracking for complex scenarios

Level 4: Meta-Learning & Self-Refinement
- Learn from previous generations
- Self-critique and improve
- Adaptive prompt modification

Level 5: RLHF Optimization
- Human feedback integration
- Reward model training
- Policy optimization for prompt generation

Level 6: Multi-Agent Architecture
- Specialized expert agents
- Collaborative prompt construction
- Adversarial validation
"""
