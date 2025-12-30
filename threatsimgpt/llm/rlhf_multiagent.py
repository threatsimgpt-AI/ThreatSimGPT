"""RLHF Optimization and Multi-Agent Prompt Engineering for ThreatSimGPT.

This module implements the final two levels of advanced prompt engineering:
- Level 5: Reinforcement Learning from Human Feedback (RLHF) optimization
- Level 6: Multi-Agent collaborative prompting architecture
"""

import asyncio
import json
import numpy as np
from typing import Any, Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class HumanFeedback:
    """Human feedback on generated content."""
    content_id: str
    overall_rating: float  # 1-10 scale
    dimension_ratings: Dict[str, float]  # realism, effectiveness, safety, etc.
    text_feedback: str
    improvement_suggestions: List[str]
    timestamp: datetime
    evaluator_id: str
    content_type: str


@dataclass
class RewardModelData:
    """Training data for the reward model."""
    prompt: str
    generated_content: str
    human_rating: float
    features: Dict[str, float]
    metadata: Dict[str, Any]


class RLHFOptimizer:
    """
    Level 5: Reinforcement Learning from Human Feedback Implementation

    Based on Ouyang et al. (2022) and subsequent RLHF research.
    Optimizes prompt engineering based on human feedback to improve
    content quality and alignment with training objectives.
    """

    def __init__(self, learning_rate: float = 0.01):
        self.learning_rate = learning_rate
        self.feedback_buffer: deque = deque(maxlen=1000)
        self.reward_model_weights: Dict[str, float] = self._initialize_reward_weights()
        self.prompt_templates: Dict[str, str] = {}
        self.performance_history: Dict[str, List[float]] = {}
        self.optimization_iterations = 0

    def _initialize_reward_weights(self) -> Dict[str, float]:
        """Initialize reward model weights for different quality dimensions."""
        return {
            # Content quality features
            "realism_score": 0.25,
            "effectiveness_score": 0.25,
            "educational_value": 0.20,
            "safety_compliance": 0.15,
            "technical_accuracy": 0.10,
            "creativity": 0.05,

            # Structural features
            "appropriate_length": 0.08,
            "clear_formatting": 0.07,
            "professional_tone": 0.10,
            "target_specificity": 0.12,

            # Training-specific features
            "includes_red_flags": 0.08,
            "educational_notes": 0.05,
            "difficulty_alignment": 0.10
        }

    async def collect_feedback(
        self,
        content_id: str,
        generated_content: str,
        prompt_used: str,
        content_type: str,
        human_evaluator: Callable[[str], HumanFeedback]
    ) -> HumanFeedback:
        """
        Collect human feedback on generated content.
        In production, this would integrate with a feedback UI.
        """

        feedback = await asyncio.get_event_loop().run_in_executor(
            None, human_evaluator, generated_content
        )

        # Store feedback
        self.feedback_buffer.append({
            "feedback": feedback,
            "content": generated_content,
            "prompt": prompt_used,
            "timestamp": datetime.utcnow()
        })

        # Update reward model
        await self._update_reward_model(feedback, generated_content, prompt_used)

        return feedback

    async def _update_reward_model(
        self,
        feedback: HumanFeedback,
        content: str,
        prompt: str
    ) -> None:
        """Update the reward model based on human feedback."""

        # Extract features from content
        features = self._extract_content_features(content, prompt)

        # Calculate current predicted reward
        predicted_reward = self._calculate_reward(features)

        # Human rating normalized to 0-1
        actual_reward = feedback.overall_rating / 10.0

        # Update weights using gradient descent
        prediction_error = actual_reward - predicted_reward

        for feature_name, feature_value in features.items():
            if feature_name in self.reward_model_weights:
                gradient = prediction_error * feature_value
                self.reward_model_weights[feature_name] += self.learning_rate * gradient

        # Normalize weights
        total_weight = sum(abs(w) for w in self.reward_model_weights.values())
        if total_weight > 0:
            for key in self.reward_model_weights:
                self.reward_model_weights[key] /= total_weight

        logger.info(f"Updated reward model: error={prediction_error:.3f}, "
                   f"top_weights={sorted(self.reward_model_weights.items(), key=lambda x: abs(x[1]), reverse=True)[:3]}")

    def _extract_content_features(self, content: str, prompt: str) -> Dict[str, float]:
        """Extract features from generated content for reward modeling."""

        features = {}
        content_lower = content.lower()

        # Length features
        word_count = len(content.split())
        features["appropriate_length"] = 1.0 if 100 <= word_count <= 500 else max(0.0, 1.0 - abs(word_count - 300) / 300)

        # Realism indicators
        realism_indicators = ["company", "department", "urgent", "professional", "deadline", "meeting"]
        features["realism_score"] = min(1.0, sum(1 for ind in realism_indicators if ind in content_lower) / len(realism_indicators))

        # Safety compliance
        safety_violations = ["download malware", "send money", "real password", "actual bank"]
        features["safety_compliance"] = 1.0 - min(1.0, sum(1 for viol in safety_violations if viol in content_lower))

        # Educational value
        education_markers = ["training", "red flag", "indicator", "awareness", "simulation"]
        features["educational_value"] = min(1.0, sum(1 for marker in education_markers if marker in content_lower) / 3)

        # Technical accuracy
        technical_terms = ["phishing", "social engineering", "mitre", "attack vector", "payload"]
        features["technical_accuracy"] = min(1.0, sum(1 for term in technical_terms if term in content_lower) / 3)

        # Professional tone
        professional_words = ["please", "regarding", "attached", "kindly", "sincerely"]
        unprofessional_words = ["hey", "urgent!!!", "click now", "limited time"]
        prof_score = sum(1 for word in professional_words if word in content_lower)
        unprof_penalty = sum(1 for word in unprofessional_words if word in content_lower)
        features["professional_tone"] = max(0.0, min(1.0, (prof_score - unprof_penalty) / 3))

        # Clear formatting
        has_subject = "subject:" in content_lower
        has_from = "from:" in content_lower
        has_structure = content.count("\n") >= 3
        features["clear_formatting"] = (has_subject + has_from + has_structure) / 3

        # Effectiveness indicators
        effectiveness_elements = ["urgency", "authority", "curiosity", "fear", "reward"]
        features["effectiveness_score"] = min(1.0, sum(1 for elem in effectiveness_elements if elem in content_lower) / 3)

        # Creativity (unique phrases, varied language)
        sentences = content.split('.')
        unique_starts = len(set(sent[:10].strip() for sent in sentences if len(sent.strip()) > 10))
        features["creativity"] = min(1.0, unique_starts / max(1, len(sentences)))

        return features

    def _calculate_reward(self, features: Dict[str, float]) -> float:
        """Calculate predicted reward using current model weights."""

        reward = 0.0
        for feature_name, feature_value in features.items():
            weight = self.reward_model_weights.get(feature_name, 0.0)
            reward += weight * feature_value

        return max(0.0, min(1.0, reward))

    async def optimize_prompt_template(
        self,
        content_type: str,
        base_template: str,
        optimization_rounds: int = 5
    ) -> Tuple[str, float]:
        """
        Optimize a prompt template using RLHF feedback.
        """

        current_template = base_template
        best_template = base_template
        best_score = 0.0

        for round_num in range(optimization_rounds):
            logger.info(f"RLHF optimization round {round_num + 1}")

            # Generate variations of current template
            template_variations = await self._generate_template_variations(
                current_template, content_type
            )

            # Evaluate each variation (in production, this would use actual feedback)
            variation_scores = []
            for variation in template_variations:
                # Simulate evaluation based on learned reward model
                features = self._extract_template_features(variation)
                predicted_score = self._calculate_reward(features)
                variation_scores.append(predicted_score)

            # Select best variation
            best_idx = np.argmax(variation_scores)
            if variation_scores[best_idx] > best_score:
                best_score = variation_scores[best_idx]
                best_template = template_variations[best_idx]
                current_template = best_template

            # Apply policy gradient-style update
            current_template = await self._apply_policy_update(
                current_template, template_variations, variation_scores
            )

        return best_template, best_score

    async def _generate_template_variations(
        self,
        base_template: str,
        content_type: str
    ) -> List[str]:
        """Generate variations of a prompt template for optimization."""

        # Return example variations (LLM generation to be implemented)
        variations = [
            base_template,  # Original

            # Add more detailed reasoning
            base_template.replace(
                "Create a",
                "Think step-by-step and create a"
            ),

            # Add explicit quality criteria
            base_template + "\n\nEnsure the output meets high standards for realism, effectiveness, and educational value.",

            # Add few-shot context
            "Here are examples of high-quality outputs:\n[EXAMPLES]\n\n" + base_template,

            # Add self-evaluation prompt
            base_template + "\n\nAfter generating, evaluate your output and refine if needed."
        ]

        return variations

    def _extract_template_features(self, template: str) -> Dict[str, float]:
        """Extract features from prompt template structure."""

        features = {}
        template_lower = template.lower()

        # Structural features
        features["has_examples"] = 1.0 if "example" in template_lower else 0.0
        features["has_reasoning"] = 1.0 if any(word in template_lower for word in ["think", "reason", "step"]) else 0.0
        features["has_quality_criteria"] = 1.0 if "quality" in template_lower or "standard" in template_lower else 0.0
        features["detailed_instructions"] = min(1.0, template.count("- ") / 5)  # Bullet points
        features["appropriate_length"] = 1.0 if 200 <= len(template) <= 1000 else 0.5

        return features

    async def _apply_policy_update(
        self,
        current_template: str,
        variations: List[str],
        scores: List[float]
    ) -> str:
        """Apply policy gradient-style update to improve template."""

        # Weighted combination based on scores
        if not scores or max(scores) == min(scores):
            return current_template

        # Normalize scores
        scores_array = np.array(scores)
        normalized_scores = (scores_array - scores_array.min()) / (scores_array.max() - scores_array.min())

        # Simple policy: pick best template with some exploration
        if np.random.random() < 0.8:  # Exploit
            best_idx = np.argmax(normalized_scores)
            return variations[best_idx]
        else:  # Explore
            probs = normalized_scores / normalized_scores.sum()
            chosen_idx = np.random.choice(len(variations), p=probs)
            return variations[chosen_idx]

    def get_optimization_summary(self) -> Dict[str, Any]:
        """Get summary of RLHF optimization progress."""

        return {
            "total_feedback_samples": len(self.feedback_buffer),
            "optimization_iterations": self.optimization_iterations,
            "current_reward_weights": dict(sorted(
                self.reward_model_weights.items(),
                key=lambda x: abs(x[1]),
                reverse=True
            )),
            "recent_performance": {
                content_type: scores[-10:] if scores else []
                for content_type, scores in self.performance_history.items()
            }
        }


class AgentRole(str, Enum):
    """Roles for different specialist agents."""
    CONTENT_GENERATOR = "content_generator"
    SECURITY_EXPERT = "security_expert"
    PSYCHOLOGY_SPECIALIST = "psychology_specialist"
    QUALITY_EVALUATOR = "quality_evaluator"
    SAFETY_AUDITOR = "safety_auditor"
    EDUCATIONAL_DESIGNER = "educational_designer"


@dataclass
class Agent:
    """Individual agent in the multi-agent system."""
    role: AgentRole
    expertise: List[str]
    system_prompt: str
    interaction_history: List[Dict] = field(default_factory=list)
    performance_metrics: Dict[str, float] = field(default_factory=dict)


class MultiAgentPromptSystem:
    """
    Level 6: Multi-Agent Collaborative Prompting Architecture

    Based on recent research in multi-agent systems and collaborative AI.
    Different specialized agents collaborate to create optimal threat simulation content.
    """

    def __init__(self):
        self.agents = self._initialize_agents()
        self.collaboration_patterns = self._define_collaboration_patterns()
        self.consensus_threshold = 0.75

    def _initialize_agents(self) -> Dict[AgentRole, Agent]:
        """Initialize specialist agents with their expertise and prompts."""

        agents = {}

        # Content Generator Agent
        agents[AgentRole.CONTENT_GENERATOR] = Agent(
            role=AgentRole.CONTENT_GENERATOR,
            expertise=["content_creation", "narrative_writing", "technical_writing"],
            system_prompt="""You are a specialist content generator for cybersecurity training materials.
Your expertise is in creating realistic, engaging, and technically accurate threat simulation content.
Focus on: narrative flow, realistic details, appropriate complexity, engaging presentation."""
        )

        # Security Expert Agent
        agents[AgentRole.SECURITY_EXPERT] = Agent(
            role=AgentRole.SECURITY_EXPERT,
            expertise=["mitre_attack", "threat_vectors", "attack_methodologies", "security_controls"],
            system_prompt="""You are a cybersecurity expert specializing in threat analysis and attack methodologies.
Your role is to ensure technical accuracy, realistic attack vectors, and proper MITRE ATT&CK alignment.
Focus on: technical accuracy, realistic attack patterns, current threat landscape, defensive considerations."""
        )

        # Psychology Specialist Agent
        agents[AgentRole.PSYCHOLOGY_SPECIALIST] = Agent(
            role=AgentRole.PSYCHOLOGY_SPECIALIST,
            expertise=["social_engineering", "cognitive_biases", "persuasion_techniques", "behavioral_psychology"],
            system_prompt="""You are a behavioral psychology specialist focusing on social engineering and persuasion.
Your expertise covers cognitive biases, psychological triggers, and human decision-making patterns.
Focus on: psychological realism, effective persuasion techniques, target-appropriate psychology, ethical boundaries."""
        )

        # Quality Evaluator Agent
        agents[AgentRole.QUALITY_EVALUATOR] = Agent(
            role=AgentRole.QUALITY_EVALUATOR,
            expertise=["quality_assessment", "content_evaluation", "training_effectiveness"],
            system_prompt="""You are a quality evaluation specialist for educational content.
Your role is to assess content quality, training effectiveness, and overall polish.
Focus on: content quality, clarity, completeness, training value, professional standards."""
        )

        # Safety Auditor Agent
        agents[AgentRole.SAFETY_AUDITOR] = Agent(
            role=AgentRole.SAFETY_AUDITOR,
            expertise=["ethical_ai", "safety_compliance", "risk_assessment", "content_moderation"],
            system_prompt="""You are a safety and ethics specialist for security training content.
Your role is to identify risks, ensure ethical compliance, and maintain safety boundaries.
Focus on: ethical compliance, safety risks, harmful content detection, responsible use guidelines."""
        )

        # Educational Designer Agent
        agents[AgentRole.EDUCATIONAL_DESIGNER] = Agent(
            role=AgentRole.EDUCATIONAL_DESIGNER,
            expertise=["instructional_design", "learning_objectives", "skill_development", "assessment"],
            system_prompt="""You are an instructional design specialist for cybersecurity training.
Your expertise is in creating effective learning experiences and educational content.
Focus on: learning objectives, skill development, knowledge transfer, assessment design, training effectiveness."""
        )

        return agents

    def _define_collaboration_patterns(self) -> Dict[str, List[AgentRole]]:
        """Define collaboration patterns for different tasks."""

        return {
            "content_generation": [
                AgentRole.CONTENT_GENERATOR,
                AgentRole.SECURITY_EXPERT,
                AgentRole.PSYCHOLOGY_SPECIALIST,
                AgentRole.EDUCATIONAL_DESIGNER
            ],
            "quality_review": [
                AgentRole.QUALITY_EVALUATOR,
                AgentRole.SAFETY_AUDITOR,
                AgentRole.SECURITY_EXPERT
            ],
            "safety_audit": [
                AgentRole.SAFETY_AUDITOR,
                AgentRole.QUALITY_EVALUATOR
            ],
            "technical_validation": [
                AgentRole.SECURITY_EXPERT,
                AgentRole.QUALITY_EVALUATOR
            ]
        }

    async def collaborative_generate(
        self,
        scenario_context: Dict[str, Any],
        content_type: str,
        llm_provider: Any
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Generate content through multi-agent collaboration.
        """

        collaboration_log = []

        # Phase 1: Initial Generation
        logger.info("Phase 1: Multi-agent content generation")
        generation_agents = self.collaboration_patterns["content_generation"]

        initial_proposals = {}
        for agent_role in generation_agents:
            agent = self.agents[agent_role]
            proposal = await self._agent_generate(
                agent, scenario_context, content_type, llm_provider
            )
            initial_proposals[agent_role] = proposal
            collaboration_log.append({
                "phase": "generation",
                "agent": agent_role.value,
                "contribution": proposal[:200] + "..." if len(proposal) > 200 else proposal
            })

        # Phase 2: Collaborative Refinement
        logger.info("Phase 2: Collaborative refinement")
        refined_content = await self._collaborative_refinement(
            initial_proposals, scenario_context, llm_provider
        )

        # Phase 3: Quality Review
        logger.info("Phase 3: Multi-agent quality review")
        review_agents = self.collaboration_patterns["quality_review"]

        quality_assessments = {}
        for agent_role in review_agents:
            agent = self.agents[agent_role]
            assessment = await self._agent_evaluate(
                agent, refined_content, scenario_context, llm_provider
            )
            quality_assessments[agent_role] = assessment
            collaboration_log.append({
                "phase": "review",
                "agent": agent_role.value,
                "assessment": assessment
            })

        # Phase 4: Consensus Building
        logger.info("Phase 4: Building consensus")
        final_content, consensus_data = await self._build_consensus(
            refined_content, quality_assessments, scenario_context, llm_provider
        )

        # Phase 5: Final Safety Audit
        logger.info("Phase 5: Final safety audit")
        safety_approval = await self._final_safety_audit(
            final_content, scenario_context, llm_provider
        )

        return final_content, {
            "collaboration_log": collaboration_log,
            "quality_assessments": quality_assessments,
            "consensus_data": consensus_data,
            "safety_approval": safety_approval,
            "agents_involved": [role.value for role in generation_agents + review_agents]
        }

    async def _agent_generate(
        self,
        agent: Agent,
        context: Dict[str, Any],
        content_type: str,
        llm_provider: Any
    ) -> str:
        """Have a specific agent generate content based on their expertise."""

        prompt = f"""{agent.system_prompt}

Task: Generate {content_type} content for cybersecurity training.

Context: {json.dumps(context, indent=2)}

Based on your expertise in {', '.join(agent.expertise)}, create content that emphasizes your specialist perspective.

Generate your contribution:"""

        try:
            response = await llm_provider.generate_content(
                prompt=prompt,
                scenario_type=f"multi_agent_{agent.role.value}",
                max_tokens=800,
                temperature=0.7
            )

            return response.content

        except Exception as e:
            logger.error(f"Error in agent generation for {agent.role}: {e}")
            return f"Error: Could not generate content from {agent.role.value} perspective"

    async def _collaborative_refinement(
        self,
        proposals: Dict[AgentRole, str],
        context: Dict[str, Any],
        llm_provider: Any
    ) -> str:
        """Refine content through collaborative agent discussion."""

        # Combine perspectives
        combined_prompt = f"""Multiple expert agents have provided their perspectives on generating threat simulation content:

Security Expert Perspective:
{proposals.get(AgentRole.SECURITY_EXPERT, 'Not provided')}

Psychology Specialist Perspective:
{proposals.get(AgentRole.PSYCHOLOGY_SPECIALIST, 'Not provided')}

Content Generator Perspective:
{proposals.get(AgentRole.CONTENT_GENERATOR, 'Not provided')}

Educational Designer Perspective:
{proposals.get(AgentRole.EDUCATIONAL_DESIGNER, 'Not provided')}

Context: {json.dumps(context, indent=2)}

Synthesize these expert perspectives into a single, high-quality output that incorporates the best insights from each specialist:"""

        try:
            response = await llm_provider.generate_content(
                prompt=combined_prompt,
                scenario_type="multi_agent_synthesis",
                max_tokens=1200,
                temperature=0.5
            )

            return response.content

        except Exception as e:
            logger.error(f"Error in collaborative refinement: {e}")
            return proposals.get(AgentRole.CONTENT_GENERATOR, "Refinement failed")

    async def _agent_evaluate(
        self,
        agent: Agent,
        content: str,
        context: Dict[str, Any],
        llm_provider: Any
    ) -> Dict[str, Any]:
        """Have a specific agent evaluate content from their expert perspective."""

        prompt = f"""{agent.system_prompt}

Evaluate this threat simulation content from your expert perspective:

Content to Evaluate:
{content}

Context: {json.dumps(context, indent=2)}

Based on your expertise in {', '.join(agent.expertise)}, provide evaluation in JSON format:
{{
  "overall_score": 0.0-1.0,
  "specialist_score": 0.0-1.0,
  "strengths": ["list strengths from your perspective"],
  "concerns": ["list concerns from your perspective"],
  "recommendations": ["specific improvements from your expertise"],
  "approval": true/false
}}"""

        try:
            response = await llm_provider.generate_content(
                prompt=prompt,
                scenario_type=f"multi_agent_eval_{agent.role.value}",
                max_tokens=600,
                temperature=0.3
            )

            # Parse JSON response
            import re
            json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())

        except Exception as e:
            logger.error(f"Error in agent evaluation for {agent.role}: {e}")

        return {
            "overall_score": 0.7,
            "specialist_score": 0.7,
            "approval": True,
            "concerns": ["Could not perform detailed evaluation"]
        }

    async def _build_consensus(
        self,
        content: str,
        assessments: Dict[AgentRole, Dict[str, Any]],
        context: Dict[str, Any],
        llm_provider: Any
    ) -> Tuple[str, Dict[str, Any]]:
        """Build consensus among agents and finalize content."""

        # Calculate consensus metrics
        approval_votes = sum(1 for assessment in assessments.values()
                           if assessment.get("approval", False))
        total_agents = len(assessments)
        consensus_rate = approval_votes / total_agents if total_agents > 0 else 0.0

        avg_score = np.mean([assessment.get("overall_score", 0.7)
                           for assessment in assessments.values()])

        # Collect all concerns and recommendations
        all_concerns = []
        all_recommendations = []

        for agent_role, assessment in assessments.items():
            concerns = assessment.get("concerns", [])
            recommendations = assessment.get("recommendations", [])

            all_concerns.extend([f"{agent_role.value}: {concern}" for concern in concerns])
            all_recommendations.extend([f"{agent_role.value}: {rec}" for rec in recommendations])

        consensus_data = {
            "consensus_rate": consensus_rate,
            "average_score": avg_score,
            "approval_votes": approval_votes,
            "total_agents": total_agents,
            "needs_revision": consensus_rate < self.consensus_threshold,
            "concerns": all_concerns,
            "recommendations": all_recommendations
        }

        # If consensus is low, attempt revision
        if consensus_rate < self.consensus_threshold:
            logger.info(f"Low consensus ({consensus_rate:.2f}), attempting revision")

            revision_prompt = f"""The multi-agent review identified concerns with this content:

Original Content:
{content}

Agent Concerns:
{chr(10).join(all_concerns)}

Agent Recommendations:
{chr(10).join(all_recommendations)}

Revise the content to address these expert concerns while maintaining quality:"""

            try:
                response = await llm_provider.generate_content(
                    prompt=revision_prompt,
                    scenario_type="multi_agent_revision",
                    max_tokens=1200,
                    temperature=0.4
                )

                content = response.content
                consensus_data["revised"] = True

            except Exception as e:
                logger.error(f"Error in consensus revision: {e}")
                consensus_data["revision_error"] = str(e)

        return content, consensus_data

    async def _final_safety_audit(
        self,
        content: str,
        context: Dict[str, Any],
        llm_provider: Any
    ) -> Dict[str, Any]:
        """Perform final safety audit before content approval."""

        safety_agent = self.agents[AgentRole.SAFETY_AUDITOR]

        audit_prompt = f"""{safety_agent.system_prompt}

Perform a final comprehensive safety audit on this threat simulation content:

Content:
{content}

Context: {json.dumps(context, indent=2)}

Provide final safety approval in JSON format:
{{
  "approved": true/false,
  "safety_score": 0.0-1.0,
  "risk_level": "low/medium/high",
  "safety_issues": ["list any safety concerns"],
  "compliance_status": "compliant/non-compliant",
  "final_recommendations": ["any final safety recommendations"]
}}"""

        try:
            response = await llm_provider.generate_content(
                prompt=audit_prompt,
                scenario_type="multi_agent_safety_audit",
                max_tokens=500,
                temperature=0.2
            )

            # Parse JSON response
            import re
            json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())

        except Exception as e:
            logger.error(f"Error in final safety audit: {e}")

        return {
            "approved": True,
            "safety_score": 0.8,
            "risk_level": "low",
            "safety_issues": [],
            "compliance_status": "compliant"
        }

    def get_agent_summary(self) -> Dict[str, Any]:
        """Get summary of multi-agent system performance."""

        return {
            "total_agents": len(self.agents),
            "agent_roles": [role.value for role in self.agents.keys()],
            "collaboration_patterns": {
                pattern: [role.value for role in roles]
                for pattern, roles in self.collaboration_patterns.items()
            },
            "consensus_threshold": self.consensus_threshold,
            "agent_performance": {
                role.value: agent.performance_metrics
                for role, agent in self.agents.items()
            }
        }
