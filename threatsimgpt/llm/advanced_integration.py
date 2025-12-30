"""Advanced Prompt Engineering Integration for ThreatSimGPT.

This module integrates all 6 levels of advanced prompt engineering techniques
into a unified system for optimal threat simulation content generation.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple, Union
from enum import Enum
from dataclasses import dataclass

from .advanced_prompts import ChainOfThoughtPromptEngine, FewShotLearningEngine
from .advanced_reasoning import TreeOfThoughtsEngine, MetaLearningEngine
from .rlhf_multiagent import RLHFOptimizer, MultiAgentPromptSystem, AgentRole
from .models import ContentType, PromptContext

logger = logging.getLogger(__name__)


class AdvancedPromptingLevel(str, Enum):
    """Available advanced prompting levels."""
    BASIC = "basic"  # Current template-based system
    CHAIN_OF_THOUGHT = "chain_of_thought"  # Level 1
    FEW_SHOT = "few_shot"  # Level 2
    TREE_OF_THOUGHTS = "tree_of_thoughts"  # Level 3
    META_LEARNING = "meta_learning"  # Level 4
    RLHF_OPTIMIZED = "rlhf_optimized"  # Level 5
    MULTI_AGENT = "multi_agent"  # Level 6


@dataclass
class AdvancedGenerationResult:
    """Result from advanced prompt engineering generation."""
    content: str
    technique_used: AdvancedPromptingLevel
    quality_score: float
    generation_metadata: Dict[str, Any]
    reasoning_trace: Optional[List[str]] = None
    agent_contributions: Optional[Dict[str, str]] = None
    optimization_history: Optional[List[Dict]] = None


class AdvancedPromptEngineering:
    """
    Unified Advanced Prompt Engineering System for ThreatSimGPT

    Integrates all 6 levels of advanced prompt engineering:
    1. Chain-of-Thought (CoT) prompting
    2. Few-Shot Learning with dynamic examples
    3. Tree of Thoughts (ToT) for complex reasoning
    4. Meta-Learning and Self-Refinement
    5. RLHF optimization based on human feedback
    6. Multi-Agent collaborative generation
    """

    def __init__(self, default_level: AdvancedPromptingLevel = AdvancedPromptingLevel.CHAIN_OF_THOUGHT):
        self.default_level = default_level

        # Initialize all engines
        self.cot_engine = ChainOfThoughtPromptEngine()
        self.few_shot_engine = FewShotLearningEngine()
        self.tot_engine = TreeOfThoughtsEngine()
        self.meta_engine = MetaLearningEngine()
        self.rlhf_optimizer = RLHFOptimizer()
        self.multi_agent_system = MultiAgentPromptSystem()

        # Performance tracking
        self.technique_performance: Dict[AdvancedPromptingLevel, List[float]] = {}
        self.generation_count = 0

    async def generate_advanced_content(
        self,
        context: PromptContext,
        content_type: ContentType,
        llm_provider: Any,
        technique: Optional[AdvancedPromptingLevel] = None,
        **kwargs
    ) -> AdvancedGenerationResult:
        """
        Generate content using advanced prompt engineering techniques.

        Args:
            context: Prompt context with scenario details
            content_type: Type of content to generate
            llm_provider: LLM provider instance
            technique: Specific technique to use (or auto-select)
            **kwargs: Additional parameters for specific techniques

        Returns:
            Advanced generation result with content and metadata
        """

        # Auto-select technique if not specified
        if technique is None:
            technique = self._select_optimal_technique(context, content_type)

        logger.info(f"Generating content using {technique.value} technique")

        try:
            if technique == AdvancedPromptingLevel.CHAIN_OF_THOUGHT:
                return await self._generate_with_cot(context, content_type, llm_provider, **kwargs)

            elif technique == AdvancedPromptingLevel.FEW_SHOT:
                return await self._generate_with_few_shot(context, content_type, llm_provider, **kwargs)

            elif technique == AdvancedPromptingLevel.TREE_OF_THOUGHTS:
                return await self._generate_with_tot(context, content_type, llm_provider, **kwargs)

            elif technique == AdvancedPromptingLevel.META_LEARNING:
                return await self._generate_with_meta_learning(context, content_type, llm_provider, **kwargs)

            elif technique == AdvancedPromptingLevel.RLHF_OPTIMIZED:
                return await self._generate_with_rlhf(context, content_type, llm_provider, **kwargs)

            elif technique == AdvancedPromptingLevel.MULTI_AGENT:
                return await self._generate_with_multi_agent(context, content_type, llm_provider, **kwargs)

            else:  # BASIC fallback
                return await self._generate_basic(context, content_type, llm_provider, **kwargs)

        except Exception as e:
            logger.error(f"Error in advanced generation with {technique.value}: {e}")
            # Fallback to simpler technique
            if technique != AdvancedPromptingLevel.BASIC:
                return await self._generate_basic(context, content_type, llm_provider, **kwargs)
            raise

    def _select_optimal_technique(
        self,
        context: PromptContext,
        content_type: ContentType
    ) -> AdvancedPromptingLevel:
        """
        Automatically select the most appropriate technique based on context.
        """

        # Consider complexity factors
        complexity_score = 0

        # Difficulty level
        complexity_score += context.difficulty_level / 10.0

        # Target sophistication
        if context.target_technical_level == "high":
            complexity_score += 0.3
        elif context.target_technical_level == "low":
            complexity_score -= 0.2

        # Security awareness
        complexity_score += context.security_awareness_level / 20.0

        # Content type complexity
        complex_content_types = [ContentType.PRETEXT_SCENARIO, ContentType.VOICE_SCRIPT]
        if content_type in complex_content_types:
            complexity_score += 0.2

        # Historical performance
        best_technique = self._get_best_performing_technique(content_type)
        if best_technique and complexity_score > 0.6:
            return best_technique

        # Technique selection based on complexity
        if complexity_score >= 0.8:
            return AdvancedPromptingLevel.MULTI_AGENT
        elif complexity_score >= 0.7:
            return AdvancedPromptingLevel.TREE_OF_THOUGHTS
        elif complexity_score >= 0.6:
            return AdvancedPromptingLevel.META_LEARNING
        elif complexity_score >= 0.4:
            return AdvancedPromptingLevel.FEW_SHOT
        else:
            return AdvancedPromptingLevel.CHAIN_OF_THOUGHT

    def _get_best_performing_technique(
        self,
        content_type: ContentType
    ) -> Optional[AdvancedPromptingLevel]:
        """Get the best performing technique for this content type."""

        if not self.technique_performance:
            return None

        # Calculate average performance for each technique
        avg_performance = {}
        for technique, scores in self.technique_performance.items():
            if scores:
                avg_performance[technique] = sum(scores) / len(scores)

        if not avg_performance:
            return None

        # Return technique with highest average performance
        return max(avg_performance.items(), key=lambda x: x[1])[0]

    async def _generate_with_cot(
        self,
        context: PromptContext,
        content_type: ContentType,
        llm_provider: Any,
        **kwargs
    ) -> AdvancedGenerationResult:
        """Generate content using Chain-of-Thought prompting."""

        # Generate CoT prompt
        cot_prompt = self.cot_engine.generate_cot_prompt(content_type, context)

        # Generate content
        response = await llm_provider.generate_content(
            prompt=cot_prompt,
            scenario_type=f"cot_{content_type.value}",
            max_tokens=kwargs.get("max_tokens", 1500),
            temperature=kwargs.get("temperature", 0.7)
        )

        # Extract reasoning chain
        reasoning_chain = self.cot_engine.extract_reasoning_chain(response.content)

        # Calculate quality score based on reasoning depth
        quality_score = min(1.0, 0.6 + (len(reasoning_chain) * 0.08))

        return AdvancedGenerationResult(
            content=response.content,
            technique_used=AdvancedPromptingLevel.CHAIN_OF_THOUGHT,
            quality_score=quality_score,
            generation_metadata={
                "reasoning_steps": len(reasoning_chain),
                "prompt_length": len(cot_prompt),
                "response_length": len(response.content)
            },
            reasoning_trace=[step.description for step in reasoning_chain]
        )

    async def _generate_with_few_shot(
        self,
        context: PromptContext,
        content_type: ContentType,
        llm_provider: Any,
        **kwargs
    ) -> AdvancedGenerationResult:
        """Generate content using Few-Shot Learning."""

        # Generate few-shot prompt
        few_shot_prompt = self.few_shot_engine.generate_few_shot_prompt(content_type, context)

        # Generate content
        response = await llm_provider.generate_content(
            prompt=few_shot_prompt,
            scenario_type=f"few_shot_{content_type.value}",
            max_tokens=kwargs.get("max_tokens", 1200),
            temperature=kwargs.get("temperature", 0.6)
        )

        # Get selected examples info
        selected_examples = self.few_shot_engine.select_best_examples(context, num_examples=2)

        quality_score = 0.7 + (len(selected_examples) * 0.1)  # Base + example bonus

        return AdvancedGenerationResult(
            content=response.content,
            technique_used=AdvancedPromptingLevel.FEW_SHOT,
            quality_score=quality_score,
            generation_metadata={
                "examples_used": len(selected_examples),
                "example_quality": [ex.quality_score for ex in selected_examples],
                "prompt_length": len(few_shot_prompt)
            }
        )

    async def _generate_with_tot(
        self,
        context: PromptContext,
        content_type: ContentType,
        llm_provider: Any,
        **kwargs
    ) -> AdvancedGenerationResult:
        """Generate content using Tree of Thoughts."""

        # Convert context to scenario format
        scenario_data = {
            "name": f"{context.threat_type} scenario",
            "target_profile": {
                "role": context.target_role,
                "department": context.target_department,
                "technical_level": context.target_technical_level
            },
            "difficulty_level": context.difficulty_level
        }

        # Generate with ToT
        content, reasoning_path = await self.tot_engine.generate_with_tot(
            scenario_data, content_type.value, llm_provider
        )

        # Calculate quality based on reasoning depth and scores
        path_scores = [node.score for node in reasoning_path if node.score > 0]
        quality_score = max(path_scores) if path_scores else 0.7

        return AdvancedGenerationResult(
            content=content,
            technique_used=AdvancedPromptingLevel.TREE_OF_THOUGHTS,
            quality_score=quality_score,
            generation_metadata={
                "reasoning_depth": len(reasoning_path),
                "explored_nodes": sum(1 for node in reasoning_path if node.score > 0),
                "best_path_score": max(path_scores) if path_scores else 0.0
            },
            reasoning_trace=[f"{node.content} (score: {node.score:.2f})" for node in reasoning_path]
        )

    async def _generate_with_meta_learning(
        self,
        context: PromptContext,
        content_type: ContentType,
        llm_provider: Any,
        **kwargs
    ) -> AdvancedGenerationResult:
        """Generate content using Meta-Learning and Self-Refinement."""

        # Convert context to scenario format
        scenario_data = {
            "content_type": content_type.value,
            "target_profile": {
                "role": context.target_role,
                "department": context.target_department
            },
            "difficulty_level": context.difficulty_level,
            "threat_type": context.threat_type
        }

        # Generate with meta-learning
        content, metadata = await self.meta_engine.meta_generate_with_refinement(
            scenario_data, content_type.value, llm_provider
        )

        final_evaluation = metadata.get("final_evaluation", {})
        quality_score = final_evaluation.get("overall_score", 0.7)

        return AdvancedGenerationResult(
            content=content,
            technique_used=AdvancedPromptingLevel.META_LEARNING,
            quality_score=quality_score,
            generation_metadata=metadata,
            optimization_history=metadata.get("refinement_history", [])
        )

    async def _generate_with_rlhf(
        self,
        context: PromptContext,
        content_type: ContentType,
        llm_provider: Any,
        **kwargs
    ) -> AdvancedGenerationResult:
        """Generate content using RLHF-optimized prompts."""

        # Use optimized template (learned templates to be implemented)
        base_template = f"Generate high-quality {content_type.value} content for threat simulation training."

        # Apply RLHF optimizations
        optimized_template, optimization_score = await self.rlhf_optimizer.optimize_prompt_template(
            content_type.value, base_template, optimization_rounds=3
        )

        # Generate content with optimized prompt
        enhanced_prompt = f"""{optimized_template}

Context:
- Target: {context.target_role} in {context.target_department}
- Technical Level: {context.target_technical_level}
- Security Awareness: {context.security_awareness_level}/10
- Difficulty: {context.difficulty_level}/10

Generate content:"""

        response = await llm_provider.generate_content(
            prompt=enhanced_prompt,
            scenario_type=f"rlhf_{content_type.value}",
            max_tokens=kwargs.get("max_tokens", 1200),
            temperature=kwargs.get("temperature", 0.5)
        )

        return AdvancedGenerationResult(
            content=response.content,
            technique_used=AdvancedPromptingLevel.RLHF_OPTIMIZED,
            quality_score=optimization_score,
            generation_metadata={
                "optimization_score": optimization_score,
                "template_optimized": True,
                "rlhf_summary": self.rlhf_optimizer.get_optimization_summary()
            }
        )

    async def _generate_with_multi_agent(
        self,
        context: PromptContext,
        content_type: ContentType,
        llm_provider: Any,
        **kwargs
    ) -> AdvancedGenerationResult:
        """Generate content using Multi-Agent collaboration."""

        # Convert context to scenario format
        scenario_data = {
            "target_profile": {
                "role": context.target_role,
                "department": context.target_department,
                "technical_level": context.target_technical_level,
                "security_awareness": context.security_awareness_level
            },
            "threat_type": context.threat_type,
            "difficulty_level": context.difficulty_level,
            "psychological_triggers": context.psychological_triggers,
            "social_engineering_tactics": context.social_engineering_tactics
        }

        # Generate with multi-agent system
        content, collaboration_data = await self.multi_agent_system.collaborative_generate(
            scenario_data, content_type.value, llm_provider
        )

        # Calculate quality based on consensus
        consensus_data = collaboration_data.get("consensus_data", {})
        quality_score = consensus_data.get("average_score", 0.8)

        # Extract agent contributions
        agent_contributions = {}
        for log_entry in collaboration_data.get("collaboration_log", []):
            if log_entry.get("phase") == "generation":
                agent_contributions[log_entry["agent"]] = log_entry["contribution"]

        return AdvancedGenerationResult(
            content=content,
            technique_used=AdvancedPromptingLevel.MULTI_AGENT,
            quality_score=quality_score,
            generation_metadata=collaboration_data,
            agent_contributions=agent_contributions
        )

    async def _generate_basic(
        self,
        context: PromptContext,
        content_type: ContentType,
        llm_provider: Any,
        **kwargs
    ) -> AdvancedGenerationResult:
        """Generate content using basic template-based approach (fallback)."""

        basic_prompt = f"""Generate {content_type.value} content for cybersecurity training.

Target Profile:
- Role: {context.target_role}
- Department: {context.target_department}
- Technical Level: {context.target_technical_level}
- Security Awareness: {context.security_awareness_level}/10

Requirements:
- Appropriate for training environment
- Realistic but safe content
- Educational value included

Generate the content:"""

        response = await llm_provider.generate_content(
            prompt=basic_prompt,
            scenario_type=f"basic_{content_type.value}",
            max_tokens=kwargs.get("max_tokens", 1000),
            temperature=kwargs.get("temperature", 0.7)
        )

        return AdvancedGenerationResult(
            content=response.content,
            technique_used=AdvancedPromptingLevel.BASIC,
            quality_score=0.6,  # Base quality score
            generation_metadata={"fallback_used": True}
        )

    def record_performance(
        self,
        technique: AdvancedPromptingLevel,
        quality_score: float
    ) -> None:
        """Record performance for technique optimization."""

        if technique not in self.technique_performance:
            self.technique_performance[technique] = []

        self.technique_performance[technique].append(quality_score)

        # Keep only recent performance data
        if len(self.technique_performance[technique]) > 100:
            self.technique_performance[technique] = self.technique_performance[technique][-100:]

        self.generation_count += 1

        logger.info(f"Recorded performance for {technique.value}: {quality_score:.3f}")

    def get_system_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of the advanced prompt engineering system."""

        avg_performance = {}
        for technique, scores in self.technique_performance.items():
            if scores:
                avg_performance[technique.value] = {
                    "average_score": sum(scores) / len(scores),
                    "total_generations": len(scores),
                    "best_score": max(scores),
                    "recent_trend": scores[-10:] if len(scores) >= 10 else scores
                }

        return {
            "total_generations": self.generation_count,
            "available_techniques": [level.value for level in AdvancedPromptingLevel],
            "default_technique": self.default_level.value,
            "technique_performance": avg_performance,
            "engines_initialized": {
                "chain_of_thought": bool(self.cot_engine),
                "few_shot": bool(self.few_shot_engine),
                "tree_of_thoughts": bool(self.tot_engine),
                "meta_learning": bool(self.meta_engine),
                "rlhf_optimizer": bool(self.rlhf_optimizer),
                "multi_agent": bool(self.multi_agent_system)
            },
            "rlhf_summary": self.rlhf_optimizer.get_optimization_summary(),
            "multi_agent_summary": self.multi_agent_system.get_agent_summary()
        }


# Example usage and testing functions
async def demonstrate_advanced_techniques():
    """Demonstrate all advanced prompting techniques.

    NOTE: This function is for documentation and demonstration purposes only.
    In production, use a properly configured LLM provider from the providers module.

    Example with real provider:
        from threatsimgpt.llm.providers.openai_provider import OpenAIProvider
        provider = OpenAIProvider({"api_key": "your-key", "model": "gpt-4"})
        await provider.initialize()
    """

    # Demonstration-only provider (returns placeholder content for testing)
    class DemoLLMProvider:
        """Demonstration provider for testing - NOT for production use."""
        async def generate_content(self, prompt, scenario_type, max_tokens=1000, temperature=0.7):
            class DemoResponse:
                def __init__(self):
                    self.content = f"[DEMO] Generated content for {scenario_type} scenario"
            return DemoResponse()

    # Initialize system
    advanced_system = AdvancedPromptEngineering()
    demo_llm = DemoLLMProvider()

    # Create test context
    test_context = PromptContext(
        threat_type="phishing",
        delivery_vector="email",
        difficulty_level=7,
        target_role="CEO",
        target_department="executive",
        target_seniority="senior",
        target_technical_level="moderate",
        target_industry="technology",
        security_awareness_level=6,
        psychological_triggers=["authority", "urgency"],
        social_engineering_tactics=["impersonation", "pretext"],
        mitre_techniques=["T1566.001"],
        urgency_level=8,
        tone="professional",
        company_name="TechCorp Inc."
    )

    # Test each technique
    techniques_to_test = [
        AdvancedPromptingLevel.CHAIN_OF_THOUGHT,
        AdvancedPromptingLevel.FEW_SHOT,
        AdvancedPromptingLevel.TREE_OF_THOUGHTS,
        AdvancedPromptingLevel.META_LEARNING,
        AdvancedPromptingLevel.MULTI_AGENT
    ]

    results = {}

    for technique in techniques_to_test:
        try:
            result = await advanced_system.generate_advanced_content(
                context=test_context,
                content_type=ContentType.EMAIL_PHISHING,
                llm_provider=demo_llm,
                technique=technique
            )

            results[technique.value] = {
                "success": True,
                "quality_score": result.quality_score,
                "content_length": len(result.content),
                "metadata": result.generation_metadata
            }

            # Record performance
            advanced_system.record_performance(technique, result.quality_score)

        except Exception as e:
            results[technique.value] = {
                "success": False,
                "error": str(e)
            }

    return results, advanced_system.get_system_summary()


if __name__ == "__main__":
    # Run demonstration
    results, summary = asyncio.run(demonstrate_advanced_techniques())
    print("Advanced Prompt Engineering Demonstration Results:")
    print(json.dumps(results, indent=2))
    print("\nSystem Summary:")
    print(json.dumps(summary, indent=2))
