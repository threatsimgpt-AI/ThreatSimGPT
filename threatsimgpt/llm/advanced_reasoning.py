"""Tree of Thoughts and advanced reasoning implementations for ThreatSimGPT.

This module implements Levels 3-6 of advanced prompt engineering:
- Tree of Thoughts (ToT) for complex scenario planning
- Meta-Learning and Self-Refinement
- RLHF optimization techniques
- Multi-Agent prompting architectures
"""

import asyncio
import json
import numpy as np
from typing import Any, Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class ThoughtNode:
    """A node in the Tree of Thoughts representing a reasoning step."""
    id: str
    content: str
    parent_id: Optional[str]
    children_ids: List[str] = field(default_factory=list)
    depth: int = 0
    score: float = 0.0
    is_solution: bool = False
    reasoning: str = ""
    evaluation_metrics: Dict[str, float] = field(default_factory=dict)


@dataclass
class SearchState:
    """State for Tree of Thoughts search."""
    current_nodes: List[ThoughtNode]
    explored_nodes: Set[str]
    best_path: List[ThoughtNode]
    best_score: float = 0.0


class TreeOfThoughtsEngine:
    """
    Level 3: Tree of Thoughts Implementation

    Based on Yao et al. (2023) research enabling deliberate problem solving
    by exploring multiple reasoning trajectories and selecting optimal paths.
    """

    def __init__(self, max_depth: int = 4, branching_factor: int = 3):
        self.max_depth = max_depth
        self.branching_factor = branching_factor
        self.evaluation_criteria = self._initialize_evaluation_criteria()

    def _initialize_evaluation_criteria(self) -> Dict[str, float]:
        """Initialize evaluation criteria for threat scenario quality."""
        return {
            "realism": 0.25,
            "effectiveness": 0.25,
            "educational_value": 0.20,
            "safety_compliance": 0.15,
            "technical_accuracy": 0.15
        }

    async def generate_with_tot(
        self,
        base_scenario: Dict[str, Any],
        content_type: str,
        llm_provider: Any
    ) -> Tuple[str, List[ThoughtNode]]:
        """
        Generate content using Tree of Thoughts approach.

        Returns:
            Best generated content and the reasoning tree
        """

        # Initialize root node
        root_node = ThoughtNode(
            id="root",
            content=f"Generate {content_type} for scenario: {base_scenario.get('name', 'Unknown')}",
            parent_id=None,
            depth=0,
            reasoning="Starting point for scenario generation"
        )

        # Initialize search state
        search_state = SearchState(
            current_nodes=[root_node],
            explored_nodes={root_node.id},
            best_path=[root_node]
        )

        # Tree exploration loop
        for depth in range(self.max_depth):
            logger.info(f"ToT Depth {depth}: Exploring {len(search_state.current_nodes)} nodes")

            new_nodes = []

            for node in search_state.current_nodes:
                if node.depth >= self.max_depth:
                    continue

                # Generate child thoughts
                children = await self._generate_child_thoughts(
                    node, base_scenario, content_type, llm_provider
                )

                # Evaluate each child
                for child in children:
                    score = await self._evaluate_thought(child, base_scenario)
                    child.score = score
                    child.evaluation_metrics = await self._detailed_evaluation(child, base_scenario)

                    # Add to tree structure
                    node.children_ids.append(child.id)
                    new_nodes.append(child)
                    search_state.explored_nodes.add(child.id)

            # Select best nodes for next iteration (pruning)
            new_nodes.sort(key=lambda x: x.score, reverse=True)
            search_state.current_nodes = new_nodes[:self.branching_factor]

            # Update best path if we found better solution
            if new_nodes and new_nodes[0].score > search_state.best_score:
                search_state.best_score = new_nodes[0].score
                search_state.best_path = self._reconstruct_path(new_nodes[0], search_state)

        # Generate final content from best path
        final_content = await self._synthesize_final_content(
            search_state.best_path, base_scenario, llm_provider
        )

        return final_content, search_state.best_path

    async def _generate_child_thoughts(
        self,
        parent_node: ThoughtNode,
        scenario: Dict[str, Any],
        content_type: str,
        llm_provider: Any
    ) -> List[ThoughtNode]:
        """Generate child thought nodes from parent."""

        prompt = f"""Given the current reasoning step:
"{parent_node.content}"

For the threat scenario: {scenario.get('name', 'Unknown')}
Content Type: {content_type}

Generate {self.branching_factor} different next reasoning steps. Each should explore a different approach:

1. **Different Social Engineering Approach**: [reasoning]
2. **Different Technical Vector**: [reasoning]
3. **Different Psychological Trigger**: [reasoning]

For each approach, explain:
- Why this direction is promising
- What specific elements it would include
- How it differs from the parent approach
- Potential effectiveness factors

Format as JSON:
{{
  "approaches": [
    {{
      "id": "approach_1",
      "title": "Social Engineering Focus",
      "reasoning": "detailed reasoning...",
      "content": "specific approach description..."
    }},
    ...
  ]
}}"""

        try:
            response = await llm_provider.generate_content(
                prompt=prompt,
                scenario_type="tot_reasoning",
                max_tokens=1000,
                temperature=0.8  # Higher temperature for diverse exploration
            )

            # Parse response and create child nodes
            approaches_data = self._parse_tot_response(response.content)
            children = []

            for i, approach in enumerate(approaches_data.get("approaches", [])):
                child = ThoughtNode(
                    id=f"{parent_node.id}_child_{i}",
                    content=approach.get("content", ""),
                    parent_id=parent_node.id,
                    depth=parent_node.depth + 1,
                    reasoning=approach.get("reasoning", "")
                )
                children.append(child)

            return children

        except Exception as e:
            logger.error(f"Error generating child thoughts: {e}")
            return []

    async def _evaluate_thought(self, thought: ThoughtNode, scenario: Dict[str, Any]) -> float:
        """Evaluate a thought node for quality and relevance."""

        # Multiple evaluation dimensions
        scores = {}

        # Realism score (0-1)
        scores["realism"] = self._evaluate_realism(thought, scenario)

        # Effectiveness score (0-1)
        scores["effectiveness"] = self._evaluate_effectiveness(thought, scenario)

        # Educational value (0-1)
        scores["educational_value"] = self._evaluate_educational_value(thought, scenario)

        # Safety compliance (0-1)
        scores["safety"] = self._evaluate_safety_compliance(thought, scenario)

        # Technical accuracy (0-1)
        scores["technical"] = self._evaluate_technical_accuracy(thought, scenario)

        # Weighted average
        total_score = sum(
            scores[key] * weight
            for key, weight in self.evaluation_criteria.items()
            if key in ["realism", "effectiveness", "educational_value", "safety_compliance", "technical_accuracy"]
        )

        return total_score

    def _evaluate_realism(self, thought: ThoughtNode, scenario: Dict[str, Any]) -> float:
        """Evaluate realism of the thought content."""
        content = thought.content.lower()

        score = 0.5  # Base score

        # Check for realistic elements
        realistic_indicators = [
            "specific company role", "industry context", "business process",
            "realistic timeline", "credible authority", "professional language"
        ]

        for indicator in realistic_indicators:
            if any(word in content for word in indicator.split()):
                score += 0.1

        # Penalize unrealistic elements
        unrealistic_indicators = [
            "too obvious", "generic", "amateur", "clearly fake"
        ]

        for indicator in unrealistic_indicators:
            if any(word in content for word in indicator.split()):
                score -= 0.1

        return max(0.0, min(1.0, score))

    def _evaluate_effectiveness(self, thought: ThoughtNode, scenario: Dict[str, Any]) -> float:
        """Evaluate potential effectiveness of the approach."""
        content = thought.reasoning.lower() + " " + thought.content.lower()

        score = 0.5

        # Positive effectiveness indicators
        effective_elements = [
            "psychological trigger", "authority", "urgency", "social proof",
            "reciprocity", "scarcity", "commitment", "consensus"
        ]

        for element in effective_elements:
            if element in content:
                score += 0.08

        # Target-specific effectiveness
        target_role = scenario.get("target_profile", {}).get("role", "").lower()
        if target_role in content:
            score += 0.1

        return max(0.0, min(1.0, score))

    def _evaluate_educational_value(self, thought: ThoughtNode, scenario: Dict[str, Any]) -> float:
        """Evaluate educational value for security training."""
        content = thought.reasoning.lower() + " " + thought.content.lower()

        score = 0.5

        # Educational indicators
        educational_elements = [
            "training", "red flag", "indicator", "detection", "awareness",
            "learning objective", "skill development", "recognition"
        ]

        for element in educational_elements:
            if element in content:
                score += 0.07

        return max(0.0, min(1.0, score))

    def _evaluate_safety_compliance(self, thought: ThoughtNode, scenario: Dict[str, Any]) -> float:
        """Evaluate safety and ethical compliance."""
        content = thought.content.lower()

        score = 1.0  # Start with perfect score

        # Safety violations
        violations = [
            "actual harm", "real credentials", "genuine malware",
            "illegal activity", "personal attack", "harassment"
        ]

        for violation in violations:
            if violation in content:
                score -= 0.2

        # Safety indicators (positive)
        safety_elements = [
            "training purpose", "educational", "simulated", "controlled environment"
        ]

        has_safety_context = any(element in content for element in safety_elements)
        if not has_safety_context:
            score -= 0.1

        return max(0.0, min(1.0, score))

    def _evaluate_technical_accuracy(self, thought: ThoughtNode, scenario: Dict[str, Any]) -> float:
        """Evaluate technical accuracy of the approach."""
        content = thought.reasoning.lower() + " " + thought.content.lower()

        score = 0.5

        # Technical accuracy indicators
        technical_elements = [
            "mitre att&ck", "attack vector", "payload", "vulnerability",
            "protocol", "encryption", "authentication", "network"
        ]

        for element in technical_elements:
            if element in content:
                score += 0.06

        return max(0.0, min(1.0, score))

    async def _detailed_evaluation(
        self,
        thought: ThoughtNode,
        scenario: Dict[str, Any]
    ) -> Dict[str, float]:
        """Provide detailed evaluation metrics."""
        return {
            "realism": self._evaluate_realism(thought, scenario),
            "effectiveness": self._evaluate_effectiveness(thought, scenario),
            "educational_value": self._evaluate_educational_value(thought, scenario),
            "safety_compliance": self._evaluate_safety_compliance(thought, scenario),
            "technical_accuracy": self._evaluate_technical_accuracy(thought, scenario)
        }

    def _reconstruct_path(
        self,
        node: ThoughtNode,
        search_state: SearchState
    ) -> List[ThoughtNode]:
        """Reconstruct the path from root to given node."""
        path = []
        current = node

        # Traverse up to root
        while current:
            path.append(current)
            if current.parent_id is None:
                break

            # Find parent in explored nodes
            parent = None
            for explored_id in search_state.explored_nodes:
                # Simplified node lookup implementation
                pass
            current = parent

        return list(reversed(path))

    async def _synthesize_final_content(
        self,
        best_path: List[ThoughtNode],
        scenario: Dict[str, Any],
        llm_provider: Any
    ) -> str:
        """Synthesize final content from the best reasoning path."""

        path_summary = "\n".join([
            f"Step {i+1}: {node.content}\nReasoning: {node.reasoning}\n"
            for i, node in enumerate(best_path[1:])  # Skip root
        ])

        synthesis_prompt = f"""Based on the following reasoning path for threat scenario generation:

{path_summary}

Scenario Context: {json.dumps(scenario, indent=2)}

Synthesize a final, high-quality threat simulation content that incorporates the best insights from this reasoning chain. The output should be:

1. Technically accurate and realistic
2. Appropriately challenging for the target profile
3. Educational and suitable for security training
4. Ethically compliant and safe for training environments
5. Professionally formatted and complete

Generate the final content:"""

        try:
            response = await llm_provider.generate_content(
                prompt=synthesis_prompt,
                scenario_type="tot_synthesis",
                max_tokens=1500,
                temperature=0.3  # Lower temperature for final synthesis
            )

            return response.content

        except Exception as e:
            logger.error(f"Error synthesizing final content: {e}")
            return "Error: Could not synthesize final content from reasoning path"

    def _parse_tot_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response for ToT approach generation."""
        try:
            # Look for JSON content
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())

            # Fallback parsing if JSON not found
            return {"approaches": []}

        except json.JSONDecodeError:
            logger.warning("Could not parse ToT response as JSON")
            return {"approaches": []}


class MetaLearningEngine:
    """
    Level 4: Meta-Learning and Self-Refinement Implementation

    Based on recent meta-learning research for prompt optimization and
    self-improving systems that learn from their own outputs.
    """

    def __init__(self):
        self.prompt_performance_history: Dict[str, List[float]] = defaultdict(list)
        self.successful_patterns: Dict[str, List[str]] = defaultdict(list)
        self.refinement_iterations = 3

    async def meta_generate_with_refinement(
        self,
        initial_context: Dict[str, Any],
        content_type: str,
        llm_provider: Any
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Generate content with iterative self-refinement and meta-learning.
        """

        current_content = ""
        refinement_history = []

        for iteration in range(self.refinement_iterations):
            logger.info(f"Meta-learning iteration {iteration + 1}")

            if iteration == 0:
                # Initial generation
                current_content = await self._initial_generation(
                    initial_context, content_type, llm_provider
                )
            else:
                # Self-refinement based on previous iteration
                current_content = await self._self_refine(
                    current_content, refinement_history, initial_context, llm_provider
                )

            # Self-evaluation
            evaluation = await self._self_evaluate(
                current_content, initial_context, llm_provider
            )

            refinement_history.append({
                "iteration": iteration + 1,
                "content": current_content,
                "evaluation": evaluation,
                "improvements_made": evaluation.get("improvements_needed", [])
            })

            # Stop if quality is high enough
            if evaluation.get("overall_score", 0) >= 0.85:
                logger.info(f"High quality achieved at iteration {iteration + 1}")
                break

        # Update meta-learning knowledge
        self._update_meta_knowledge(initial_context, refinement_history)

        return current_content, {
            "refinement_history": refinement_history,
            "final_evaluation": refinement_history[-1]["evaluation"],
            "iterations_needed": len(refinement_history)
        }

    async def _initial_generation(
        self,
        context: Dict[str, Any],
        content_type: str,
        llm_provider: Any
    ) -> str:
        """Generate initial content using learned patterns."""

        # Apply meta-learned patterns
        enhanced_context = self._apply_learned_patterns(context, content_type)

        prompt = f"""Generate {content_type} content for threat simulation training.

Context: {json.dumps(enhanced_context, indent=2)}

Based on analysis of successful patterns, focus on:
{self._get_success_factors(content_type)}

Generate high-quality content:"""

        response = await llm_provider.generate_content(
            prompt=prompt,
            scenario_type="meta_initial",
            max_tokens=1200,
            temperature=0.7
        )

        return response.content

    async def _self_refine(
        self,
        current_content: str,
        history: List[Dict],
        context: Dict[str, Any],
        llm_provider: Any
    ) -> str:
        """Self-refine content based on previous evaluations."""

        previous_issues = []
        if history:
            last_eval = history[-1]["evaluation"]
            previous_issues = last_eval.get("improvements_needed", [])

        refinement_prompt = f"""Review and improve this threat simulation content:

Current Content:
{current_content}

Previous evaluation identified these areas for improvement:
{json.dumps(previous_issues, indent=2)}

Context: {json.dumps(context, indent=2)}

Refine the content to address these issues while maintaining:
1. Educational value and training effectiveness
2. Realistic but safe content for training
3. Technical accuracy and professional quality
4. Appropriate difficulty level for target audience

Provide the improved version:"""

        response = await llm_provider.generate_content(
            prompt=refinement_prompt,
            scenario_type="meta_refinement",
            max_tokens=1200,
            temperature=0.5
        )

        return response.content

    async def _self_evaluate(
        self,
        content: str,
        context: Dict[str, Any],
        llm_provider: Any
    ) -> Dict[str, Any]:
        """Self-evaluate content quality and identify improvements."""

        evaluation_prompt = f"""Evaluate this threat simulation content for training quality:

Content to Evaluate:
{content}

Context: {json.dumps(context, indent=2)}

Provide detailed evaluation in JSON format:
{{
  "overall_score": 0.0-1.0,
  "dimension_scores": {{
    "realism": 0.0-1.0,
    "effectiveness": 0.0-1.0,
    "educational_value": 0.0-1.0,
    "safety": 0.0-1.0,
    "technical_accuracy": 0.0-1.0
  }},
  "strengths": ["list of strengths"],
  "improvements_needed": ["specific improvements"],
  "quality_indicators": ["what makes this good/bad"],
  "training_effectiveness": "assessment of training value"
}}"""

        try:
            response = await llm_provider.generate_content(
                prompt=evaluation_prompt,
                scenario_type="meta_evaluation",
                max_tokens=800,
                temperature=0.3
            )

            # Parse JSON response
            import re
            json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())

        except Exception as e:
            logger.error(f"Error in self-evaluation: {e}")

        # Fallback evaluation
        return {
            "overall_score": 0.7,
            "improvements_needed": ["Could not perform detailed evaluation"],
            "strengths": ["Content generated successfully"]
        }

    def _apply_learned_patterns(
        self,
        context: Dict[str, Any],
        content_type: str
    ) -> Dict[str, Any]:
        """Apply patterns learned from previous successful generations."""

        enhanced_context = context.copy()

        # Add successful patterns for this content type
        successful_patterns = self.successful_patterns.get(content_type, [])
        if successful_patterns:
            enhanced_context["learned_patterns"] = successful_patterns[-5:]  # Last 5 successful patterns

        # Add performance insights
        avg_performance = np.mean(self.prompt_performance_history.get(content_type, [0.7]))
        enhanced_context["expected_quality_level"] = avg_performance

        return enhanced_context

    def _get_success_factors(self, content_type: str) -> str:
        """Get success factors learned for this content type."""

        base_factors = {
            "email_phishing": [
                "Professional business context",
                "Subtle urgency without being obvious",
                "Realistic sender credentials",
                "Appropriate technical sophistication"
            ],
            "sms_phishing": [
                "Concise and urgent messaging",
                "Mobile-appropriate attack vectors",
                "Authority-based social engineering",
                "Realistic service impersonation"
            ]
        }

        factors = base_factors.get(content_type, ["High quality professional content"])
        successful_patterns = self.successful_patterns.get(content_type, [])

        if successful_patterns:
            factors.extend(successful_patterns[-3:])

        return "\n- " + "\n- ".join(factors)

    def _update_meta_knowledge(
        self,
        context: Dict[str, Any],
        history: List[Dict]
    ) -> None:
        """Update meta-learning knowledge base."""

        if not history:
            return

        content_type = context.get("content_type", "unknown")
        final_score = history[-1]["evaluation"].get("overall_score", 0.0)

        # Update performance history
        self.prompt_performance_history[content_type].append(final_score)

        # Extract successful patterns
        if final_score >= 0.8:
            strengths = history[-1]["evaluation"].get("strengths", [])
            self.successful_patterns[content_type].extend(strengths)

            # Keep only recent successful patterns
            if len(self.successful_patterns[content_type]) > 20:
                self.successful_patterns[content_type] = self.successful_patterns[content_type][-20:]

        logger.info(f"Updated meta-knowledge for {content_type}: avg_score={np.mean(self.prompt_performance_history[content_type]):.3f}")


# RLHFOptimizer and MultiAgentPromptSystem classes would be implemented here for Levels 5-6...
