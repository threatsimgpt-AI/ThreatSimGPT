"""
ThreatSimGPT Feedback Loop Orchestrator

The main controller that coordinates the continuous improvement cycle:
    Scenario Generation → Playbook Generation → Analysis → Learning → Enhancement → Repeat

This orchestrator ensures that every generated piece of content contributes
to the knowledge base and improves future generations.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .models import (
    ScenarioFeedback,
    PlaybookFeedback,
    QualityMetrics,
    LearningInsight,
    ImprovementSuggestion,
    EvolutionCycle,
    FeedbackStore,
    FeedbackType,
    QualityDimension,
)
from .analyzer import ScenarioAnalyzer, PlaybookAnalyzer, FeedbackAggregator, CrossAnalyzer
from .enhancer import ScenarioEnhancer, PlaybookEnhancer


logger = logging.getLogger(__name__)


class CyclePhase(str, Enum):
    """Current phase in the improvement cycle."""
    IDLE = "idle"
    GENERATING = "generating"
    ANALYZING = "analyzing"
    LEARNING = "learning"
    ENHANCING = "enhancing"
    STORING = "storing"


@dataclass
class CycleState:
    """Current state of the feedback loop cycle."""
    phase: CyclePhase = CyclePhase.IDLE
    cycle_number: int = 0
    scenarios_processed: int = 0
    playbooks_processed: int = 0
    learnings_extracted: int = 0
    improvements_applied: int = 0
    last_cycle_time: Optional[datetime] = None
    quality_trend: List[float] = field(default_factory=list)

    @property
    def average_quality_improvement(self) -> float:
        """Calculate average quality improvement over time."""
        if len(self.quality_trend) < 2:
            return 0.0
        improvements = [
            self.quality_trend[i] - self.quality_trend[i-1]
            for i in range(1, len(self.quality_trend))
        ]
        return sum(improvements) / len(improvements) if improvements else 0.0


@dataclass
class GenerationContext:
    """Context for content generation with applied learnings."""
    base_parameters: Dict[str, Any]
    applied_learnings: List[LearningInsight]
    enhancement_history: List[str]
    quality_target: float = 0.8

    def to_prompt_context(self) -> str:
        """Convert to context string for LLM prompts."""
        context_parts = []

        if self.applied_learnings:
            context_parts.append("## Applied Learnings from Previous Generations:")
            for learning in self.applied_learnings[:5]:  # Top 5 most relevant
                context_parts.append(f"- {learning.insight}")
                if learning.improvement_action:
                    context_parts.append(f"  Action: {learning.improvement_action}")

        if self.enhancement_history:
            context_parts.append("\n## Recent Improvements Applied:")
            for enhancement in self.enhancement_history[-3:]:
                context_parts.append(f"- {enhancement}")

        return "\n".join(context_parts)


class FeedbackLoop:
    """
    Main orchestrator for the continuous improvement cycle.

    The feedback loop works as follows:
    1. GENERATE: Create scenarios/playbooks with applied learnings
    2. ANALYZE: Assess quality and effectiveness
    3. LEARN: Extract insights and patterns
    4. ENHANCE: Apply improvements to future generations
    5. STORE: Persist learnings in Neo4j knowledge graph
    6. REPEAT: Use accumulated knowledge for better generations
    """

    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_password: Optional[str] = None,
        llm_provider: Optional[Any] = None,
    ):
        self.neo4j_uri = neo4j_uri
        self.neo4j_password = neo4j_password
        self.llm_provider = llm_provider

        # Initialize components
        self.feedback_store = FeedbackStore(neo4j_uri, neo4j_password)
        self.scenario_analyzer = ScenarioAnalyzer(llm_provider)
        self.playbook_analyzer = PlaybookAnalyzer(llm_provider)
        self.scenario_enhancer = ScenarioEnhancer(llm_provider, self.feedback_store)
        self.playbook_enhancer = PlaybookEnhancer(llm_provider, self.feedback_store)
        self.cross_analyzer = CrossAnalyzer()
        self.aggregator = FeedbackAggregator()

        # Cycle state
        self.state = CycleState()

        # In-memory caches for current cycle
        self._scenario_feedbacks: List[ScenarioFeedback] = []
        self._playbook_feedbacks: List[PlaybookFeedback] = []
        self._pending_learnings: List[LearningInsight] = []

        logger.info("FeedbackLoop orchestrator initialized")

    async def initialize(self) -> None:
        """Initialize the feedback loop and load historical state."""
        try:
            # Initialize Neo4j store
            await self.feedback_store.initialize()

            # Load historical metrics to continue quality trend
            historical_cycles = await self._load_historical_cycles()
            if historical_cycles:
                self.state.cycle_number = len(historical_cycles)
                self.state.quality_trend = [
                    cycle.quality_delta for cycle in historical_cycles
                ]

            logger.info(f"Feedback loop initialized with {self.state.cycle_number} historical cycles")

        except Exception as e:
            logger.error(f"Failed to initialize feedback loop: {e}")
            raise

    async def _load_historical_cycles(self) -> List[EvolutionCycle]:
        """Load historical evolution cycles from Neo4j."""
        return await self.feedback_store.get_evolution_history(limit=100)

    # =========================================================================
    # PHASE 1: GENERATION WITH LEARNINGS
    # =========================================================================

    async def prepare_generation_context(
        self,
        content_type: str,
        parameters: Dict[str, Any],
    ) -> GenerationContext:
        """
        Prepare context for content generation by retrieving relevant learnings.

        Args:
            content_type: 'scenario' or 'playbook'
            parameters: Generation parameters (attack type, target, etc.)

        Returns:
            GenerationContext with applied learnings
        """
        self.state.phase = CyclePhase.GENERATING

        # Retrieve relevant learnings from knowledge graph
        relevant_learnings = await self._retrieve_relevant_learnings(
            content_type, parameters
        )

        # Get recent enhancements that worked well
        enhancement_history = await self._get_successful_enhancements(content_type)

        context = GenerationContext(
            base_parameters=parameters,
            applied_learnings=relevant_learnings,
            enhancement_history=enhancement_history,
            quality_target=self._calculate_quality_target(),
        )

        logger.info(
            f"Prepared generation context with {len(relevant_learnings)} learnings "
            f"and {len(enhancement_history)} enhancement patterns"
        )

        return context

    async def _retrieve_relevant_learnings(
        self,
        content_type: str,
        parameters: Dict[str, Any],
    ) -> List[LearningInsight]:
        """Retrieve learnings relevant to the current generation."""
        learnings = []

        # Get learnings by attack type
        if attack_type := parameters.get("attack_type"):
            type_learnings = await self.feedback_store.get_learnings_by_context(
                context_type="attack_type",
                context_value=attack_type,
            )
            learnings.extend(type_learnings)

        # Get learnings by target industry
        if target := parameters.get("target"):
            target_learnings = await self.feedback_store.get_learnings_by_context(
                context_type="target",
                context_value=target,
            )
            learnings.extend(target_learnings)

        # Get high-impact learnings
        high_impact = await self.feedback_store.get_high_impact_learnings(limit=5)
        learnings.extend(high_impact)

        # Deduplicate and sort by relevance
        seen = set()
        unique_learnings = []
        for learning in learnings:
            if learning.id not in seen:
                seen.add(learning.id)
                unique_learnings.append(learning)

        # Sort by confidence score
        unique_learnings.sort(key=lambda x: x.confidence_score, reverse=True)

        return unique_learnings[:10]  # Top 10 most relevant

    async def _get_successful_enhancements(self, content_type: str) -> List[str]:
        """Get list of successful enhancement patterns."""
        return await self.feedback_store.get_successful_enhancements(
            content_type=content_type,
            min_improvement=0.1,  # At least 10% improvement
            limit=5,
        )

    def _calculate_quality_target(self) -> float:
        """Calculate target quality based on historical performance."""
        if not self.state.quality_trend:
            return 0.7  # Default target

        # Aim slightly above current average
        current_avg = sum(self.state.quality_trend[-10:]) / min(10, len(self.state.quality_trend))
        return min(0.95, current_avg + 0.05)  # Cap at 95%

    # =========================================================================
    # PHASE 2: ANALYSIS
    # =========================================================================

    async def analyze_scenario(
        self,
        scenario: Dict[str, Any],
        scenario_id: str,
    ) -> ScenarioFeedback:
        """
        Analyze a generated scenario for quality and effectiveness.

        Args:
            scenario: The generated scenario content
            scenario_id: Unique identifier for the scenario

        Returns:
            ScenarioFeedback with quality metrics and insights
        """
        self.state.phase = CyclePhase.ANALYZING

        # Perform comprehensive analysis
        feedback = await self.scenario_analyzer.analyze(scenario, scenario_id)

        # Cache for batch processing
        self._scenario_feedbacks.append(feedback)
        self.state.scenarios_processed += 1

        logger.info(
            f"Analyzed scenario {scenario_id}: "
            f"overall_score={feedback.quality_metrics.overall_score:.2f}"
        )

        return feedback

    async def analyze_playbook(
        self,
        playbook: Dict[str, Any],
        playbook_id: str,
        linked_scenario_id: Optional[str] = None,
    ) -> PlaybookFeedback:
        """
        Analyze a generated playbook for quality and effectiveness.

        Args:
            playbook: The generated playbook content
            playbook_id: Unique identifier for the playbook
            linked_scenario_id: ID of the scenario this playbook responds to

        Returns:
            PlaybookFeedback with quality metrics and insights
        """
        self.state.phase = CyclePhase.ANALYZING

        # Perform comprehensive analysis
        feedback = await self.playbook_analyzer.analyze(
            playbook, playbook_id, linked_scenario_id
        )

        # Cache for batch processing
        self._playbook_feedbacks.append(feedback)
        self.state.playbooks_processed += 1

        logger.info(
            f"Analyzed playbook {playbook_id}: "
            f"overall_score={feedback.quality_metrics.overall_score:.2f}"
        )

        return feedback

    async def analyze_scenario_playbook_pair(
        self,
        scenario: Dict[str, Any],
        playbook: Dict[str, Any],
        scenario_id: str,
        playbook_id: str,
    ) -> Tuple[ScenarioFeedback, PlaybookFeedback, List[LearningInsight]]:
        """
        Analyze a scenario-playbook pair together for cross-insights.

        This is the most valuable analysis as it captures how well
        the playbook addresses the scenario and vice versa.
        """
        # Analyze both individually
        scenario_feedback = await self.analyze_scenario(scenario, scenario_id)
        playbook_feedback = await self.analyze_playbook(
            playbook, playbook_id, linked_scenario_id=scenario_id
        )

        # Perform cross-analysis
        cross_insights = await self.cross_analyzer.analyze_pair(
            scenario_feedback, playbook_feedback
        )

        return scenario_feedback, playbook_feedback, cross_insights

    # =========================================================================
    # PHASE 3: LEARNING EXTRACTION
    # =========================================================================

    async def extract_learnings(self) -> List[LearningInsight]:
        """
        Extract learnings from all analyzed content in current cycle.

        Returns:
            List of extracted learning insights
        """
        self.state.phase = CyclePhase.LEARNING
        learnings = []

        # Extract from scenario feedbacks
        for feedback in self._scenario_feedbacks:
            scenario_learnings = await self._extract_scenario_learnings(feedback)
            learnings.extend(scenario_learnings)

        # Extract from playbook feedbacks
        for feedback in self._playbook_feedbacks:
            playbook_learnings = await self._extract_playbook_learnings(feedback)
            learnings.extend(playbook_learnings)

        # Aggregate and deduplicate learnings
        aggregated = await self._aggregate_learnings(learnings)

        self._pending_learnings.extend(aggregated)
        self.state.learnings_extracted += len(aggregated)

        logger.info(f"Extracted {len(aggregated)} unique learnings from current cycle")

        return aggregated

    async def _extract_scenario_learnings(
        self,
        feedback: ScenarioFeedback,
    ) -> List[LearningInsight]:
        """Extract learnings from a single scenario feedback."""
        learnings = []
        metrics = feedback.quality_metrics

        # Learn from high-quality aspects
        if metrics.realism_score > 0.8:
            learnings.append(LearningInsight(
                id=f"learning_{feedback.scenario_id}_realism",
                source_type="scenario",
                source_id=feedback.scenario_id,
                insight=f"High realism achieved through: {feedback.strengths[0] if feedback.strengths else 'detailed context'}",
                dimension=QualityDimension.REALISM,
                confidence_score=metrics.realism_score,
                improvement_action="Apply similar realism techniques to future scenarios",
                context={"attack_type": feedback.metadata.get("attack_type")},
                created_at=datetime.now(),
            ))

        # Learn from weaknesses to avoid
        for weakness in feedback.weaknesses:
            learnings.append(LearningInsight(
                id=f"learning_{feedback.scenario_id}_weakness",
                source_type="scenario",
                source_id=feedback.scenario_id,
                insight=f"Weakness identified: {weakness}",
                dimension=QualityDimension.EFFECTIVENESS,
                confidence_score=0.7,
                improvement_action=f"Address in future generations: {weakness}",
                context=feedback.metadata,
                created_at=datetime.now(),
            ))

        return learnings

    async def _extract_playbook_learnings(
        self,
        feedback: PlaybookFeedback,
    ) -> List[LearningInsight]:
        """Extract learnings from a single playbook feedback."""
        learnings = []
        metrics = feedback.quality_metrics

        # Learn from effective response patterns
        if metrics.effectiveness_score > 0.8:
            learnings.append(LearningInsight(
                id=f"learning_{feedback.playbook_id}_effective",
                source_type="playbook",
                source_id=feedback.playbook_id,
                insight=f"Effective response pattern: {feedback.strengths[0] if feedback.strengths else 'comprehensive coverage'}",
                dimension=QualityDimension.EFFECTIVENESS,
                confidence_score=metrics.effectiveness_score,
                improvement_action="Replicate this response pattern for similar scenarios",
                context={"linked_scenario": feedback.linked_scenario_id},
                created_at=datetime.now(),
            ))

        # Learn about coverage gaps
        if metrics.coverage_score < 0.7:
            learnings.append(LearningInsight(
                id=f"learning_{feedback.playbook_id}_coverage",
                source_type="playbook",
                source_id=feedback.playbook_id,
                insight="Coverage gap: Playbook needs better coverage of attack vectors",
                dimension=QualityDimension.COVERAGE,
                confidence_score=0.8,
                improvement_action="Ensure playbooks cover all identified TTPs",
                context=feedback.metadata,
                created_at=datetime.now(),
            ))

        return learnings

    async def _aggregate_learnings(
        self,
        learnings: List[LearningInsight],
    ) -> List[LearningInsight]:
        """Aggregate similar learnings and boost confidence of repeated patterns."""
        if not learnings:
            return []

        # Group by insight similarity (simplified - just by dimension for now)
        grouped: Dict[QualityDimension, List[LearningInsight]] = {}
        for learning in learnings:
            if learning.dimension not in grouped:
                grouped[learning.dimension] = []
            grouped[learning.dimension].append(learning)

        aggregated = []
        for dimension, group in grouped.items():
            if len(group) == 1:
                aggregated.append(group[0])
            else:
                # Merge similar learnings, boost confidence
                merged = group[0]
                merged.confidence_score = min(0.95, merged.confidence_score + 0.1 * (len(group) - 1))
                aggregated.append(merged)

        return aggregated

    # =========================================================================
    # PHASE 4: ENHANCEMENT APPLICATION
    # =========================================================================

    async def enhance_scenario(
        self,
        scenario: Dict[str, Any],
        scenario_id: str,
    ) -> Dict[str, Any]:
        """
        Enhance a scenario using accumulated learnings.

        Args:
            scenario: The scenario to enhance
            scenario_id: Unique identifier

        Returns:
            Enhanced scenario
        """
        self.state.phase = CyclePhase.ENHANCING

        enhanced = await self.scenario_enhancer.enhance(
            scenario=scenario,
            scenario_id=scenario_id,
            target_quality=self._calculate_quality_target(),
        )

        self.state.improvements_applied += 1

        return enhanced

    async def enhance_playbook(
        self,
        playbook: Dict[str, Any],
        playbook_id: str,
        linked_scenario_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Enhance a playbook using accumulated learnings.

        Args:
            playbook: The playbook to enhance
            playbook_id: Unique identifier
            linked_scenario_id: ID of linked scenario

        Returns:
            Enhanced playbook
        """
        self.state.phase = CyclePhase.ENHANCING

        enhanced = await self.playbook_enhancer.enhance(
            playbook=playbook,
            playbook_id=playbook_id,
            linked_scenario_id=linked_scenario_id,
            target_quality=self._calculate_quality_target(),
        )

        self.state.improvements_applied += 1

        return enhanced

    # =========================================================================
    # PHASE 5: STORAGE
    # =========================================================================

    async def store_cycle_results(self) -> EvolutionCycle:
        """
        Store all results from current cycle in Neo4j.

        Returns:
            EvolutionCycle record
        """
        self.state.phase = CyclePhase.STORING

        # Calculate cycle metrics
        scenario_avg = self.aggregator.aggregate_scenario_quality(self._scenario_feedbacks)
        playbook_avg = self.aggregator.aggregate_playbook_quality(self._playbook_feedbacks)
        overall_quality = (scenario_avg + playbook_avg) / 2 if (scenario_avg and playbook_avg) else 0

        # Calculate improvement from previous cycle
        previous_quality = self.state.quality_trend[-1] if self.state.quality_trend else 0.5
        quality_delta = overall_quality - previous_quality

        # Create cycle record
        cycle = EvolutionCycle(
            cycle_id=f"cycle_{self.state.cycle_number + 1}",
            started_at=self.state.last_cycle_time or datetime.now(),
            completed_at=datetime.now(),
            scenarios_processed=len(self._scenario_feedbacks),
            playbooks_processed=len(self._playbook_feedbacks),
            learnings_generated=len(self._pending_learnings),
            improvements_applied=self.state.improvements_applied,
            quality_delta=quality_delta,
            scenario_feedbacks=[f.scenario_id for f in self._scenario_feedbacks],
            playbook_feedbacks=[f.playbook_id for f in self._playbook_feedbacks],
            learnings=[l.id for l in self._pending_learnings],
        )

        # Store in Neo4j
        await self.feedback_store.store_cycle(cycle)

        # Store all learnings
        for learning in self._pending_learnings:
            await self.feedback_store.store_learning(learning)

        # Store feedbacks
        for feedback in self._scenario_feedbacks:
            await self.feedback_store.store_scenario_feedback(feedback)

        for feedback in self._playbook_feedbacks:
            await self.feedback_store.store_playbook_feedback(feedback)

        # Update state
        self.state.cycle_number += 1
        self.state.quality_trend.append(overall_quality)
        self.state.last_cycle_time = datetime.now()

        # Clear caches for next cycle
        self._scenario_feedbacks.clear()
        self._playbook_feedbacks.clear()
        self._pending_learnings.clear()
        self.state.improvements_applied = 0

        logger.info(
            f"Completed evolution cycle {cycle.cycle_id}: "
            f"quality_delta={quality_delta:+.2f}, "
            f"learnings={cycle.learnings_generated}"
        )

        self.state.phase = CyclePhase.IDLE

        return cycle

    # =========================================================================
    # FULL CYCLE EXECUTION
    # =========================================================================

    async def run_improvement_cycle(
        self,
        scenarios: List[Dict[str, Any]],
        playbooks: List[Dict[str, Any]],
        scenario_playbook_mapping: Optional[Dict[str, str]] = None,
    ) -> EvolutionCycle:
        """
        Run a complete improvement cycle on a batch of content.

        Args:
            scenarios: List of scenarios to analyze and improve
            playbooks: List of playbooks to analyze and improve
            scenario_playbook_mapping: Optional mapping of scenario_id -> playbook_id

        Returns:
            EvolutionCycle with results
        """
        self.state.last_cycle_time = datetime.now()

        # Phase 2: Analyze all content
        for i, scenario in enumerate(scenarios):
            scenario_id = scenario.get("id", f"scenario_{i}")
            await self.analyze_scenario(scenario, scenario_id)

        for i, playbook in enumerate(playbooks):
            playbook_id = playbook.get("id", f"playbook_{i}")
            linked_scenario = scenario_playbook_mapping.get(playbook_id) if scenario_playbook_mapping else None
            await self.analyze_playbook(playbook, playbook_id, linked_scenario)

        # Phase 3: Extract learnings
        await self.extract_learnings()

        # Phase 5: Store results
        cycle = await self.store_cycle_results()

        return cycle

    async def get_status(self) -> Dict[str, Any]:
        """Get current status of the feedback loop."""
        return {
            "phase": self.state.phase.value,
            "cycle_number": self.state.cycle_number,
            "total_scenarios_processed": self.state.scenarios_processed,
            "total_playbooks_processed": self.state.playbooks_processed,
            "total_learnings": self.state.learnings_extracted,
            "average_quality_improvement": self.state.average_quality_improvement,
            "quality_trend": self.state.quality_trend[-10:],  # Last 10 cycles
            "current_quality_target": self._calculate_quality_target(),
            "pending_feedbacks": len(self._scenario_feedbacks) + len(self._playbook_feedbacks),
            "pending_learnings": len(self._pending_learnings),
        }

    async def close(self) -> None:
        """Clean up resources."""
        await self.feedback_store.close()
        logger.info("Feedback loop orchestrator closed")


# Convenience function for integration
async def create_feedback_loop(
    neo4j_uri: str = "bolt://localhost:7687",
    neo4j_password: Optional[str] = None,
    llm_provider: Optional[Any] = None,
) -> FeedbackLoop:
    """Create and initialize a feedback loop instance."""
    loop = FeedbackLoop(neo4j_uri, neo4j_password, llm_provider)
    await loop.initialize()
    return loop
