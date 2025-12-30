"""
Feedback Loop Data Models
=========================

Data models for the continuous improvement feedback loop system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import hashlib
import json


class FeedbackType(Enum):
    """Types of feedback in the loop."""
    SCENARIO_TO_PLAYBOOK = "scenario_to_playbook"
    PLAYBOOK_TO_SCENARIO = "playbook_to_scenario"
    USER_FEEDBACK = "user_feedback"
    AUTOMATED_ANALYSIS = "automated_analysis"
    SIMULATION_RESULT = "simulation_result"


class QualityDimension(Enum):
    """Dimensions of quality measurement."""
    REALISM = "realism"
    TECHNIQUE_COVERAGE = "technique_coverage"
    ENGAGEMENT = "engagement"
    TRAINING_VALUE = "training_value"
    DETECTION_DIFFICULTY = "detection_difficulty"
    COMPLIANCE_ALIGNMENT = "compliance_alignment"
    SECTOR_RELEVANCE = "sector_relevance"
    TEMPORAL_RELEVANCE = "temporal_relevance"


class ImprovementCategory(Enum):
    """Categories of improvement suggestions."""
    TECHNIQUE_ADDITION = "technique_addition"
    NARRATIVE_ENHANCEMENT = "narrative_enhancement"
    REALISM_BOOST = "realism_boost"
    SECTOR_CUSTOMIZATION = "sector_customization"
    DETECTION_EVASION = "detection_evasion"
    SOCIAL_ENGINEERING = "social_engineering"
    TECHNICAL_DEPTH = "technical_depth"
    COMPLIANCE_GAP = "compliance_gap"


@dataclass
class QualityMetrics:
    """
    Quality metrics for scenarios and playbooks.

    Tracks multiple dimensions of quality to guide improvements.
    """
    realism_score: float = 0.0          # 0-1: How realistic is the content
    technique_coverage: float = 0.0      # 0-1: MITRE technique coverage
    engagement_score: float = 0.0        # 0-1: How engaging for training
    training_value: float = 0.0          # 0-1: Educational effectiveness
    detection_difficulty: float = 0.0    # 0-1: How hard to detect
    compliance_alignment: float = 0.0    # 0-1: Regulatory alignment
    sector_relevance: float = 0.0        # 0-1: Sector-specific relevance
    temporal_relevance: float = 0.0      # 0-1: Current threat landscape fit

    # Calculated
    overall_score: float = 0.0

    # Metadata
    evaluated_at: datetime = field(default_factory=datetime.utcnow)
    evaluator: str = "automated"  # automated, human, hybrid

    def __post_init__(self):
        """Calculate overall score."""
        if self.overall_score == 0.0:
            scores = [
                self.realism_score,
                self.technique_coverage,
                self.engagement_score,
                self.training_value,
                self.detection_difficulty,
                self.compliance_alignment,
                self.sector_relevance,
                self.temporal_relevance,
            ]
            non_zero = [s for s in scores if s > 0]
            if non_zero:
                self.overall_score = sum(non_zero) / len(non_zero)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "realism_score": self.realism_score,
            "technique_coverage": self.technique_coverage,
            "engagement_score": self.engagement_score,
            "training_value": self.training_value,
            "detection_difficulty": self.detection_difficulty,
            "compliance_alignment": self.compliance_alignment,
            "sector_relevance": self.sector_relevance,
            "temporal_relevance": self.temporal_relevance,
            "overall_score": self.overall_score,
            "evaluated_at": self.evaluated_at.isoformat(),
            "evaluator": self.evaluator,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QualityMetrics":
        """Create from dictionary."""
        data = data.copy()
        if "evaluated_at" in data and isinstance(data["evaluated_at"], str):
            data["evaluated_at"] = datetime.fromisoformat(data["evaluated_at"])
        return cls(**data)


@dataclass
class ScenarioLearning:
    """
    Learning extracted from a scenario for playbook improvement.

    Captures what worked well in a scenario that can improve
    future playbook generation.
    """
    id: str = ""
    scenario_id: str = ""

    # Extracted learnings
    effective_techniques: List[str] = field(default_factory=list)
    successful_narratives: List[str] = field(default_factory=list)
    engagement_patterns: List[str] = field(default_factory=list)
    sector_insights: Dict[str, Any] = field(default_factory=dict)

    # What made this scenario effective
    success_factors: List[str] = field(default_factory=list)

    # Applicable contexts
    applicable_sectors: List[str] = field(default_factory=list)
    applicable_threat_types: List[str] = field(default_factory=list)

    # Quality metrics from this scenario
    metrics: Optional[QualityMetrics] = None

    # Metadata
    extracted_at: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 0.8

    def __post_init__(self):
        """Generate ID if not provided."""
        if not self.id:
            content = f"{self.scenario_id}{self.effective_techniques}"
            self.id = f"sl_{hashlib.sha256(content.encode()).hexdigest()[:12]}"


@dataclass
class PlaybookLearning:
    """
    Learning extracted from a playbook for scenario improvement.

    Captures insights from playbooks that can enhance
    future scenario generation.
    """
    id: str = ""
    playbook_id: str = ""

    # Defense insights for better offense
    defensive_gaps: List[str] = field(default_factory=list)
    detection_blind_spots: List[str] = field(default_factory=list)
    response_delays: List[str] = field(default_factory=list)

    # Technique effectiveness
    technique_effectiveness: Dict[str, float] = field(default_factory=dict)

    # Evasion opportunities
    evasion_techniques: List[str] = field(default_factory=list)
    timing_opportunities: List[str] = field(default_factory=list)

    # Sector-specific vulnerabilities
    sector_vulnerabilities: Dict[str, List[str]] = field(default_factory=dict)

    # Compliance-related opportunities
    compliance_gaps: List[str] = field(default_factory=list)

    # Quality metrics
    metrics: Optional[QualityMetrics] = None

    # Metadata
    extracted_at: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 0.8

    def __post_init__(self):
        """Generate ID if not provided."""
        if not self.id:
            content = f"{self.playbook_id}{self.defensive_gaps}"
            self.id = f"pl_{hashlib.sha256(content.encode()).hexdigest()[:12]}"


@dataclass
class ImprovementSuggestion:
    """
    A specific suggestion for improving a scenario or playbook.
    """
    id: str = ""

    # What to improve
    target_type: str = "scenario"  # scenario, playbook
    target_id: str = ""

    # The suggestion
    category: ImprovementCategory = ImprovementCategory.REALISM_BOOST
    title: str = ""
    description: str = ""

    # Implementation details
    suggested_changes: List[str] = field(default_factory=list)
    techniques_to_add: List[str] = field(default_factory=list)
    narratives_to_enhance: List[str] = field(default_factory=list)

    # Expected impact
    expected_improvement: float = 0.0  # Expected score increase
    affected_dimensions: List[QualityDimension] = field(default_factory=list)

    # Source of suggestion
    source_type: str = "automated"  # automated, user, hybrid
    source_id: str = ""  # Learning ID or user ID

    # Priority
    priority: int = 5  # 1-10, 10 being highest

    # Status
    status: str = "pending"  # pending, applied, rejected, deferred
    applied_at: Optional[datetime] = None

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)

    def __post_init__(self):
        """Generate ID if not provided."""
        if not self.id:
            content = f"{self.target_type}{self.target_id}{self.title}"
            self.id = f"is_{hashlib.sha256(content.encode()).hexdigest()[:12]}"


@dataclass
class FeedbackEntry:
    """
    A single feedback entry in the improvement loop.
    """
    id: str = ""
    feedback_type: FeedbackType = FeedbackType.AUTOMATED_ANALYSIS

    # Source and target
    source_id: str = ""  # ID of source (scenario, playbook, user)
    source_type: str = ""  # scenario, playbook, user
    target_id: str = ""
    target_type: str = ""

    # Feedback content
    learnings: List[str] = field(default_factory=list)
    suggestions: List[ImprovementSuggestion] = field(default_factory=list)

    # Quality assessment
    quality_before: Optional[QualityMetrics] = None
    quality_after: Optional[QualityMetrics] = None

    # Impact tracking
    improvement_achieved: float = 0.0

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    processed: bool = False
    processed_at: Optional[datetime] = None

    def __post_init__(self):
        """Generate ID if not provided."""
        if not self.id:
            content = f"{self.source_id}{self.target_id}{self.created_at}"
            self.id = f"fb_{hashlib.sha256(content.encode()).hexdigest()[:12]}"


@dataclass
class GenerationCycle:
    """
    Represents one cycle of the feedback loop.

    Tracks the progression from scenario → simulation → playbook → learning → enhanced scenario.
    """
    id: str = ""
    cycle_number: int = 0

    # Cycle components
    scenario_id: str = ""
    simulation_id: str = ""
    playbook_id: str = ""

    # Learnings from this cycle
    scenario_learning: Optional[ScenarioLearning] = None
    playbook_learning: Optional[PlaybookLearning] = None

    # Quality progression
    initial_quality: Optional[QualityMetrics] = None
    final_quality: Optional[QualityMetrics] = None

    # Improvements applied
    improvements_applied: List[ImprovementSuggestion] = field(default_factory=list)

    # Cycle status
    status: str = "in_progress"  # in_progress, completed, failed

    # Timing
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    def __post_init__(self):
        """Generate ID if not provided."""
        if not self.id:
            self.id = f"cycle_{self.cycle_number}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    @property
    def improvement_delta(self) -> float:
        """Calculate improvement from this cycle."""
        if self.initial_quality and self.final_quality:
            return self.final_quality.overall_score - self.initial_quality.overall_score
        return 0.0


@dataclass
class CycleMetrics:
    """
    Aggregate metrics across multiple improvement cycles.
    """
    total_cycles: int = 0
    completed_cycles: int = 0

    # Quality progression
    average_initial_score: float = 0.0
    average_final_score: float = 0.0
    best_score_achieved: float = 0.0

    # Improvement tracking
    total_improvement: float = 0.0
    average_improvement_per_cycle: float = 0.0

    # Learning statistics
    total_learnings_extracted: int = 0
    total_improvements_applied: int = 0

    # Dimension-specific improvements
    dimension_improvements: Dict[str, float] = field(default_factory=dict)

    # Time tracking
    average_cycle_duration_seconds: float = 0.0

    # Trends
    improvement_trend: str = "stable"  # improving, stable, declining

    def update_from_cycle(self, cycle: GenerationCycle):
        """Update metrics from a completed cycle."""
        self.total_cycles += 1

        if cycle.status == "completed":
            self.completed_cycles += 1

            if cycle.initial_quality:
                # Update averages
                prev_total = self.average_initial_score * (self.completed_cycles - 1)
                self.average_initial_score = (prev_total + cycle.initial_quality.overall_score) / self.completed_cycles

            if cycle.final_quality:
                prev_total = self.average_final_score * (self.completed_cycles - 1)
                self.average_final_score = (prev_total + cycle.final_quality.overall_score) / self.completed_cycles

                if cycle.final_quality.overall_score > self.best_score_achieved:
                    self.best_score_achieved = cycle.final_quality.overall_score

            # Track improvement
            improvement = cycle.improvement_delta
            self.total_improvement += improvement
            self.average_improvement_per_cycle = self.total_improvement / self.completed_cycles

            # Track learnings
            if cycle.scenario_learning:
                self.total_learnings_extracted += 1
            if cycle.playbook_learning:
                self.total_learnings_extracted += 1

            self.total_improvements_applied += len(cycle.improvements_applied)

            # Update trend
            if self.average_improvement_per_cycle > 0.05:
                self.improvement_trend = "improving"
            elif self.average_improvement_per_cycle < -0.02:
                self.improvement_trend = "declining"
            else:
                self.improvement_trend = "stable"
