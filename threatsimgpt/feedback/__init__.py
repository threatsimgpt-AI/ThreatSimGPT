"""
ThreatSimGPT Feedback Loop System
=================================

Implements a continuous improvement cycle where:
1. Playbooks inform better scenario generation
2. Better scenarios produce better playbooks
3. Quality metrics drive optimization
4. The cycle continues toward optimal threat simulation

Architecture:
┌─────────────────────────────────────────────────────────────────────┐
│                   CONTINUOUS IMPROVEMENT CYCLE                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│         ┌──────────────────┐                                        │
│         │    SCENARIOS     │◄────────────────────┐                  │
│         │   Generation     │                     │                  │
│         └────────┬─────────┘                     │                  │
│                  │                               │                  │
│                  ▼                               │                  │
│         ┌──────────────────┐           ┌────────┴───────┐          │
│         │   SIMULATIONS    │           │   ENHANCEMENT  │          │
│         │    Execution     │           │     ENGINE     │          │
│         └────────┬─────────┘           │  (AI-Powered)  │          │
│                  │                     └────────▲───────┘          │
│                  ▼                               │                  │
│         ┌──────────────────┐                     │                  │
│         │    PLAYBOOKS     │                     │                  │
│         │   Generation     │                     │                  │
│         └────────┬─────────┘                     │                  │
│                  │                               │                  │
│                  ▼                               │                  │
│         ┌──────────────────┐           ┌────────┴───────┐          │
│         │    ANALYSIS      │──────────►│   LEARNINGS    │          │
│         │  & Evaluation    │           │   Extraction   │          │
│         └──────────────────┘           └────────────────┘          │
│                                                                      │
│  Quality Metrics:                                                    │
│  • Realism Score      • Technique Coverage   • Detection Rate       │
│  • Engagement Level   • Training Value       • Compliance Alignment │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘

Components:
- FeedbackLoop: Orchestrates the continuous improvement cycle
- ScenarioEnhancer: Uses playbook insights to improve scenarios
- PlaybookAnalyzer: Evaluates playbook quality and extracts learnings
- QualityMetrics: Tracks improvement over generations
- FeedbackStore: Persists learnings in Neo4j for retrieval
"""

__version__ = "1.0.0"

from .models import (
    FeedbackType,
    QualityDimension,
    QualityMetrics,
    LearningInsight,
    ImprovementSuggestion,
    ScenarioFeedback,
    PlaybookFeedback,
    EvolutionCycle,
    FeedbackStore,
)

from .analyzer import (
    ScenarioAnalyzer,
    PlaybookAnalyzer,
    FeedbackAggregator,
    CrossAnalyzer,
)

from .enhancer import (
    ScenarioEnhancer,
    PlaybookEnhancer,
)

from .orchestrator import (
    FeedbackLoop,
    CyclePhase,
    CycleState,
    GenerationContext,
    create_feedback_loop,
)

__all__ = [
    # Orchestrator - Main entry point
    "FeedbackLoop",
    "CyclePhase",
    "CycleState",
    "GenerationContext",
    "create_feedback_loop",
    # Models
    "FeedbackType",
    "QualityDimension",
    "QualityMetrics",
    "LearningInsight",
    "ImprovementSuggestion",
    "ScenarioFeedback",
    "PlaybookFeedback",
    "EvolutionCycle",
    "FeedbackStore",
    # Analysis
    "ScenarioAnalyzer",
    "PlaybookAnalyzer",
    "FeedbackAggregator",
    "CrossAnalyzer",
    # Enhancement
    "ScenarioEnhancer",
    "PlaybookEnhancer",
]
