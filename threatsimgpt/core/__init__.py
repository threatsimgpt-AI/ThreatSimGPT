"""Core simulation engine and models.

Contains the main simulation orchestration logic, data models,
and business logic for threat scenario execution.
"""

from threatsimgpt.core.models import (
    SimulationResult,
    ThreatScenario,
    SimulationStatus,
    SimulationStage,
)
from threatsimgpt.core.simulator import ThreatSimulator
from threatsimgpt.core.exceptions import (
    ThreatSimGPTError,
    SimulationError,
    ConfigurationError,
    ValidationError,
    LLMProviderError,
)
from threatsimgpt.core.mitigation_generator import (
    MitigationGenerator,
    MitigationPlaybook,
    generate_mitigation_playbook,
)
from threatsimgpt.core.team_playbooks import (
    TeamPlaybookGenerator,
    TeamPlaybook,
    SecurityTeam,
    generate_team_playbook,
    generate_all_team_playbooks,
)
from threatsimgpt.core.ai_enhanced_playbooks import (
    AIEnhancedPlaybookGenerator,
    PlaybookContext,
    PlaybookQuality,
    generate_ai_enhanced_manual,
    generate_all_ai_enhanced_manuals,
)
from threatsimgpt.core.playbook_validator import (
    PlaybookValidator,
    ValidationReport,
    ValidationFinding,
    ValidationScore,
    ValidationSeverity,
    ValidationCategory,
    ComplianceFramework,
    validate_playbook,
    get_validation_summary,
)
from threatsimgpt.core.batch_processor import (
    BatchProcessor,
    BatchConfig,
    BatchProgress,
    BatchResult,
    BatchStatus,
    BatchMetrics,
    JobResult,
    JobStatus,
    process_scenarios_batch,
    process_scenarios_batch_sync,
)
from threatsimgpt.core.event_sourcing import (
    Event,
    EventStore,
    EventSourcedAggregate,
    EventSourcedRepository,
    AggregateType,
    EventStoreError,
    ConcurrencyError,
)
from threatsimgpt.core.postgres_event_store import (
    PostgresEventStore,
)

__all__ = [
    "SimulationResult",
    "ThreatScenario",
    "SimulationStatus",
    "SimulationStage",
    "ThreatSimulator",
    "ThreatSimGPTError",
    "SimulationError",
    "ConfigurationError",
    "ValidationError",
    "LLMProviderError",
    "MitigationGenerator",
    "MitigationPlaybook",
    "generate_mitigation_playbook",
    "TeamPlaybookGenerator",
    "TeamPlaybook",
    "SecurityTeam",
    "generate_team_playbook",
    "generate_all_team_playbooks",
    "AIEnhancedPlaybookGenerator",
    "PlaybookContext",
    "PlaybookQuality",
    "generate_ai_enhanced_manual",
    "generate_all_ai_enhanced_manuals",
    # Playbook Validation
    "PlaybookValidator",
    "ValidationReport",
    "ValidationFinding",
    "ValidationScore",
    "ValidationSeverity",
    "ValidationCategory",
    "ComplianceFramework",
    "validate_playbook",
    "get_validation_summary",
    # Batch Processing
    "BatchProcessor",
    "BatchConfig",
    "BatchProgress",
    "BatchResult",
    "BatchStatus",
    "BatchMetrics",
    "JobResult",
    "JobStatus",
    "process_scenarios_batch",
    "process_scenarios_batch_sync",
    # Event Sourcing
    "Event",
    "EventStore",
    "EventSourcedAggregate",
    "EventSourcedRepository",
    "AggregateType",
    "EventStoreError",
    "ConcurrencyError",
    # PostgreSQL Event Store
    "PostgresEventStore",
]
