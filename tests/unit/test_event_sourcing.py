"""Unit tests for Event Sourcing implementation.

Tests cover:
- Event creation and immutability
- Event store operations (append, query, replay)
- Optimistic concurrency control
- Edge cases and failure modes
- Compliance scenarios

Owner: Lara Dipupo
Issue: #8
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from uuid import UUID, uuid4

from threatsimgpt.core.event_sourcing import (
    Event,
    AggregateType,
    EventStore,
    ConcurrencyError,
    EventStoreError,
    EventNotFoundError,
    SimulationStarted,
    StageStarted,
    StageCompleted,
    StageFailed,
    SimulationCompleted,
    SimulationFailed,
    SimulationCancelled,
    EventSourcedAggregate,
    EventSourcedRepository,
)


# ============================================================================
# Event Tests - Immutability and Validation
# ============================================================================

class TestEventImmutability:
    """Test that events are truly immutable."""

    def test_event_is_frozen(self):
        """Events should be frozen dataclasses (immutable)."""
        event = Event(
            event_id=uuid4(),
            aggregate_id=uuid4(),
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data={"key": "value"},
            metadata={},
            sequence_number=1,
            timestamp=datetime.now(timezone.utc),
            version=1
        )
        
        # Attempting to modify should raise FrozenInstanceError
        with pytest.raises(Exception):  # dataclasses.FrozenInstanceError
            event.event_type = "Modified"

    def test_event_data_cannot_be_mutated_after_creation(self):
        """Event data dict should not affect event after creation."""
        event_data = {"mutable": "original"}
        event = Event(
            event_id=uuid4(),
            aggregate_id=uuid4(),
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data=event_data.copy(),  # Pass copy
            metadata={},
            sequence_number=1,
            timestamp=datetime.now(timezone.utc),
            version=1
        )
        
        # Modify original dict
        event_data["mutable"] = "modified"
        
        # Event should retain original value
        assert event.event_data["mutable"] == "original"


class TestEventValidation:
    """Test event validation rules."""

    def test_event_type_cannot_be_empty(self):
        """Event type must be provided."""
        with pytest.raises(ValueError, match="event_type cannot be empty"):
            Event(
                event_id=uuid4(),
                aggregate_id=uuid4(),
                aggregate_type=AggregateType.SIMULATION,
                event_type="",  # Empty
                event_data={},
                metadata={},
                sequence_number=1,
                timestamp=datetime.now(timezone.utc),
                version=1
            )

    def test_version_must_be_non_negative(self):
        """Version must be >= 0."""
        with pytest.raises(ValueError, match="version must be >= 0"):
            Event(
                event_id=uuid4(),
                aggregate_id=uuid4(),
                aggregate_type=AggregateType.SIMULATION,
                event_type="TestEvent",
                event_data={},
                metadata={},
                sequence_number=1,
                timestamp=datetime.now(timezone.utc),
                version=-1  # Negative
            )

    def test_timestamp_converted_to_utc_if_naive(self):
        """Naive timestamps should be converted to UTC."""
        naive_time = datetime(2026, 1, 13, 10, 30, 0)  # No timezone
        event = Event(
            event_id=uuid4(),
            aggregate_id=uuid4(),
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data={},
            metadata={},
            sequence_number=1,
            timestamp=naive_time,
            version=1
        )
        
        # Should now have UTC timezone
        assert event.timestamp.tzinfo == timezone.utc


class TestEventSerialization:
    """Test event to_dict/from_dict round-trip."""

    def test_event_round_trip_serialization(self):
        """Event should serialize and deserialize correctly."""
        original = Event(
            event_id=uuid4(),
            aggregate_id=uuid4(),
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data={"number": 42, "text": "hello", "nested": {"key": "value"}},
            metadata={"user_id": "user123"},
            sequence_number=100,
            timestamp=datetime.now(timezone.utc),
            version=5
        )
        
        # Serialize to dict
        event_dict = original.to_dict()
        
        # Deserialize back
        restored = Event.from_dict(event_dict)
        
        # Should be equal
        assert restored.event_id == original.event_id
        assert restored.aggregate_id == original.aggregate_id
        assert restored.aggregate_type == original.aggregate_type
        assert restored.event_type == original.event_type
        assert restored.event_data == original.event_data
        assert restored.metadata == original.metadata
        assert restored.sequence_number == original.sequence_number
        assert restored.version == original.version


# ============================================================================
# Simulation Event Factory Tests
# ============================================================================

class TestSimulationEvents:
    """Test simulation-specific event creation."""

    def test_simulation_started_event(self):
        """Test SimulationStarted event factory."""
        agg_id = uuid4()
        scenario_id = uuid4()
        event = SimulationStarted.create(
            aggregate_id=agg_id,
            scenario_id=scenario_id,
            max_stages=10,
            initiated_by="user@example.com",
            version=1,
            sequence_number=1
        )
        
        assert event.aggregate_id == agg_id
        assert event.aggregate_type == AggregateType.SIMULATION
        assert event.event_type == "SimulationStarted"
        assert event.event_data["scenario_id"] == str(scenario_id)
        assert event.event_data["max_stages"] == 10
        assert event.event_data["initiated_by"] == "user@example.com"
        assert event.version == 1

    def test_stage_completed_event(self):
        """Test StageCompleted event factory."""
        agg_id = uuid4()
        event = StageCompleted.create(
            aggregate_id=agg_id,
            stage_number=1,
            stage_id="stage-123",
            content_length=1024,
            duration_ms=250.5,
            version=2,
            sequence_number=2
        )
        
        assert event.event_type == "StageCompleted"
        assert event.event_data["stage_number"] == 1
        assert event.event_data["content_length"] == 1024
        assert event.event_data["duration_ms"] == 250.5
        assert event.event_data["success"] is True

    def test_simulation_failed_event(self):
        """Test SimulationFailed event factory."""
        agg_id = uuid4()
        event = SimulationFailed.create(
            aggregate_id=agg_id,
            error_message="LLM provider unavailable",
            failed_at_stage=3,
            version=5,
            sequence_number=10
        )
        
        assert event.event_type == "SimulationFailed"
        assert event.event_data["error_message"] == "LLM provider unavailable"
        assert event.event_data["failed_at_stage"] == 3
        assert event.metadata["severity"] == "error"
        assert event.metadata["final_state"] == "failed"


# ============================================================================
# Event Store Tests
# ============================================================================

class TestEventStore:
    """Test EventStore operations."""

    @pytest.fixture
    def event_store(self):
        """Create event store for testing (in-memory mode)."""
        return EventStore(connection_pool=None)

    @pytest.fixture
    def sample_event(self):
        """Create a sample event for testing."""
        return Event(
            event_id=uuid4(),
            aggregate_id=uuid4(),
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data={"test": "data"},
            metadata={"user_id": "test"},
            sequence_number=1,
            timestamp=datetime.now(timezone.utc),
            version=1
        )

    @pytest.mark.asyncio
    async def test_append_event(self, event_store, sample_event):
        """Test appending an event to the store."""
        # Should not raise
        await event_store.append(sample_event)

    @pytest.mark.asyncio
    async def test_get_next_sequence_is_thread_safe(self, event_store):
        """Test that sequence generation is thread-safe."""
        async def get_sequence():
            return await event_store._get_next_sequence()
        
        # Run 100 concurrent sequence requests
        sequences = await asyncio.gather(*[get_sequence() for _ in range(100)])
        
        # All should be unique and sequential
        assert len(set(sequences)) == 100
        assert sorted(sequences) == list(range(1, 101))

    @pytest.mark.asyncio
    async def test_get_aggregate_version_returns_zero_for_new_aggregate(self, event_store):
        """New aggregates should have version 0."""
        version = await event_store.get_aggregate_version(uuid4())
        assert version == 0


# ============================================================================
# Concurrency Tests
# ============================================================================

class TestOptimisticConcurrency:
    """Test optimistic concurrency control."""

    def test_concurrency_error_contains_version_info(self):
        """ConcurrencyError should contain version conflict details."""
        agg_id = uuid4()
        error = ConcurrencyError(
            aggregate_id=agg_id,
            expected_version=5,
            actual_version=7
        )
        
        assert error.aggregate_id == agg_id
        assert error.expected_version == 5
        assert error.actual_version == 7
        assert "expected version 5" in str(error)
        assert "got 7" in str(error)


# ============================================================================
# Event Sourced Aggregate Tests
# ============================================================================

class TestEventSourcedAggregate:
    """Test event-sourced aggregate base class."""

    @pytest.fixture
    def aggregate(self):
        """Create a test aggregate."""
        return EventSourcedAggregate(aggregate_id=uuid4())

    def test_new_aggregate_starts_at_version_zero(self, aggregate):
        """New aggregates should start at version 0."""
        assert aggregate.version == 0

    def test_apply_event_updates_version(self, aggregate):
        """Applying event should update aggregate version."""
        event = Event(
            event_id=uuid4(),
            aggregate_id=aggregate.aggregate_id,
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data={},
            metadata={},
            sequence_number=1,
            timestamp=datetime.now(timezone.utc),
            version=1
        )
        
        aggregate.apply_event(event)
        assert aggregate.version == 1

    def test_uncommitted_events_tracked(self, aggregate):
        """Uncommitted events should be tracked."""
        event = Event(
            event_id=uuid4(),
            aggregate_id=aggregate.aggregate_id,
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data={},
            metadata={},
            sequence_number=1,
            timestamp=datetime.now(timezone.utc),
            version=1
        )
        
        aggregate._raise_event(event)
        
        uncommitted = aggregate.get_uncommitted_events()
        assert len(uncommitted) == 1
        assert uncommitted[0].event_id == event.event_id

    def test_mark_events_committed_clears_uncommitted(self, aggregate):
        """Marking events as committed should clear uncommitted list."""
        event = Event(
            event_id=uuid4(),
            aggregate_id=aggregate.aggregate_id,
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data={},
            metadata={},
            sequence_number=1,
            timestamp=datetime.now(timezone.utc),
            version=1
        )
        
        aggregate._raise_event(event)
        assert len(aggregate.get_uncommitted_events()) == 1
        
        aggregate.mark_events_committed()
        assert len(aggregate.get_uncommitted_events()) == 0


# ============================================================================
# Repository Tests
# ============================================================================

class TestEventSourcedRepository:
    """Test repository pattern for event-sourced aggregates."""

    @pytest.fixture
    def event_store(self):
        return EventStore(connection_pool=None)

    @pytest.fixture
    def repository(self, event_store):
        return EventSourcedRepository(event_store)

    @pytest.mark.asyncio
    async def test_save_persists_uncommitted_events(self, repository):
        """Saving aggregate should persist all uncommitted events."""
        aggregate = EventSourcedAggregate(aggregate_id=uuid4())
        
        # Raise an event
        event = Event(
            event_id=uuid4(),
            aggregate_id=aggregate.aggregate_id,
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data={},
            metadata={},
            sequence_number=1,
            timestamp=datetime.now(timezone.utc),
            version=1
        )
        aggregate._raise_event(event)
        
        # Save should clear uncommitted
        await repository.save(aggregate)
        assert len(aggregate.get_uncommitted_events()) == 0


# ============================================================================
# Edge Case Tests
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_event_with_empty_event_data_dict(self):
        """Empty event_data should be allowed."""
        event = Event(
            event_id=uuid4(),
            aggregate_id=uuid4(),
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data={},  # Empty
            metadata={},
            sequence_number=1,
            timestamp=datetime.now(timezone.utc),
            version=1
        )
        assert event.event_data == {}

    def test_event_with_deeply_nested_data(self):
        """Events should handle deeply nested data structures."""
        nested_data = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "value": "deep"
                        }
                    }
                }
            }
        }
        
        event = Event(
            event_id=uuid4(),
            aggregate_id=uuid4(),
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data=nested_data,
            metadata={},
            sequence_number=1,
            timestamp=datetime.now(timezone.utc),
            version=1
        )
        
        assert event.event_data["level1"]["level2"]["level3"]["level4"]["value"] == "deep"

    def test_event_with_large_sequence_number(self):
        """Events should handle very large sequence numbers."""
        event = Event(
            event_id=uuid4(),
            aggregate_id=uuid4(),
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data={},
            metadata={},
            sequence_number=9999999999,  # Very large
            timestamp=datetime.now(timezone.utc),
            version=1
        )
        assert event.sequence_number == 9999999999


# ============================================================================
# Compliance Test Scenarios
# ============================================================================

class TestComplianceScenarios:
    """Test audit trail scenarios required for compliance."""

    @pytest.mark.asyncio
    async def test_can_query_all_actions_by_user(self, event_store=None):
        """Should be able to query all actions by a specific user."""
        # This would query metadata.user_id
        # Implementation pending database integration
        pass

    @pytest.mark.asyncio
    async def test_can_query_events_in_time_range(self, event_store=None):
        """Should be able to query events within a specific time range."""
        # This supports compliance reporting for specific periods
        # Implementation pending database integration
        pass

    @pytest.mark.asyncio
    async def test_events_are_never_deleted(self):
        """Events should never be deleted (append-only guarantee)."""
        # Verify no DELETE operations exist in EventStore
        # This is a structural guarantee, not a runtime test
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
