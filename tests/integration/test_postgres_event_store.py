"""Integration tests for PostgreSQL Event Store.

These tests verify the PostgreSQL persistence layer for event sourcing.
Requires a running PostgreSQL instance (use docker-compose for local testing).

Issue: #119 - Event Sourcing Phase 2
Author: Omolara Oladipupo (@laradipupo)
Track: core_dev
"""

import asyncio
import os
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from typing import List

# Skip all tests if asyncpg not available
asyncpg = pytest.importorskip("asyncpg")

from threatsimgpt.core.event_sourcing import (
    Event,
    AggregateType,
    ConcurrencyError,
    EventStoreError,
    SimulationStarted,
    StageCompleted,
    SimulationCompleted,
)
from threatsimgpt.core.postgres_event_store import (
    PostgresEventStore,
    append_with_retry,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="module")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
def database_url():
    """Get database URL from environment or use default test URL."""
    return os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/threatsimgpt_test"
    )


@pytest.fixture
async def event_store(database_url):
    """Create and initialize event store for testing."""
    try:
        store = await PostgresEventStore.create(
            database_url,
            min_connections=1,
            max_connections=5
        )
        yield store
    finally:
        # Cleanup: drop test data
        async with store._acquire() as conn:
            await conn.execute("DELETE FROM audit.events WHERE TRUE")
            await conn.execute("DELETE FROM audit.snapshots WHERE TRUE")
        await store.close()


@pytest.fixture
def sample_aggregate_id():
    """Generate a unique aggregate ID for tests."""
    return uuid4()


def create_test_event(
    aggregate_id,
    event_type: str = "TestEvent",
    version: int = 1,
    sequence: int = 1,
    **kwargs
) -> Event:
    """Helper to create test events."""
    return Event(
        event_id=uuid4(),
        aggregate_id=aggregate_id,
        aggregate_type=AggregateType.SIMULATION,
        event_type=event_type,
        event_data=kwargs.get("event_data", {"test": "data"}),
        metadata=kwargs.get("metadata", {}),
        sequence_number=sequence,
        timestamp=datetime.now(timezone.utc),
        version=version
    )


# =============================================================================
# Connection & Initialization Tests
# =============================================================================

class TestConnectionAndSetup:
    """Test database connection and schema setup."""

    @pytest.mark.asyncio
    async def test_create_connection_pool(self, database_url):
        """Test that connection pool can be created."""
        store = await PostgresEventStore.create(database_url)
        assert store is not None
        assert store._pool is not None
        await store.close()

    @pytest.mark.asyncio
    async def test_schema_initialized(self, event_store):
        """Test that schema is properly initialized."""
        assert event_store._initialized is True
        
        # Verify events table exists
        async with event_store._acquire() as conn:
            result = await conn.fetchval(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'audit' AND table_name = 'events'
                )
                """
            )
            assert result is True

    @pytest.mark.asyncio
    async def test_context_manager(self, database_url):
        """Test async context manager properly closes pool."""
        async with await PostgresEventStore.create(database_url) as store:
            assert store._pool is not None
        # Pool should be closed after exiting context
        assert store._pool._closed


# =============================================================================
# Basic CRUD Operations
# =============================================================================

class TestAppendOperations:
    """Test event append operations."""

    @pytest.mark.asyncio
    async def test_append_single_event(self, event_store, sample_aggregate_id):
        """Test appending a single event."""
        event = create_test_event(sample_aggregate_id)
        sequence = await event_store.append(event)
        
        assert sequence is not None
        assert sequence > 0

    @pytest.mark.asyncio
    async def test_append_returns_sequence_number(self, event_store, sample_aggregate_id):
        """Test that append returns incrementing sequence numbers."""
        event1 = create_test_event(sample_aggregate_id, version=1)
        event2 = create_test_event(sample_aggregate_id, version=2)
        
        seq1 = await event_store.append(event1)
        seq2 = await event_store.append(event2)
        
        assert seq2 > seq1

    @pytest.mark.asyncio
    async def test_append_batch(self, event_store, sample_aggregate_id):
        """Test batch event append."""
        events = [
            create_test_event(sample_aggregate_id, version=i+1, event_type=f"Event{i}")
            for i in range(5)
        ]
        
        sequences = await event_store.append_batch(events)
        
        assert len(sequences) == 5
        # Sequences should be in order
        for i in range(1, len(sequences)):
            assert sequences[i] > sequences[i-1]

    @pytest.mark.asyncio
    async def test_append_with_simulation_events(self, event_store):
        """Test appending real simulation event types."""
        aggregate_id = uuid4()
        scenario_id = uuid4()
        
        # Create simulation started event
        event = SimulationStarted.create(
            aggregate_id=aggregate_id,
            scenario_id=scenario_id,
            max_stages=5,
            initiated_by="test_user",
            version=1,
            sequence_number=1
        )
        
        sequence = await event_store.append(event)
        assert sequence > 0
        
        # Retrieve and verify
        events = await event_store.get_events(aggregate_id)
        assert len(events) == 1
        assert events[0].event_type == "SimulationStarted"
        assert events[0].event_data["max_stages"] == 5


# =============================================================================
# Read Operations
# =============================================================================

class TestReadOperations:
    """Test event retrieval operations."""

    @pytest.mark.asyncio
    async def test_get_events_for_aggregate(self, event_store, sample_aggregate_id):
        """Test retrieving all events for an aggregate."""
        # Append several events
        for i in range(3):
            event = create_test_event(
                sample_aggregate_id, 
                version=i+1, 
                event_type=f"Event{i+1}"
            )
            await event_store.append(event)
        
        # Retrieve events
        events = await event_store.get_events(sample_aggregate_id)
        
        assert len(events) == 3
        # Should be ordered by version
        for i, event in enumerate(events):
            assert event.version == i + 1

    @pytest.mark.asyncio
    async def test_get_events_version_range(self, event_store, sample_aggregate_id):
        """Test retrieving events within version range."""
        # Append 5 events
        for i in range(5):
            event = create_test_event(sample_aggregate_id, version=i+1)
            await event_store.append(event)
        
        # Get events from version 2 to 4
        events = await event_store.get_events(
            sample_aggregate_id, 
            from_version=2, 
            to_version=4
        )
        
        assert len(events) == 3
        assert events[0].version == 2
        assert events[-1].version == 4

    @pytest.mark.asyncio
    async def test_get_events_by_type(self, event_store):
        """Test querying events by event type."""
        # Create events of different types
        agg1 = uuid4()
        agg2 = uuid4()
        
        await event_store.append(
            create_test_event(agg1, event_type="TypeA", version=1)
        )
        await event_store.append(
            create_test_event(agg2, event_type="TypeB", version=1)
        )
        await event_store.append(
            create_test_event(agg1, event_type="TypeA", version=2)
        )
        
        # Query TypeA events
        now = datetime.now(timezone.utc)
        events = await event_store.get_events_by_type(
            "TypeA",
            from_timestamp=now - timedelta(hours=1),
            to_timestamp=now + timedelta(hours=1)
        )
        
        assert len(events) == 2
        assert all(e.event_type == "TypeA" for e in events)

    @pytest.mark.asyncio
    async def test_get_events_empty_aggregate(self, event_store):
        """Test retrieving events for non-existent aggregate."""
        events = await event_store.get_events(uuid4())
        assert events == []

    @pytest.mark.asyncio
    async def test_get_aggregate_version(self, event_store, sample_aggregate_id):
        """Test getting current aggregate version."""
        # Initially no events
        version = await event_store.get_aggregate_version(sample_aggregate_id)
        assert version == 0
        
        # Add some events
        for i in range(3):
            event = create_test_event(sample_aggregate_id, version=i+1)
            await event_store.append(event)
        
        # Check version
        version = await event_store.get_aggregate_version(sample_aggregate_id)
        assert version == 3


# =============================================================================
# Concurrency Control Tests
# =============================================================================

class TestConcurrencyControl:
    """Test optimistic concurrency control."""

    @pytest.mark.asyncio
    async def test_concurrency_error_on_version_conflict(self, event_store, sample_aggregate_id):
        """Test that version conflicts raise ConcurrencyError."""
        # Append first event
        event1 = create_test_event(sample_aggregate_id, version=1)
        await event_store.append(event1)
        
        # Try to append another event with same version
        event2 = create_test_event(sample_aggregate_id, version=1)
        
        with pytest.raises(ConcurrencyError) as exc_info:
            await event_store.append(event2)
        
        assert exc_info.value.expected_version == 0
        assert exc_info.value.actual_version == 1

    @pytest.mark.asyncio
    async def test_concurrency_error_on_gap(self, event_store, sample_aggregate_id):
        """Test that version gaps raise ConcurrencyError."""
        # Append first event
        event1 = create_test_event(sample_aggregate_id, version=1)
        await event_store.append(event1)
        
        # Try to append event with version 3 (skipping 2)
        event3 = create_test_event(sample_aggregate_id, version=3)
        
        with pytest.raises(ConcurrencyError):
            await event_store.append(event3)

    @pytest.mark.asyncio
    async def test_append_with_retry_success(self, event_store, sample_aggregate_id):
        """Test append_with_retry succeeds on first try."""
        def event_factory(version):
            return create_test_event(sample_aggregate_id, version=version)
        
        event = await append_with_retry(
            event_store,
            event_factory,
            sample_aggregate_id
        )
        
        assert event.version == 1

    @pytest.mark.asyncio
    async def test_concurrent_appends(self, event_store):
        """Test handling of concurrent append attempts."""
        aggregate_id = uuid4()
        
        async def append_event(version):
            event = create_test_event(aggregate_id, version=version)
            try:
                await event_store.append(event)
                return True
            except ConcurrencyError:
                return False
        
        # Try to append same version concurrently
        await event_store.append(create_test_event(aggregate_id, version=1))
        
        # Both try version 2
        results = await asyncio.gather(
            append_event(2),
            append_event(2),
            return_exceptions=True
        )
        
        # Only one should succeed
        successes = sum(1 for r in results if r is True)
        assert successes == 1


# =============================================================================
# Event Replay Tests
# =============================================================================

class TestEventReplay:
    """Test event replay functionality."""

    @pytest.mark.asyncio
    async def test_replay_events(self, event_store, sample_aggregate_id):
        """Test replaying events through handler."""
        # Append events
        for i in range(5):
            event = create_test_event(
                sample_aggregate_id,
                version=i+1,
                event_type=f"Event{i+1}"
            )
            await event_store.append(event)
        
        # Replay events
        replayed_events = []
        
        async def handler(event):
            replayed_events.append(event)
        
        count = await event_store.replay_events(sample_aggregate_id, handler)
        
        assert count == 5
        assert len(replayed_events) == 5
        # Should be in order
        for i, event in enumerate(replayed_events):
            assert event.version == i + 1

    @pytest.mark.asyncio
    async def test_replay_with_sync_handler(self, event_store, sample_aggregate_id):
        """Test replay with synchronous handler."""
        await event_store.append(create_test_event(sample_aggregate_id, version=1))
        
        replayed = []
        
        def sync_handler(event):
            replayed.append(event)
        
        count = await event_store.replay_events(sample_aggregate_id, sync_handler)
        
        assert count == 1
        assert len(replayed) == 1


# =============================================================================
# Statistics & Monitoring Tests
# =============================================================================

class TestStatistics:
    """Test statistics and monitoring functions."""

    @pytest.mark.asyncio
    async def test_get_event_count(self, event_store, sample_aggregate_id):
        """Test getting event count."""
        # Initial count for this aggregate should be 0
        count = await event_store.get_event_count(aggregate_id=sample_aggregate_id)
        assert count == 0
        
        # Add events
        for i in range(3):
            event = create_test_event(sample_aggregate_id, version=i+1)
            await event_store.append(event)
        
        count = await event_store.get_event_count(aggregate_id=sample_aggregate_id)
        assert count == 3

    @pytest.mark.asyncio
    async def test_get_latest_sequence(self, event_store, sample_aggregate_id):
        """Test getting latest sequence number."""
        event = create_test_event(sample_aggregate_id, version=1)
        seq = await event_store.append(event)
        
        latest = await event_store.get_latest_sequence()
        assert latest >= seq

    @pytest.mark.asyncio
    async def test_aggregate_exists(self, event_store, sample_aggregate_id):
        """Test checking if aggregate exists."""
        # Should not exist initially
        exists = await event_store.aggregate_exists(sample_aggregate_id)
        assert exists is False
        
        # Add event
        event = create_test_event(sample_aggregate_id, version=1)
        await event_store.append(event)
        
        # Now should exist
        exists = await event_store.aggregate_exists(sample_aggregate_id)
        assert exists is True

    @pytest.mark.asyncio
    async def test_get_all_aggregate_ids(self, event_store):
        """Test getting all aggregate IDs."""
        # Create events for multiple aggregates
        agg_ids = [uuid4() for _ in range(3)]
        
        for agg_id in agg_ids:
            event = create_test_event(agg_id, version=1)
            await event_store.append(event)
        
        all_ids = await event_store.get_all_aggregate_ids()
        
        for agg_id in agg_ids:
            assert agg_id in all_ids


# =============================================================================
# Data Integrity Tests
# =============================================================================

class TestDataIntegrity:
    """Test data integrity and serialization."""

    @pytest.mark.asyncio
    async def test_event_data_preserved(self, event_store, sample_aggregate_id):
        """Test that event data is preserved through storage."""
        original_data = {
            "complex": {
                "nested": ["array", "values"],
                "number": 42,
                "boolean": True,
                "null": None
            },
            "unicode": "Hello 世界 🌍"
        }
        
        event = create_test_event(
            sample_aggregate_id,
            version=1,
            event_data=original_data
        )
        await event_store.append(event)
        
        # Retrieve and verify
        events = await event_store.get_events(sample_aggregate_id)
        assert events[0].event_data == original_data

    @pytest.mark.asyncio
    async def test_metadata_preserved(self, event_store, sample_aggregate_id):
        """Test that metadata is preserved."""
        original_metadata = {
            "user_id": "user123",
            "correlation_id": str(uuid4()),
            "tags": ["important", "audit"]
        }
        
        event = create_test_event(
            sample_aggregate_id,
            version=1,
            metadata=original_metadata
        )
        await event_store.append(event)
        
        events = await event_store.get_events(sample_aggregate_id)
        assert events[0].metadata == original_metadata

    @pytest.mark.asyncio
    async def test_timestamp_preserved(self, event_store, sample_aggregate_id):
        """Test that timestamps are preserved with timezone."""
        original_timestamp = datetime.now(timezone.utc)
        
        event = Event(
            event_id=uuid4(),
            aggregate_id=sample_aggregate_id,
            aggregate_type=AggregateType.SIMULATION,
            event_type="TestEvent",
            event_data={},
            metadata={},
            sequence_number=1,
            timestamp=original_timestamp,
            version=1
        )
        await event_store.append(event)
        
        events = await event_store.get_events(sample_aggregate_id)
        
        # Timestamps should be within 1 second
        time_diff = abs((events[0].timestamp - original_timestamp).total_seconds())
        assert time_diff < 1


# =============================================================================
# Performance Tests
# =============================================================================

class TestPerformance:
    """Performance tests for large event volumes."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_append_1000_events(self, event_store, sample_aggregate_id):
        """Test appending 1000 events."""
        events = [
            create_test_event(sample_aggregate_id, version=i+1)
            for i in range(1000)
        ]
        
        # Batch append
        sequences = await event_store.append_batch(events)
        assert len(sequences) == 1000
        
        # Verify retrieval
        retrieved = await event_store.get_events(sample_aggregate_id)
        assert len(retrieved) == 1000

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_replay_large_aggregate(self, event_store, sample_aggregate_id):
        """Test replaying aggregate with many events."""
        # First append events
        events = [
            create_test_event(sample_aggregate_id, version=i+1)
            for i in range(500)
        ]
        await event_store.append_batch(events)
        
        # Replay
        count = 0
        
        def counter(event):
            nonlocal count
            count += 1
        
        await event_store.replay_events(sample_aggregate_id, counter)
        assert count == 500
