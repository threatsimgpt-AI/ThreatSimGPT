"""PostgreSQL Event Store Implementation for ThreatSimGPT.

This module provides the PostgreSQL persistence layer for the event sourcing system.
It implements async database operations using asyncpg with connection pooling.

Issue: #119 - Event Sourcing Phase 2 - PostgreSQL Persistence & Integration
Author: Omolara Oladipupo (@laradipupo)
Track: core_dev
"""

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, AsyncIterator
from uuid import UUID

try:
    import asyncpg
    from asyncpg import Pool, Connection
    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False
    Pool = Any
    Connection = Any

from .event_sourcing import (
    Event,
    AggregateType,
    EventStoreError,
    ConcurrencyError,
    EventNotFoundError,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Database Schema SQL
# =============================================================================

EVENTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit.events (
    -- Primary identification
    event_id UUID PRIMARY KEY,
    sequence_number BIGSERIAL UNIQUE NOT NULL,
    
    -- Aggregate information
    aggregate_id UUID NOT NULL,
    aggregate_type VARCHAR(50) NOT NULL,
    version INTEGER NOT NULL,
    
    -- Event data
    event_type VARCHAR(100) NOT NULL,
    event_data JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    
    -- Timestamps
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT unique_aggregate_version UNIQUE (aggregate_id, version)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_events_aggregate_id ON audit.events(aggregate_id);
CREATE INDEX IF NOT EXISTS idx_events_aggregate_type ON audit.events(aggregate_type);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON audit.events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON audit.events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_aggregate_version ON audit.events(aggregate_id, version);

-- GIN index for JSONB queries
CREATE INDEX IF NOT EXISTS idx_events_event_data ON audit.events USING GIN (event_data);
CREATE INDEX IF NOT EXISTS idx_events_metadata ON audit.events USING GIN (metadata);
"""

SNAPSHOTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit.snapshots (
    aggregate_id UUID PRIMARY KEY,
    aggregate_type VARCHAR(50) NOT NULL,
    version INTEGER NOT NULL,
    state JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
"""


# =============================================================================
# PostgreSQL Event Store Implementation
# =============================================================================

class PostgresEventStore:
    """PostgreSQL-backed event store with async support and connection pooling.
    
    Features:
    - Async operations using asyncpg
    - Connection pooling for high concurrency
    - Optimistic concurrency control via version checking
    - Event replay for aggregate reconstruction
    - Temporal queries for compliance
    - Automatic schema creation
    
    Usage:
        async with PostgresEventStore.create(database_url) as store:
            await store.append(event)
            events = await store.get_events(aggregate_id)
    """

    def __init__(self, pool: Pool):
        """Initialize with an existing connection pool.
        
        Use PostgresEventStore.create() for automatic pool management.
        
        Args:
            pool: asyncpg connection pool
        """
        if not ASYNCPG_AVAILABLE:
            raise ImportError(
                "asyncpg is required for PostgresEventStore. "
                "Install with: pip install asyncpg"
            )
        self._pool = pool
        self._initialized = False
        logger.info("PostgresEventStore created with connection pool")

    @classmethod
    async def create(
        cls,
        database_url: Optional[str] = None,
        min_connections: int = 2,
        max_connections: int = 10,
        **pool_kwargs
    ) -> 'PostgresEventStore':
        """Create a new PostgresEventStore with connection pool.
        
        Args:
            database_url: PostgreSQL connection string (or from DATABASE_URL env)
            min_connections: Minimum pool connections
            max_connections: Maximum pool connections
            **pool_kwargs: Additional arguments for asyncpg.create_pool
            
        Returns:
            Initialized PostgresEventStore
            
        Example:
            store = await PostgresEventStore.create(
                "postgresql://user:pass@localhost/db"
            )
        """
        if not ASYNCPG_AVAILABLE:
            raise ImportError(
                "asyncpg is required for PostgresEventStore. "
                "Install with: pip install asyncpg"
            )
            
        url = database_url or os.getenv("DATABASE_URL")
        if not url:
            raise ValueError(
                "Database URL required. Provide database_url or set DATABASE_URL env var"
            )
        
        logger.info(f"Creating connection pool (min={min_connections}, max={max_connections})")
        
        pool = await asyncpg.create_pool(
            url,
            min_size=min_connections,
            max_size=max_connections,
            **pool_kwargs
        )
        
        store = cls(pool)
        await store.initialize_schema()
        return store

    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool:
            await self._pool.close()
            logger.info("Connection pool closed")

    async def __aenter__(self) -> 'PostgresEventStore':
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit - close pool."""
        await self.close()

    @asynccontextmanager
    async def _acquire(self) -> AsyncIterator[Connection]:
        """Acquire a connection from the pool."""
        async with self._pool.acquire() as conn:
            yield conn

    async def initialize_schema(self) -> None:
        """Create database tables if they don't exist."""
        if self._initialized:
            return
            
        async with self._acquire() as conn:
            # Ensure audit schema exists
            await conn.execute("CREATE SCHEMA IF NOT EXISTS audit")
            
            # Create events table
            await conn.execute(EVENTS_TABLE_SQL)
            
            # Create snapshots table (for future Phase 3)
            await conn.execute(SNAPSHOTS_TABLE_SQL)
            
            self._initialized = True
            logger.info("Event store schema initialized")

    # =========================================================================
    # Core Operations
    # =========================================================================

    async def append(self, event: Event) -> int:
        """Append an event to the store with optimistic concurrency control.
        
        Args:
            event: The event to append
            
        Returns:
            The assigned sequence number
            
        Raises:
            ConcurrencyError: If version conflict detected
            EventStoreError: If write fails
        """
        async with self._acquire() as conn:
            async with conn.transaction():
                # Check current version for optimistic concurrency
                current_version = await self._get_aggregate_version(conn, event.aggregate_id)
                
                expected_version = event.version - 1
                if current_version != expected_version:
                    raise ConcurrencyError(
                        event.aggregate_id,
                        expected_version,
                        current_version
                    )
                
                # Insert the event
                sequence = await conn.fetchval(
                    """
                    INSERT INTO audit.events (
                        event_id, aggregate_id, aggregate_type, version,
                        event_type, event_data, metadata, timestamp
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    RETURNING sequence_number
                    """,
                    event.event_id,
                    event.aggregate_id,
                    event.aggregate_type.value,
                    event.version,
                    event.event_type,
                    json.dumps(event.event_data),
                    json.dumps(event.metadata),
                    event.timestamp
                )
                
                logger.debug(
                    f"Event appended: {event.event_type} for "
                    f"{event.aggregate_type}:{event.aggregate_id} "
                    f"(v{event.version}, seq={sequence})"
                )
                
                return sequence

    async def append_batch(self, events: List[Event]) -> List[int]:
        """Append multiple events atomically.
        
        All events must be for the same aggregate and sequential versions.
        
        Args:
            events: List of events to append
            
        Returns:
            List of assigned sequence numbers
            
        Raises:
            ConcurrencyError: If version conflict detected
            EventStoreError: If write fails
        """
        if not events:
            return []
            
        # Validate all events are for same aggregate
        aggregate_id = events[0].aggregate_id
        if not all(e.aggregate_id == aggregate_id for e in events):
            raise EventStoreError("All events in batch must be for same aggregate")
        
        # Validate versions are sequential
        for i, event in enumerate(events):
            if i > 0 and event.version != events[i-1].version + 1:
                raise EventStoreError("Event versions must be sequential")
        
        async with self._acquire() as conn:
            async with conn.transaction():
                # Check current version
                current_version = await self._get_aggregate_version(conn, aggregate_id)
                expected_version = events[0].version - 1
                
                if current_version != expected_version:
                    raise ConcurrencyError(aggregate_id, expected_version, current_version)
                
                # Insert all events
                sequences = []
                for event in events:
                    sequence = await conn.fetchval(
                        """
                        INSERT INTO audit.events (
                            event_id, aggregate_id, aggregate_type, version,
                            event_type, event_data, metadata, timestamp
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        RETURNING sequence_number
                        """,
                        event.event_id,
                        event.aggregate_id,
                        event.aggregate_type.value,
                        event.version,
                        event.event_type,
                        json.dumps(event.event_data),
                        json.dumps(event.metadata),
                        event.timestamp
                    )
                    sequences.append(sequence)
                
                logger.debug(f"Batch of {len(events)} events appended for {aggregate_id}")
                return sequences

    async def get_events(
        self,
        aggregate_id: UUID,
        from_version: int = 0,
        to_version: Optional[int] = None
    ) -> List[Event]:
        """Get all events for an aggregate within version range.
        
        Args:
            aggregate_id: ID of the aggregate
            from_version: Start version (inclusive, default 0)
            to_version: End version (inclusive), None for latest
            
        Returns:
            List of events ordered by version
        """
        async with self._acquire() as conn:
            if to_version is not None:
                rows = await conn.fetch(
                    """
                    SELECT event_id, aggregate_id, aggregate_type, version,
                           event_type, event_data, metadata, sequence_number, timestamp
                    FROM audit.events
                    WHERE aggregate_id = $1 AND version >= $2 AND version <= $3
                    ORDER BY version ASC
                    """,
                    aggregate_id, from_version, to_version
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT event_id, aggregate_id, aggregate_type, version,
                           event_type, event_data, metadata, sequence_number, timestamp
                    FROM audit.events
                    WHERE aggregate_id = $1 AND version >= $2
                    ORDER BY version ASC
                    """,
                    aggregate_id, from_version
                )
            
            return [self._row_to_event(row) for row in rows]

    async def get_events_by_type(
        self,
        event_type: str,
        from_timestamp: datetime,
        to_timestamp: datetime,
        limit: int = 1000
    ) -> List[Event]:
        """Query events by type within time range.
        
        Useful for compliance and audit queries.
        
        Args:
            event_type: Event type to filter
            from_timestamp: Start time (inclusive)
            to_timestamp: End time (inclusive)
            limit: Maximum events to return
            
        Returns:
            List of events ordered by timestamp
        """
        async with self._acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT event_id, aggregate_id, aggregate_type, version,
                       event_type, event_data, metadata, sequence_number, timestamp
                FROM audit.events
                WHERE event_type = $1 
                  AND timestamp >= $2 
                  AND timestamp <= $3
                ORDER BY timestamp ASC
                LIMIT $4
                """,
                event_type, from_timestamp, to_timestamp, limit
            )
            
            return [self._row_to_event(row) for row in rows]

    async def get_events_by_aggregate_type(
        self,
        aggregate_type: AggregateType,
        from_timestamp: datetime,
        to_timestamp: datetime,
        limit: int = 1000
    ) -> List[Event]:
        """Query events by aggregate type within time range.
        
        Args:
            aggregate_type: Type of aggregate
            from_timestamp: Start time (inclusive)
            to_timestamp: End time (inclusive)
            limit: Maximum events to return
            
        Returns:
            List of events ordered by timestamp
        """
        async with self._acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT event_id, aggregate_id, aggregate_type, version,
                       event_type, event_data, metadata, sequence_number, timestamp
                FROM audit.events
                WHERE aggregate_type = $1 
                  AND timestamp >= $2 
                  AND timestamp <= $3
                ORDER BY timestamp ASC
                LIMIT $4
                """,
                aggregate_type.value, from_timestamp, to_timestamp, limit
            )
            
            return [self._row_to_event(row) for row in rows]

    async def get_aggregate_version(self, aggregate_id: UUID) -> int:
        """Get current version of an aggregate.
        
        Args:
            aggregate_id: ID of aggregate
            
        Returns:
            Current version number (0 if aggregate doesn't exist)
        """
        async with self._acquire() as conn:
            return await self._get_aggregate_version(conn, aggregate_id)

    async def _get_aggregate_version(self, conn: Connection, aggregate_id: UUID) -> int:
        """Internal version lookup (within existing connection)."""
        result = await conn.fetchval(
            """
            SELECT COALESCE(MAX(version), 0)
            FROM audit.events
            WHERE aggregate_id = $1
            """,
            aggregate_id
        )
        return result or 0

    async def aggregate_exists(self, aggregate_id: UUID) -> bool:
        """Check if an aggregate has any events."""
        async with self._acquire() as conn:
            result = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM audit.events WHERE aggregate_id = $1)",
                aggregate_id
            )
            return result

    # =========================================================================
    # Event Replay & State Reconstruction
    # =========================================================================

    async def replay_events(
        self,
        aggregate_id: UUID,
        handler: callable
    ) -> int:
        """Replay all events for an aggregate through a handler.
        
        This is the core event replay capability for state reconstruction.
        
        Args:
            aggregate_id: ID of aggregate to replay
            handler: Async or sync function called with each event
            
        Returns:
            Number of events replayed
        """
        events = await self.get_events(aggregate_id)
        
        for event in events:
            if asyncio.iscoroutinefunction(handler):
                await handler(event)
            else:
                handler(event)
        
        logger.debug(f"Replayed {len(events)} events for aggregate {aggregate_id}")
        return len(events)

    async def get_all_aggregate_ids(
        self,
        aggregate_type: Optional[AggregateType] = None
    ) -> List[UUID]:
        """Get all unique aggregate IDs, optionally filtered by type.
        
        Args:
            aggregate_type: Optional filter by aggregate type
            
        Returns:
            List of unique aggregate IDs
        """
        async with self._acquire() as conn:
            if aggregate_type:
                rows = await conn.fetch(
                    """
                    SELECT DISTINCT aggregate_id
                    FROM audit.events
                    WHERE aggregate_type = $1
                    """,
                    aggregate_type.value
                )
            else:
                rows = await conn.fetch(
                    "SELECT DISTINCT aggregate_id FROM audit.events"
                )
            
            return [row['aggregate_id'] for row in rows]

    # =========================================================================
    # Statistics & Monitoring
    # =========================================================================

    async def get_event_count(
        self,
        aggregate_id: Optional[UUID] = None,
        event_type: Optional[str] = None
    ) -> int:
        """Get count of events with optional filters."""
        async with self._acquire() as conn:
            if aggregate_id and event_type:
                return await conn.fetchval(
                    "SELECT COUNT(*) FROM audit.events WHERE aggregate_id = $1 AND event_type = $2",
                    aggregate_id, event_type
                )
            elif aggregate_id:
                return await conn.fetchval(
                    "SELECT COUNT(*) FROM audit.events WHERE aggregate_id = $1",
                    aggregate_id
                )
            elif event_type:
                return await conn.fetchval(
                    "SELECT COUNT(*) FROM audit.events WHERE event_type = $1",
                    event_type
                )
            else:
                return await conn.fetchval("SELECT COUNT(*) FROM audit.events")

    async def get_latest_sequence(self) -> int:
        """Get the latest global sequence number."""
        async with self._acquire() as conn:
            result = await conn.fetchval(
                "SELECT COALESCE(MAX(sequence_number), 0) FROM audit.events"
            )
            return result or 0

    # =========================================================================
    # Helpers
    # =========================================================================

    def _row_to_event(self, row: asyncpg.Record) -> Event:
        """Convert database row to Event object."""
        return Event(
            event_id=row['event_id'],
            aggregate_id=row['aggregate_id'],
            aggregate_type=AggregateType(row['aggregate_type']),
            event_type=row['event_type'],
            event_data=json.loads(row['event_data']) if isinstance(row['event_data'], str) else row['event_data'],
            metadata=json.loads(row['metadata']) if isinstance(row['metadata'], str) else row['metadata'],
            sequence_number=row['sequence_number'],
            timestamp=row['timestamp'],
            version=row['version']
        )


# =============================================================================
# Retry Logic for Concurrency Conflicts
# =============================================================================

async def append_with_retry(
    store: PostgresEventStore,
    event_factory: callable,
    aggregate_id: UUID,
    max_retries: int = 3,
    retry_delay: float = 0.1
) -> Event:
    """Append an event with automatic retry on concurrency conflicts.
    
    Args:
        store: The event store
        event_factory: Function that creates the event given current version
        aggregate_id: ID of the aggregate
        max_retries: Maximum retry attempts
        retry_delay: Delay between retries (seconds)
        
    Returns:
        The successfully appended event
        
    Raises:
        ConcurrencyError: If all retries exhausted
    """
    last_error = None
    
    for attempt in range(max_retries + 1):
        try:
            current_version = await store.get_aggregate_version(aggregate_id)
            event = event_factory(current_version + 1)
            await store.append(event)
            return event
            
        except ConcurrencyError as e:
            last_error = e
            if attempt < max_retries:
                logger.warning(
                    f"Concurrency conflict (attempt {attempt + 1}/{max_retries + 1}), "
                    f"retrying in {retry_delay}s"
                )
                await asyncio.sleep(retry_delay * (attempt + 1))  # Exponential backoff
            else:
                logger.error(f"All {max_retries + 1} attempts failed due to concurrency conflicts")
    
    raise last_error
