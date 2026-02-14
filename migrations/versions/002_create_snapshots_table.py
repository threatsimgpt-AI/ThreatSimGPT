"""Create snapshots table for performance optimization

Revision ID: 002_create_snapshots_table
Revises: 001_create_events_table
Create Date: 2026-01-23

Issue: #119 - Event Sourcing Phase 2
Author: Omolara Oladipupo (@laradipupo)
Note: Snapshots will be fully implemented in Phase 3, but table created now
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '002_create_snapshots_table'
down_revision: Union[str, None] = '001_create_events_table'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create snapshots table for aggregate state caching."""
    
    op.create_table(
        'snapshots',
        sa.Column('aggregate_id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('aggregate_type', sa.String(50), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('state', postgresql.JSONB(), nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.func.current_timestamp()),
        schema='audit'
    )
    
    op.create_index(
        'idx_snapshots_aggregate_type',
        'snapshots',
        ['aggregate_type'],
        schema='audit'
    )


def downgrade() -> None:
    """Drop the snapshots table."""
    op.drop_table('snapshots', schema='audit')
