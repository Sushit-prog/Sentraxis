"""entities + events: normalized telemetry foundation

Revision ID: 0002_entities_events
Revises: 0001_initial
Create Date: 2026-08-24

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0002_entities_events"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "entities",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("type", sa.String(length=16), nullable=False),
        sa.Column("identifier", sa.String(length=255), nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("type", "identifier", name="uq_entities_type_identifier"),
    )

    op.create_table(
        "events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("src_entity_id", sa.BigInteger(), nullable=False),
        sa.Column("dst_entity_id", sa.BigInteger(), nullable=True),
        sa.Column("ground_truth_label", sa.Boolean(), nullable=True),
        sa.Column("features", JSONB(), nullable=False),
        sa.Column(
            "ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(["src_entity_id"], ["entities.id"], name="fk_events_src_entity"),
        sa.ForeignKeyConstraint(["dst_entity_id"], ["entities.id"], name="fk_events_dst_entity"),
        sa.UniqueConstraint("event_id", name="uq_events_event_id"),
    )
    op.create_index("ix_events_src_entity_ts", "events", ["src_entity_id", "ts"])
    op.create_index("ix_events_ts", "events", ["ts"])


def downgrade() -> None:
    op.drop_index("ix_events_ts", table_name="events")
    op.drop_index("ix_events_src_entity_ts", table_name="events")
    op.drop_table("events")
    op.drop_table("entities")
