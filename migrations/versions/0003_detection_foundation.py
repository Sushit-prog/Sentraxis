"""Detection foundation: detections, worker cursors, per-entity metric state

Revision ID: 0003_detection_foundation
Revises: 0002_entities_events
Create Date: 2026-08-24

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0003_detection_foundation"
down_revision: str | None = "0002_entities_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detections",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.Column("entity_id", sa.BigInteger(), nullable=False),
        sa.Column("detector", sa.String(length=64), nullable=False),
        sa.Column("detector_version", sa.Integer(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("details", JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], name="fk_detections_event"),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], name="fk_detections_entity"),
        sa.UniqueConstraint(
            "event_id", "detector", "detector_version", name="uq_detections_event_detector"
        ),
    )
    op.create_index("ix_detections_created", "detections", ["created_at"])
    op.create_index("ix_detections_entity", "detections", ["entity_id"])

    op.create_table(
        "worker_cursors",
        sa.Column("name", sa.String(length=64), primary_key=True),
        sa.Column("last_event_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )

    op.create_table(
        "entity_metric_state",
        sa.Column("entity_id", sa.BigInteger(), primary_key=True),
        sa.Column("metric", sa.String(length=64), primary_key=True),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("cur_bucket_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cur_value", sa.Float(), nullable=False),
        sa.Column("cur_extra", JSONB(), nullable=True),
        sa.Column("mean", sa.Float(), nullable=False),
        sa.Column("m2", sa.Float(), nullable=False),
        sa.Column("n", sa.BigInteger(), nullable=False),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], name="fk_metric_state_entity"),
    )


def downgrade() -> None:
    op.drop_table("entity_metric_state")
    op.drop_table("worker_cursors")
    op.drop_index("ix_detections_entity", table_name="detections")
    op.drop_index("ix_detections_created", table_name="detections")
    op.drop_table("detections")
