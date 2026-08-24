"""Incidents, correlation evidence links, LLM call ledger, users

Revision ID: 0004_incidents_correlation
Revises: 0003_detection_foundation
Create Date: 2026-08-24

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0004_incidents_correlation"
down_revision: str | None = "0003_detection_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "llm_calls",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=96), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False),
        sa.Column("completion_tokens", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("cache_hit", sa.Boolean(), nullable=False),
        sa.Column("error_detail", sa.String(length=512), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_llm_calls_created", "llm_calls", ["created_at"])
    op.create_index("ix_llm_calls_outcome", "llm_calls", ["outcome"])

    op.create_table(
        "incidents",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("narrative", sa.String(length=4000), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("techniques", JSONB(), nullable=False),
        sa.Column("correlation_mode", sa.String(length=8), nullable=False),
        sa.Column("entity_id", sa.BigInteger(), nullable=False),
        sa.Column("detection_count", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], name="fk_incidents_entity"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_entity", "incidents", ["entity_id"])
    op.create_index("ix_incidents_last_seen", "incidents", ["last_seen_at"])

    op.create_table(
        "incident_detections",
        sa.Column(
            "incident_id",
            sa.BigInteger(),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "detection_id", sa.BigInteger(), sa.ForeignKey("detections.id"), primary_key=True
        ),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("disabled", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )


def downgrade() -> None:
    op.drop_table("users")
    op.drop_table("incident_detections")
    op.drop_index("ix_incidents_last_seen", table_name="incidents")
    op.drop_index("ix_incidents_entity", table_name="incidents")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_table("incidents")
    op.drop_index("ix_llm_calls_outcome", table_name="llm_calls")
    op.drop_index("ix_llm_calls_created", table_name="llm_calls")
    op.drop_table("llm_calls")
