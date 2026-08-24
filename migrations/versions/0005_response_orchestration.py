"""Response orchestration: playbooks, actions, immutable audit chain

Revision ID: 0005_response_orchestration
Revises: 0004_incidents_correlation
Create Date: 2026-08-24

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0005_response_orchestration"
down_revision: str | None = "0004_incidents_correlation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTION_STATES = (
    "pending_approval",
    "rejected",
    "expired",
    "queued",
    "executing",
    "executed",
    "failed",
    "dead",
)


def upgrade() -> None:
    op.create_table(
        "playbooks",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("trigger_detectors", JSONB(), nullable=False),
        sa.Column("requires_external_source", sa.Boolean(), nullable=False),
        sa.Column("min_risk", sa.Float(), nullable=False),
        sa.Column("blast_radius", sa.String(length=8), nullable=False),
        sa.Column("action_type", sa.String(length=48), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.UniqueConstraint("name", "version", name="uq_playbooks_name_version"),
    )

    op.create_table(
        "actions",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("playbook_id", sa.BigInteger(), nullable=True),
        sa.Column("playbook_version", sa.Integer(), nullable=True),
        sa.Column("action_type", sa.String(length=48), nullable=False),
        sa.Column("blast_radius", sa.String(length=8), nullable=False),
        sa.Column("entity_id", sa.BigInteger(), nullable=False),
        sa.Column("params", JSONB(), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("result", JSONB(), nullable=True),
        sa.Column("decided_by", sa.BigInteger(), nullable=True),
        sa.Column("decision_reason", sa.String(length=300), nullable=True),
        sa.Column(
            "idem_key",
            sa.String(length=80),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], name="fk_actions_incident"),
        sa.ForeignKeyConstraint(["playbook_id"], ["playbooks.id"], name="fk_actions_playbook"),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], name="fk_actions_entity"),
        sa.ForeignKeyConstraint(["decided_by"], ["users.id"], name="fk_actions_decider"),
        sa.CheckConstraint(
            "state IN (" + ",".join(f"'{s}'" for s in _ACTION_STATES) + ")",
            name="ck_actions_state",
        ),
        sa.CheckConstraint("blast_radius IN ('low','high')", name="ck_actions_blast_radius"),
    )
    op.create_index("ix_actions_state", "actions", ["state"])
    op.create_index("ix_actions_incident", "actions", ["incident_id"])
    op.create_unique_constraint("uq_actions_idem_key", "actions", ["idem_key"])

    op.add_column(
        "entities",
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
    )
    op.add_column("entities", sa.Column("quarantined_until", sa.DateTime(timezone=True)))

    op.create_table(
        "audit_log",
        sa.Column("seq", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("actor", sa.String(length=96), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("ref_type", sa.String(length=32), nullable=True),
        sa.Column("ref_id", sa.BigInteger(), nullable=True),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
    )
    op.create_index("ix_audit_event_type", "audit_log", ["event_type", "seq"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_column("entities", "quarantined_until")
    op.drop_column("entities", "status")
    op.drop_index("ix_actions_incident", table_name="actions")
    op.drop_index("ix_actions_state", table_name="actions")
    op.drop_constraint("uq_actions_idem_key", "actions", type_="unique")
    op.drop_constraint("ck_actions_state", "actions", type_="check")
    op.drop_constraint("ck_actions_blast_radius", "actions", type_="check")
    op.drop_table("actions")
    op.drop_table("playbooks")
