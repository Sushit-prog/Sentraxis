"""ORM models (SQLAlchemy 2.0 declarative).

Partitioning of ``events`` is intentionally DEFERRED — see
docs/decisions/ADR-001-postgres.md (amendment). Plain tables keep FK integrity
to the evidence table, which the incident/audit story depends on.
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class EntityRow(Base):
    """Observed infrastructure identities (hosts/users/subnets).

    Why this data exists: behavioral baselines and ATT&CK mapping are keyed by
    entity; storing normalized identities once keeps events slim and dedupable.
    """

    __tablename__ = "entities"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (UniqueConstraint("type", "identifier", name="uq_entities_type_identifier"),)


class EventRow(Base):
    """Immutable, normalized telemetry facts (insert-only).

    Why this data exists: the evidence base. Detections reference these rows;
    idempotent ingestion is enforced by uq_events_event_id so at-least-once
    stream delivery has exactly-once storage effect.
    """

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    event_id: Mapped[UUID] = mapped_column(nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    src_entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), nullable=False)
    dst_entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id"), nullable=True)
    ground_truth_label: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    features: Mapped[dict] = mapped_column(JSONB, nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("event_id", name="uq_events_event_id"),
        Index("ix_events_src_entity_ts", "src_entity_id", "ts"),
        Index("ix_events_ts", "ts"),
    )
