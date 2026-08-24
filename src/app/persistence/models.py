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


class DetectionRow(Base):
    """Output of one detector firing on one event.

    Why this data exists: detections are the evidence units correlation and
    response consume. Unique (event_id, detector, version) makes replayed or
    re-delivered batches storage-idempotent.
    """

    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), nullable=False)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), nullable=False)
    detector: Mapped[str] = mapped_column(String(64), nullable=False)
    detector_version: Mapped[int] = mapped_column(nullable=False)
    score: Mapped[float] = mapped_column(nullable=False)
    severity: Mapped[int] = mapped_column(nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "event_id", "detector", "detector_version", name="uq_detections_event_detector"
        ),
        Index("ix_detections_created", "created_at"),
        Index("ix_detections_entity", "entity_id"),
    )


class WorkerCursorRow(Base):
    """Incremental consumption cursors (e.g., detector -> max processed event id).

    Why this data exists: advancing the cursor inside the same transaction as
    derived writes makes crash recovery exact — restart reprocesses the same
    batch, unique constraints absorb duplicates.
    """

    __tablename__ = "worker_cursors"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_event_id: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EntityMetricStateRow(Base):
    """Per-entity streaming metric state (tumbling buckets + Welford history).

    Why this data exists: behavioral deviation requires stored 'normal'.
    One row per (entity, metric); current partial bucket lives beside the
    finalized-history statistics.
    """

    __tablename__ = "entity_metric_state"

    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), primary_key=True)
    metric: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_seconds: Mapped[int] = mapped_column(nullable=False)
    cur_bucket_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cur_value: Mapped[float] = mapped_column(nullable=False, default=0.0)
    cur_extra: Mapped[dict | None] = mapped_column(JSONB)  # e.g. distinct ports, fired flag
    mean: Mapped[float] = mapped_column(nullable=False, default=0.0)
    m2: Mapped[float] = mapped_column(nullable=False, default=0.0)
    n: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
