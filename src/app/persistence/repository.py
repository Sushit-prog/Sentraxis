"""Batch-oriented data access for the ingestion path.

All functions are idempotent:
- upsert_entities: ON CONFLICT bump last_seen_at, stable ids returned
- insert_events_batch: ON CONFLICT DO NOTHING on uq_events_event_id; RETURNING
  reports only genuinely inserted rows, so at-least-once stream delivery has an
  exactly-once storage effect.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

import structlog
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.domain.events import CanonicalEvent, EntityRef
from app.persistence.models import EntityRow, EventRow

logger = structlog.get_logger(__name__)

EntityKey = tuple[str, str]  # (EntityType value, normalized identifier)


@dataclass(slots=True)
class InsertReport:
    inserted: int
    duplicates: int


def extract_entity_refs(events: Sequence[CanonicalEvent]) -> set[EntityRef]:
    refs: set[EntityRef] = set()
    for event in events:
        refs.add(event.src_entity)
        if event.dst_entity is not None:
            refs.add(event.dst_entity)
    return refs


def _ref_key(ref: EntityRef) -> EntityKey:
    return (ref.type.value, ref.identifier)


def upsert_entities(session: Session, refs: Iterable[EntityRef]) -> dict[EntityKey, int]:
    """Insert missing entities, refresh last_seen_at for existing ones."""
    unique_refs = sorted(set(refs), key=_ref_key)
    if not unique_refs:
        return {}

    stmt = (
        pg_insert(EntityRow)
        .values([{"type": ref.type.value, "identifier": ref.identifier} for ref in unique_refs])
        .on_conflict_do_update(
            index_elements=["type", "identifier"],
            set_={"last_seen_at": func.greatest(EntityRow.last_seen_at, func.now())},
        )
        .returning(EntityRow.id, EntityRow.type, EntityRow.identifier)
    )
    rows = session.execute(stmt).all()
    return {(row.type, row.identifier): row.id for row in rows}


def insert_events_batch(
    session: Session,
    events: Sequence[CanonicalEvent],
    entity_ids: Mapping[EntityKey, int],
) -> InsertReport:
    """Insert a batch atomically; duplicates are skipped and counted.

    Raises on unexpected database failures so callers can retry the whole batch.
    """
    if not events:
        return InsertReport(inserted=0, duplicates=0)

    values = []
    for event in events:
        dst_id = None
        if event.dst_entity is not None:
            dst_id = entity_ids[_ref_key(event.dst_entity)]
        values.append(
            {
                "event_id": event.event_id,
                "ts": event.ts,
                "source": event.source.value,
                "src_entity_id": entity_ids[_ref_key(event.src_entity)],
                "dst_entity_id": dst_id,
                "ground_truth_label": event.ground_truth_label,
                "features": event.features.model_dump(mode="json"),
            }
        )

    stmt = (
        pg_insert(EventRow)
        .values(values)
        .on_conflict_do_nothing(index_elements=["event_id"])
        .returning(EventRow.id)
    )
    inserted_ids = session.execute(stmt).scalars().all()
    inserted = len(inserted_ids)
    report = InsertReport(inserted=inserted, duplicates=len(events) - inserted)
    if report.duplicates:
        logger.debug("duplicate_events_skipped", duplicates=report.duplicates)
    return report


class NonRetryableBatchError(Exception):
    """Raised when a batch cannot succeed on retry (schema/constraint bug)."""


def persist_batch(session: Session, events: Sequence[CanonicalEvent]) -> InsertReport:
    """Resolve entities + insert events in one transaction.

    Transient connection issues propagate to the caller for stream-level retry;
    deterministic constraint/schema errors raise NonRetryableBatchError so the
    caller can isolate poison rows instead of looping forever.
    """
    try:
        with session.begin():
            entity_ids = upsert_entities(session, extract_entity_refs(events))
            return insert_events_batch(session, events, entity_ids)
    except OperationalError:
        raise  # transient: redelivery will handle it
    except IntegrityError as exc:
        raise NonRetryableBatchError(f"constraint failure during batch insert: {exc}") from exc
