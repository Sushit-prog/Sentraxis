"""Integration tests: repository idempotency against live PostgreSQL.

Requires: docker compose up -d postgres redis
"""

import uuid

import pytest
from sqlalchemy import func, select, text

from app.domain.events import (
    CanonicalEvent,
    EntityRef,
    EntityType,
    EventSource,
    NetworkFlowFeatures,
)
from app.persistence.models import EntityRow
from app.persistence.repository import extract_entity_refs, persist_batch, upsert_entities

pytestmark = [pytest.mark.integration]


def make_event(
    seq: int, ts: str = "2026-08-24T09:03:47Z", label: bool | None = None
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid.UUID(f"5f0a1c7e-dead-4a10-b100-{seq:012d}"),
        source=EventSource.network_flow,
        ts=ts,
        src_entity=EntityRef(type=EntityType.host, identifier="203.0.113.77"),
        dst_entity=EntityRef(type=EntityType.host, identifier="192.168.10.50"),
        ground_truth_label=label,
        features=NetworkFlowFeatures(
            protocol="tcp",
            src_port=40021,
            dst_port=21,
            duration_s=0.002,
            src_bytes=0,
            dst_bytes=0,
            src_pkts=1,
            dst_pkts=1,
            conn_state="RST",
        ),
    )


@pytest.fixture()
def clean_db(session_factory):
    with session_factory() as session:
        session.execute(text("TRUNCATE events, entities RESTART IDENTITY CASCADE"))
        session.commit()
    yield session_factory


def test_extract_entity_refs_deduplicates(clean_db) -> None:
    events = [make_event(1), make_event(2)]
    refs = extract_entity_refs(events)
    assert len(refs) == 2  # src + dst, shared across both events


def test_upsert_entities_is_idempotent_with_stable_ids(session_factory) -> None:
    refs = {
        EntityRef(type=EntityType.host, identifier=i) for i in ("203.0.113.77", "192.168.10.50")
    }

    def upsert_once() -> dict:
        # NB: explicit transaction — a bare session.execute() autobegins and rolls
        # back on session close (identity sequences do NOT roll back).
        with session_factory() as session, session.begin():
            return upsert_entities(session, refs)

    first = upsert_once()
    second = upsert_once()

    assert set(first) == set(second)
    assert all(first[k] == second[k] for k in first)
    with session_factory() as session:
        count = session.scalar(select(func.count()).select_from(EntityRow))
    assert count == 2


def test_persist_batch_inserts_then_counts_duplicates(clean_db) -> None:
    events = [make_event(1, label=True), make_event(2, label=False), make_event(3)]

    with clean_db() as session:
        report = persist_batch(session, events)
    assert report.inserted == 3 and report.duplicates == 0

    # identical replay: fully absorbed
    with clean_db() as session:
        report = persist_batch(session, events)
    assert report.inserted == 0 and report.duplicates == 3

    # partial overlap: one old + one new
    with clean_db() as session:
        report = persist_batch(session, [*events[:1], make_event(99)])
    assert report.inserted == 1 and report.duplicates == 1


def test_persist_batch_resolves_entities_and_round_trips_features(clean_db) -> None:
    event = make_event(7, label=True)
    with clean_db() as session:
        persist_batch(session, [event])
        rows = session.execute(
            text(
                "SELECT e.event_id, e.source, e.features->>'dst_port' AS port, "
                "s.identifier AS src_id, d.identifier AS dst_id, e.ground_truth_label "
                "FROM events e JOIN entities s ON s.id = e.src_entity_id "
                "LEFT JOIN entities d ON d.id = e.dst_entity_id"
            )
        ).all()

    assert len(rows) == 1
    row = rows[0]
    assert str(row.event_id) == str(event.event_id)
    assert row.port == "21"
    assert row.src_id == "203.0.113.77"
    assert row.dst_id == "192.168.10.50"
    assert row.ground_truth_label is True


def test_timestamps_stored_utc(clean_db) -> None:
    event = make_event(11, ts="2026-08-24T12:00:00+05:30")
    with clean_db() as session:
        persist_batch(session, [event])
        stored = session.execute(text("SELECT ts FROM events")).scalar_one()
    assert stored.utcoffset() is not None
    assert stored.hour == 6 and stored.minute == 30 and stored.tzinfo is not None
