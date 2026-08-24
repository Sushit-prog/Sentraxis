"""Integration tests: normalizer end-to-end over live Redis + PostgreSQL.

Covers: valid ingestion, poison dead-lettering, duplicate absorption,
stale-pending reclaim. Redis db 1 isolates from the containerized normalizer.
"""

import json

import pytest
from sqlalchemy import text

from app.persistence.repository import persist_batch
from app.workers.normalizer import Normalizer
from app.workers.streams import DEAD_STREAM, NORMALIZER_GROUP, RAW_STREAM
from tests.integration._factories import make_event_dict

pytestmark = [pytest.mark.integration]


def make_normalizer(rclient, session_factory, claim_idle_ms: int = 100) -> Normalizer:
    return Normalizer(
        redis_client=rclient,
        session_factory=session_factory,
        batch_size=10,
        consumer_name="test-consumer",
        claim_idle_ms=claim_idle_ms,
        read_block_ms=50,
    )


def db_event_count(session_factory) -> int:
    with session_factory() as session:
        return session.execute(text("SELECT count(*) FROM events")).scalar_one()


def test_ingests_valid_dead_letters_poison_absorbs_duplicates(
    rclient, session_factory, clean_db
) -> None:
    norm = make_normalizer(rclient, session_factory)
    norm.ensure_group()

    good1 = json.dumps(make_event_dict(1))
    good2 = json.dumps(make_event_dict(2))
    malformed = b"{definitely not json"
    schema_invalid = json.dumps({**make_event_dict(3), "unknown_field": True})

    rclient.xadd(RAW_STREAM, {"payload": good1})
    rclient.xadd(RAW_STREAM, {"payload": malformed})
    rclient.xadd(RAW_STREAM, {"payload": schema_invalid})
    rclient.xadd(RAW_STREAM, {"payload": good2})

    result = norm.process_batch()
    assert result.received == 4
    assert result.parsed_ok == 2
    assert result.dead_lettered == 2
    assert result.inserted == 2
    assert result.duplicates == 0
    assert db_event_count(session_factory) == 2
    assert rclient.xlen(DEAD_STREAM) == 2
    # everything ACKed: nothing pending in the group
    summary = rclient.xpending(RAW_STREAM, NORMALIZER_GROUP)
    assert summary["pending"] == 0

    # replay of the same events: absorbed by unique constraint
    rclient.xadd(RAW_STREAM, {"payload": good1})
    rclient.xadd(RAW_STREAM, {"payload": good2})
    result2 = norm.process_batch()
    assert result2.inserted == 0
    assert result2.duplicates == 2
    assert db_event_count(session_factory) == 2


def test_stale_pending_entries_are_reclaimed(rclient, session_factory, clean_db) -> None:
    norm = make_normalizer(rclient, session_factory, claim_idle_ms=100)
    norm.ensure_group()

    # a ghost consumer reads a message and "crashes" without ACKing
    payload = json.dumps(make_event_dict(42))
    msg_id = rclient.xadd(RAW_STREAM, {"payload": payload})
    rclient.xreadgroup(NORMALIZER_GROUP, "ghost", {RAW_STREAM: ">"}, count=1)

    import time

    time.sleep(0.15)  # exceed claim_idle_ms

    result = norm.process_batch()
    assert result.inserted == 1
    assert db_event_count(session_factory) == 1
    # message now ACKed by the reclaiming consumer
    summary = rclient.xpending(RAW_STREAM, NORMALIZER_GROUP)
    assert summary["pending"] == 0
    assert str(msg_id) is not None


def test_transient_db_error_retries_inline_then_succeeds(
    rclient, session_factory, clean_db, monkeypatch
) -> None:
    """Healthy worker: transient blips retry inline and complete in one batch call."""
    import app.workers.normalizer as normalizer_module
    from app.persistence.repository import OperationalError as SaOperationalError

    norm = make_normalizer(rclient, session_factory)
    norm.ensure_group()

    calls = {"n": 0}

    def flaky(session, events):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise SaOperationalError("simulated connection blip", None, Exception("boom"))
        return persist_batch(session, events)

    monkeypatch.setattr(normalizer_module, "persist_batch", flaky)

    rclient.xadd(RAW_STREAM, {"payload": json.dumps(make_event_dict(7))})

    result = norm.process_batch()
    assert calls["n"] == 3  # two failures + one success, inline
    assert result.inserted == 1 and not result.errors
    assert db_event_count(session_factory) == 1
    assert rclient.xpending(RAW_STREAM, NORMALIZER_GROUP)["pending"] == 0


def test_sustained_db_error_defers_to_reclaim_without_ack(
    rclient, session_factory, clean_db, monkeypatch
) -> None:
    """Real outage: inline retries exhaust, message stays pending for slow reclaim."""
    import app.workers.normalizer as normalizer_module
    from app.persistence.repository import OperationalError as SaOperationalError

    norm = make_normalizer(rclient, session_factory)
    norm.ensure_group()

    def always_down(session, events):
        raise SaOperationalError("database is down", None, Exception("boom"))

    monkeypatch.setattr(normalizer_module, "persist_batch", always_down)

    rclient.xadd(RAW_STREAM, {"payload": json.dumps(make_event_dict(8))})

    result = norm.process_batch()
    assert result.errors, "exhausted retries must be visible"
    assert result.inserted == 0
    assert db_event_count(session_factory) == 0
    assert rclient.xpending(RAW_STREAM, NORMALIZER_GROUP)["pending"] == 1
