"""Integration tests: hash-chained audit ledger integrity."""

import pytest
from sqlalchemy import text

from app.orchestration.audit import append_entry, verify_chain
from app.persistence.models import AuditLogRow

pytestmark = [pytest.mark.integration]


def test_chain_appends_link_and_verify_clean(session_factory) -> None:
    with session_factory() as s, s.begin():
        s.execute(text("TRUNCATE audit_log RESTART IDENTITY"))
    with session_factory() as s, s.begin():
        for i in range(5):
            append_entry(s, actor="system:test", event_type="evt", payload={"i": i})
        checked, bad = verify_chain(s)
    assert checked == 5 and bad is None


def test_tampered_history_is_detected(session_factory) -> None:
    from app.persistence.models import AuditLogRow

    with session_factory() as s, s.begin():
        s.execute(text("TRUNCATE audit_log RESTART IDENTITY"))
        for i in range(4):
            append_entry(s, actor="system:test", event_type="evt", payload={"i": i})

    # attacker edits a historical payload in place
    with session_factory() as s, s.begin():
        victim = s.query(AuditLogRow).order_by(AuditLogRow.seq).offset(1).first()
        victim.payload = {"i": "forged"}

    with session_factory() as s:
        checked, bad_seq = verify_chain(s)
    assert bad_seq is not None, "forged entry must break the chain"
    assert checked < 4  # walk stops at the first inconsistency


def test_deletion_gap_breaks_verification(session_factory) -> None:
    """Deleting the middle row orphans hashes; verify must flag it."""
    with session_factory() as s, s.begin():
        s.execute(text("TRUNCATE audit_log RESTART IDENTITY"))
        for i in range(3):
            append_entry(s, actor="system:test", event_type="evt", payload={"i": i})

    with session_factory() as s, s.begin():
        middle = s.query(AuditLogRow).order_by(AuditLogRow.seq).offset(1).first()
        s.delete(middle)

    with session_factory() as s:
        checked, bad_seq = verify_chain(s)
    assert bad_seq is not None
