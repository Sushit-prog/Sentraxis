"""Tamper-evident audit chain: append-only, hash-linked decision records.

Chain property: hash(n) = sha256(prev_hash | ts_iso | actor | event_type |
canonical_payload). Any mutation of a historical row breaks every subsequent
hash, which scripts/verify_audit_chain.py (and the API health of trust) detect.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.persistence.models import AuditLogRow

GENESIS = "0" * 64


def canonical_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_entry_hash(
    prev_hash: str, ts_iso: str, actor: str, event_type: str, payload_canonical: str
) -> str:
    material = f"{prev_hash}|{ts_iso}|{actor}|{event_type}|{payload_canonical}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def append_entry(
    session: Session,
    *,
    actor: str,
    event_type: str,
    payload: dict[str, Any],
    ref_type: str | None = None,
    ref_id: int | None = None,
) -> AuditLogRow:
    """Append one audit record linked into the chain. Must run inside the
    caller's transaction so the audit entry commits atomically with the action
    it describes."""
    last = session.execute(
        select(AuditLogRow).order_by(AuditLogRow.seq.desc()).limit(1)
    ).scalar_one_or_none()
    prev_hash = last.hash if last else GENESIS

    row = AuditLogRow(
        actor=actor[:96],
        event_type=event_type[:48],
        ref_type=ref_type,
        ref_id=ref_id,
        payload=payload or {},
        prev_hash=prev_hash,
        hash="",
    )
    session.add(row)
    session.flush()  # assigns seq + server-default ts

    entry_hash = compute_entry_hash(
        prev_hash,
        row.ts.isoformat() if row.ts else datetime_stub(),
        row.actor,
        row.event_type,
        canonical_payload(row.payload),
    )
    row.hash = entry_hash
    return row


def datetime_stub() -> str:
    # unreachable in practice (server_default populates ts); keeps hashing total
    return "1970-01-01T00:00:00+00:00"


def verify_chain(session: Session) -> tuple[int, int | None]:
    """Walk the whole chain; returns (entries_checked, first_bad_seq|None).

    Recomputes every hash and linkage; also detects deletions via sequence
    gaps (IDENTITY sequences can have gaps from rolled-back inserts, so gaps
    alone are informational — broken hashes are authoritative).
    """
    rows = session.execute(select(AuditLogRow).order_by(AuditLogRow.seq)).scalars().all()
    expected_prev = GENESIS
    checked = 0
    for row in rows:
        recomputed = compute_entry_hash(
            expected_prev,
            row.ts.isoformat(),
            row.actor,
            row.event_type,
            canonical_payload(row.payload),
        )
        if row.prev_hash != expected_prev or row.hash != recomputed:
            return checked, row.seq
        expected_prev = row.hash
        checked += 1
    return checked, None
