"""Integration tests: response orchestrator state machine + HITL flow."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app.orchestration.audit import verify_chain
from app.persistence.models import (
    ActionRow,
    AuditLogRow,
    DetectionRow,
    EntityRow,
    EventRow,
    IncidentDetectionRow,
    IncidentRow,
)
from app.workers.orchestrator import (
    ResponseOrchestrator,
    seed_playbooks,
)

pytestmark = [pytest.mark.integration]

T0 = datetime(2026, 8, 24, 9, 0, 0, tzinfo=UTC)


@pytest.fixture()
def orch(session_factory, it_settings):
    from app.workers.orchestrator import DEFAULT_EFFECTORS

    return ResponseOrchestrator(
        session_factory=session_factory,
        settings=it_settings,
        effectors=dict(DEFAULT_EFFECTORS),
    )


@pytest.fixture()
def fresh_state(session_factory):
    with session_factory() as s, s.begin():
        s.execute(
            text(
                "TRUNCATE events, entities, detections, entity_metric_state,"
                " worker_cursors, incidents, incident_detections, llm_calls,"
                " actions, playbooks, audit_log RESTART IDENTITY CASCADE"
            )
        )
        seed_playbooks(s)
        from app.persistence.models import UserRow
        from app.security import hash_password

        # idempotent across runs: users table survives the truncate list above
        s.query(UserRow).filter(UserRow.email == "approver@test").delete(synchronize_session=False)
        s.add(UserRow(email="approver@test", password_hash=hash_password("x"), role="approver"))
    yield


def _approver_id(session_factory) -> int:
    from app.persistence.models import UserRow

    with session_factory() as s:
        u = s.query(UserRow).filter_by(email="approver@test").one()
        return int(u.id)


def _seed_incident_with_detection(
    session_factory,
    *,
    identifier: str,
    detector: str,
    risk: float,
) -> int:
    """Create entity/event/detection/incident/evidence; return incident id."""
    import uuid as uuid_mod

    with session_factory() as s, s.begin():
        ent = EntityRow(type="host", identifier=identifier)
        s.add(ent)
        s.flush()
        ev = EventRow(
            event_id=uuid_mod.uuid4(),
            ts=T0,
            source="network_flow",
            src_entity_id=ent.id,
            features={"dst_port": 21},
        )
        s.add(ev)
        s.flush()
        det = DetectionRow(
            event_id=ev.id,
            entity_id=ent.id,
            detector=detector,
            detector_version=1,
            score=risk,
            severity=3,
            details={"observed": 11},
        )
        s.add(det)
        s.flush()
        inc = IncidentRow(
            status="open",
            title="Test incident",
            narrative="",
            risk_score=risk,
            techniques=[],
            correlation_mode="rules",
            entity_id=ent.id,
            detection_count=1,
            first_seen_at=T0,
            last_seen_at=T0,
        )
        s.add(inc)
        s.flush()
        s.add(IncidentDetectionRow(incident_id=inc.id, detection_id=det.id))
        return inc.id


def test_high_blast_creates_pending_approval_then_executes_on_approval(
    orch, session_factory, fresh_state
) -> None:
    _seed_incident_with_detection(
        session_factory, identifier="203.0.113.77", detector="port_velocity", risk=0.7
    )

    summary = orch.tick(force=True)
    assert summary["actions_created"] == 1

    with session_factory() as s:
        action = s.query(ActionRow).one()
        assert action.state == "pending_approval"
        assert action.blast_radius == "high"
        assert action.action_type == "quarantine_host"

        # approval (human decision surface)
        worker_decision = orch.decide(
            s,
            action_id=action.id,
            decision="approve",
            approver_email="approver@test",
            approver_id=_approver_id(session_factory),
            reason="confirmed",
        )
        s.commit()
        assert worker_decision.state == "executed"

        ent = s.query(EntityRow).one()
        assert ent.status == "quarantined" and ent.quarantined_until is not None

        audits = s.query(AuditLogRow).order_by(AuditLogRow.seq).all()
        types = [a.event_type for a in audits]
        assert types == ["action_created", "action_queued", "action_executing", "action_executed"]
        checked, bad = verify_chain(s)
        assert bad is None and checked == len(audits)


def test_rejection_is_terminal_and_audited(orch, session_factory, fresh_state) -> None:
    _seed_incident_with_detection(
        session_factory, identifier="203.0.113.77", detector="port_velocity", risk=0.8
    )
    orch.tick(force=True)

    with session_factory() as s:
        action = s.query(ActionRow).one()
        orch.decide(
            session=s,
            action_id=action.id,
            decision="reject",
            approver_email="approver@test",
            approver_id=_approver_id(session_factory),
            reason="false positive",
        )
        s.commit()

    with session_factory() as s:
        action = s.query(ActionRow).one()
        assert action.state == "rejected"
        ent = s.query(EntityRow).one()
        assert ent.status == "active", "rejected action must not change entity"


def test_low_blast_auto_executes_without_approval(orch, session_factory, fresh_state) -> None:
    _seed_incident_with_detection(
        session_factory, identifier="203.0.113.77", detector="rate_deviation", risk=0.9
    )
    summary = orch.tick(force=True)
    assert summary["auto_executed"] == 1
    with session_factory() as s:
        # rate_deviation at high risk matches BOTH playbooks by design;
        # assert on the low-blast one specifically
        block = s.query(ActionRow).filter_by(action_type="block_ip").one()
        assert block.state == "executed"
        ent = s.query(EntityRow).one()
        assert ent.status == "blocked"


def test_duplicate_action_suppressed_across_ticks(orch, session_factory, fresh_state) -> None:
    _seed_incident_with_detection(
        session_factory, identifier="203.0.113.77", detector="port_velocity", risk=0.7
    )
    first = orch.tick(force=True)
    second = orch.tick(force=True)
    assert first["actions_created"] == 1
    assert second["incidents"] == 0, "cursor advanced: no reprocessing"
    with session_factory() as s:
        assert s.query(ActionRow).count() == 1


def test_internal_host_never_quarantined(orch, session_factory, fresh_state) -> None:
    _seed_incident_with_detection(
        session_factory, identifier="192.168.10.21", detector="port_velocity", risk=0.9
    )
    summary = orch.tick(force=True)
    assert summary["actions_created"] == 0
    with session_factory() as s:
        assert s.query(ActionRow).count() == 0


def test_effector_failure_marks_failed_and_audits(orch, session_factory, fresh_state) -> None:
    def broken(session, action):
        raise RuntimeError("edr offline")

    orch.register_effector("quarantine_host", broken)
    _seed_incident_with_detection(
        session_factory, identifier="203.0.113.77", detector="port_velocity", risk=0.7
    )
    # high blast still requires approval first; approve path exercises effector
    orch.tick(force=True)
    with session_factory() as s:
        action = s.query(ActionRow).one()
        orch.decide(
            session=s,
            action_id=action.id,
            decision="approve",
            approver_email="a@t",
            approver_id=_approver_id(session_factory),
        )
        s.commit()
        assert action.state == "failed"
        assert "edr offline" in (action.result or {}).get("error", "")


def test_pending_approvals_expire(orch, session_factory, fresh_state, it_settings) -> None:
    _seed_incident_with_detection(
        session_factory, identifier="203.0.113.77", detector="port_velocity", risk=0.7
    )
    orch.tick(force=True)
    # age the pending action beyond the timeout
    with session_factory() as s, s.begin():
        cutoff = datetime.now(UTC) - timedelta(minutes=it_settings.orch_approval_timeout_min + 5)
        s.query(ActionRow).update({"created_at": cutoff}, synchronize_session=False)

    summary = orch.tick(force=True)
    assert summary.get("detections", 0) == 0  # idle tick still sweeps
    with session_factory() as s:
        assert s.query(ActionRow).one().state == "expired"
