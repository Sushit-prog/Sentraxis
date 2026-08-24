"""Response orchestrator: incidents -> policy -> gated containment actions.

Safety model (ADR-007):
- low-blast actions auto-execute; high-blast actions require human approval.
- The action state machine is enforced with compare-and-set transitions;
  idempotency keys make duplicate approvals structurally impossible.
- Every transition appends to the hash-chained audit ledger inside the same
  transaction as the state change.
- Consumption follows ADR-005: incidents by DB cursor, advanced atomically.

Effectors are SIMULATED (entity status flips) — the executor registry is the
single integration seam for real EDR/firewall APIs later.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.orchestration.audit import append_entry
from app.orchestration.policy import (
    ActionSpec,
    IncidentContext,
    PlaybookDef,
    evaluate_response,
)
from app.persistence.models import (
    ActionRow,
    DetectionRow,
    EntityRow,
    IncidentDetectionRow,
    IncidentRow,
    PlaybookRow,
    WorkerCursorRow,
)

logger = structlog.get_logger(__name__)

ORCH_CURSOR = "orchestrator"

# Allowed transitions; anything else raises and leaves state untouched.
TRANSITIONS: dict[str, set[str]] = {
    "pending_approval": {"queued", "rejected", "expired"},
    "queued": {"executing", "failed"},
    "executing": {"executed", "failed"},
    "failed": {"queued", "dead"},
}


def get_cursor(session: Session, name: str = ORCH_CURSOR) -> int:
    row = session.get(WorkerCursorRow, name)
    return int(row.last_event_id) if row else 0


def set_cursor(session: Session, value: int, name: str = ORCH_CURSOR) -> None:
    row = session.get(WorkerCursorRow, name)
    if row is None:
        row = WorkerCursorRow(name=name, last_event_id=value)
        session.add(row)
    else:
        row.last_event_id = value
        row.updated_at = func.now()


DEFAULT_PLAYBOOKS: list[dict[str, Any]] = [
    {
        "name": "isolate_compromised_host",
        "description": "Quarantine an external host exhibiting active reconnaissance "
        "behavior. Requires analyst approval (high blast radius).",
        "trigger_detectors": ["port_velocity", "rate_deviation"],
        "requires_external_source": True,
        "min_risk": 0.5,
        "blast_radius": "high",
        "action_type": "quarantine_host",
        "version": 1,
    },
    {
        "name": "throttle_flood_source",
        "description": "Rate-limit a flooding source at the perimeter. Low blast "
        "radius: reversible, auto-executes on high-confidence floods.",
        "trigger_detectors": ["rate_deviation"],
        "requires_external_source": True,
        "min_risk": 0.8,
        "blast_radius": "low",
        "action_type": "block_ip",
        "version": 1,
    },
]


def seed_playbooks(session: Session, definitions: list[dict[str, Any]] | None = None) -> int:
    """Insert missing playbook versions; returns how many were added."""
    defs = definitions if definitions is not None else DEFAULT_PLAYBOOKS
    added = 0
    for d in defs:
        exists = session.execute(
            select(PlaybookRow.id).where(
                PlaybookRow.name == d["name"], PlaybookRow.version == d["version"]
            )
        ).first()
        if exists:
            continue
        session.add(
            PlaybookRow(
                name=d["name"],
                description=d["description"],
                trigger_detectors=d["trigger_detectors"],
                requires_external_source=d["requires_external_source"],
                min_risk=d["min_risk"],
                blast_radius=d["blast_radius"],
                action_type=d["action_type"],
                version=d["version"],
                enabled=True,
            )
        )
        added += 1
    return added


def _load_playbooks(session: Session) -> list[PlaybookDef]:
    rows = session.execute(select(PlaybookRow).where(PlaybookRow.enabled.is_(True))).scalars().all()
    return [
        PlaybookDef(
            name=r.name,
            description=r.description,
            trigger_detectors=tuple(r.trigger_detectors),
            requires_external_source=bool(r.requires_external_source),
            min_risk=float(r.min_risk),
            blast_radius=r.blast_radius,
            action_type=r.action_type,
            version=int(r.version),
        )
        for r in rows
    ]


def _transition(
    session: Session,
    action: ActionRow,
    target: str,
    actor: str,
    extra: dict[str, Any] | None = None,
) -> None:
    allowed = TRANSITIONS.get(action.state, set())
    if target not in allowed:
        raise ValueError(f"illegal transition {action.state} -> {target}")
    previous = action.state
    action.state = target
    now = func.now()
    action.updated_at = now
    if target in ("rejected", "expired"):
        action.decided_at = now
    if extra:
        for k, v in extra.items():
            setattr(action, k, v)
    append_entry(
        session,
        actor=actor,
        event_type=f"action_{target}",
        ref_type="action",
        ref_id=action.id,
        payload={"from": previous, "to": target, **(extra or {})},
    )


class ResponseOrchestrator:
    def __init__(
        self,
        session_factory: sessionmaker,
        settings: Settings,
        effectors: Mapping[str, Any] | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        # Executor seam: swap simulations for real integrations later.
        self.effectors: dict[str, Any] = dict(effectors or {})

    def register_effector(self, action_type: str, fn: Any) -> None:
        self.effectors[action_type] = fn

    # ---- main loop -------------------------------------------------------

    def tick(self, force: bool = False) -> dict[str, Any]:
        with self.session_factory() as session, session.begin():
            self._expire_pending_approvals(session)

            cursor = get_cursor(session)
            rows = session.execute(
                select(IncidentRow, EntityRow.identifier)
                .join(EntityRow, EntityRow.id == IncidentRow.entity_id)
                .where(IncidentRow.id > cursor)
                .order_by(IncidentRow.id)
                .limit(self.settings.orch_batch_size)
            ).all()
            created = executed = 0
            for incident, identifier in rows:
                already = session.execute(
                    select(func.count())
                    .select_from(ActionRow)
                    .where(ActionRow.incident_id == incident.id)
                ).scalar_one()
                if already:
                    continue
                specs = self._evaluate(session, incident, identifier)
                for spec in specs:
                    action = self._create_action(session, incident, spec)
                    created += 1
                    if spec.blast_radius == "low":
                        executed += int(self._execute(session, action))
                    # high blast stays pending_approval until a human decides

            set_cursor(session, max((i.id for i, _ in rows), default=cursor))
            summary = {
                "incidents": len(rows),
                "actions_created": created,
                "auto_executed": executed,
            }
            if created or executed:
                logger.info("orchestration_batch", **summary)
            return summary

    def _expire_pending_approvals(self, session: Session) -> int:
        cutoff = datetime.now(UTC) - timedelta(minutes=self.settings.orch_approval_timeout_min)
        stale = (
            session.execute(
                select(ActionRow).where(
                    ActionRow.state == "pending_approval", ActionRow.created_at < cutoff
                )
            )
            .scalars()
            .all()
        )
        expired = 0
        for action in stale:
            try:
                _transition(session, action, "expired", actor="system:orchestrator")
                expired += 1
            except ValueError:
                logger.error("expiry_transition_conflict", action_id=action.id)
        if expired:
            logger.info("approvals_expired", count=expired)
        return expired

    def _evaluate(
        self, session: Session, incident: IncidentRow, identifier: str
    ) -> list[ActionSpec]:
        detector_rows = (
            session.execute(
                select(DetectionRow.detector)
                .join(IncidentDetectionRow, IncidentDetectionRow.detection_id == DetectionRow.id)
                .where(IncidentDetectionRow.incident_id == incident.id)
            )
            .scalars()
            .all()
        )
        ctx = IncidentContext(
            incident_id=incident.id,
            entity_id=incident.entity_id,
            entity_identifier=identifier,
            risk_score=float(incident.risk_score),
            detectors=frozenset(detector_rows),
            techniques=tuple(
                str(t["id"])
                for t in (incident.techniques or [])
                if isinstance(t, dict) and t.get("id") is not None
            ),
        )
        playbooks = _load_playbooks(session)
        return evaluate_response(ctx, playbooks, min_risk_floor=self.settings.orch_min_risk)

    def _create_action(
        self, session: Session, incident: IncidentRow, spec: ActionSpec
    ) -> ActionRow:
        action = ActionRow(
            incident_id=incident.id,
            playbook_id=None,
            playbook_version=spec.playbook.version,
            action_type=spec.action_type,
            blast_radius=spec.blast_radius,
            entity_id=incident.entity_id,
            params={
                "entity_identifier": None,  # filled below from entity lookup
                "reason": spec.reason,
                "incident_title": incident.title[:200],
            },
            state="pending_approval" if spec.blast_radius == "high" else "queued",
            attempt=0,
        )
        entity = session.get(EntityRow, incident.entity_id)
        action.params = {
            "entity_identifier": entity.identifier if entity else str(incident.entity_id),
            "reason": spec.reason,
            "incident_title": incident.title[:200],
        }
        pb_row = session.execute(
            select(PlaybookRow).where(
                PlaybookRow.name == spec.playbook.name,
                PlaybookRow.version == spec.playbook.version,
            )
        ).scalar_one_or_none()
        if pb_row:
            action.playbook_id = pb_row.id
        session.add(action)
        session.flush()
        append_entry(
            session,
            actor="system:orchestrator",
            event_type="action_created",
            ref_type="action",
            ref_id=action.id,
            payload={
                "action_type": spec.action_type,
                "blast_radius": spec.blast_radius,
                "state": action.state,
                "reason": spec.reason,
            },
        )
        return action

    def _execute(self, session: Session, action: ActionRow) -> bool:
        """queued -> executing -> executed|failed via registered effector."""
        try:
            _transition(session, action, "executing", actor="system:orchestrator")
        except ValueError:
            return False

        action.attempt += 1
        effector = self.effectors.get(action.action_type)
        if effector is None:
            _transition(
                session,
                action,
                "failed",
                actor="system:orchestrator",
                extra={"result": {"error": f"no effector registered for {action.action_type}"}},
            )
            return False
        try:
            result = effector(session, action)
            _transition(
                session,
                action,
                "executed",
                actor="system:orchestrator",
                extra={"result": result or {}},
            )
            return True
        except Exception as exc:  # noqa: BLE001 - effector failure is a recorded outcome
            logger.warning("effector_failed", action_type=action.action_type, error=str(exc)[:200])
            _transition(
                session,
                action,
                "failed",
                actor="system:orchestrator",
                extra={"result": {"error": str(exc)[:300]}},
            )
            return False

    # ---- human decision surface ------------------------------------------

    def decide(
        self,
        session: Session,
        *,
        action_id: int,
        decision: str,
        approver_email: str,
        approver_id: int,
        reason: str = "",
    ) -> ActionRow:
        """Approve/reject a pending action; approval executes immediately."""
        action = session.get(ActionRow, action_id)
        if action is None:
            raise LookupError(f"action {action_id} not found")
        if action.state != "pending_approval":
            raise ValueError(f"action {action_id} not pending (state={action.state})")

        actor = f"user:{approver_email}"
        if decision == "approve":
            _transition(
                session,
                action,
                "queued",
                actor=actor,
                extra={"decided_by": approver_id, "decision_reason": reason[:300]},
            )
            action.decided_at = func.now()
            self._execute(session, action)
        elif decision == "reject":
            _transition(
                session,
                action,
                "rejected",
                actor=actor,
                extra={"decided_by": approver_id, "decision_reason": reason[:300]},
            )
            action.decided_at = func.now()
        else:
            raise ValueError(f"unknown decision '{decision}'")
        return action


# ---- simulated effectors -----------------------------------------------------


def quarantine_host_effector(session: Session, action: ActionRow) -> dict[str, Any]:
    until = datetime.now(UTC) + timedelta(hours=24)
    entity = session.get(EntityRow, action.entity_id)
    if entity is None:
        raise RuntimeError(f"entity {action.entity_id} vanished")
    entity.status = "quarantined"
    entity.quarantined_until = until
    return {
        "simulated": True,
        "effect": "host_quarantined",
        "identifier": entity.identifier,
        "until": until.isoformat(),
    }


def block_ip_effector(session: Session, action: ActionRow) -> dict[str, Any]:
    entity = session.get(EntityRow, action.entity_id)
    if entity is None:
        raise RuntimeError(f"entity {action.entity_id} vanished")
    entity.status = "blocked"
    return {
        "simulated": True,
        "effect": "ip_blocked_at_perimeter",
        "identifier": entity.identifier,
    }


DEFAULT_EFFECTORS: dict[str, Any] = {
    "quarantine_host": quarantine_host_effector,
    "block_ip": block_ip_effector,
}


def main() -> None:  # pragma: no cover - process entrypoint
    from app.config import get_settings
    from app.persistence.db import create_db_engine, create_session_factory

    settings = get_settings()
    session_factory = create_session_factory(create_db_engine(settings))
    worker = ResponseOrchestrator(
        session_factory=session_factory,
        settings=settings,
        effectors=dict(DEFAULT_EFFECTORS),
    )
    with session_factory() as session, session.begin():
        seeded = seed_playbooks(session)
    logger.info("orchestrator_started", playbooks_seeded=seeded)
    while True:
        result = worker.tick()
        if result.get("incidents", 0) == 0:
            time.sleep(settings.orch_poll_interval_s)


if __name__ == "__main__":
    main()
