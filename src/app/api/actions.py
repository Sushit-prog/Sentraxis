"""Action endpoints: approval inbox + human decision surface."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.api.deps import AnyRole, ApproverOrAdmin, DbDep, SettingsDep
from app.persistence.models import ActionRow, UserRow

router = APIRouter(prefix="/actions", tags=["actions"])


class ActionOut(BaseModel):
    id: int
    incident_id: int
    action_type: str
    blast_radius: str
    state: str
    entity_id: int
    params: dict[str, Any]
    result: dict[str, Any] | None
    decision_reason: str | None
    created_at: datetime
    decided_at: datetime | None


class PaginatedActions(BaseModel):
    items: list[ActionOut]
    total: int
    limit: int
    offset: int


class DecisionBody(BaseModel):
    reason: str = Field(default="", max_length=300)


_EMPTY_DECISION = DecisionBody()


def _to_out(row: ActionRow) -> ActionOut:
    return ActionOut(
        id=row.id,
        incident_id=row.incident_id,
        action_type=row.action_type,
        blast_radius=row.blast_radius,
        state=row.state,
        entity_id=row.entity_id,
        params=row.params or {},
        result=row.result,
        decision_reason=row.decision_reason,
        created_at=row.created_at,
        decided_at=row.decided_at,
    )


@router.get("", response_model=PaginatedActions)
def list_actions(
    user: AnyRole,
    db: DbDep,
    state_filter: Annotated[str | None, Query(alias="state")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedActions:
    query = db.query(ActionRow)
    if state_filter:
        query = query.filter(ActionRow.state == state_filter)
    total = query.count()
    rows = query.order_by(ActionRow.created_at.desc()).offset(offset).limit(limit).all()
    return PaginatedActions(
        items=[_to_out(r) for r in rows], total=total, limit=limit, offset=offset
    )


def _decision_response(row: ActionRow, replayed: bool) -> dict[str, Any]:
    body = _to_out(row).model_dump()
    body["replayed"] = replayed
    return body


def _decide(
    request: Request,
    db: DbDep,
    settings: SettingsDep,
    user: UserRow,
    action_id: int,
    decision: str,
    reason: str,
    idem_key: str | None,
) -> dict[str, Any]:
    from app.workers.orchestrator import ResponseOrchestrator

    row = db.get(ActionRow, action_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Action not found")

    if idem_key:
        existing = db.query(ActionRow).filter(ActionRow.idem_key == idem_key).first()
        if existing is not None:
            # Same key = retried request: return the recorded outcome instead
            # of re-processing (or 409-ing on) the decision.
            return _decision_response(existing, replayed=True)

    if row.state != "pending_approval":
        raise HTTPException(
            status_code=409,
            detail=f"Action is not pending approval (state={row.state})",
        )

    worker = ResponseOrchestrator(
        session_factory=request.app.state.session_factory,
        settings=settings,
        effectors=_effectors(),
    )
    try:
        updated = worker.decide(
            session=db,
            action_id=action_id,
            decision=decision,
            approver_email=user.email,
            approver_id=user.id,
            reason=reason,
        )
        if idem_key and row.idem_key is None:
            row.idem_key = idem_key
        db.commit()
        db.refresh(updated)
        return _decision_response(updated, replayed=False)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _effectors() -> dict[str, Any]:
    from app.workers.orchestrator import DEFAULT_EFFECTORS

    return dict(DEFAULT_EFFECTORS)


@router.post("/{action_id}/approve")
def approve_action(
    request: Request,
    action_id: int,
    user: ApproverOrAdmin,
    db: DbDep,
    settings: SettingsDep,
    body: DecisionBody = _EMPTY_DECISION,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    return _decide(
        request,
        db,
        settings,
        user,
        action_id,
        "approve",
        body.reason or f"approved by {user.email}",
        idempotency_key,
    )


@router.post("/{action_id}/reject")
def reject_action(
    request: Request,
    action_id: int,
    user: ApproverOrAdmin,
    db: DbDep,
    settings: SettingsDep,
    body: DecisionBody = _EMPTY_DECISION,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    return _decide(
        request,
        db,
        settings,
        user,
        action_id,
        "reject",
        body.reason or f"rejected by {user.email}",
        idempotency_key,
    )
