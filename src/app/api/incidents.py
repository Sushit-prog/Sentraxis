"""Incident endpoints: analyst-facing read paths + on-demand enrichment."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.api.deps import AnalystOrAdmin, CurrentUser, DbDep, SettingsDep
from app.persistence.models import (
    DetectionRow,
    EntityRow,
    EventRow,
    IncidentRow,
    LlmCallRow,
)
from app.persistence.models import (
    IncidentDetectionRow as IncidentDetectionLink,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])


class TechniqueOut(BaseModel):
    id: str
    name: str
    confidence: float
    evidence_detection_ids: list[int]


class IncidentOut(BaseModel):
    id: int
    status: str
    title: str
    narrative: str
    risk_score: float
    techniques: list[TechniqueOut]
    correlation_mode: str
    detection_count: int
    first_seen_at: datetime
    last_seen_at: datetime


class DetectionRefOut(BaseModel):
    detection_id: int
    detector: str
    score: float
    severity: int
    event_ts: datetime


class IncidentDetailOut(IncidentOut):
    detections: list[DetectionRefOut]


class PaginatedIncidents(BaseModel):
    items: list[IncidentOut]
    total: int
    limit: int
    offset: int


def _techniques(raw: Any) -> list[TechniqueOut]:
    if isinstance(raw, str):
        import json

        raw = json.loads(raw)
    return [TechniqueOut(**t) for t in (raw or [])]


def _to_out(row: IncidentRow) -> IncidentOut:
    return IncidentOut(
        id=row.id,
        status=row.status,
        title=row.title,
        narrative=row.narrative,
        risk_score=row.risk_score,
        techniques=_techniques(row.techniques),
        correlation_mode=row.correlation_mode,
        detection_count=row.detection_count,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
    )


@router.get("", response_model=PaginatedIncidents)
def list_incidents(
    user: CurrentUser,
    db: DbDep,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedIncidents:
    query = db.query(IncidentRow)
    if status_filter:
        query = query.filter(IncidentRow.status == status_filter)
    total = query.count()
    rows = query.order_by(IncidentRow.last_seen_at.desc()).offset(offset).limit(limit).all()
    return PaginatedIncidents(
        items=[_to_out(r) for r in rows], total=total, limit=limit, offset=offset
    )


@router.get("/{incident_id}", response_model=IncidentDetailOut)
def get_incident(
    incident_id: int,
    user: CurrentUser,
    db: DbDep,
) -> IncidentDetailOut:
    row = db.get(IncidentRow, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    links = (
        db.query(DetectionRow, EventRow.ts)
        .join(IncidentDetectionLink, IncidentDetectionLink.detection_id == DetectionRow.id)
        .join(EventRow, EventRow.id == DetectionRow.event_id)
        .filter(IncidentDetectionLink.incident_id == incident_id)
        .all()
    )
    out = IncidentDetailOut(
        **_to_out(row).model_dump(),
        detections=[
            DetectionRefOut(
                detection_id=d.id,
                detector=d.detector,
                score=d.score,
                severity=d.severity,
                event_ts=ts,
            )
            for d, ts in links
        ],
    )
    return out


@router.post("/{incident_id}/analyze", response_model=IncidentOut)
def analyze_incident(
    incident_id: int,
    user: AnalystOrAdmin,
    db: DbDep,
    settings: SettingsDep,
) -> IncidentOut:
    """Re-run LLM enrichment for one incident (synchronous, bounded)."""
    from app.correlation.agent import CorrelationAgent, analysis_facts_from_rows
    from app.correlation.rules import IncidentDraft
    from app.llm.gateway import LlmGateway
    from app.workers.connections import create_redis

    row = db.get(IncidentRow, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if (
        not settings.groq_api_key.get_secret_value()
        and not settings.openrouter_api_key.get_secret_value()
        and not settings.mistral_api_key.get_secret_value()
    ):
        raise HTTPException(status_code=503, detail="LLM providers not configured")

    gateway = LlmGateway(settings, create_redis(settings))
    agent = CorrelationAgent(gateway, settings)

    linked = (
        db.query(DetectionRow, EventRow.ts, EntityRow.identifier)
        .join(IncidentDetectionLink, IncidentDetectionLink.detection_id == DetectionRow.id)
        .join(EventRow, EventRow.id == DetectionRow.event_id)
        .join(EntityRow, EntityRow.id == DetectionRow.entity_id)
        .filter(IncidentDetectionLink.incident_id == incident_id)
        .all()
    )
    if not linked:
        raise HTTPException(status_code=409, detail="Incident has no evidence to analyze")

    identifier = linked[0][2]
    facts_rows = [
        {
            "id": d.id,
            "detector": d.detector,
            "score": d.score,
            "severity": d.severity,
            "event_ts": ts,
            "observed": (d.details or {}).get("observed"),
            "metric": (d.details or {}).get("metric"),
        }
        for d, ts in linked
    ]
    draft = IncidentDraft(
        entity_id=row.entity_id,
        title="",
        narrative="",
        risk_score=row.risk_score,
        first_seen_at=min(f["event_ts"] for f in facts_rows),
        last_seen_at=max(f["event_ts"] for f in facts_rows),
        detection_count=len(facts_rows),
        detection_ids=sorted(f["id"] for f in facts_rows),
        distinct_detectors=sorted({f["detector"] for f in facts_rows}),
    )

    result = agent.analyze(
        identifier, draft, analysis_facts_from_rows(facts_rows), set(draft.detection_ids)
    )
    analysis, meta, repaired = result if result else (None, None, False)

    db.add(
        LlmCallRow(
            purpose="incident_correlation",
            provider=(meta or {}).get("provider", "-"),
            model=(meta or {}).get("model", "-"),
            prompt_tokens=int((meta or {}).get("prompt_tokens", 0)),
            completion_tokens=int((meta or {}).get("completion_tokens", 0)),
            latency_ms=int((meta or {}).get("latency_ms", 0)),
            outcome=str((meta or {}).get("outcome", "unavailable")),
            cache_hit=bool((meta or {}).get("cache_hit", False)),
            error_detail=(meta or {}).get("error_detail"),
        )
    )

    if analysis is None:
        raise HTTPException(
            status_code=503, detail="LLM analysis unavailable; incident kept in rules mode"
        )

    row.title = analysis.title[:200]
    row.narrative = analysis.narrative
    row.risk_score = max(row.risk_score, analysis.risk_score)
    row.techniques = [t.model_dump() for t in analysis.techniques]
    row.correlation_mode = "llm"
    row.version += 1
    db.commit()
    db.refresh(row)
    return _to_out(row)
