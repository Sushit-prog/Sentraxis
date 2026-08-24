"""Correlation worker: detections -> incidents (rules) -> LLM enrichment.

Consumption mirrors the detection worker (ADR-005): DB cursor advanced in the
same transaction as incident/evidence writes, so crashes reprocess exactly one
batch and idempotent writes absorb it. A watermark (now - correlation window)
holds back recent detections until they can no longer gain cluster members;
`tick(force=True)` bypasses the watermark for evals and tests.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import structlog
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.correlation.agent import CorrelationAgent, analysis_facts_from_rows
from app.correlation.rules import (
    DetectionFact,
    IncidentDraft,
    build_incident_draft,
    cluster_by_entity_and_time,
)
from app.persistence.models import (
    DetectionRow,
    EntityRow,
    EventRow,
    IncidentDetectionRow,
    IncidentRow,
    LlmCallRow,
    WorkerCursorRow,
)

logger = structlog.get_logger(__name__)

CORRELATOR_CURSOR = "correlator"


class AgentLike(Protocol):
    """Minimal seam so tests can stub richer analysis behavior."""

    def analyze(
        self,
        entity_identifier: str,
        draft: IncidentDraft,
        facts: list[dict[str, Any]],
        allowed_detection_ids: set[int],
    ) -> Any: ...


_CANDIDATE_QUERY = (
    select(
        DetectionRow.id.label("id"),
        DetectionRow.entity_id.label("entity_id"),
        DetectionRow.detector.label("detector"),
        DetectionRow.detector_version.label("detector_version"),
        DetectionRow.score.label("score"),
        DetectionRow.severity.label("severity"),
        DetectionRow.details["observed"].as_float().label("observed"),
        DetectionRow.details["metric"].as_string().label("metric"),
        EventRow.ts.label("event_ts"),
        EntityRow.identifier.label("identifier"),
    )
    .join(EventRow, EventRow.id == DetectionRow.event_id)
    .join(EntityRow, EntityRow.id == DetectionRow.entity_id)
)


def get_cursor(session: Session, name: str = CORRELATOR_CURSOR) -> int:
    row = session.get(WorkerCursorRow, name)
    return int(row.last_event_id) if row else 0


def set_cursor(session: Session, value: int, name: str = CORRELATOR_CURSOR) -> None:
    row = session.get(WorkerCursorRow, name)
    if row is None:
        row = WorkerCursorRow(name=name, last_event_id=value)
        session.add(row)
    else:
        row.last_event_id = value
        row.updated_at = func.now()


class CorrelationWorker:
    def __init__(
        self,
        session_factory: sessionmaker,
        agent: AgentLike | None,
        window_seconds: int,
        batch_size: int,
    ) -> None:
        self.session_factory = session_factory
        self.agent = agent
        self.window_s = window_seconds
        self.batch_size = batch_size

    def _fetch(self, session: Session, cursor: int, force: bool) -> Any:
        query = _CANDIDATE_QUERY.where(DetectionRow.id > cursor)
        if not force:
            watermark = datetime.now(UTC) - timedelta(seconds=self.window_s)
            query = query.where(EventRow.ts <= watermark)
        return session.execute(query.order_by(DetectionRow.id).limit(self.batch_size)).all()

    def tick(self, force: bool = False) -> dict[str, Any]:
        """Process one batch. Returns a summary; detections=0 means idle."""
        with self.session_factory() as session, session.begin():
            cursor = get_cursor(session)
            rows = self._fetch(session, cursor, force=force)
            if not rows:
                return {"detections": 0, "incidents": 0}

            facts = [
                DetectionFact(
                    detection_id=r.id,
                    entity_id=r.entity_id,
                    detector=r.detector,
                    detector_version=r.detector_version,
                    score=r.score,
                    severity=r.severity,
                    event_ts=r.event_ts,
                )
                for r in rows
            ]
            clusters = cluster_by_entity_and_time(facts, self.window_s)
            rows_by_id: Mapping[int, Any] = {r.id: r for r in rows}

            created = 0
            for cluster in clusters:
                draft = build_incident_draft(cluster)
                identifier = rows_by_id[cluster[0].detection_id].identifier
                self._create_incident(session, draft, identifier, rows_by_id)
                created += 1

            through = max(r.id for r in rows)
            set_cursor(session, through)
            logger.info(
                "correlation_batch",
                detections=len(rows),
                incidents=created,
                through_detection=through,
            )
            return {"detections": len(rows), "incidents": created}

    def _create_incident(
        self, session: Session, draft: IncidentDraft, identifier: str, rows_by_id: Mapping[int, Any]
    ) -> IncidentRow:
        title = f"Behavioral anomalies on {identifier}: {', '.join(draft.distinct_detectors)}"
        incident = IncidentRow(
            status="open",
            title=title[:200],
            narrative=draft.narrative,
            risk_score=draft.risk_score,
            techniques=[],
            correlation_mode="rules",
            entity_id=draft.entity_id,
            detection_count=draft.detection_count,
            first_seen_at=draft.first_seen_at,
            last_seen_at=draft.last_seen_at,
        )
        session.add(incident)
        session.flush()  # assigns incident.id before evidence linkage

        for did in draft.detection_ids:
            session.add(IncidentDetectionRow(incident_id=incident.id, detection_id=did))

        if self.agent is not None:
            fact_rows = [dict(rows_by_id[did]._mapping) for did in draft.detection_ids]
            result = self.agent.analyze(
                identifier,
                draft,
                analysis_facts_from_rows(fact_rows),
                set(draft.detection_ids),
            )
            analysis, meta, repaired = result if result else (None, None, False)

            call_row = LlmCallRow(
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
            session.add(call_row)

            if analysis is not None:
                mode_was = incident.correlation_mode
                incident.title = analysis.title[:200]
                incident.narrative = analysis.narrative[:4000]
                incident.risk_score = max(incident.risk_score, analysis.risk_score)
                incident.techniques = [t.model_dump() for t in analysis.techniques]
                incident.correlation_mode = "llm"
                logger.info(
                    "incident_enriched",
                    incident_id=incident.id,
                    previous_mode=mode_was,
                    repaired=repaired,
                    risk=analysis.risk_score,
                    techniques=[t.id for t in analysis.techniques],
                )

        return incident


def main() -> None:  # pragma: no cover - process entrypoint
    from app.config import get_settings
    from app.llm.gateway import LlmGateway
    from app.persistence.db import create_db_engine, create_session_factory
    from app.workers.connections import create_redis

    settings = get_settings()
    session_factory = create_session_factory(create_db_engine(settings))
    gateway = LlmGateway(settings, create_redis(settings))
    agent = (
        CorrelationAgent(gateway, settings)
        if gateway.has_providers
        else CorrelationAgent(gateway, settings)
    )
    worker = CorrelationWorker(
        session_factory=session_factory,
        agent=agent,
        window_seconds=settings.corr_window_seconds,
        batch_size=settings.corr_batch_size,
    )
    logger.info(
        "correlator_started",
        providers=[p.name for p in gateway.providers],
        window_s=settings.corr_window_seconds,
    )
    while True:
        result = worker.tick()
        if result.get("detections", 0) == 0:
            time.sleep(2.0)


if __name__ == "__main__":
    main()
