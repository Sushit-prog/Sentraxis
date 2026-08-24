"""Prometheus exposition backed by live committed system state.

Design note (documented trade-off): workers run as separate processes, so
instead of multiprocess prometheus plumbing we export DB-derived gauges with a
short TTL cache. One authoritative scrape target reflecting committed state at
second-level freshness — appropriate for a single-host deployment.

Access requires an authenticated principal (any role) so telemetry cannot be
enumerated anonymously.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter
from fastapi.responses import Response
from prometheus_client import CollectorRegistry, generate_latest
from sqlalchemy import text

from app.api.deps import AnyRole, DbDep

router = APIRouter(tags=["metrics"])

_CACHE_TTL_S = 5.0
_cache: dict[str, tuple[float, dict[str, float]]] = {}

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _grouped(db: Any, key: str, sql: str) -> dict[str, float]:
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and now - hit[0] < _CACHE_TTL_S:
        return hit[1]
    rows = db.execute(text(sql)).all()
    values = {str(r[0]): float(r[1]) for r in rows}
    _cache[key] = (now, values)
    return values


def _scalar(db: Any, key: str, sql: str) -> float:
    return next(iter(_grouped(db, key, sql).values()), 0.0)


def _collect(db: Any, registry: CollectorRegistry) -> None:
    from prometheus_client import Gauge

    def fill(g: Any, values: dict[str, float]) -> None:
        # Labeled gauges vanish from exposition when empty; seed a sentinel so
        # the series always exists for scrapers/alerts.
        if not values:
            g.labels("_none").set(0)
            return
        for k, v in values.items():
            g.labels(k).set(v)

    Gauge("sentraxis_events_total", "Normalized events stored", registry=registry).set(
        _scalar(db, "events", "SELECT 'all', count(*) FROM events")
    )

    fill(
        Gauge(
            "sentraxis_detections_total", "Detections per detector", ["detector"], registry=registry
        ),
        _grouped(db, "detections", "SELECT detector, count(*) FROM detections GROUP BY detector"),
    )

    fill(
        Gauge("sentraxis_incidents_total", "Incidents by status", ["status"], registry=registry),
        _grouped(db, "incidents", "SELECT status, count(*) FROM incidents GROUP BY status"),
    )

    fill(
        Gauge(
            "sentraxis_incident_correlation_mode_total",
            "Incidents by correlation mode",
            ["mode"],
            registry=registry,
        ),
        _grouped(
            db,
            "incident_modes",
            "SELECT correlation_mode, count(*) FROM incidents GROUP BY correlation_mode",
        ),
    )

    fill(
        Gauge("sentraxis_actions_total", "Response actions by state", ["state"], registry=registry),
        _grouped(db, "actions", "SELECT state, count(*) FROM actions GROUP BY state"),
    )

    fill(
        Gauge("sentraxis_llm_calls_total", "LLM calls by outcome", ["outcome"], registry=registry),
        _grouped(db, "llm", "SELECT outcome, count(*) FROM llm_calls GROUP BY outcome"),
    )

    Gauge(
        "sentraxis_llm_latency_ms_avg",
        "Average successful LLM latency (ms)",
        registry=registry,
    ).set(
        _scalar(
            db,
            "llm_latency",
            "SELECT 'ms', coalesce(avg(latency_ms), 0) FROM llm_calls WHERE outcome LIKE 'ok%'",
        )
    )

    Gauge(
        "sentraxis_entities_quarantined",
        "Currently quarantined entities",
        registry=registry,
    ).set(
        _scalar(
            db, "quarantined", "SELECT 'n', count(*) FROM entities WHERE status = 'quarantined'"
        )
    )


@router.get("/metrics")
def metrics(user: AnyRole, db: DbDep) -> Response:
    registry = CollectorRegistry()
    _collect(db, registry)
    return Response(content=generate_latest(registry), media_type=CONTENT_TYPE)
