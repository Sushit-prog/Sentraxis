"""DistinctPortVelocityDetector: breadth-of-ports sweeps per source entity.

Counts DISTINCT destination ports a source entity contacts within its current
60s bucket. Crossing the threshold fires once per entity per bucket — the
signature of a horizontal service sweep, independent of per-flow volume.
"""

from typing import Any

import structlog
from sqlalchemy.orm import Session

from app.detectors.base import (
    Detection,
    EventView,
    MetricState,
    bucket_start_for,
    roll_buckets,
    score_distinct_ports,
)
from app.persistence.models import EntityMetricStateRow

logger = structlog.get_logger(__name__)

NAME = "port_velocity"
VERSION = 1
METRIC = "distinct_dst_ports_60s"


class DistinctPortVelocityDetector:
    def __init__(self, window_s: int, port_threshold: int) -> None:
        # Session-per-call: see rate_deviation note / ADR-005.
        self.window_s = window_s
        self.port_threshold = port_threshold
        self.window_s = window_s
        self.port_threshold = port_threshold

    def _load(self, entity_id: int) -> MetricState:
        row = self.session.get(EntityMetricStateRow, {"entity_id": entity_id, "metric": METRIC})
        if row is None:
            return MetricState(entity_id=entity_id, metric=METRIC, window_seconds=self.window_s)
        return MetricState(
            entity_id=entity_id,
            metric=METRIC,
            window_seconds=row.window_seconds,
            cur_bucket_start=row.cur_bucket_start,
            cur_value=row.cur_value,
            cur_extra=dict(row.cur_extra or {}),
            mean=row.mean,
            m2=row.m2,
            n=row.n,
        )

    def _save(self, state: MetricState) -> None:
        row = self.session.get(
            EntityMetricStateRow, {"entity_id": state.entity_id, "metric": METRIC}
        )
        if row is None:
            row = EntityMetricStateRow(
                entity_id=state.entity_id, metric=METRIC, window_seconds=self.window_s
            )
            self.session.add(row)
        row.window_seconds = state.window_seconds
        row.cur_bucket_start = state.cur_bucket_start
        row.cur_value = state.cur_value
        row.cur_extra = state.cur_extra or None
        row.mean = state.mean
        row.m2 = state.m2
        row.n = state.n
        from sqlalchemy import func as sa_func

        row.updated_at = sa_func.now()

    def process(self, session: Session, events: list[EventView]) -> list[Detection]:
        self.session = session
        detections: list[Detection] = []
        by_entity: dict[int, list[EventView]] = {}
        for ev in events:
            by_entity.setdefault(ev.src_entity_id, []).append(ev)

        for entity_id, evs in sorted(by_entity.items()):
            state = self._load(entity_id)
            late = 0
            for ev in evs:
                ev_bucket = bucket_start_for(ev.ts, self.window_s)
                if state.cur_bucket_start is not None and ev_bucket < state.cur_bucket_start:
                    late += 1
                    continue
                roll_buckets(state, ev.ts)
                if state.cur_value == 0.0:
                    # first event in this bucket: seed bookkeeping fields
                    pass
                ports: set[int] = set(state.cur_extra.get("ports", []))
                before = len(ports)
                ports.add(ev.dst_port)
                if len(ports) != before:
                    state.cur_extra["ports"] = sorted(ports)
                state.cur_value = float(len(ports))

                fired_already = bool(state.cur_extra.get("fired"))
                observed = int(state.cur_value)
                if not fired_already and observed > self.port_threshold:
                    score, severity = score_distinct_ports(observed, self.port_threshold)
                    detections.append(
                        Detection(
                            event_id=ev.id,
                            entity_id=entity_id,
                            detector=NAME,
                            detector_version=VERSION,
                            score=score,
                            severity=severity,
                            details={
                                "metric": METRIC,
                                "window_s": self.window_s,
                                "bucket_start": state.cur_bucket_start.isoformat()
                                if state.cur_bucket_start
                                else None,
                                "observed": observed,
                                "threshold": self.port_threshold,
                                "ports": sorted(ports)[:32],
                            },
                        )
                    )
                    state.cur_extra["fired"] = True
            self._save(state)

        if detections:
            logger.info("detector_fired", detector=NAME, count=len(detections))
        return detections

    def describe(self) -> dict[str, Any]:
        return {
            "name": NAME,
            "version": VERSION,
            "metric": METRIC,
            "threshold": self.port_threshold,
            "window_s": self.window_s,
        }
