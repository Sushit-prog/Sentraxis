"""RateDeviationDetector: per-source-entity event-rate spikes.

Maintains a tumbling 60s bucket of flow counts per source entity plus Welford
history over finalized buckets. Fires (once per entity per bucket) when the
live bucket count exceeds mean + z*std with sufficient history.
"""

from typing import Any

import structlog
from sqlalchemy.orm import Session

from app.detectors.base import (
    Detection,
    EventView,
    MetricState,
    bucket_start_for,
    detection_from_z,
    roll_buckets,
    zscore,
)
from app.persistence.models import EntityMetricStateRow

logger = structlog.get_logger(__name__)

NAME = "rate_deviation"
VERSION = 1
METRIC = "flow_count_60s"


class RateDeviationDetector:
    def __init__(
        self,
        window_s: int,
        z_trigger: float,
        z_cap: float,
        min_history: int,
    ) -> None:
        # NOTE: no session is held between calls; the worker passes the active
        # transactional session into process() so state writes commit atomically
        # alongside detections and the cursor (ADR-005).
        self.window_s = window_s
        self.z_trigger = z_trigger
        self.z_cap = z_cap
        self.min_history = min_history
        self.window_s = window_s
        self.z_trigger = z_trigger
        self.z_cap = z_cap
        self.min_history = min_history

    # ---- state accessors -------------------------------------------------

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

    # ---- processing ------------------------------------------------------

    def process(self, session: Session, events: list[EventView]) -> list[Detection]:
        self.session = session
        detections: list[Detection] = []
        # batch arrives id-ordered; group consecutive events per source entity
        by_entity: dict[int, list[EventView]] = {}
        for ev in events:
            by_entity.setdefault(ev.src_entity_id, []).append(ev)

        for entity_id, evs in sorted(by_entity.items()):
            state = self._load(entity_id)
            late = 0
            for ev in evs:
                ev_bucket = bucket_start_for(ev.ts, self.window_s)
                if state.cur_bucket_start is not None and ev_bucket < state.cur_bucket_start:
                    # Late/out-of-order event (e.g., cross-scenario replay):
                    # attributing it to the live bucket would corrupt history
                    # and never rolls backward -> skip for metric purposes.
                    late += 1
                    continue
                roll_buckets(state, ev.ts)
                state.cur_value += 1.0

                fired_already = bool(state.cur_extra.get("fired"))
                if not fired_already and state.n >= self.min_history:
                    std = state.std
                    z = zscore(state.cur_value, state.mean, std)
                    scored = detection_from_z(z, self.z_trigger, self.z_cap)
                    if scored is not None:
                        score, severity = scored
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
                                    "observed": state.cur_value,
                                    "mean": round(state.mean, 3),
                                    "std": round(std, 3),
                                    "z": round(z, 2),
                                    "history_n": state.n,
                                },
                            )
                        )
                        state.cur_extra = {"fired": True}
            self._save(state)

        if detections:
            logger.info("detector_fired", detector=NAME, count=len(detections))
        return detections

    def describe(self) -> dict[str, Any]:
        return {
            "name": NAME,
            "version": VERSION,
            "metric": METRIC,
            "z_trigger": self.z_trigger,
            "min_history": self.min_history,
            "window_s": self.window_s,
        }
