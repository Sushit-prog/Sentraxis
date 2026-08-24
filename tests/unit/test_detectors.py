"""Detector behavior tests with in-memory fake state (no DB).

Exercises the real detector classes by stubbing their _load/_save state
accessors — the SQL path is covered separately by integration tests.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.detectors.base import EventView, MetricState
from app.detectors.port_velocity import DistinctPortVelocityDetector
from app.detectors.rate_deviation import RateDeviationDetector

BASE = datetime(2026, 8, 24, 9, 0, 0, tzinfo=UTC)


class FakeStore:
    def __init__(self) -> None:
        self.rows: dict[tuple[int, str], MetricState] = {}

    def load(self, entity_id: int, metric: str) -> MetricState | None:
        return self.rows.get((entity_id, metric))

    def save(self, state: MetricState) -> None:
        self.rows[(state.entity_id, state.metric)] = state


@pytest.fixture()
def store() -> FakeStore:
    return FakeStore()


def _wire(detector: Any, store: FakeStore) -> None:
    metric = detector.window_s  # noqa: F841 - clarity only

    def load(entity_id: int) -> MetricState:
        got = store.load(entity_id, detector.METRIC_NAME)
        if got is None:
            return MetricState(
                entity_id=entity_id, metric=detector.METRIC_NAME, window_seconds=detector.window_s
            )
        return got

    def save(state: MetricState) -> None:
        store.save(state)

    detector._load = load  # type: ignore[method-assign]
    detector._save = save  # type: ignore[method-assign]


def _ev(seq: int, src: int, ts: datetime, dst_port: int = 80) -> EventView:
    return EventView(
        id=seq, ts=ts, src_entity_id=src, dst_entity_id=9, dst_port=dst_port, label=False
    )


def test_rate_detector_ignores_history_building_then_fires_on_spike(store: FakeStore) -> None:
    det = RateDeviationDetector(window_s=60, z_trigger=4.0, z_cap=12.0, min_history=20)
    det.METRIC_NAME = "flow_count_60s"
    _wire(det, store)

    # Build history: 25 quiet buckets of exactly 2 events/min from entity 1.
    seq = 0
    for minute in range(25):
        t = BASE + timedelta(minutes=minute)
        for _ in range(2):
            seq += 1
            assert det.process(None, [_ev(seq, 1, t)]) == []

    # Spike: 40 events in one minute (20x baseline).
    spike_ts = BASE + timedelta(minutes=30)
    fired = []
    for _ in range(40):
        seq += 1
        fired.extend(det.process(None, [_ev(seq, 1, spike_ts)]))

    assert len(fired) == 1, "must fire once per bucket per entity"
    d = fired[0]
    assert d.detector == "rate_deviation" and d.entity_id == 1
    assert (
        d.details["observed"] >= 4.0 * (d.details["mean"] + d.details["std"])
        or d.details["z"] >= 4.0
    )


def test_rate_detector_scopes_state_per_entity(store: FakeStore) -> None:
    det = RateDeviationDetector(window_s=60, z_trigger=4.0, z_cap=12.0, min_history=5)
    det.METRIC_NAME = "flow_count_60s"
    _wire(det, store)

    t = BASE
    # entity 7 builds dense history; entity 8 is brand new
    for minute in range(10):
        tt = t + timedelta(minutes=minute)
        for _ in range(6):
            det.process(None, [_ev(minute * 10, 7, tt)])
    out = det.process(None, [_ev(999, 8, t + timedelta(minutes=11))])
    assert out == [], "new entity without history must never fire"


def test_port_velocity_fires_on_breadth_not_volume(store: FakeStore) -> None:
    det = DistinctPortVelocityDetector(window_s=60, port_threshold=10)
    det.METRIC_NAME = "distinct_dst_ports_60s"
    _wire(det, store)

    t = BASE
    # 15 events but only 3 distinct ports -> no fire
    for i in range(15):
        assert det.process(None, [_ev(i, 1, t, dst_port=[80, 443, 53][i % 3])]) == []

    # sweep: crossing the threshold (11th distinct port > 10) fires exactly once
    t2 = t + timedelta(seconds=61)
    fired = []
    for i, port in enumerate(range(21, 34)):  # 13 distinct ports total
        fired.extend(det.process(None, [_ev(100 + i, 1, t2, dst_port=port)]))
    assert len(fired) == 1
    assert fired[0].details["observed"] == 11
    assert fired[0].detector == "port_velocity"

    # continuing the sweep in same bucket stays silent (once-per-bucket)
    more = det.process(None, [_ev(200, 1, t2 + timedelta(seconds=1), dst_port=99)])
    assert more == []


def test_port_velocity_buckets_isolate(store: FakeStore) -> None:
    det = DistinctPortVelocityDetector(window_s=60, port_threshold=5)
    det.METRIC_NAME = "distinct_dst_ports_60s"
    _wire(det, store)

    # bucket A: hit threshold and fire
    t = BASE
    fired = []
    for i, port in enumerate(range(21, 27)):
        fired.extend(det.process(None, [_ev(i, 1, t, dst_port=port)]))
    assert len(fired) == 1

    # next bucket resets: below-threshold traffic is quiet again
    quiet = det.process(None, [_ev(50, 1, t + timedelta(seconds=90), dst_port=80)])
    assert quiet == []
