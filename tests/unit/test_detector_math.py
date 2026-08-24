"""Pure-function tests for detection math (no DB)."""

from datetime import UTC, datetime, timedelta

from app.detectors.base import (
    MetricState,
    bucket_start_for,
    detection_from_z,
    roll_buckets,
    score_distinct_ports,
    severity_for_score,
    update_welford,
    zscore,
)


def test_bucket_start_floors_to_window() -> None:
    ts = datetime(2026, 8, 24, 9, 3, 47, tzinfo=UTC)
    assert bucket_start_for(ts, 60) == datetime(2026, 8, 24, 9, 3, 0, tzinfo=UTC)
    # 13 seconds later is still inside the same 09:03-09:04 window? No:
    # 09:04:00 begins the next window.
    ts2 = datetime(2026, 8, 24, 9, 3, 47, tzinfo=UTC) + timedelta(seconds=13)
    assert bucket_start_for(ts2, 60) == datetime(2026, 8, 24, 9, 4, 0, tzinfo=UTC)
    assert bucket_start_for(ts + timedelta(seconds=12), 60) == datetime(
        2026, 8, 24, 9, 3, 0, tzinfo=UTC
    )


def test_welford_matches_batch_statistics() -> None:
    values = [3.0, 5.0, 7.0, 9.0, 11.0]
    mean = m2 = 0.0
    n = 0
    for v in values:
        mean, m2, n = update_welford(mean, m2, n, v)
    assert n == 5
    assert abs(mean - 7.0) < 1e-9
    sample_var = m2 / (n - 1)
    expected_var = sum((v - 7.0) ** 2 for v in values) / (n - 1)
    assert abs(sample_var - expected_var) < 1e-9


def test_zscore_zero_std_positive_value_is_infinite() -> None:
    assert zscore(50.0, mean=0.0, std=0.0) == float("inf")
    assert zscore(0.0, mean=0.0, std=0.0) == 0.0


def test_detection_from_z_below_trigger_returns_none() -> None:
    assert detection_from_z(2.0, trigger=4.0, cap=12.0) is None


def test_detection_from_z_scores_monotonically_and_caps() -> None:
    low = detection_from_z(4.0, trigger=4.0, cap=12.0)
    mid = detection_from_z(8.0, trigger=4.0, cap=12.0)
    high = detection_from_z(20.0, trigger=4.0, cap=12.0)  # beyond cap
    assert low and mid and high
    assert low[0] < mid[0] < high[0] <= 1.0
    assert low[1] < high[1]


def test_score_distinct_ports_scales_with_excess() -> None:
    at_threshold = score_distinct_ports(10, threshold=10)  # not > threshold usage-wise
    double = score_distinct_ports(20, threshold=10)
    triple = score_distinct_ports(30, threshold=10)
    assert at_threshold[0] == 0.5
    assert double[0] == 1.0
    assert triple[0] == 1.0  # capped


def test_severity_boundaries() -> None:
    assert severity_for_score(0.99) == 4
    assert severity_for_score(0.75) == 3
    assert severity_for_score(0.55) == 2
    assert severity_for_score(0.1) == 1


def _mk_state(**kw) -> MetricState:
    defaults = dict(entity_id=1, metric="m", window_seconds=60)
    defaults.update(kw)
    return MetricState(**defaults)


def test_roll_buckets_initializes_on_first_event() -> None:
    state = _mk_state()
    ts = datetime(2026, 8, 24, 9, 0, 30, tzinfo=UTC)
    finalized = roll_buckets(state, ts)
    assert finalized == []
    assert state.cur_bucket_start == datetime(2026, 8, 24, 9, 0, 0, tzinfo=UTC)


def test_roll_buckets_finalizes_own_values_and_zeroes_gaps() -> None:
    state = _mk_state()
    t0 = datetime(2026, 8, 24, 9, 0, 10, tzinfo=UTC)
    roll_buckets(state, t0)
    state.cur_value = 7.0  # busy first bucket

    # jump 4 minutes: buckets at 09:01..09:04 were empty; 09:00 finalizes with 7
    t_next = datetime(2026, 8, 24, 9, 4, 5, tzinfo=UTC)
    finalized = roll_buckets(state, t_next)

    assert finalized == [7.0, 0.0, 0.0, 0.0]
    assert state.n == 4
    assert state.cur_bucket_start == datetime(2026, 8, 24, 9, 4, 0, tzinfo=UTC)
    assert state.cur_value == 0.0

    # same-bucket event does not finalize anything
    assert roll_buckets(state, t_next + timedelta(seconds=20)) == []
