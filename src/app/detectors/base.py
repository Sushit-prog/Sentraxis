"""Detector contracts, pure scoring math, and shared state container.

Design (ADR-004): a detector is a class holding one session-scoped view over
per-entity metric state. All arithmetic lives in pure functions here so the
statistics are testable without Postgres.
"""

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

SEVERITY_CRITICAL = 4
SEVERITY_HIGH = 3
SEVERITY_MEDIUM = 2
SEVERITY_LOW = 1


@dataclass(frozen=True, slots=True)
class EventView:
    """Slim projection of a persisted event for detector consumption."""

    id: int
    ts: datetime
    src_entity_id: int
    dst_entity_id: int | None
    dst_port: int
    label: bool | None


@dataclass(slots=True)
class MetricState:
    """Mutable per-(entity, metric) streaming state."""

    entity_id: int
    metric: str
    window_seconds: int
    cur_bucket_start: datetime | None = None
    cur_value: float = 0.0
    cur_extra: dict[str, Any] = field(default_factory=dict)
    mean: float = 0.0
    m2: float = 0.0
    n: int = 0

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(max(self.m2 / (self.n - 1), 0.0))


@dataclass(frozen=True, slots=True)
class Detection:
    event_id: int
    entity_id: int
    detector: str
    detector_version: int
    score: float
    severity: int
    details: dict[str, Any]


def bucket_start_for(ts: datetime, window_seconds: int) -> datetime:
    """Floor a timestamp onto its tumbling-window start (UTC)."""
    ts_utc = ts.astimezone(UTC)
    epoch_seconds = int(ts_utc.timestamp())
    floored = epoch_seconds - (epoch_seconds % window_seconds)
    return datetime.fromtimestamp(floored, tz=UTC)


def update_welford(mean: float, m2: float, n: int, value: float) -> tuple[float, float, int]:
    """One step of Welford's online variance; returns (mean, m2, n)."""
    n_new = n + 1
    delta = value - mean
    mean_new = mean + delta / n_new
    m2_new = m2 + delta * (value - mean_new)
    return mean_new, m2_new, n_new


def zscore(value: float, mean: float, std: float) -> float:
    if std <= 1e-9:
        # zero historical variance: any nonzero value is maximally surprising,
        # but only meaningful once we have history at all
        return 0.0 if value <= mean else float("inf") if value > 0 else 0.0
    return (value - mean) / std


def detection_from_z(
    z: float, trigger: float, cap: float, base_score: float = 0.4
) -> tuple[float, int] | None:
    """Map a z-score to (score, severity); None when below trigger."""
    if z < trigger:
        return None
    capped = min(z, cap)
    score = base_score + (1.0 - base_score) * ((capped - trigger) / max(cap - trigger, 1e-9))
    return round(score, 4), severity_for_score(score)


def score_distinct_ports(observed: int, threshold: int) -> tuple[float, int]:
    """Breadth-based score: ratio above threshold drives 0.5 -> 1.0."""
    ratio = observed / max(threshold, 1)
    score = min(1.0, 0.5 + 0.5 * (ratio - 1.0))
    return round(score, 4), severity_for_score(score)


def severity_for_score(score: float) -> int:
    if score >= 0.85:
        return SEVERITY_CRITICAL
    if score >= 0.7:
        return SEVERITY_HIGH
    if score >= 0.5:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def roll_buckets(state: MetricState, ts: datetime) -> list[float]:
    """Advance state's tumbling buckets up to ts, returning finalized values.

    Each bucket that ends at or before ts is finalized with ITS OWN accumulated
    cur_value (empty gap windows therefore contribute 0 to history), feeding
    Welford stats. After rolling, the bucket containing ts is fresh and the
    caller records this event into it.
    """
    finalized: list[float] = []
    window = timedelta(seconds=state.window_seconds)
    if state.cur_bucket_start is None:
        state.cur_bucket_start = bucket_start_for(ts, state.window_seconds)
        state.cur_value = 0.0
        state.cur_extra = {}
        return finalized
    while state.cur_bucket_start + window <= ts:
        finalized.append(state.cur_value)
        state.mean, state.m2, state.n = update_welford(
            state.mean, state.m2, state.n, state.cur_value
        )
        state.cur_bucket_start += window
        state.cur_value = 0.0
        state.cur_extra = {}
    return finalized
