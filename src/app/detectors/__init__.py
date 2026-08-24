"""Detection engine (ADR-004): pure detectors over canonical event batches.

Detectors own per-entity streaming state (tumbling buckets + Welford history,
persisted in entity_metric_state) and emit Detection records. All scoring math
is implemented as pure functions in base.py so it is unit-testable without a
database.
"""

from typing import Any

from app.config import Settings
from app.detectors.base import (
    Detection,
    EventView,
    MetricState,
    bucket_start_for,
    detection_from_z,
    score_distinct_ports,
    severity_for_score,
    update_welford,
)
from app.detectors.port_velocity import DistinctPortVelocityDetector
from app.detectors.rate_deviation import RateDeviationDetector

DETECTOR_CURSOR_NAME = "detector"

__all__ = [
    "DETECTOR_CURSOR_NAME",
    "Detection",
    "DistinctPortVelocityDetector",
    "EventView",
    "MetricState",
    "RateDeviationDetector",
    "bucket_start_for",
    "build_registry",
    "detection_from_z",
    "score_distinct_ports",
    "severity_for_score",
    "update_welford",
]


def build_registry(settings: "Settings | Any") -> list[Any]:
    """Instantiate all active detectors against one session."""
    return [
        RateDeviationDetector(
            window_s=settings.det_window_seconds,
            z_trigger=settings.det_rate_z_trigger,
            z_cap=settings.det_rate_z_cap,
            min_history=settings.det_rate_min_history,
        ),
        DistinctPortVelocityDetector(
            window_s=settings.det_window_seconds,
            port_threshold=settings.det_port_threshold,
        ),
    ]
