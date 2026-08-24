"""Rule-based correlation: deterministic clustering of detections into incidents.

Pure functions only — no DB access — so clustering semantics are unit-testable.
The correlator worker fetches candidate rows and applies these functions.

Clustering rule (v1): detections from the same source entity whose event
timestamps are within `window_seconds` of the previous detection in the group
form one incident. Multi-signal clusters (distinct detectors) score higher:
risk = max_score + 0.15 * (n_detectors - 1), capped at 1.0.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True, slots=True)
class DetectionFact:
    """Slim projection of a detection row for correlation."""

    detection_id: int
    entity_id: int
    detector: str
    detector_version: int
    score: float
    severity: int
    event_ts: datetime


@dataclass(slots=True)
class IncidentDraft:
    entity_id: int
    title: str
    narrative: str
    risk_score: float
    first_seen_at: datetime
    last_seen_at: datetime
    detection_count: int
    detection_ids: list[int]
    distinct_detectors: list[str]


def cluster_by_entity_and_time(
    facts: list[DetectionFact], window_seconds: int
) -> list[list[DetectionFact]]:
    """Group per entity; split when the inter-detection gap exceeds the window.

    Input may arrive in any order; ordering is applied deterministically.
    """
    by_entity: dict[int, list[DetectionFact]] = {}
    for fact in sorted(facts, key=lambda f: (f.entity_id, f.event_ts, f.detection_id)):
        by_entity.setdefault(fact.entity_id, []).append(fact)

    clusters: list[list[DetectionFact]] = []
    window = timedelta(seconds=window_seconds)
    for _entity, rows in sorted(by_entity.items()):
        current: list[DetectionFact] = []
        for row in rows:
            if current and row.event_ts - current[-1].event_ts > window:
                clusters.append(current)
                current = []
            current.append(row)
        if current:
            clusters.append(current)
    return clusters


def build_incident_draft(cluster: list[DetectionFact]) -> IncidentDraft:
    """Deterministic rules-mode incident from one cluster."""
    detectors = sorted({f.detector for f in cluster})
    max_score = max(f.score for f in cluster)
    risk = min(1.0, round(max_score + 0.15 * (len(detectors) - 1), 4))
    first_seen = min(f.event_ts for f in cluster)
    last_seen = max(f.event_ts for f in cluster)

    title = f"Behavioral anomalies on entity #{cluster[0].entity_id}: {', '.join(detectors)}"
    narrative = (
        f"{len(cluster)} detection(s) from {len(detectors)} detector(s) "
        f"between {first_seen.isoformat()} and {last_seen.isoformat()}. "
        "Correlated by rule-based time/entity proximity."
    )
    return IncidentDraft(
        entity_id=cluster[0].entity_id,
        title=title,
        narrative=narrative,
        risk_score=risk,
        first_seen_at=first_seen,
        last_seen_at=last_seen,
        detection_count=len(cluster),
        detection_ids=sorted(f.detection_id for f in cluster),
        distinct_detectors=detectors,
    )
