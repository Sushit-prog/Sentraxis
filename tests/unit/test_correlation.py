"""Unit tests: correlation clustering + agent output validation."""

from datetime import UTC, datetime, timedelta

import pytest

from app.correlation.agent import validate_analysis_payload
from app.correlation.attack_reference import ATTACK_REFERENCE, is_known_technique
from app.correlation.rules import (
    DetectionFact,
    build_incident_draft,
    cluster_by_entity_and_time,
)

T0 = datetime(2026, 8, 24, 9, 0, 0, tzinfo=UTC)


def _fact(
    did: int, entity: int, ts: datetime, detector: str = "port_velocity", score: float = 0.7
) -> DetectionFact:
    return DetectionFact(
        detection_id=did,
        entity_id=entity,
        detector=detector,
        detector_version=1,
        score=score,
        severity=3,
        event_ts=ts,
    )


# ---- clustering -----------------------------------------------------------


def test_clusters_split_on_entity_and_gap() -> None:
    facts = [
        _fact(1, 1, T0),
        _fact(2, 1, T0 + timedelta(seconds=30)),
        _fact(3, 1, T0 + timedelta(minutes=20)),  # gap > window -> new cluster
        _fact(4, 2, T0),  # different entity
    ]
    clusters = cluster_by_entity_and_time(facts, window_seconds=600)
    assert len(clusters) == 3
    sizes = sorted(len(c) for c in clusters)
    assert sizes == [1, 1, 2]


def test_cluster_is_order_independent() -> None:
    a = [_fact(1, 1, T0), _fact(2, 1, T0 + timedelta(seconds=10))]
    b = list(reversed(a))
    ca = cluster_by_entity_and_time(a, 600)
    cb = cluster_by_entity_and_time(b, 600)
    assert [[f.detection_id for f in c] for c in ca] == [[f.detection_id for f in c] for c in cb]


def test_draft_multi_signal_risk_bonus_and_ids_sorted() -> None:
    cluster = [
        _fact(5, 1, T0, detector="port_velocity", score=0.55),
        _fact(3, 1, T0 + timedelta(seconds=5), detector="rate_deviation", score=0.9),
    ]
    draft = build_incident_draft(cluster)
    assert draft.detection_ids == [3, 5]
    assert draft.risk_score == pytest.approx(min(1.0, 0.9 + 0.15))
    assert draft.distinct_detectors == ["port_velocity", "rate_deviation"]
    assert draft.first_seen_at == T0


# ---- agent payload validation ---------------------------------------------


VALID_PAYLOAD = {
    "title": "Coordinated port sweep against server",
    "narrative": "A single external source rapidly contacted many distinct service ports, "
    "consistent with reconnaissance scanning before a targeted intrusion attempt.",
    "risk_score": 0.8,
    "confidence_overall": 0.75,
    "techniques": [
        {
            "id": "T1046",
            "name": ATTACK_REFERENCE["T1046"],
            "confidence": 0.8,
            "evidence_detection_ids": [11],
        }
    ],
}

ALLOWED = {11}


def test_valid_payload_accepted() -> None:
    result = validate_analysis_payload(dict(VALID_PAYLOAD), ALLOWED)
    assert not isinstance(result, list)
    assert result.title.startswith("Coordinated")


def test_hallucinated_technique_rejected() -> None:
    bad = dict(VALID_PAYLOAD)
    bad["techniques"] = [
        {
            "id": "T9999",
            "name": "Made Up Technique",
            "confidence": 0.5,
            "evidence_detection_ids": [11],
        }
    ]
    errors = validate_analysis_payload(bad, ALLOWED)
    assert isinstance(errors, list)
    assert any("allowlist" in e for e in errors)


def test_wrong_technique_name_rejected() -> None:
    bad = dict(VALID_PAYLOAD)
    bad["techniques"] = [
        {
            "id": "T1046",
            "name": "Totally Different",
            "confidence": 0.8,
            "evidence_detection_ids": [11],
        }
    ]
    errors = validate_analysis_payload(bad, ALLOWED)
    assert isinstance(errors, list)
    assert any("mismatch" in e for e in errors)


def test_hallucinated_evidence_rejected() -> None:
    bad = json_deepcopy(VALID_PAYLOAD)
    bad["techniques"][0]["evidence_detection_ids"] = [11, 404]
    errors = validate_analysis_payload(bad, ALLOWED)
    assert isinstance(errors, list)
    assert any("not part of this incident" in e for e in errors)


def test_risk_confidence_disconnect_rejected() -> None:
    bad = json_deepcopy(VALID_PAYLOAD)
    bad["risk_score"] = 0.05
    errors = validate_analysis_payload(bad, ALLOWED)
    assert isinstance(errors, list)
    assert any("inconsistent" in e for e in errors)


def test_extra_fields_rejected() -> None:
    bad = json_deepcopy(VALID_PAYLOAD)
    bad["recommended_action"] = "rm -rf /"
    errors = validate_analysis_payload(bad, ALLOWED)
    assert isinstance(errors, list)


def test_allowlist_contains_expected_core() -> None:
    assert is_known_technique("T1046")
    assert is_known_technique("T1595.002")
    assert not is_known_technique("T1337")


def json_deepcopy(obj):  # local helper keeps test imports minimal
    import copy

    return copy.deepcopy(obj)
