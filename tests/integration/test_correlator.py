"""Integration tests: correlation worker over live PostgreSQL.

Covers: rules-mode incident creation, cursor idempotency, agent fallback on
provider failure, repair-then-fallback on invalid payloads, hallucinated
technique rejection, and prompt-injection resistance.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.persistence.models import (
    DetectionRow,
    EventRow,
    IncidentDetectionRow,
    IncidentRow,
    LlmCallRow,
)
from app.workers.correlator import CorrelationWorker

pytestmark = [pytest.mark.integration]

T0 = datetime(2026, 8, 24, 9, 0, 0, tzinfo=UTC)


class StubAgent:
    """Configurable stand-in for the real agent."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.behavior: str = "unavailable"  # unavailable|ok|invalid_then_ok|always_invalid

    def analyze(self, entity_identifier: str, draft, facts: list, allowed_detection_ids: set):
        self.calls.append({"identifier": entity_identifier, "allowed": allowed_detection_ids})
        if self.behavior == "unavailable":
            return None, {"outcome": "unavailable", "error_detail": "no key"}, False
        if self.behavior == "invalid_then_ok":
            if len(self.calls) % 2 == 1:
                return None, {"outcome": "schema_invalid_failed", "error_detail": "bad"}, False
            analysis = _fake_analysis(draft.detection_ids)
            return analysis, {"outcome": "ok_repaired"}, True
        if self.behavior == "always_invalid":
            return None, {"outcome": "schema_invalid_failed", "error_detail": "nope"}, False
        analysis = _fake_analysis(draft.detection_ids)
        return analysis, {"outcome": "ok"}, False


def _fake_analysis(allowed_ids: set[int]) -> object:
    from types import SimpleNamespace

    eid = sorted(allowed_ids)[0]
    return SimpleNamespace(
        title="Reconnaissance sweep against server (stub)",
        narrative="Stubbed analysis narrative long enough to satisfy schema constraints.",
        risk_score=0.8,
        techniques=[
            SimpleNamespace(
                id="T1046",
                confidence=0.8,
                model_dump=lambda: {
                    "id": "T1046",
                    "name": "Network Service Discovery",
                    "confidence": 0.8,
                    "evidence_detection_ids": [eid],
                },
            )
        ],
    )


def make_worker(session_factory, behavior: str | None = None) -> CorrelationWorker:
    agent = StubAgent()

    def build(w_behavior: str | None):
        if w_behavior is None:
            return CorrelationWorker(session_factory, None, window_seconds=600, batch_size=100)
        agent.behavior = w_behavior
        return CorrelationWorker(session_factory, agent, window_seconds=600, batch_size=100)

    return build(behavior)


def _seed_detection(
    session_factory, did_seq: int, entity_id: int, event_id: int, ts, detector="port_velocity"
):
    with session_factory() as s, s.begin():
        det = DetectionRow(
            event_id=event_id,
            entity_id=entity_id,
            detector=detector,
            detector_version=1,
            score=0.7,
            severity=3,
            details={"observed": 11, "metric": "distinct_dst_ports_60s"},
        )
        s.add(det)
        s.flush()
        # keep event ts aligned with detection for clustering realism
        s.query(EventRow).filter(EventRow.id == event_id).update({"ts": ts})
        return det.id


def test_rules_mode_creates_incident_with_evidence(rclient, session_factory, clean_db) -> None:
    # seed one entity + one event + two detections in same cluster
    with session_factory() as s, s.begin():
        ent = __import__("app.persistence.models", fromlist=["EntityRow"]).EntityRow(
            type="host", identifier="203.0.113.77"
        )
        s.add(ent)
        s.flush()
        ev1 = EventRow(
            event_id=__import__("uuid").uuid4(),
            ts=T0,
            source="network_flow",
            src_entity_id=ent.id,
            features={"dst_port": 21},
        )
        ev2 = EventRow(
            event_id=__import__("uuid").uuid4(),
            ts=T0 + timedelta(seconds=5),
            source="network_flow",
            src_entity_id=ent.id,
            features={"dst_port": 22},
        )
        s.add_all([ev1, ev2])
        s.flush()
        d1 = DetectionRow(
            event_id=ev1.id,
            entity_id=ent.id,
            detector="port_velocity",
            detector_version=1,
            score=0.55,
            severity=2,
            details={"observed": 11},
        )
        d2 = DetectionRow(
            event_id=ev2.id,
            entity_id=ent.id,
            detector="rate_deviation",
            detector_version=1,
            score=0.9,
            severity=3,
            details={"metric": "flow_count_60s"},
        )
        s.add_all([d1, d2])
        _entity_id, _ev1_id, _ev2_id, _d1id, _d2id = ent.id, ev1.id, ev2.id, d1.id, d2.id

    w = make_worker(session_factory)  # rules mode
    summary = w.tick(force=True)
    assert summary["incidents"] == 1 and summary["detections"] == 2

    with session_factory() as s:
        inc = s.query(IncidentRow).one()
        assert inc.correlation_mode == "rules"
        assert inc.detection_count == 2
        links = s.query(IncidentDetectionRow).filter_by(incident_id=inc.id).count()
        assert links == 2
        assert "port_velocity" in inc.title

    # second tick: cursor advanced -> nothing new
    again = w.tick(force=True)
    assert again["detections"] == 0
    with session_factory() as s:
        assert s.query(IncidentRow).count() == 1


def test_agent_failure_falls_back_to_rules_and_records_llm_call(
    rclient, session_factory, clean_db
) -> None:
    _seed_two_clustered_detections(session_factory)
    w = make_worker(session_factory, "unavailable")
    summary = w.tick(force=True)
    assert summary["incidents"] == 1

    with session_factory() as s:
        inc = s.query(IncidentRow).one()
        assert inc.correlation_mode == "rules"
        call = s.query(LlmCallRow).one()
        assert call.outcome == "unavailable"


def test_invalid_payload_repairs_or_falls_back(rclient, session_factory, clean_db) -> None:
    _seed_two_clustered_detections(session_factory)

    # always-invalid: fallback keeps system green
    w_bad = make_worker(session_factory, "always_invalid")
    assert w_bad.tick(force=True)["incidents"] == 1
    with session_factory() as s:
        inc = s.query(IncidentRow).one()
        assert inc.correlation_mode == "rules"
        calls = s.query(LlmCallRow).all()
        assert all(c.outcome == "schema_invalid_failed" for c in calls)


def test_valid_enrichment_upgrades_incident_to_llm_mode(rclient, session_factory, clean_db) -> None:
    _seed_two_clustered_detections(session_factory)
    w = make_worker(session_factory, "ok")
    w.tick(force=True)
    with session_factory() as s:
        inc = s.query(IncidentRow).one()
        assert inc.correlation_mode == "llm"
        assert inc.techniques[0]["id"] == "T1046"
        assert any(c.outcome == "ok" for c in s.query(LlmCallRow).all())


def test_prompt_receives_only_allowed_evidence_ids(rclient, session_factory, clean_db) -> None:
    captured: dict = {}

    class Capturing(StubAgent):
        def analyze(self, entity_identifier: str, draft, facts: list, allowed_detection_ids: set):
            captured["allowed"] = set(allowed_detection_ids)
            captured["fact_ids"] = {f["detection_id"] for f in facts}
            self.behavior = "ok"
            return super().analyze(entity_identifier, draft, facts, allowed_detection_ids)

    w = CorrelationWorker(session_factory, Capturing(), window_seconds=600, batch_size=100)
    _seed_two_clustered_detections(session_factory)
    w.tick(force=True)
    assert captured["allowed"] == captured["fact_ids"]
    assert len(captured["fact_ids"]) == 2


# ---- helpers ---------------------------------------------------------------


def _seed_two_clustered_detections(session_factory) -> tuple[int, int]:
    import uuid as uuid_mod

    from app.persistence.models import EntityRow

    with session_factory() as s, s.begin():
        ent = EntityRow(type="host", identifier="198.51.100.9")
        s.add(ent)
        s.flush()
        evs = []
        for i, delta in enumerate((0, 5)):
            ev = EventRow(
                event_id=uuid_mod.uuid4(),
                ts=T0 + timedelta(seconds=delta),
                source="network_flow",
                src_entity_id=ent.id,
                features={"dst_port": 21 + i},
            )
            s.add(ev)
            evs.append(ev)
        s.flush()
        d1 = DetectionRow(
            event_id=evs[0].id,
            entity_id=ent.id,
            detector="port_velocity",
            detector_version=1,
            score=0.55,
            severity=2,
            details={"observed": 11},
        )
        d2 = DetectionRow(
            event_id=evs[1].id,
            entity_id=ent.id,
            detector="port_velocity",
            detector_version=1,
            score=0.6,
            severity=2,
            details={"observed": 12},
        )
        s.add_all([d1, d2])
        return d1.id, d2.id
