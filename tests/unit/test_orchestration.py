"""Unit tests: response policy decisions + audit chain hashing."""

from app.orchestration.audit import (
    GENESIS,
    compute_entry_hash,
)
from app.orchestration.policy import (
    IncidentContext,
    PlaybookDef,
    evaluate_response,
    is_external_identifier,
)

PB_QUARANTINE = PlaybookDef(
    name="isolate_compromised_host",
    description="",
    trigger_detectors=("port_velocity",),
    requires_external_source=True,
    min_risk=0.5,
    blast_radius="high",
    action_type="quarantine_host",
    version=1,
)
PB_BLOCK = PlaybookDef(
    name="throttle_flood_source",
    description="",
    trigger_detectors=("rate_deviation",),
    requires_external_source=True,
    min_risk=0.8,
    blast_radius="low",
    action_type="block_ip",
    version=1,
)


def _ctx(
    risk=0.7, identifier="203.0.113.77", detectors=frozenset({"port_velocity"})
) -> IncidentContext:
    return IncidentContext(
        incident_id=1,
        entity_id=9,
        entity_identifier=identifier,
        risk_score=risk,
        detectors=detectors,
    )


# ---- external/internal classification --------------------------------------


def test_external_classification() -> None:
    assert is_external_identifier("203.0.113.77")
    assert not is_external_identifier("192.168.10.50")
    assert not is_external_identifier("127.0.0.1")
    assert is_external_identifier("scan.example.com")  # hostname: unknown provenance


# ---- policy matching --------------------------------------------------------


def test_no_action_below_floor() -> None:
    specs = evaluate_response(_ctx(risk=0.4), [PB_QUARANTINE], min_risk_floor=0.5)
    assert specs == []


def test_quarantine_matches_sweep_external() -> None:
    specs = evaluate_response(_ctx(), [PB_QUARANTINE], min_risk_floor=0.5)
    assert len(specs) == 1 and specs[0].blast_radius == "high"


def test_internal_source_never_quarantined() -> None:
    specs = evaluate_response(_ctx(identifier="192.168.10.21"), [PB_QUARANTINE], min_risk_floor=0.5)
    assert specs == []


def test_detector_mismatch_no_match() -> None:
    specs = evaluate_response(
        _ctx(detectors=frozenset({"beacon_regularity"})), [PB_QUARANTINE], 0.5
    )
    assert specs == []


def test_flood_auto_block_low_blast() -> None:
    ctx = _ctx(risk=0.9, identifier="203.0.113.77", detectors=frozenset({"rate_deviation"}))
    specs = evaluate_response(ctx, [PB_BLOCK], 0.5)
    assert len(specs) == 1 and specs[0].blast_radius == "low"
    # below the stricter playbook threshold: nothing
    low_risk = IncidentContext(
        incident_id=ctx.incident_id,
        entity_id=ctx.entity_id,
        entity_identifier=ctx.entity_identifier,
        risk_score=0.6,
        detectors=ctx.detectors,
    )
    assert evaluate_response(low_risk, [PB_BLOCK], 0.5) == []


def test_both_playbooks_can_fire_on_mixed_incident() -> None:
    ctx = _ctx(risk=0.95, detectors=frozenset({"port_velocity", "rate_deviation"}))
    specs = evaluate_response(ctx, [PB_QUARANTINE, PB_BLOCK], 0.5)
    assert {s.action_type for s in specs} == {"quarantine_host", "block_ip"}


# ---- audit chain ------------------------------------------------------------


def test_compute_entry_hash_is_deterministic_and_sensitive() -> None:
    a = compute_entry_hash(GENESIS, "2026-01-01T00:00:00+00:00", "sys", "evt", '{"a":1}')
    b = compute_entry_hash(GENESIS, "2026-01-01T00:00:00+00:00", "sys", "evt", '{"a":1}')
    c = compute_entry_hash(GENESIS, "2026-01-01T00:00:00+00:00", "sys", "evt", '{"a":2}')
    assert a == b and a != c
