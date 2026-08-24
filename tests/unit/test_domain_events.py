"""Unit tests for the canonical event contract."""

import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.domain.events import (
    CanonicalEvent,
    EventSource,
    NetworkFlowFeatures,
    normalize_host_identifier,
    parse_event_payload,
)

BASE_EVENT = {
    "event_id": str(uuid4()),
    "source": "network_flow",
    "ts": "2026-08-24T09:03:47Z",
    "src_entity": {"type": "host", "identifier": "203.0.113.77"},
    "dst_entity": {"type": "host", "identifier": "192.168.10.50"},
    "ground_truth_label": True,
    "features": {
        "protocol": "tcp",
        "src_port": 40021,
        "dst_port": 21,
        "duration_s": 0.002,
        "src_bytes": 0,
        "dst_bytes": 0,
        "src_pkts": 1,
        "dst_pkts": 1,
        "conn_state": "RST",
    },
}


def test_valid_event_parses_and_round_trips() -> None:
    event = parse_event_payload(json.dumps(BASE_EVENT))
    assert event.source == EventSource.network_flow
    assert event.features.src_port == 40021
    # round trip: serialized form parses identically
    again = parse_event_payload(event.model_dump_json())
    assert again == event


def test_unknown_field_rejected() -> None:
    payload = dict(BASE_EVENT)
    payload["sneaky_extra"] = "should not pass"
    # contract: ALL malformed input surfaces as ValueError at the boundary
    with pytest.raises(ValueError, match="invalid canonical event"):
        parse_event_payload(json.dumps(payload))


def test_unknown_feature_rejected() -> None:
    features = dict(BASE_EVENT["features"], weird_metric=1)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        NetworkFlowFeatures(**features)


def test_entity_ref_is_hashable_value_object() -> None:
    ref1 = CanonicalEvent(**BASE_EVENT).src_entity
    ref2 = CanonicalEvent(**BASE_EVENT).src_entity
    assert ref1 == ref2 and {ref1} == {ref2}
    with pytest.raises(ValidationError):
        ref1.identifier = "10.0.0.1"  # immutable by design


def test_naive_timestamp_coerced_to_utc() -> None:
    payload = dict(BASE_EVENT, ts="2026-08-24T09:00:00")  # naive
    event = parse_event_payload(json.dumps(payload))
    assert event.ts.tzinfo is not None and event.ts.utcoffset().total_seconds() == 0


def test_non_utc_offset_converted() -> None:
    payload = dict(BASE_EVENT, ts="2026-08-24T12:00:00+05:30")
    event = parse_event_payload(json.dumps(payload))
    assert event.ts.hour == 6 and event.ts.minute == 30


def test_invalid_protocol_rejected() -> None:
    features = dict(BASE_EVENT["features"], protocol="smtp")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        NetworkFlowFeatures(**features)


def test_port_out_of_range_rejected() -> None:
    features = dict(BASE_EVENT["features"], dst_port=70000)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        NetworkFlowFeatures(**features)


def test_malformed_json_raises_value_error_not_validation_error() -> None:
    with pytest.raises(ValueError, match="invalid canonical event"):
        parse_event_payload(b"{not json")


def test_host_identifier_normalization() -> None:
    assert normalize_host_identifier(" 192.168.10.50 ") == "192.168.10.50"
    assert normalize_host_identifier("EXAMPLE.COM") == "example.com"
    compressed = normalize_host_identifier("::FFFF:192.168.10.5")
    assert compressed.startswith("::ffff")


def test_empty_identifier_rejected() -> None:
    with pytest.raises(ValidationError):
        CanonicalEvent(**dict(BASE_EVENT, src_entity={"type": "host", "identifier": "   "}))
