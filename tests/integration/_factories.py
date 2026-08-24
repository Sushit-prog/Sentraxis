"""Canonical event dict factory shared by integration tests."""

from typing import Any

EVENT_TEMPLATE: dict[str, Any] = {
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


def make_event_dict(seq: int) -> dict[str, Any]:
    payload = dict(EVENT_TEMPLATE)
    payload["event_id"] = f"5f0a1c7e-dead-4a10-b100-{seq:012d}"
    return payload
