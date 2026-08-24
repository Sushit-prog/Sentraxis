"""Response policy: pure decision logic mapping incidents to containment actions.

No DB access — the orchestrator worker supplies typed context and receives
action specifications. This keeps trigger semantics unit-testable and reviewable
(see ADR-007: blast-radius gating is the core safety property).

External-source rule: identifiers that parse as private/loopback IPs are
internal; everything else (public IPs, hostnames) is treated as external.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class PlaybookDef:
    name: str
    description: str
    trigger_detectors: tuple[str, ...]
    requires_external_source: bool
    min_risk: float
    blast_radius: str  # "low" | "high"
    action_type: str
    version: int


@dataclass(frozen=True, slots=True)
class IncidentContext:
    incident_id: int
    entity_id: int
    entity_identifier: str
    risk_score: float
    detectors: frozenset[str]
    techniques: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ActionSpec:
    playbook: PlaybookDef
    action_type: str
    blast_radius: str
    reason: str


# Explicit internal space. Deliberately NOT using ipaddress.is_private: it also
# flags documentation ranges (TEST-NET-3 / 203.0.113.0/24 etc.) which our
# benchmark scenarios use as public-internet attackers.
_INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
        "fe80::/10",
    )
]


def is_external_identifier(identifier: str) -> bool:
    """Public IP or non-IP hostname => external. RFC1918/loopback => internal."""
    try:
        ip = ipaddress.ip_address(identifier.strip())
    except ValueError:
        return True  # hostnames: unknown provenance, treat as external
    return not any(ip in net for net in _INTERNAL_NETWORKS)


def evaluate_response(
    ctx: IncidentContext,
    playbooks: list[PlaybookDef],
    min_risk_floor: float,
) -> list[ActionSpec]:
    """Return one ActionSpec per matching, enabled-by-threshold playbook.

    Matching requires: risk >= max(playbook.min_risk, min_risk_floor),
    at least one overlapping trigger detector, and (when the playbook demands
    it) an external source. One action per playbook — never duplicates.
    """
    specs: list[ActionSpec] = []
    external = is_external_identifier(ctx.entity_identifier)
    for pb in playbooks:
        threshold = max(pb.min_risk, min_risk_floor)
        if ctx.risk_score < threshold:
            continue
        if pb.requires_external_source and not external:
            continue
        overlap = set(pb.trigger_detectors) & set(ctx.detectors)
        if not overlap:
            continue
        reason = (
            f"risk={ctx.risk_score:.2f} >= threshold={threshold:.2f}; "
            f"detectors={','.join(sorted(overlap))}; "
            f"source={'external' if external else 'internal'}"
        )
        specs.append(
            ActionSpec(
                playbook=pb,
                action_type=pb.action_type,
                blast_radius=pb.blast_radius,
                reason=reason,
            )
        )
    return specs
