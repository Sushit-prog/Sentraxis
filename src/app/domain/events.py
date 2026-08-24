"""Canonical event models: the validated contract between ingestion and detection.

Every telemetry record crossing a process boundary MUST parse into a CanonicalEvent.
Validation is strict (extra="forbid"): unknown or malformed fields are rejected at
the edge so downstream stages never see ambiguous data.

Extension point: when a second telemetry source (auth/process) arrives, replace
the concrete ``features`` field with a discriminated union keyed by ``source``.
"""

import ipaddress
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
)
from pydantic_core import to_jsonable_python


class EventSource(StrEnum):
    network_flow = "network_flow"


class EntityType(StrEnum):
    host = "host"
    user = "user"
    subnet = "subnet"


class Protocol(StrEnum):
    tcp = "tcp"
    udp = "udp"
    icmp = "icmp"


def normalize_host_identifier(raw: str) -> str:
    """Canonicalize a host identifier.

    IPs are stored as their compressed canonical string form. Non-IP identifiers
    (hostnames from datasets) are lowercased and stripped.
    """
    value = raw.strip()
    if not value:
        raise ValueError("empty host identifier")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value.lower()


class EntityRef(BaseModel):
    """Immutable, hashable entity reference (safe as dict/set key)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: EntityType
    identifier: str

    @field_validator("identifier")
    @classmethod
    def _normalize(cls, value: str, info: ValidationInfo) -> str:
        etype = info.data.get("type")
        if etype == EntityType.host:
            return normalize_host_identifier(value)
        stripped = value.strip()
        if not stripped:
            raise ValueError("empty entity identifier")
        return stripped.lower()


class NetworkFlowFeatures(BaseModel):
    """Typed projection of a network flow record (CICIDS2017-aligned subset)."""

    model_config = ConfigDict(extra="forbid")

    protocol: Protocol = Protocol.tcp
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    duration_s: float = Field(ge=0)
    src_bytes: int = Field(ge=0)
    dst_bytes: int = Field(ge=0)
    src_pkts: int = Field(ge=0)
    dst_pkts: int = Field(ge=0)
    conn_state: str = Field(min_length=1, max_length=16)


class CanonicalEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    source: EventSource
    ts: datetime
    src_entity: EntityRef
    dst_entity: EntityRef | None = None
    ground_truth_label: bool | None = None
    features: NetworkFlowFeatures

    @field_validator("ts")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def parse_event_payload(raw: str | bytes) -> CanonicalEvent:
    """Parse a stream payload into a CanonicalEvent.

    Raises ValueError (with original detail chained) on any malformed input so
    callers can dead-letter uniformly.
    """
    try:
        return CanonicalEvent.model_validate_json(raw)
    except ValidationError as exc:
        raise ValueError(f"invalid canonical event: {exc.error_count()} error(s)") from exc


def to_jsonable(obj: object) -> object:
    """Best-effort JSON-safe conversion (used by stream producers)."""
    return to_jsonable_python(obj)
