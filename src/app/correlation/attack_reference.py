"""MITRE ATT&CK Enterprise technique reference for correlation validation.

Loads the full technique index (id -> name) built from mitre/cti by
scripts/fetch_attack_reference.py and committed as a compact JSON resource.
If that resource is missing at import time we degrade to a curated mini
allowlist so the system still functions — validation coverage is simply
narrower until the index is regenerated.

This module is the single seam ADR-006 identified for future retrieval-based
upgrades; callers only ever see is_known_technique()/technique_name().
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path

# Curated fallback used only when the full index resource is unavailable.
_MINI_ALLOWLIST: dict[str, str] = {
    "T1046": "Network Service Discovery",
    "T1595": "Active Scanning",
    "T1595.001": "Scanning IP Blocks",
    "T1595.002": "Vulnerability Scanning",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1071": "Application Layer Protocol",
    "T1027": "Obfuscated Files or Information",
    "T1203": "Exploitation for Client Execution",
    "T1190": "Exploit Public-Facing Application",
    "T1499": "Endpoint Denial of Service",
    "T1498": "Network Denial of Service",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1041": "Exfiltration Over C2 Channel",
    "T1078": "Valid Accounts",
    "T1021": "Remote Services",
    "T1098": "Account Manipulation",
    "T1489": "Service Stop",
}

TECHNIQUE_ID_PATTERN = r"^T\d{4}(\.\d{3})?$"

_INDEX_RESOURCE = "attack_index.json"


@lru_cache(maxsize=1)
def _load_index() -> tuple[dict[str, str], str]:
    """Return (index, source). Full index preferred; mini allowlist as fallback."""
    try:
        resource = resources.files("app.correlation").joinpath("data", _INDEX_RESOURCE)
        if resource.is_file():
            return json.loads(resource.read_text(encoding="utf-8")), "full-index"
    except (FileNotFoundError, ModuleNotFoundError, json.JSONDecodeError):
        pass
    # dev fallback: repo-relative path (e.g., when running without install)
    local = Path(__file__).parent / "data" / _INDEX_RESOURCE
    if local.is_file():
        return json.loads(local.read_text(encoding="utf-8")), "full-index"
    return dict(_MINI_ALLOWLIST), "mini-fallback"


def index_size() -> int:
    return len(_load_index()[0])


def index_source() -> str:
    return _load_index()[1]


def is_known_technique(technique_id: str) -> bool:
    return technique_id in _load_index()[0]


def technique_name(technique_id: str) -> str | None:
    return _load_index()[0].get(technique_id)


def known_techniques() -> list[str]:
    return sorted(_load_index()[0])
