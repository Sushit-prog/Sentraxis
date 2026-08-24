"""Curated MITRE ATT&CK Enterprise technique allowlist.

Validating LLM output against a bundled reference prevents hallucinated
technique IDs without shipping the full STIX bundle. Upgrade path (M4+):
replace with RAG over the complete enterprise-attack.json, keeping this module
as the validation seam.
"""

ATTACK_REFERENCE: dict[str, str] = {
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


def is_known_technique(technique_id: str) -> bool:
    return technique_id in ATTACK_REFERENCE


def technique_name(technique_id: str) -> str | None:
    return ATTACK_REFERENCE.get(technique_id)
