# =============================================================================
# detection/mitre_mapping.py — MITRE ATT&CK Framework Mapping
# Maps detected attack types to MITRE ATT&CK Techniques
# Reference: https://attack.mitre.org/
# =============================================================================

# ── MITRE ATT&CK Technique Mapping ───────────────────────────────────────────
# Format: "Attack Type" → {"id": "TXXXX", "name": "Technique Name", "tactic": "Tactic"}

MITRE_MAP = {
    "Brute Force": {
        "id":     "T1110",
        "name":   "Brute Force",
        "tactic": "Credential Access",
        "url":    "https://attack.mitre.org/techniques/T1110/",
    },
    "SQL Injection": {
        "id":     "T1190",
        "name":   "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url":    "https://attack.mitre.org/techniques/T1190/",
    },
    "XSS Attack": {
        "id":     "T1059.007",
        "name":   "JavaScript (Client-Side Script Execution)",
        "tactic": "Execution",
        "url":    "https://attack.mitre.org/techniques/T1059/007/",
    },
    "Command Injection": {
        "id":     "T1059",
        "name":   "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url":    "https://attack.mitre.org/techniques/T1059/",
    },
    "Path Traversal": {
        "id":     "T1083",
        "name":   "File and Directory Discovery",
        "tactic": "Discovery",
        "url":    "https://attack.mitre.org/techniques/T1083/",
    },
    "DoS Simulation": {
        "id":     "T1499",
        "name":   "Endpoint Denial of Service",
        "tactic": "Impact",
        "url":    "https://attack.mitre.org/techniques/T1499/",
    },
    "Multi-Vector Attack": {
        "id":     "T1078",
        "name":   "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "url":    "https://attack.mitre.org/techniques/T1078/",
    },
    "Credential Stuffing": {
        "id":     "T1110.004",
        "name":   "Credential Stuffing",
        "tactic": "Credential Access",
        "url":    "https://attack.mitre.org/techniques/T1110/004/",
    },
    "Suspicious Activity": {
        "id":     "T1071",
        "name":   "Application Layer Protocol",
        "tactic": "Command and Control",
        "url":    "https://attack.mitre.org/techniques/T1071/",
    },
}

# Default for unknown types
_DEFAULT = {
    "id":     "T0000",
    "name":   "Unknown Technique",
    "tactic": "Unknown",
    "url":    "https://attack.mitre.org/",
}


def get_technique(attack_type: str) -> dict:
    """Return the MITRE technique dict for a given attack type."""
    return MITRE_MAP.get(attack_type, _DEFAULT)


def get_technique_id(attack_type: str) -> str:
    """Return just the technique ID string, e.g. 'T1110'."""
    return get_technique(attack_type)["id"]


def get_technique_label(attack_type: str) -> str:
    """Return a compact label like 'T1110 · Brute Force'."""
    t = get_technique(attack_type)
    return f"{t['id']} · {t['name']}"


def get_all_techniques() -> list:
    """Return all unique MITRE techniques referenced in the mapping."""
    seen = {}
    for v in MITRE_MAP.values():
        if v["id"] not in seen:
            seen[v["id"]] = v
    return list(seen.values())
