# =============================================================================
# detection/canary.py — Canary Token / Deception Trap System
# Plants fake sensitive files and endpoints. Any access = immediate Critical alert.
# This is real enterprise deception technology (like Thinkst Canary tokens).
# =============================================================================

import re

# ── Fake files planted in SSH honeypot ────────────────────────────────────────
CANARY_FILES = [
    "passwords.txt", "password.txt", "passwords.csv",
    "credentials.json", "credentials.txt", "creds.txt",
    "backup.sql", "database.sql", "db_backup.sql", "dump.sql",
    "id_rsa", "id_rsa.pub", ".ssh/id_rsa",
    "config.ini", "config.php", ".env", "settings.py",
    "secret.key", "private.key", "server.key",
    "admin.txt", "admin_credentials.txt",
    "api_keys.txt", "api_key.txt",
    "wallet.dat", "bitcoin.txt",
]

# ── Fake web paths (deception lures) ──────────────────────────────────────────
CANARY_WEB_PATHS = [
    "/passwords.txt", "/password.txt",
    "/credentials.json", "/credentials.txt",
    "/backup.sql", "/database.sql", "/db.sql",
    "/config.bak", "/config.old",
    "/.git/config", "/.git/HEAD",
    "/wp-config.php", "/config.php.bak",
    "/admin.txt", "/secret.txt",
    "/api_keys.txt", "/api-keys.json",
    "/env.bak", "/.env.backup", "/.env.local",
    "/id_rsa", "/server.key", "/private.key",
    "/users.sql", "/users.csv",
    "/access.log.bak",
]

# ── Canary SSH commands (trigger when attacker tries to read planted files) ───
CANARY_COMMAND_PATTERNS = [
    r'cat\s+.*(password|credential|backup|id_rsa|secret|config|admin|api.?key|wallet|\.env)',
    r'(nano|vim|vi|less|more|head|tail)\s+.*(password|credential|backup|id_rsa|secret)',
    r'(wget|curl).*(password|credential|backup|dump|id_rsa)',
    r'(cp|mv|scp)\s+.*(password|credential|id_rsa|backup)',
    r'find\s+.*-name\s+.*(password|credential|\.key|id_rsa)',
    r'grep\s+.*(password|passwd|secret|credential)',
]

# ── Fake credential content shown to attacker (deception) ─────────────────────
FAKE_CREDENTIAL_RESPONSE = """
=== ADMIN CREDENTIALS (INTERNAL USE ONLY) ===
admin_user: soc_admin
admin_pass: S3cur3P@ss!2024
db_user: dbadmin
db_pass: Db#Secure99
api_key: sk-proj-XXXX-FAKE-CANARY-TOKEN-XXXX
server_ip: 192.168.1.100
ssh_key: /home/admin/.ssh/id_rsa
"""

# ── Canary descriptions for alerts ────────────────────────────────────────────
CANARY_DESCRIPTIONS = {
    "ssh_file_access":  "Attacker accessed a planted canary credential file",
    "web_path_access":  "Attacker triggered a web deception lure endpoint",
    "credential_grep":  "Attacker searched for credentials using grep/find",
    "key_file_access":  "Attacker attempted to steal private SSH key file",
    "config_file":      "Attacker accessed a fake configuration/secrets file",
    "database_dump":    "Attacker found and accessed a fake database backup",
}


def check_ssh_command(command: str) -> dict | None:
    """
    Check if an SSH command triggered a canary trap.
    Returns a canary event dict if triggered, else None.
    """
    if not command:
        return None

    cmd_lower = command.lower().strip()

    # Direct file access check
    for f in CANARY_FILES:
        if f in cmd_lower:
            ctype = _classify_file(f)
            return {
                "triggered":    True,
                "canary_type":  "ssh_file_access",
                "canary_file":  f,
                "description":  CANARY_DESCRIPTIONS.get(ctype, "Canary trap triggered"),
                "deception_note": f"Attacker ran: `{command[:120]}`",
            }

    # Pattern-based detection
    for pattern in CANARY_COMMAND_PATTERNS:
        if re.search(pattern, cmd_lower):
            return {
                "triggered":    True,
                "canary_type":  "credential_grep",
                "canary_file":  "credential search",
                "description":  CANARY_DESCRIPTIONS["credential_grep"],
                "deception_note": f"Attacker ran: `{command[:120]}`",
            }

    return None


def check_web_path(path: str) -> dict | None:
    """
    Check if a web request path triggered a canary lure.
    Returns a canary event dict if triggered, else None.
    """
    if not path:
        return None

    path_lower = path.lower().split("?")[0]  # strip query params

    for canary_path in CANARY_WEB_PATHS:
        if path_lower == canary_path or path_lower.startswith(canary_path):
            return {
                "triggered":   True,
                "canary_type": "web_path_access",
                "canary_file": canary_path,
                "description": CANARY_DESCRIPTIONS["web_path_access"],
                "deception_note": f"Attacker fetched deception URL: {path}",
            }

    return None


def build_canary_attack(base_record: dict, canary_info: dict) -> dict:
    """
    Build a Critical canary attack record on top of an existing attack record.
    """
    record = dict(base_record)
    record["attack_type"]    = "CANARY TRAP TRIGGERED"
    record["severity"]       = "Critical"
    record["risk_score"]     = 10
    record["rule"]           = "DECEPTION_TECHNOLOGY"
    record["canary_type"]    = canary_info.get("canary_type", "unknown")
    record["canary_file"]    = canary_info.get("canary_file", "unknown")
    record["deception_note"] = canary_info.get("deception_note", "")
    record["payload"]        = (
        f"[CANARY TRIGGERED] {canary_info.get('description', '')} | "
        f"{canary_info.get('deception_note', '')} | "
        f"File/Path: {canary_info.get('canary_file', '?')}"
    )
    return record


def _classify_file(filename: str) -> str:
    if any(x in filename for x in ["id_rsa", ".key", "private"]):
        return "key_file_access"
    if any(x in filename for x in [".sql", "dump", "backup", "db"]):
        return "database_dump"
    if any(x in filename for x in ["config", ".env", "settings"]):
        return "config_file"
    return "ssh_file_access"
