# =============================================================================
# detection/killchain.py — Cyber Kill Chain Phase Tracker
# Maps every detected attack to one of the 8 Cyber Kill Chain stages.
# Tracks per-IP progression through the chain in real time.
# Based on the Lockheed Martin Cyber Kill Chain framework.
# =============================================================================

# ── Kill Chain Phases ─────────────────────────────────────────────────────────
PHASES = {
    1: {"name": "Reconnaissance",       "icon": "🔍", "color": "#64748b", "mitre": "TA0043"},
    2: {"name": "Initial Access",        "icon": "🚪", "color": "#f59e0b", "mitre": "TA0001"},
    3: {"name": "Execution",             "icon": "⚡", "color": "#f97316", "mitre": "TA0002"},
    4: {"name": "Persistence",           "icon": "🔒", "color": "#ef4444", "mitre": "TA0003"},
    5: {"name": "Privilege Escalation",  "icon": "⬆",  "color": "#dc2626", "mitre": "TA0004"},
    6: {"name": "Credential Access",     "icon": "🗝",  "color": "#b91c1c", "mitre": "TA0006"},
    7: {"name": "Lateral Movement",      "icon": "↔",  "color": "#7c3aed", "mitre": "TA0008"},
    8: {"name": "Exfiltration",          "icon": "📤", "color": "#9333ea", "mitre": "TA0010"},
}

# ── Keyword → Phase mapping ───────────────────────────────────────────────────
PHASE_RULES = [
    # Reconnaissance
    (1, "attack_type", ["scan", "probe", "directory traversal", "enumerat",
                        "fingerprint", "banner grab", "info gather",
                        "robots.txt", "sitemap", "port scan", "nmap",
                        "discovery", "phpinfo", "server-status"]),
    (1, "payload",     [".env", "robots.txt", "sitemap.xml", "phpinfo",
                        "server-status", "server-info", "/.git",
                        "/.svn", "nmap", "masscan"]),
    (1, "url_path",    ["/.env", "/robots.txt", "/.git", "/phpinfo",
                        "/server-status", "/sitemap"]),

    # Initial Access
    (2, "attack_type", ["brute force", "login attempt", "auth", "credential",
                        "sql injection", "xss", "rce", "command injection",
                        "web shell", "backdoor", "exploit", "ftp login",
                        "telnet login", "ssh auth", "wp-login", "phpmyadmin"]),
    (2, "payload",     ["union select", "' or '", "or 1=1", "<script>",
                        "alert(", "onerror=", "passwd", "admin",
                        "wp-login", "phpmyadmin"]),

    # Execution
    (3, "attack_type", ["command exec", "shell exec", "rce", "code exec",
                        "script exec", "remote exec", "webshell exec"]),
    (3, "payload",     ["whoami", "id;", "/bin/sh", "/bin/bash",
                        "cmd.exe", "powershell", "python -c", "perl -e",
                        "php -r", "ruby -e", "nc -e", "bash -i",
                        "exec(", "system(", "passthru(", "shell_exec("]),

    # Persistence
    (4, "payload",     ["crontab", "/etc/cron", ".bashrc", ".bash_profile",
                        ".profile", "authorized_keys", "/etc/rc.local",
                        "systemctl enable", "chkconfig", "/etc/init.d",
                        "startup", "autostart", "registry run"]),

    # Privilege Escalation
    (5, "attack_type", ["privilege escal", "sudo", "suid", "priv esc",
                        "root escalation", "kernel exploit"]),
    (5, "payload",     ["sudo ", "sudo-l", "sudo -l", "chmod +s",
                        "chmod 4755", "/etc/sudoers", "pkexec",
                        "SUID", "setuid", "sudo su", "su root",
                        "kernel exploit", "dirty cow", "dirtycow"]),

    # Credential Access
    (6, "attack_type", ["credential", "password dump", "hash dump",
                        "credential harvest", "password spray",
                        "pass the hash"]),
    (6, "payload",     ["/etc/passwd", "/etc/shadow", "id_rsa",
                        "credentials", "passwords.txt", "hashdump",
                        "mimikatz", "procdump", "lsass", "secretsdump",
                        "ntds.dit", "sam database", "credential",
                        "password hash", "rainbow table"]),

    # Lateral Movement
    (7, "attack_type", ["lateral", "pivot", "spread", "move"]),
    (7, "payload",     ["ssh pivot", "port forward", "tunnel",
                        "proxychains", "socks5", "chisel", "ligolo",
                        "psexec", "wmiexec", "pass-the-hash",
                        "kerberoast", "golden ticket"]),

    # Exfiltration
    (8, "attack_type", ["exfil", "data theft", "upload", "transfer"]),
    (8, "payload",     ["wget http", "curl http", "curl -o", "wget -O",
                        "scp ", "rsync ", "ftp put", "nc -w",
                        "tar czf", "zip -r", "base64 -w",
                        "openssl enc", "python -m http"]),
]


def map_attack_to_phase(attack_record: dict) -> dict | None:
    """
    Maps an attack record to the highest matching Kill Chain phase.
    Returns phase info dict or None if no match.
    """
    attack_type = (attack_record.get("attack_type") or "").lower()
    payload     = (attack_record.get("payload")     or "").lower()
    url_path    = (attack_record.get("url_path")    or "").lower()
    service     = (attack_record.get("service")     or "").lower()

    best_phase = None

    # FTP/Telnet/SSH initial login = Initial Access minimum
    if service in ("ftp", "telnet") and not best_phase:
        best_phase = 2
    if service == "ssh" and "command" not in attack_type:
        if not best_phase:
            best_phase = 2

    for phase_num, field, keywords in PHASE_RULES:
        text = {"attack_type": attack_type, "payload": payload, "url_path": url_path}.get(field, "")
        for kw in keywords:
            if kw in text:
                if best_phase is None or phase_num > best_phase:
                    best_phase = phase_num
                break

    if best_phase is None:
        # Default: any web probe = Recon
        if service == "web":
            best_phase = 1
        else:
            best_phase = 2

    phase_info = PHASES[best_phase].copy()
    phase_info["phase_num"] = best_phase
    return phase_info


def get_ip_kill_chain_summary(phase_records: list) -> dict:
    """
    Given a list of (phase_num) values for an IP, produce a summary dict.
    Returns: {phases_reached: [1,2,3,...], max_phase: N, progression_pct: 0-100}
    """
    if not phase_records:
        return {"phases_reached": [], "max_phase": 0, "progression_pct": 0}

    phases_reached = sorted(set(phase_records))
    max_phase      = max(phases_reached)
    progression    = round((max_phase / 8) * 100)

    return {
        "phases_reached":  phases_reached,
        "max_phase":       max_phase,
        "max_phase_name":  PHASES[max_phase]["name"],
        "max_phase_icon":  PHASES[max_phase]["icon"],
        "max_phase_color": PHASES[max_phase]["color"],
        "progression_pct": progression,
        "phases_detail":   [PHASES[p] | {"phase_num": p} for p in phases_reached],
        "all_phases":      [{**PHASES[i], "phase_num": i, "reached": i in phases_reached}
                            for i in range(1, 9)],
    }
