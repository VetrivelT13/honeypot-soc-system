# =============================================================================
# detection/attacker_profiler.py  --  AI Attacker Behaviour Profiler
# Analyses attack records per IP and classifies the attacker as:
#   BOT           - Automated scanner / worm
#   SCRIPT KIDDIE - Uses downloaded exploit tools, no real skill
#   SKILLED       - Manual, targeted, methodical attacker
# No external ML library required -- pure rule-based scoring system
# =============================================================================

import re
import logging
from collections import Counter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signature dictionaries
# ---------------------------------------------------------------------------

# Commands that automated bots/worms typically run (or none at all)
BOT_SIGNATURES = [
    "masscan", "nmap", "zmap", "zgrab",
    "bot", "crawler", "scanner", "probe",
    "echo Y", "busybox", "uname -a && cat /proc/cpuinfo",   # Mirai
    "/bin/busybox", "ECCHI", "tftp",                          # Mirai variants
    "rm -rf /tmp/*; wget",                                    # cryptominer dropper
]

# Commands script kiddies run (copy-paste from tutorials / Metasploit)
SKID_SIGNATURES = [
    "wget http", "curl http", "curl -O", "chmod +x",
    "/tmp/", "python -c 'import", "perl -e",
    "nc -e /bin/sh", "nc -e /bin/bash",
    "bash -i >& /dev/tcp",                                   # reverse shell
    "exec 5<>/dev/tcp",
    "/dev/shm/", "python3 -c",
    "msfvenom", "meterpreter",
    "php -r", "php -l",
    "tar xf", "tar xvf",
]

# Commands a skilled / targeted attacker runs during reconnaissance
RECON_COMMANDS = [
    "whoami", "id", "uname -a", "uname -r",
    "cat /etc/passwd", "cat /etc/shadow", "cat /etc/os-release",
    "ps aux", "ps -ef", "netstat", "ss -tlnp",
    "ifconfig", "ip addr", "ip route",
    "ls -la", "ls -lah", "find /",
    "cat /proc/version", "cat /proc/cpuinfo",
    "env", "printenv", "history",
    "crontab -l", "cat /etc/crontab",
    "last", "who", "w",
    "sudo -l", "sudo -ll",
    "awk", "sed", "cut",
    "ssh-keygen", "cat ~/.ssh",
]

LATERAL_COMMANDS = [
    "ssh ", "scp ", "rsync",
    "mount", "df -h",
    "iptables", "ufw",
    "useradd", "adduser", "passwd",
    "visudo", "/etc/sudoers",
]

PERSISTENCE_COMMANDS = [
    "crontab -e", "cron", "systemctl",
    ".bashrc", ".profile", ".bash_profile",
    "authorized_keys", "known_hosts",
    "/etc/init.d", "/etc/rc.local",
]


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def classify_attacker(ip_address: str, attacks: list) -> dict:
    """
    Analyse all attack records for a given IP and return a profile dict:
      {
        "profile":     "BOT" | "SCRIPT KIDDIE" | "SKILLED",
        "confidence":  0-100,
        "reason":      "human-readable explanation",
        "indicators":  ["list", "of", "matched", "indicators"],
        "threat_score": 0-100   # how dangerous this attacker is
      }
    """
    if not attacks:
        return _default_profile()

    # ---- gather raw data -----------------------------------------------
    all_commands   = []
    attack_types   = [a.get("attack_type", "") for a in attacks]
    services       = [a.get("service", "") for a in attacks]
    payloads       = [str(a.get("payload", "")).lower() for a in attacks]
    event_count    = len(attacks)
    unique_types   = len(set(attack_types))
    unique_svcs    = len(set(services))

    # extract actual shell commands from payloads
    for p in payloads:
        if p and p not in ("", "none", "null"):
            all_commands.append(p)

    combined = " ".join(all_commands)

    # ---- scoring buckets ------------------------------------------------
    bot_score   = 0
    skid_score  = 0
    skill_score = 0
    indicators  = []

    # -- BOT signals --
    if event_count > 30:
        bot_score += 4
        indicators.append(f"High volume: {event_count} events")

    if event_count > 100:
        bot_score += 4
        indicators.append("Extremely high event volume (worm-like)")

    if unique_types == 1 and event_count > 5:
        bot_score += 3
        indicators.append("Single attack type repeated (automated)")

    for sig in BOT_SIGNATURES:
        if sig.lower() in combined:
            bot_score += 5
            indicators.append(f"Bot signature: '{sig}'")
            break

    # password stuffing (same service, many attempts)
    if attack_types.count("Brute Force") > 10:
        bot_score += 3
        indicators.append("Credential stuffing pattern detected")

    # all attacks on same service = scanner
    if unique_svcs == 1 and event_count > 10:
        bot_score += 2
        indicators.append("Single service targeted (port scanner)")

    if len(all_commands) == 0 and event_count > 3:
        bot_score += 4
        indicators.append("No commands executed (pure scanner / auth probe)")

    # -- SCRIPT KIDDIE signals --
    for sig in SKID_SIGNATURES:
        if sig.lower() in combined:
            skid_score += 4
            indicators.append(f"Script kiddie tool: '{sig}'")

    if "wget" in combined or "curl" in combined:
        skid_score += 3
        indicators.append("Attempted file download (dropper pattern)")

    if "/tmp/" in combined:
        skid_score += 2
        indicators.append("Writing to /tmp (common malware staging)")

    if "chmod +x" in combined:
        skid_score += 3
        indicators.append("chmod +x detected (running downloaded binary)")

    if unique_types >= 3 and skill_score < 5:
        skid_score += 2
        indicators.append("Multiple attack types (spray-and-pray pattern)")

    # -- SKILLED HACKER signals --
    recon_hits = sum(1 for cmd in RECON_COMMANDS if cmd in combined)
    if recon_hits >= 3:
        skill_score += recon_hits * 2
        indicators.append(f"Deep reconnaissance: {recon_hits} recon commands")

    lateral_hits = sum(1 for cmd in LATERAL_COMMANDS if cmd in combined)
    if lateral_hits >= 1:
        skill_score += lateral_hits * 3
        indicators.append(f"Lateral movement attempt: {lateral_hits} indicators")

    persist_hits = sum(1 for cmd in PERSISTENCE_COMMANDS if cmd in combined)
    if persist_hits >= 1:
        skill_score += persist_hits * 4
        indicators.append(f"Persistence mechanism: {persist_hits} indicators")

    if "cat /etc/shadow" in combined:
        skill_score += 5
        indicators.append("Attempted to read /etc/shadow (privilege escalation)")

    if "sudo" in combined:
        skill_score += 3
        indicators.append("Privilege escalation attempt via sudo")

    if unique_svcs > 2:
        skill_score += 4
        indicators.append(f"Multi-service attack across {unique_svcs} services")

    if unique_types >= 4:
        skill_score += 3
        indicators.append("Diverse attack types (adaptive attacker)")

    # command injection AND sql injection together = sophisticated
    if "Command Injection" in attack_types and "SQL Injection" in attack_types:
        skill_score += 4
        indicators.append("Combined SQLi + CMDi (chained attack technique)")

    # ---- classify -------------------------------------------------------
    total = bot_score + skid_score + skill_score or 1
    bot_pct   = (bot_score   / total) * 100
    skid_pct  = (skid_score  / total) * 100
    skill_pct = (skill_score / total) * 100

    if bot_score >= skid_score and bot_score >= skill_score:
        profile    = "BOT"
        confidence = min(int(bot_pct * 1.2), 98)
        reason     = _bot_reason(event_count, indicators)
    elif skid_score >= skill_score:
        profile    = "SCRIPT KIDDIE"
        confidence = min(int(skid_pct * 1.2), 95)
        reason     = _skid_reason(indicators)
    else:
        profile    = "SKILLED"
        confidence = min(int(skill_pct * 1.3), 99)
        reason     = _skill_reason(indicators)

    # fall back: if no signals at all, call it a BOT
    if bot_score == 0 and skid_score == 0 and skill_score == 0:
        profile    = "BOT"
        confidence = 50
        reason     = "No distinguishing signals; defaulting to automated probe"
        indicators = ["No shell commands executed"]

    # ---- threat score (independent of profile) -------------------------
    threat_score = _threat_score(profile, event_count, skill_score,
                                 skid_score, unique_svcs, attacks)

    return {
        "profile":      profile,
        "confidence":   confidence,
        "reason":       reason,
        "indicators":   indicators[:6],   # top 6 only
        "threat_score": threat_score,
    }


# ---------------------------------------------------------------------------
# Threat score (0-100, how dangerous regardless of profile type)
# ---------------------------------------------------------------------------

def _threat_score(profile, event_count, skill_score, skid_score,
                  unique_svcs, attacks) -> int:
    score = 0
    severities = [a.get("severity", "Low") for a in attacks]
    sev_map    = {"Low": 1, "Medium": 2, "High": 4, "Critical": 8}

    score += min(sum(sev_map.get(s, 1) for s in severities), 40)
    score += min(event_count // 5, 20)
    score += skill_score * 2
    score += skid_score
    score += unique_svcs * 3

    if profile == "SKILLED":
        score += 20
    elif profile == "SCRIPT KIDDIE":
        score += 10

    return min(score, 100)


# ---------------------------------------------------------------------------
# Human-readable reason builders
# ---------------------------------------------------------------------------

def _bot_reason(event_count, indicators) -> str:
    if event_count > 100:
        return "Worm-like mass-scanning behaviour with no human interaction."
    if "No commands executed" in str(indicators):
        return "Pure port/auth scanner — connected and probed without executing any shell commands."
    return "Automated tool detected based on attack frequency and signature patterns."


def _skid_reason(indicators) -> str:
    ind_str = ", ".join(indicators[:3]) if indicators else "tool signatures"
    return f"Downloaded and executed common exploit tools without custom techniques. Indicators: {ind_str}."


def _skill_reason(indicators) -> str:
    ind_str = ", ".join(indicators[:3]) if indicators else "advanced recon"
    return f"Manual, methodical attacker performing structured reconnaissance and targeted exploitation. Evidence: {ind_str}."


def _default_profile() -> dict:
    return {
        "profile":      "BOT",
        "confidence":   50,
        "reason":       "Insufficient data to classify.",
        "indicators":   [],
        "threat_score": 5,
    }


# ---------------------------------------------------------------------------
# Quick label helper (used by dashboard)
# ---------------------------------------------------------------------------

PROFILE_EMOJI = {
    "BOT":           "🤖",
    "SCRIPT KIDDIE": "💀",
    "SKILLED":       "🎯",
}

PROFILE_COLOR = {
    "BOT":           "#64748b",   # grey
    "SCRIPT KIDDIE": "#f59e0b",   # amber
    "SKILLED":       "#ef4444",   # red
}


def profile_label(profile: str) -> str:
    emoji = PROFILE_EMOJI.get(profile, "❓")
    return f"{emoji} {profile}"
