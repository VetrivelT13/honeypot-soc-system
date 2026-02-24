# =============================================================================
# detection/threat_actor.py — Threat Actor Fingerprinting Engine
# Matches observed TTPs against known threat actor profiles.
# Based on MITRE ATT&CK threat actor intelligence.
# =============================================================================

# ── Known Threat Actor Profiles ───────────────────────────────────────────────
THREAT_ACTORS = {
    "Mirai Botnet": {
        "emoji":       "🤖",
        "type":        "Botnet",
        "origin":      "Unknown (Global)",
        "description": "IoT botnet responsible for record-breaking DDoS attacks. Scans for Telnet/SSH with default credentials.",
        "motivation":  "DDoS-for-hire, botnet recruitment",
        "ttps":        ["T1078.001", "T1498", "T1595"],
        "color":       "#64748b",
        "indicators": {
            "services":  ["telnet", "ssh"],
            "passwords": ["admin", "root", "xc3511", "vizxv", "888888", "default",
                          "1234", "12345", "123456", "password", "guest"],
            "payloads":  ["busybox", "mirai", "/bin/busybox", "wget http", "tftp -g",
                          "cd /tmp", "chmod 777", "./", "enable\nshell\n"],
            "attack_types": ["brute force", "telnet login", "ssh auth"],
        },
        "match_weights": {"service_telnet": 30, "default_creds": 25,
                          "busybox": 30, "high_volume": 15},
    },

    "APT28 (Fancy Bear)": {
        "emoji":       "🐻",
        "type":        "Nation-State APT",
        "origin":      "Russia (GRU)",
        "description": "Russian military intelligence (GRU) threat group. Known for phishing, credential theft, and long-term espionage campaigns.",
        "motivation":  "Espionage, political disruption",
        "ttps":        ["T1110", "T1003", "T1071", "T1059", "T1105"],
        "color":       "#dc2626",
        "indicators": {
            "services":  ["ssh", "web"],
            "payloads":  ["/etc/passwd", "/etc/shadow", "id_rsa", "mimikatz",
                          "secretsdump", "credential", "recon", "enumerat"],
            "attack_types": ["brute force", "credential access", "recon",
                             "command exec", "privilege escalation"],
            "multi_service": True,
        },
        "match_weights": {"credential_access": 35, "multi_service": 20,
                          "recon_commands": 25, "persistence": 20},
    },

    "Lazarus Group": {
        "emoji":       "☠",
        "type":        "Nation-State APT",
        "origin":      "North Korea (RGB)",
        "description": "North Korean state-sponsored group behind WannaCry ransomware and major financial heists including SWIFT banking attacks.",
        "motivation":  "Financial gain, espionage, sabotage",
        "ttps":        ["T1059", "T1486", "T1071", "T1027", "T1190"],
        "color":       "#7c3aed",
        "indicators": {
            "payloads":  ["ransomware", "encrypt", "bitcoin", "wallet",
                          "powershell", "wscript", "mshta", "regsvr32",
                          "base64", "obfuscat"],
            "attack_types": ["rce", "web shell", "command exec", "exploit"],
            "services":  ["web", "ssh"],
        },
        "match_weights": {"web_exploit": 30, "obfuscation": 25,
                          "encoded_payload": 25, "ransomware": 20},
    },

    "Anonymous / Hacktivist": {
        "emoji":       "🎭",
        "type":        "Hacktivist",
        "origin":      "Global (Decentralized)",
        "description": "Loosely organized hacktivist collective known for DDoS attacks, web defacement, and data leaks targeting governments and corporations.",
        "motivation":  "Political activism, ideological",
        "ttps":        ["T1498", "T1499", "T1190", "T1059"],
        "color":       "#16a34a",
        "indicators": {
            "payloads":  ["sql injection", "union select", "drop table",
                          "defac", "hacked by", "anonymous", "lulzsec",
                          "we are legion", "<script>", "xss"],
            "attack_types": ["sql injection", "xss", "web shell",
                             "directory traversal", "rce"],
            "services":  ["web"],
        },
        "match_weights": {"sql_injection": 30, "xss": 25,
                          "web_defacement": 30, "web_service": 15},
    },

    "Script Kiddie (Automated Scanner)": {
        "emoji":       "💀",
        "type":        "Script Kiddie",
        "origin":      "Unknown",
        "description": "Unskilled attacker using pre-built exploit kits and automated scanners (Metasploit, Nikto, SQLmap). No original capability.",
        "motivation":  "Curiosity, low-effort opportunism",
        "ttps":        ["T1595", "T1110", "T1059"],
        "color":       "#f59e0b",
        "indicators": {
            "payloads":  ["sqlmap", "nikto", "metasploit", "nmap",
                          "masscan", "hydra", "medusa", "wpscan",
                          "dirbuster", "gobuster", "burpsuite",
                          "wget http", "curl http", "/tmp/", "chmod +x"],
            "attack_types": ["brute force", "scan", "probe",
                             "sql injection", "directory traversal"],
        },
        "match_weights": {"tool_signatures": 40, "automated_pattern": 30,
                          "no_manual_commands": 30},
    },

    "Insider Threat": {
        "emoji":       "🕵",
        "type":        "Insider Threat",
        "origin":      "Internal Network",
        "description": "Attack originating from inside the network. Could be a malicious employee, compromised internal machine, or lateral movement from another host.",
        "motivation":  "Data theft, sabotage, financial gain",
        "ttps":        ["T1078", "T1003", "T1048", "T1005"],
        "color":       "#f97316",
        "indicators": {
            "ip_ranges": ["192.168.", "172.", "10.", "127."],
            "payloads":  ["/etc/shadow", "id_rsa", "backup", "credentials",
                          "export", "dump", "tar czf", "zip -r"],
            "attack_types": ["credential access", "data exfil",
                             "privilege escalation"],
        },
        "match_weights": {"internal_ip": 40, "credential_access": 30,
                          "exfiltration": 30},
    },
}


def fingerprint_threat_actor(ip: str, attacks: list) -> dict:
    """
    Analyse attack records for an IP and match against known threat actor profiles.
    Returns the best matching actor with confidence score and evidence.
    """
    if not attacks:
        return _unknown_actor()

    scores     = {name: 0 for name in THREAT_ACTORS}
    evidence   = {name: [] for name in THREAT_ACTORS}

    all_payloads     = " ".join((a.get("payload") or "").lower() for a in attacks)
    all_attack_types = " ".join((a.get("attack_type") or "").lower() for a in attacks)
    services_used    = set((a.get("service") or "").lower() for a in attacks)
    total_attacks    = len(attacks)
    usernames_used   = [(a.get("username") or "").lower() for a in attacks]

    for name, actor in THREAT_ACTORS.items():
        ind = actor["indicators"]
        w   = actor["match_weights"]

        # Check service match
        for svc in ind.get("services", []):
            if svc in services_used:
                scores[name] += 15
                evidence[name].append(f"Targeted {svc.upper()} service")

        # Check payload keywords
        matched_payloads = 0
        for kw in ind.get("payloads", []):
            if kw in all_payloads or kw in all_attack_types:
                matched_payloads += 1
                evidence[name].append(f"Payload matched: '{kw}'")
        if matched_payloads > 0:
            scores[name] += min(matched_payloads * 12, 40)

        # Check attack type keywords
        for kw in ind.get("attack_types", []):
            if kw in all_attack_types:
                scores[name] += 10
                evidence[name].append(f"Attack type: '{kw}'")

        # Check default/weak passwords (Mirai)
        for pw in ind.get("passwords", []):
            if pw in usernames_used or pw in all_payloads:
                scores[name] += 8
                evidence[name].append(f"Used default credential: '{pw}'")

        # Multi-service bonus
        if ind.get("multi_service") and len(services_used) >= 2:
            scores[name] += 20
            evidence[name].append(f"Multi-service attack ({', '.join(services_used).upper()})")

        # Internal IP match (Insider Threat)
        for prefix in ind.get("ip_ranges", []):
            if ip.startswith(prefix):
                scores[name] += 40
                evidence[name].append(f"Attack from internal IP range {prefix}*")

        # High volume bonus (Mirai)
        if total_attacks >= 20 and name == "Mirai Botnet":
            scores[name] += 15
            evidence[name].append(f"High volume: {total_attacks} attacks")

    # Find best match
    best_name  = max(scores, key=lambda n: scores[n])
    best_score = scores[best_name]

    if best_score < 15:
        return _unknown_actor()

    confidence = min(round((best_score / 80) * 100), 95)
    actor_info = THREAT_ACTORS[best_name].copy()

    return {
        "actor_name":   best_name,
        "emoji":        actor_info["emoji"],
        "type":         actor_info["type"],
        "origin":       actor_info["origin"],
        "description":  actor_info["description"],
        "motivation":   actor_info["motivation"],
        "ttps":         actor_info["ttps"],
        "color":        actor_info["color"],
        "confidence":   confidence,
        "score":        best_score,
        "evidence":     evidence[best_name][:5],  # top 5 evidence items
        "all_scores":   {n: scores[n] for n in THREAT_ACTORS if scores[n] > 0},
    }


def _unknown_actor() -> dict:
    return {
        "actor_name":  "Unknown Threat Actor",
        "emoji":       "❓",
        "type":        "Unknown",
        "origin":      "Unknown",
        "description": "Insufficient data to fingerprint this attacker.",
        "motivation":  "Unknown",
        "ttps":        [],
        "color":       "#475569",
        "confidence":  0,
        "score":       0,
        "evidence":    [],
        "all_scores":  {},
    }
