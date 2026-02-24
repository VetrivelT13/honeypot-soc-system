# =============================================================================
# detection/engine.py — Rule-Based Threat Detection Engine
# Analyses raw honeypot events and produces structured attack intelligence
# Now includes MITRE ATT&CK mapping and AbuseIPDB threat intel
# =============================================================================

import re
import time
import queue
import logging
import threading
from collections import defaultdict
from datetime import datetime

import sys
sys.path.insert(0, r"C:\Users\vetri\Desktop\FYProject")
import config
from geo import geo_lookup
from detection.mitre_mapping import get_technique_id, get_technique_label
from detection.attacker_profiler import classify_attacker, profile_label
from detection.killchain import map_attack_to_phase, get_ip_kill_chain_summary
from detection.canary import check_ssh_command, check_web_path, build_canary_attack
from detection.threat_actor import fingerprint_threat_actor

logger = logging.getLogger(__name__)

_SQL_RE = re.compile(
    r"(\bSELECT\b|\bUNION\b|\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b"
    r"|OR\s+1\s*=\s*1|'--|\bEXEC\b|\bSCRIPT\b|/\*.*\*/|SLEEP\s*\(|BENCHMARK\s*\()",
    re.IGNORECASE,
)
_XSS_RE = re.compile(
    r"(<\s*script|javascript\s*:|on\w+\s*=|<\s*iframe|<\s*img[^>]+onerror"
    r"|eval\s*\(|document\.cookie|window\.location)",
    re.IGNORECASE,
)
_CMDI_RE = re.compile(
    r"(&&|\|\||;|\$\(|` |/bin/|/etc/passwd|/etc/shadow|rm\s+-rf|wget\s+http"
    r"|curl\s+http|nc\s+-|python\s+-c|bash\s+-i)",
    re.IGNORECASE,
)
_PATH_TRAVERSAL_RE = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)",
    re.IGNORECASE,
)


class DetectionEngine:
    def __init__(self, event_queue, db_manager, socketio=None,
                 email_alert=None, telegram_alert=None):
        self.event_queue    = event_queue
        self.db             = db_manager
        self.socketio       = socketio
        self.email_alert    = email_alert
        self.telegram_alert = telegram_alert
        self._stop_event    = threading.Event()
        self._attempt_windows = defaultdict(list)
        self._window_lock   = threading.Lock()

    def start(self):
        logger.info("Detection engine started.")
        while not self._stop_event.is_set():
            try:
                event = self.event_queue.get(timeout=1.0)
                self._process(event)
                self.event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error("Detection engine error: %s", e, exc_info=True)

    def stop(self):
        self._stop_event.set()

    def _process(self, event: dict):
        ip         = event.get("ip", "0.0.0.0")
        service    = event.get("service", "unknown")
        event_type = event.get("event_type", "unknown")
        payload    = event.get("payload", "")
        username   = event.get("username", "")
        timestamp  = event.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        self._update_window(ip)

        attack_type, severity, risk_score, rule_triggered = self._run_rules(
            ip, service, event_type, payload
        )

        if attack_type is None:
            return

        # MITRE ATT&CK mapping
        mitre_technique = get_technique_label(attack_type)

        # Geo enrichment
        geo = geo_lookup.lookup(ip, db_manager=self.db)

        # Persist to database
        attack_id = self.db.insert_attack(
            ip_address=ip,
            country=geo["country"],
            city=geo["city"],
            latitude=geo["latitude"],
            longitude=geo["longitude"],
            service=service,
            attack_type=attack_type,
            payload=payload,
            severity=severity,
            risk_score=risk_score,
            username=username,
            mitre_technique=mitre_technique,
            abuse_score=0,
        )

        attack_record = {
            "id":             attack_id,
            "ip_address":     ip,
            "country":        geo["country"],
            "city":           geo["city"],
            "latitude":       geo["latitude"],
            "longitude":      geo["longitude"],
            "service":        service,
            "attack_type":    attack_type,
            "payload":        payload[:300],
            "severity":       severity,
            "risk_score":     risk_score,
            "username":       username,
            "timestamp":      timestamp,
            "rule":           rule_triggered,
            "mitre_technique": mitre_technique,
            "abuse_score":    0,
        }

        logger.info("[%s] %s ← %s | %s | score=%d | MITRE:%s",
                    severity, attack_type, ip, service, risk_score,
                    get_technique_id(attack_type))

        # ── Canary Token Check ─────────────────────────────────────────────
        canary_info = None
        if service == "ssh":
            canary_info = check_ssh_command(payload)
        elif service == "web":
            canary_info = check_web_path(event.get("url_path", "") or payload)
        if canary_info:
            canary_record = build_canary_attack(attack_record, canary_info)
            canary_id = self.db.insert_attack(
                ip_address=ip, country=geo["country"], city=geo["city"],
                latitude=geo["latitude"], longitude=geo["longitude"],
                service=service, attack_type=canary_record["attack_type"],
                payload=canary_record["payload"], severity="Critical",
                risk_score=10, username=username,
                mitre_technique="T1078 · Valid Accounts", abuse_score=0,
            )
            self.db.insert_canary_event(
                ip_address=ip,
                canary_type=canary_info.get("canary_type", "unknown"),
                canary_file=canary_info.get("canary_file", "unknown"),
                description=canary_info.get("description", ""),
                attack_id=canary_id,
            )
            canary_record["id"] = canary_id
            logger.warning("[🪤 CANARY] %s triggered trap: %s", ip, canary_info.get("canary_file"))
            self._emit_attack(canary_record)
            self._trigger_alerts(canary_record)
            if self.socketio:
                self.socketio.emit("canary_triggered", {
                    "ip_address":  ip,
                    "canary_file": canary_info.get("canary_file"),
                    "description": canary_info.get("description"),
                    "timestamp":   timestamp,
                }, namespace="/soc")

        self._emit_attack(attack_record)

        if severity in ("High", "Critical"):
            self._trigger_alerts(attack_record)

        if severity == "Critical":
            self._log_containment(ip, service, severity)

        # ── Kill Chain Tracking (background) ──────────────────────────────
        threading.Thread(
            target=self._run_killchain,
            args=(ip, attack_record, attack_id), daemon=True
        ).start()

        # ── AI Attacker Profiling (background) ────────────────────────────
        threading.Thread(
            target=self._run_profiler,
            args=(ip,), daemon=True
        ).start()

        # ── Threat Actor Fingerprinting (background) ───────────────────────
        threading.Thread(
            target=self._run_threat_actor,
            args=(ip,), daemon=True
        ).start()

        # AbuseIPDB check in background (non-blocking)
        if getattr(config, "ABUSEIPDB_ENABLED", False):
            try:
                from intel.abuseipdb import check_ip_async
                def _abuse_callback(checked_ip, result):
                    score = result.get("abuse_score", 0)
                    self.db.update_abuse_score(checked_ip, score)
                    if score > 0 and self.socketio:
                        self.socketio.emit("abuse_score_update", {
                            "ip_address":  checked_ip,
                            "abuse_score": score,
                            "threat_label": result.get("threat_label", "Unknown"),
                        }, namespace="/soc")
                check_ip_async(ip, callback=_abuse_callback)
            except Exception as e:
                logger.debug("AbuseIPDB check skipped: %s", e)

    def _run_rules(self, ip, service, event_type, payload):
        count = self._window_count(ip)

        if event_type in ("login_attempt", "auth") and count >= config.BRUTE_FORCE_THRESHOLD:
            return ("Brute Force", "High", 8, "R01: 5+ login attempts in 10s")

        if count >= config.DOS_THRESHOLD:
            return ("DoS Simulation", "Critical", 10, "R02: 20+ requests in 10s")

        if payload and _SQL_RE.search(payload):
            score = 9 if ("DROP" in payload.upper() or "UNION" in payload.upper()) else 7
            sev   = "Critical" if score >= 9 else "High"
            return ("SQL Injection", sev, score, "R03: SQL keyword in payload")

        if payload and _XSS_RE.search(payload):
            return ("XSS Attack", "Medium", 5, "R04: XSS pattern in payload")

        if payload and _CMDI_RE.search(payload):
            return ("Command Injection", "Critical", 9, "R05: Command injection pattern")

        if payload and _PATH_TRAVERSAL_RE.search(payload):
            return ("Path Traversal", "Medium", 5, "R06: Path traversal sequence")

        services_hit = self.db.get_distinct_services_for_ip(ip, seconds=60)
        if len(services_hit) >= config.MULTI_VECTOR_SERVICES:
            return ("Multi-Vector Attack", "Critical", 9,
                    f"R07: IP targeting {len(services_hit)} services simultaneously")

        if service == "web" and event_type == "login_attempt" and count >= 3:
            return ("Credential Stuffing", "High", 7, "R08: Rapid web login attempts")

        if event_type in ("login_attempt", "auth", "command", "web_request"):
            return ("Suspicious Activity", "Low", 2, "R09: Generic honeypot interaction")

        return (None, None, 0, None)

    def _update_window(self, ip):
        now = time.time()
        with self._window_lock:
            self._attempt_windows[ip].append(now)
            cutoff = now - config.BRUTE_FORCE_WINDOW_SECONDS
            self._attempt_windows[ip] = [t for t in self._attempt_windows[ip] if t >= cutoff]

    def _window_count(self, ip):
        with self._window_lock:
            return len(self._attempt_windows.get(ip, []))

    def _emit_attack(self, record):
        if self.socketio:
            try:
                self.socketio.emit("new_attack", record, namespace="/soc")
                if record["severity"] in ("High", "Critical"):
                    self.socketio.emit("system_alert", record, namespace="/soc")
            except Exception as e:
                logger.warning("SocketIO emit failed: %s", e)

    def _trigger_alerts(self, record):
        if self.email_alert:
            threading.Thread(target=self.email_alert.send, args=(record,), daemon=True).start()
        if self.telegram_alert:
            threading.Thread(target=self.telegram_alert.send, args=(record,), daemon=True).start()

    def _run_profiler(self, ip: str):
        """Classify attacker behaviour in background and store result."""
        try:
            attacks = self.db.get_attacks_by_ip(ip)
            result  = classify_attacker(ip, attacks)
            self.db.upsert_attacker_profile(
                ip_address   = ip,
                profile      = result["profile"],
                confidence   = result["confidence"],
                threat_score = result["threat_score"],
                reason       = result["reason"],
                indicators   = result["indicators"],
            )
            logger.info("[PROFILE] %s → %s (confidence %d%%, threat %d/100)",
                        ip, result["profile"], result["confidence"], result["threat_score"])
            if self.socketio:
                self.socketio.emit("profile_update", {
                    "ip_address":   ip,
                    "profile":      result["profile"],
                    "confidence":   result["confidence"],
                    "threat_score": result["threat_score"],
                    "label":        profile_label(result["profile"]),
                }, namespace="/soc")
        except Exception as e:
            logger.debug("Profiler error for %s: %s", ip, e)

    def _run_killchain(self, ip: str, attack_record: dict, attack_id: int):
        """Map attack to kill chain phase and update dashboard."""
        try:
            phase = map_attack_to_phase(attack_record)
            if not phase:
                return
            self.db.insert_killchain_event(
                ip_address=ip,
                phase_num=phase["phase_num"],
                phase_name=phase["name"],
                attack_id=attack_id,
            )
            # Build full summary for this IP
            kc_rows = self.db.get_killchain_for_ip(ip)
            phase_nums = [r["phase_num"] for r in kc_rows]
            summary = get_ip_kill_chain_summary(phase_nums)
            summary["ip_address"] = ip
            logger.info("[KILLCHAIN] %s reached phase %d: %s %s",
                        ip, phase["phase_num"], phase["icon"], phase["name"])
            if self.socketio:
                self.socketio.emit("killchain_update", summary, namespace="/soc")
        except Exception as e:
            logger.debug("Kill chain error for %s: %s", ip, e)

    def _run_threat_actor(self, ip: str):
        """Fingerprint threat actor based on all attacks from this IP."""
        try:
            attacks = self.db.get_attacks_by_ip(ip)
            if len(attacks) < 2:  # need at least 2 events to fingerprint
                return
            result = fingerprint_threat_actor(ip, attacks)
            if result["confidence"] > 0:
                self.db.upsert_threat_actor(
                    ip_address=ip,
                    actor_name=result["actor_name"],
                    actor_type=result["type"],
                    origin=result["origin"],
                    confidence=result["confidence"],
                    evidence=result["evidence"],
                    ttps=result["ttps"],
                    color=result["color"],
                )
                logger.info("[THREAT ACTOR] %s → %s %s (conf %d%%)",
                            ip, result["emoji"], result["actor_name"], result["confidence"])
                if self.socketio:
                    self.socketio.emit("threat_actor_update", {
                        "ip_address": ip,
                        "actor_name": result["actor_name"],
                        "emoji":      result["emoji"],
                        "type":       result["type"],
                        "confidence": result["confidence"],
                        "color":      result["color"],
                    }, namespace="/soc")
        except Exception as e:
            logger.debug("Threat actor error for %s: %s", ip, e)

    def _log_containment(self, ip, service, severity):
        action = (
            f"[SIMULATED] Blacklisted IP {ip} on {service.upper()} service. "
            f"Null-routed at perimeter firewall. Incident logged at "
            f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC."
        )
        try:
            self.db.insert_response_action(ip, service, action, severity)
            logger.warning("CONTAINMENT LOGGED for %s [%s]", ip, severity)
            if self.socketio:
                self.socketio.emit("containment_action", {
                    "ip_address":   ip,
                    "service":      service,
                    "action_taken": action,
                    "severity":     severity,
                    "timestamp":    datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                }, namespace="/soc")
        except Exception as e:
            logger.error("Failed to log containment: %s", e)
