# =============================================================================
# database/db_manager.py — SQLite Database Manager
# Handles all database operations for the Honeypot SOC System
# =============================================================================

import sqlite3
import logging
import os
from datetime import datetime
from contextlib import contextmanager

import sys
sys.path.insert(0, r"C:\Users\vetri\Desktop\FYProject")
import config

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Thread-safe SQLite database manager using connection-per-call pattern."""

    def __init__(self, db_path: str = config.DB_PATH):
        self.db_path = db_path
        self._ensure_dir()

    def _ensure_dir(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()

    def initialize(self):
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS attacks (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address      TEXT    NOT NULL,
                    country         TEXT    DEFAULT 'Unknown',
                    city            TEXT    DEFAULT 'Unknown',
                    latitude        REAL    DEFAULT 0.0,
                    longitude       REAL    DEFAULT 0.0,
                    service         TEXT    NOT NULL,
                    attack_type     TEXT    NOT NULL,
                    payload         TEXT    DEFAULT '',
                    severity        TEXT    NOT NULL,
                    risk_score      INTEGER NOT NULL DEFAULT 1,
                    username        TEXT    DEFAULT '',
                    timestamp       TEXT    NOT NULL,
                    mitre_technique TEXT    DEFAULT '',
                    abuse_score     INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS response_actions (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address  TEXT    NOT NULL,
                    service     TEXT    NOT NULL,
                    action_taken TEXT   NOT NULL,
                    severity    TEXT    NOT NULL,
                    timestamp   TEXT    NOT NULL
                );
                CREATE TABLE IF NOT EXISTS geo_cache (
                    ip_address  TEXT    PRIMARY KEY,
                    country     TEXT    DEFAULT 'Unknown',
                    city        TEXT    DEFAULT 'Unknown',
                    latitude    REAL    DEFAULT 0.0,
                    longitude   REAL    DEFAULT 0.0,
                    cached_at   TEXT    NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_attacks_ip        ON attacks(ip_address);
                CREATE INDEX IF NOT EXISTS idx_attacks_timestamp  ON attacks(timestamp);
                CREATE INDEX IF NOT EXISTS idx_attacks_severity   ON attacks(severity);
                CREATE INDEX IF NOT EXISTS idx_attacks_service    ON attacks(service);
            """)
            existing = [row[1] for row in conn.execute("PRAGMA table_info(attacks)").fetchall()]
            if "mitre_technique" not in existing:
                conn.execute("ALTER TABLE attacks ADD COLUMN mitre_technique TEXT DEFAULT ''")
            if "abuse_score" not in existing:
                conn.execute("ALTER TABLE attacks ADD COLUMN abuse_score INTEGER DEFAULT 0")
            # attacker profiles table (one row per IP)
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS attacker_profiles (
                    ip_address      TEXT PRIMARY KEY,
                    profile         TEXT DEFAULT 'BOT',
                    confidence      INTEGER DEFAULT 50,
                    threat_score    INTEGER DEFAULT 0,
                    reason          TEXT DEFAULT '',
                    indicators      TEXT DEFAULT '',
                    updated_at      TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS killchain_events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address      TEXT NOT NULL,
                    phase_num       INTEGER NOT NULL,
                    phase_name      TEXT NOT NULL,
                    attack_id       INTEGER NOT NULL,
                    timestamp       TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_kc_ip ON killchain_events(ip_address);
                CREATE TABLE IF NOT EXISTS threat_actor_profiles (
                    ip_address      TEXT PRIMARY KEY,
                    actor_name      TEXT NOT NULL,
                    actor_type      TEXT DEFAULT '',
                    origin          TEXT DEFAULT '',
                    confidence      INTEGER DEFAULT 0,
                    evidence        TEXT DEFAULT '[]',
                    ttps            TEXT DEFAULT '[]',
                    color           TEXT DEFAULT '#475569',
                    updated_at      TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS canary_events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address      TEXT NOT NULL,
                    canary_type     TEXT NOT NULL,
                    canary_file     TEXT NOT NULL,
                    description     TEXT DEFAULT '',
                    attack_id       INTEGER DEFAULT 0,
                    timestamp       TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_canary_ip ON canary_events(ip_address);
            """)
        logger.info("Database initialised at: %s", self.db_path)

    def insert_attack(self, ip_address, country, city, latitude, longitude,
                      service, attack_type, payload, severity, risk_score,
                      username="", mitre_technique="", abuse_score=0):
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            cursor = conn.execute("""
                INSERT INTO attacks
                    (ip_address, country, city, latitude, longitude,
                     service, attack_type, payload, severity, risk_score,
                     username, timestamp, mitre_technique, abuse_score)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (ip_address, country, city, latitude, longitude,
                  service, attack_type, payload[:2000], severity,
                  risk_score, username, timestamp, mitre_technique, abuse_score))
            return cursor.lastrowid

    def update_abuse_score(self, ip_address, abuse_score):
        with self._get_conn() as conn:
            conn.execute("UPDATE attacks SET abuse_score=? WHERE ip_address=?",
                         (abuse_score, ip_address))

    def get_recent_attacks(self, limit=200):
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM attacks ORDER BY id DESC LIMIT ?",
                                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_attack_by_id(self, attack_id):
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM attacks WHERE id=?", (attack_id,)).fetchone()
        return dict(row) if row else {}

    def get_attacks_by_ip(self, ip_address):
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM attacks WHERE ip_address=? ORDER BY id DESC",
                                (ip_address,)).fetchall()
        return [dict(r) for r in rows]

    def get_map_data(self):
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT ip_address, country, city, latitude, longitude,
                       MAX(severity) AS max_severity, MAX(risk_score) AS max_risk,
                       MAX(abuse_score) AS max_abuse, COUNT(*) AS attack_count
                FROM attacks WHERE latitude!=0.0 AND longitude!=0.0
                GROUP BY ip_address
            """).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self):
        with self._get_conn() as conn:
            total    = conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
            critical = conn.execute("SELECT COUNT(*) FROM attacks WHERE severity='Critical'").fetchone()[0]
            high     = conn.execute("SELECT COUNT(*) FROM attacks WHERE severity='High'").fetchone()[0]
            by_type  = conn.execute("SELECT attack_type, COUNT(*) AS cnt FROM attacks GROUP BY attack_type ORDER BY cnt DESC").fetchall()
            by_sev   = conn.execute("SELECT severity, COUNT(*) AS cnt FROM attacks GROUP BY severity").fetchall()
            by_svc   = conn.execute("SELECT service, COUNT(*) AS cnt FROM attacks GROUP BY service").fetchall()
            timeline = conn.execute("""
                SELECT strftime('%Y-%m-%d %H:%M', timestamp) AS minute, COUNT(*) AS cnt
                FROM attacks WHERE timestamp >= datetime('now', '-1 hour')
                GROUP BY minute ORDER BY minute
            """).fetchall()
            top_ips  = conn.execute("""
                SELECT ip_address, country, MAX(severity) AS max_severity,
                       MAX(risk_score) AS max_risk, MAX(abuse_score) AS max_abuse,
                       COUNT(*) AS cnt
                FROM attacks GROUP BY ip_address ORDER BY cnt DESC LIMIT 20
            """).fetchall()
            mitre_stats = conn.execute("""
                SELECT mitre_technique, COUNT(*) AS cnt FROM attacks
                WHERE mitre_technique != ''
                GROUP BY mitre_technique ORDER BY cnt DESC LIMIT 10
            """).fetchall()
        return {
            "total": total, "critical": critical, "high": high,
            "by_type": [dict(r) for r in by_type],
            "by_severity": [dict(r) for r in by_sev],
            "by_service": [dict(r) for r in by_svc],
            "timeline": [dict(r) for r in timeline],
            "top_ips": [dict(r) for r in top_ips],
            "mitre_stats": [dict(r) for r in mitre_stats],
        }

    def insert_response_action(self, ip_address, service, action_taken, severity):
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            cursor = conn.execute("""
                INSERT INTO response_actions (ip_address, service, action_taken, severity, timestamp)
                VALUES (?,?,?,?,?)
            """, (ip_address, service, action_taken, severity, timestamp))
            return cursor.lastrowid

    def get_response_actions(self, limit=100):
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM response_actions ORDER BY id DESC LIMIT ?",
                                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_cached_geo(self, ip_address):
        with self._get_conn() as conn:
            row = conn.execute("""
                SELECT * FROM geo_cache WHERE ip_address=?
                  AND datetime(cached_at, '+1 hour') > datetime('now')
            """, (ip_address,)).fetchone()
        return dict(row) if row else None

    def set_cached_geo(self, ip_address, country, city, latitude, longitude):
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO geo_cache (ip_address, country, city, latitude, longitude, cached_at)
                VALUES (?,?,?,?,?,?)
            """, (ip_address, country, city, latitude, longitude, timestamp))

    def upsert_attacker_profile(self, ip_address, profile, confidence,
                                threat_score, reason, indicators):
        import json
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO attacker_profiles
                    (ip_address, profile, confidence, threat_score, reason, indicators, updated_at)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    profile=excluded.profile, confidence=excluded.confidence,
                    threat_score=excluded.threat_score, reason=excluded.reason,
                    indicators=excluded.indicators, updated_at=excluded.updated_at
            """, (ip_address, profile, confidence, threat_score, reason,
                  json.dumps(indicators), timestamp))

    def get_attacker_profile(self, ip_address):
        import json
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM attacker_profiles WHERE ip_address=?",
                (ip_address,)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["indicators"] = json.loads(d.get("indicators", "[]"))
        except Exception:
            d["indicators"] = []
        return d

    def get_all_profiles(self):
        import json
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT p.*, COUNT(a.id) AS total_attacks
                FROM attacker_profiles p
                LEFT JOIN attacks a ON a.ip_address = p.ip_address
                GROUP BY p.ip_address
                ORDER BY p.threat_score DESC
            """).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["indicators"] = json.loads(d.get("indicators", "[]"))
            except Exception:
                d["indicators"] = []
            result.append(d)
        return result

    def get_profile_stats(self):
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT profile, COUNT(*) AS cnt FROM attacker_profiles
                GROUP BY profile
            """).fetchall()
        return {r["profile"]: r["cnt"] for r in rows}

    def count_recent_events(self, ip_address, service, seconds=10):
        with self._get_conn() as conn:
            row = conn.execute("""
                SELECT COUNT(*) FROM attacks WHERE ip_address=? AND service=?
                  AND timestamp >= datetime('now', ? || ' seconds')
            """, (ip_address, service, f"-{seconds}")).fetchone()
        return row[0] if row else 0

    def get_distinct_services_for_ip(self, ip_address, seconds=60):
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT DISTINCT service FROM attacks WHERE ip_address=?
                  AND timestamp >= datetime('now', ? || ' seconds')
            """, (ip_address, f"-{seconds}")).fetchall()
        return [r[0] for r in rows]

    # ── Kill Chain methods ────────────────────────────────────────────────────

    def insert_killchain_event(self, ip_address, phase_num, phase_name, attack_id):
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO killchain_events (ip_address, phase_num, phase_name, attack_id, timestamp)
                VALUES (?,?,?,?,?)
            """, (ip_address, phase_num, phase_name, attack_id, timestamp))

    def get_killchain_for_ip(self, ip_address):
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT DISTINCT phase_num, phase_name
                FROM killchain_events WHERE ip_address=?
                ORDER BY phase_num
            """, (ip_address,)).fetchall()
        return [dict(r) for r in rows]

    def get_killchain_summary(self):
        """Returns per-IP max kill chain phase for dashboard overview."""
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT ip_address, MAX(phase_num) AS max_phase, COUNT(*) AS event_count
                FROM killchain_events GROUP BY ip_address
                ORDER BY max_phase DESC LIMIT 20
            """).fetchall()
        return [dict(r) for r in rows]

    # ── Canary methods ────────────────────────────────────────────────────────

    def insert_canary_event(self, ip_address, canary_type, canary_file, description, attack_id=0):
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO canary_events (ip_address, canary_type, canary_file, description, attack_id, timestamp)
                VALUES (?,?,?,?,?,?)
            """, (ip_address, canary_type, canary_file, description, attack_id, timestamp))

    def get_canary_events(self, limit=50):
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT * FROM canary_events ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_canary_count(self):
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM canary_events").fetchone()
        return row[0] if row else 0

    # ── Threat Actor methods ──────────────────────────────────────────────────

    def upsert_threat_actor(self, ip_address, actor_name, actor_type, origin,
                            confidence, evidence, ttps, color):
        import json
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO threat_actor_profiles
                    (ip_address, actor_name, actor_type, origin, confidence,
                     evidence, ttps, color, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    actor_name=excluded.actor_name, actor_type=excluded.actor_type,
                    origin=excluded.origin, confidence=excluded.confidence,
                    evidence=excluded.evidence, ttps=excluded.ttps,
                    color=excluded.color, updated_at=excluded.updated_at
            """, (ip_address, actor_name, actor_type, origin, confidence,
                  json.dumps(evidence), json.dumps(ttps), color, timestamp))

    def get_threat_actor(self, ip_address):
        import json
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM threat_actor_profiles WHERE ip_address=?",
                (ip_address,)).fetchone()
        if not row:
            return None
        d = dict(row)
        for key in ("evidence", "ttps"):
            try:
                d[key] = json.loads(d.get(key, "[]"))
            except Exception:
                d[key] = []
        return d

    def get_all_threat_actors(self):
        import json
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT t.*, COUNT(a.id) AS total_attacks
                FROM threat_actor_profiles t
                LEFT JOIN attacks a ON a.ip_address = t.ip_address
                GROUP BY t.ip_address ORDER BY t.confidence DESC
            """).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            for key in ("evidence", "ttps"):
                try:
                    d[key] = json.loads(d.get(key, "[]"))
                except Exception:
                    d[key] = []
            result.append(d)
        return result
