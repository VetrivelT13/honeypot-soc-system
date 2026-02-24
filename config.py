# =============================================================================
# config.py — Central Configuration for FYProject Honeypot SOC System
# Secrets are loaded from .env — never hardcode credentials here!
# =============================================================================

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file if present (local development)
load_dotenv()

# ── Base Paths ────────────────────────────────────────────────────────────────
BASE_DIR = os.getenv("BASE_DIR", str(Path(__file__).parent.resolve()))
DB_PATH = os.path.join(BASE_DIR, "database", "honeypot.db")
COWRIE_LOG_PATH = os.path.join(BASE_DIR, "logs", "cowrie", "cowrie.json")

# ── Network Ports ─────────────────────────────────────────────────────────────
SOC_DASHBOARD_PORT   = int(os.getenv("PORT", 5000))
WEB_HONEYPOT_PORT    = 8080
TELNET_HONEYPOT_PORT = 2323
SSH_HONEYPOT_PORT    = 2222
FTP_HONEYPOT_PORT    = 2121

# ── Email Alert Configuration ─────────────────────────────────────────────────
EMAIL_ENABLED    = True
EMAIL_SENDER     = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD   = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECIPIENT  = os.getenv("EMAIL_RECIPIENT", "")
EMAIL_SMTP_HOST  = "smtp.gmail.com"
EMAIL_SMTP_PORT  = 587

# ── Telegram Alert Configuration ──────────────────────────────────────────────
TELEGRAM_ENABLED   = True
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")

# ── AbuseIPDB Threat Intelligence ─────────────────────────────────────────────
ABUSEIPDB_ENABLED = True
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# ── Geo-location Settings ─────────────────────────────────────────────────────
GEO_API_URL = "http://ip-api.com/json/{ip}"
GEO_CACHE_TTL_SECONDS = 3600

# ── Detection Engine Thresholds ───────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD     = 5
BRUTE_FORCE_WINDOW_SECONDS = 10
DOS_THRESHOLD             = 20
MULTI_VECTOR_SERVICES     = 2

# ── Severity / Risk Scoring ───────────────────────────────────────────────────
SEVERITY_THRESHOLDS = {
    "Low":      (1, 3),
    "Medium":   (4, 6),
    "High":     (7, 8),
    "Critical": (9, 10),
}

# ── Alert Severity Triggers ───────────────────────────────────────────────────
ALERT_MIN_SEVERITY       = "High"
CONTAINMENT_MIN_SEVERITY = "Critical"

# ── Dashboard Settings ────────────────────────────────────────────────────────
DASHBOARD_SECRET_KEY = os.getenv("DASHBOARD_SECRET_KEY", "change-me-in-production")
MAX_LIVE_FEED_EVENTS = 200
ATTACK_HISTORY_LIMIT = 500

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL = "INFO"
