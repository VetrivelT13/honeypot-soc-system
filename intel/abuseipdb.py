# =============================================================================
# intel/abuseipdb.py — AbuseIPDB Threat Intelligence Integration
# Checks attacker IPs against AbuseIPDB to get abuse confidence scores
# Free API: https://www.abuseipdb.com/register (1000 queries/day)
# =============================================================================

import requests
import logging
import threading

import sys
sys.path.insert(0, r"C:\Users\vetri\Desktop\FYProject")
import config

logger = logging.getLogger(__name__)

# In-memory cache to avoid repeated API calls for the same IP
_cache: dict = {}
_cache_lock = threading.Lock()


def _is_private_ip(ip: str) -> bool:
    """Return True for loopback, private, and link-local IPs."""
    private_prefixes = (
        "127.", "10.", "192.168.", "::1", "0.0.0.0",
        "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
        "172.31.", "169.254.",
    )
    return any(ip.startswith(p) for p in private_prefixes)


def check_ip(ip: str) -> dict:
    """
    Query AbuseIPDB for the given IP address.

    Returns dict with keys:
        abuse_score     : int  (0-100, confidence of abuse)
        total_reports   : int
        country_code    : str
        isp             : str
        domain          : str
        is_tor          : bool
        last_reported   : str
        threat_label    : str  ("Clean" / "Suspicious" / "Malicious")
    """
    # Default/fallback result
    default = {
        "abuse_score":   0,
        "total_reports": 0,
        "country_code":  "??",
        "isp":           "Unknown",
        "domain":        "Unknown",
        "is_tor":        False,
        "last_reported": "Never",
        "threat_label":  "Unknown",
    }

    if not getattr(config, "ABUSEIPDB_ENABLED", False):
        default["threat_label"] = "Not Checked"
        return default

    if _is_private_ip(ip):
        default["threat_label"] = "Private IP"
        return default

    # Check in-memory cache first
    with _cache_lock:
        if ip in _cache:
            return _cache[ip]

    api_key = getattr(config, "ABUSEIPDB_API_KEY", "")
    if not api_key:
        logger.warning("AbuseIPDB API key not set. Set ABUSEIPDB_API_KEY in config.py")
        default["threat_label"] = "No API Key"
        return default

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            if score >= 75:
                label = "Malicious"
            elif score >= 25:
                label = "Suspicious"
            elif score > 0:
                label = "Low Risk"
            else:
                label = "Clean"

            result = {
                "abuse_score":   score,
                "total_reports": data.get("totalReports", 0),
                "country_code":  data.get("countryCode", "??"),
                "isp":           data.get("isp", "Unknown"),
                "domain":        data.get("domain", "Unknown"),
                "is_tor":        data.get("isTor", False),
                "last_reported": data.get("lastReportedAt", "Never") or "Never",
                "threat_label":  label,
            }
            with _cache_lock:
                _cache[ip] = result
            logger.info("AbuseIPDB [%s] score=%d label=%s", ip, score, label)
            return result
        else:
            logger.warning("AbuseIPDB API error %d for IP %s", resp.status_code, ip)
    except requests.exceptions.Timeout:
        logger.warning("AbuseIPDB timeout for IP %s", ip)
    except Exception as e:
        logger.error("AbuseIPDB error for %s: %s", ip, e)

    return default


def check_ip_async(ip: str, callback=None):
    """
    Run check_ip in a background thread.
    Calls callback(ip, result) when done.
    """
    def _run():
        result = check_ip(ip)
        if callback:
            try:
                callback(ip, result)
            except Exception as e:
                logger.error("AbuseIPDB callback error: %s", e)

    t = threading.Thread(target=_run, daemon=True, name=f"AbuseIPDB-{ip}")
    t.start()
