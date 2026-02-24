# =============================================================================
# geo/geo_lookup.py — IP Geo-location Lookup with DB-backed Caching
# Uses ip-api.com (free, no key required, 45 req/min limit)
# =============================================================================

import requests
import logging
import socket
from typing import Optional

import sys
sys.path.insert(0, r"C:\Users\vetri\Desktop\FYProject")
import config

logger = logging.getLogger(__name__)

# Private / reserved IP ranges (no geo lookup needed)
_PRIVATE_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.", "169.254.", "::1", "fc", "fd",
)

_DEFAULT_GEO = {
    "country":   "Private Network",
    "city":      "Local",
    "latitude":  0.0,
    "longitude": 0.0,
}


def _is_private(ip: str) -> bool:
    """Return True if the IP is a private/reserved address."""
    return any(ip.startswith(prefix) for prefix in _PRIVATE_PREFIXES)


def lookup(ip_address: str, db_manager=None) -> dict:
    """
    Return geo data for an IP address.
    1. Return default for private IPs.
    2. Check DB cache (TTL = 1 hour).
    3. Query ip-api.com.
    4. Cache the result in the DB.

    Returns:
        {"country": str, "city": str, "latitude": float, "longitude": float}
    """
    if _is_private(ip_address):
        logger.debug("Private IP %s — skipping geo lookup", ip_address)
        return _DEFAULT_GEO.copy()

    # ── DB Cache ───────────────────────────────────────────────────────────────
    if db_manager:
        cached = db_manager.get_cached_geo(ip_address)
        if cached:
            logger.debug("Geo cache HIT for %s", ip_address)
            return {
                "country":   cached["country"],
                "city":      cached["city"],
                "latitude":  cached["latitude"],
                "longitude": cached["longitude"],
            }

    # ── Live Lookup ────────────────────────────────────────────────────────────
    url = config.GEO_API_URL.format(ip=ip_address)
    try:
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") == "success":
            result = {
                "country":   data.get("country", "Unknown"),
                "city":      data.get("city", "Unknown"),
                "latitude":  float(data.get("lat", 0.0)),
                "longitude": float(data.get("lon", 0.0)),
            }
            # Store in DB cache
            if db_manager:
                try:
                    db_manager.set_cached_geo(
                        ip_address,
                        result["country"],
                        result["city"],
                        result["latitude"],
                        result["longitude"],
                    )
                except Exception as e:
                    logger.warning("Failed to cache geo for %s: %s", ip_address, e)

            logger.info("Geo lookup SUCCESS: %s → %s, %s",
                        ip_address, result["city"], result["country"])
            return result

        else:
            logger.warning("Geo lookup FAILED for %s: %s",
                           ip_address, data.get("message", "unknown"))
            return _DEFAULT_GEO.copy()

    except requests.exceptions.Timeout:
        logger.warning("Geo lookup TIMEOUT for %s", ip_address)
        return _DEFAULT_GEO.copy()
    except requests.exceptions.ConnectionError:
        logger.warning("Geo lookup CONNECTION ERROR for %s", ip_address)
        return _DEFAULT_GEO.copy()
    except Exception as e:
        logger.error("Geo lookup unexpected error for %s: %s", ip_address, e)
        return _DEFAULT_GEO.copy()


def resolve_hostname(ip_address: str) -> Optional[str]:
    """Attempt reverse DNS lookup. Returns hostname or None."""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except Exception:
        return None
