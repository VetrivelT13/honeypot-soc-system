# =============================================================================
# alerts/telegram_alert.py — Telegram Bot Alert Module
# Sends formatted SOC alert messages via Telegram Bot API.
# Runs in background threads. Failure never crashes the main system.
# =============================================================================

import logging
import requests
from datetime import datetime

import sys
sys.path.insert(0, r"C:\Users\vetri\Desktop\FYProject")
import config

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
}

_MESSAGE_TEMPLATE = """\
{emoji} *SOC ALERT — {severity} THREAT*
━━━━━━━━━━━━━━━━━━━━━━━━
🆔 *Attack ID:*    `ATK-{attack_id}`
🕐 *Time (UTC):*   `{timestamp}`
🌐 *Attacker IP:*  `{ip_address}`
🗺 *Location:*     {city}, {country}
🔧 *Service:*      `{service}`
⚔️ *Attack Type:* `{attack_type}`
📋 *Rule:*         `{rule}`
🎯 *Risk Score:*   `{risk_score}/10`
📊 *Severity:*     `{severity}`

📦 *Payload (preview):*
```
{payload_preview}
```
━━━━━━━━━━━━━━━━━━━━━━━━
🤖 _Honeypot SOC System — Automated Alert_
"""

_CONTAINMENT_TEMPLATE = """\
🚨 *CRITICAL CONTAINMENT ACTION LOGGED*
━━━━━━━━━━━━━━━━━━━━━━━━
🌐 *IP Address:* `{ip_address}`
🔧 *Service:*    `{service}`
📊 *Severity:*   `{severity}`
🕐 *Time (UTC):* `{timestamp}`

🛡 *Action Taken:*
_{action_taken}_
━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ _Simulated containment — no real firewall change_
"""


class TelegramAlert:
    """
    Sends Telegram messages using the Bot API sendMessage endpoint.
    Each send() call is designed to run in a background daemon thread.
    """

    def __init__(self):
        self.enabled   = config.TELEGRAM_ENABLED
        self.bot_token = config.TELEGRAM_BOT_TOKEN
        self.chat_id   = config.TELEGRAM_CHAT_ID
        self._api_url  = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

    def send(self, attack_record: dict):
        """
        Send a formatted alert message. Never raises exceptions.
        """
        if not self.enabled:
            return
        try:
            text = self._build_message(attack_record)
            self._post(text)
            logger.info("Telegram alert sent for attack %s from %s",
                        attack_record.get("id"), attack_record.get("ip_address"))
        except Exception as e:
            logger.error("Telegram alert failed: %s", e)

    def send_containment(self, ip: str, service: str,
                         action: str, severity: str):
        """Send a containment action notification."""
        if not self.enabled:
            return
        try:
            text = _CONTAINMENT_TEMPLATE.format(
                ip_address   = ip,
                service      = service.upper(),
                severity     = severity,
                action_taken = action[:400],
                timestamp    = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            )
            self._post(text)
        except Exception as e:
            logger.error("Telegram containment alert failed: %s", e)

    # ── Private helpers ────────────────────────────────────────────────────────

    def _build_message(self, rec: dict) -> str:
        severity = rec.get("severity", "Unknown")
        emoji    = _SEVERITY_EMOJI.get(severity, "⚪")
        payload  = (rec.get("payload") or "")[:300]
        # Escape backticks in payload for Markdown
        payload_preview = payload.replace("`", "'")

        return _MESSAGE_TEMPLATE.format(
            emoji          = emoji,
            severity       = severity,
            attack_id      = rec.get("id", "N/A"),
            timestamp      = rec.get("timestamp", "N/A"),
            ip_address     = rec.get("ip_address", "N/A"),
            country        = rec.get("country", "Unknown"),
            city           = rec.get("city", "Unknown"),
            service        = rec.get("service", "N/A").upper(),
            attack_type    = rec.get("attack_type", "N/A"),
            rule           = rec.get("rule", "N/A"),
            risk_score     = rec.get("risk_score", 0),
            payload_preview = payload_preview,
        )

    def _post(self, text: str):
        payload = {
            "chat_id":    self.chat_id,
            "text":       text,
            "parse_mode": "Markdown",
        }
        try:
            resp = requests.post(self._api_url, json=payload, timeout=10)
            if resp.status_code != 200:
                logger.warning("Telegram API returned %d: %s",
                               resp.status_code, resp.text[:200])
        except requests.exceptions.ConnectionError:
            logger.warning("Telegram API connection error — is the bot token valid?")
        except requests.exceptions.Timeout:
            logger.warning("Telegram API request timed out.")
