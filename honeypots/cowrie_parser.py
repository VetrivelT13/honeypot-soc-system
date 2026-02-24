# =============================================================================
# honeypots/cowrie_parser.py — Cowrie SSH Honeypot JSON Log Parser
# Tails cowrie.json in real-time and feeds events to detection engine
# =============================================================================

import os
import json
import time
import queue
import logging
import threading
from datetime import datetime

import sys
sys.path.insert(0, r"C:\Users\vetri\Desktop\FYProject")
import config

logger = logging.getLogger(__name__)

# Cowrie event IDs we care about
_INTERESTING_EVENTS = {
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.command.failed",
    "cowrie.session.connect",
    "cowrie.session.closed",
    "cowrie.direct-tcpip.request",
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
}


class CowrieLogParser:
    """
    Watches the Cowrie JSON log file for new lines.
    Uses file-tail approach (seek to end on start, then follow).
    Normalises Cowrie events into the shared event format and queues them.
    """

    def __init__(self, event_queue: queue.Queue,
                 log_path: str = config.COWRIE_LOG_PATH):
        self.event_queue = event_queue
        self.log_path    = log_path
        self._stop_event = threading.Event()

    def start(self):
        """Begin tailing the log file. Blocks until stop() is called."""
        logger.info("Cowrie parser watching: %s", self.log_path)

        # Wait until the log file exists
        while not self._stop_event.is_set():
            if os.path.exists(self.log_path):
                break
            logger.debug("Cowrie log not found yet — waiting…")
            time.sleep(5)

        if self._stop_event.is_set():
            return

        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as fh:
                # Seek to end so we only process NEW events
                fh.seek(0, os.SEEK_END)
                logger.info("Cowrie parser tailing from current end of file.")

                while not self._stop_event.is_set():
                    line = fh.readline()
                    if line:
                        self._process_line(line.strip())
                    else:
                        time.sleep(0.3)   # Short sleep before retry

        except FileNotFoundError:
            logger.error("Cowrie log file disappeared: %s", self.log_path)
        except Exception as e:
            logger.error("Cowrie parser error: %s", e, exc_info=True)

    def stop(self):
        self._stop_event.set()

    def _process_line(self, line: str):
        if not line:
            return
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Non-JSON line skipped: %s", line[:80])
            return

        event_id = data.get("eventid", "")

        if event_id not in _INTERESTING_EVENTS:
            return

        ip        = data.get("src_ip", "0.0.0.0")
        timestamp = data.get("timestamp", datetime.utcnow().isoformat())
        username  = data.get("username", "")
        password  = data.get("password", "")
        command   = data.get("input", "")
        url       = data.get("url", "")

        # Map event to normalised format
        if event_id in ("cowrie.login.failed", "cowrie.login.success"):
            payload    = f"USERNAME:{username} PASSWORD:{password}"
            event_type = "login_attempt"

        elif event_id in ("cowrie.command.input", "cowrie.command.failed"):
            payload    = command
            event_type = "command"

        elif event_id == "cowrie.session.connect":
            payload    = f"SSH connection from {ip}"
            event_type = "connection"

        elif event_id in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            payload    = f"FILE:{url or data.get('filename', '')} CMD:{command}"
            event_type = "file_transfer"

        elif event_id == "cowrie.direct-tcpip.request":
            payload    = f"TCPIP:{data.get('dst_ip','')}:{data.get('dst_port','')}"
            event_type = "port_forward"

        else:
            payload    = json.dumps(data)[:500]
            event_type = "ssh_event"

        # Normalise ISO timestamp
        try:
            ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ts_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        event = {
            "ip":         ip,
            "service":    "ssh",
            "event_type": event_type,
            "payload":    payload,
            "username":   username,
            "timestamp":  ts_str,
        }

        try:
            self.event_queue.put_nowait(event)
            logger.debug("SSH event queued: %s ← %s [%s]", event_type, ip, event_id)
        except queue.Full:
            logger.warning("Event queue full — dropping Cowrie event from %s", ip)


class CowrieHistoryLoader:
    """
    One-shot loader: reads ALL existing lines from the Cowrie log file on startup
    to backfill the database with historical data.
    """

    def __init__(self, event_queue: queue.Queue,
                 log_path: str = config.COWRIE_LOG_PATH):
        self.event_queue = event_queue
        self.log_path    = log_path
        self._parser     = CowrieLogParser(event_queue, log_path)

    def load(self):
        if not os.path.exists(self.log_path):
            logger.warning("No historical Cowrie log found at %s", self.log_path)
            return

        count = 0
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    self._parser._process_line(line.strip())
                    count += 1
        except Exception as e:
            logger.error("History load error: %s", e)

        logger.info("Cowrie history loaded: %d lines processed", count)
