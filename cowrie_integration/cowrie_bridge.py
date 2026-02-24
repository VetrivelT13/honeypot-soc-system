#!/usr/bin/env python3
# =============================================================================
# cowrie_bridge.py — Fallback Log Bridge (run inside WSL if direct path fails)
# Tails Cowrie's local WSL log and copies new lines to the Windows project path
# Usage (inside WSL): python3 cowrie_bridge.py
# =============================================================================

import os
import sys
import time
import json
import shutil
import signal
import logging
from datetime import datetime

# ── Configuration ──────────────────────────────────────────────────────────────
# Cowrie's local log inside WSL
COWRIE_LOCAL_LOG  = "/opt/cowrie/var/log/cowrie/cowrie.json"

# Windows FYProject log (via WSL mount)
WINDOWS_LOG_PATH  = "/mnt/c/Users/vetri/Desktop/FYProject/logs/cowrie/cowrie.json"

POLL_INTERVAL     = 0.3   # seconds between polls
LOG_LEVEL         = logging.INFO

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [BRIDGE] %(message)s",
    datefmt="%H:%M:%S",
    level=LOG_LEVEL,
)
logger = logging.getLogger("cowrie_bridge")

# ── Signal handler ─────────────────────────────────────────────────────────────
_running = True

def _handle_signal(sig, frame):
    global _running
    logger.info("Shutdown signal received — stopping bridge.")
    _running = False

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


def ensure_windows_log():
    """Create the Windows log file and parent directories if needed."""
    win_dir = os.path.dirname(WINDOWS_LOG_PATH)
    os.makedirs(win_dir, exist_ok=True)
    if not os.path.exists(WINDOWS_LOG_PATH):
        open(WINDOWS_LOG_PATH, "w").close()
        logger.info("Created Windows log file: %s", WINDOWS_LOG_PATH)


def wait_for_cowrie_log():
    """Block until Cowrie's local log file appears."""
    logger.info("Waiting for Cowrie log at: %s", COWRIE_LOCAL_LOG)
    while _running:
        if os.path.exists(COWRIE_LOCAL_LOG):
            logger.info("Cowrie log found — starting bridge.")
            return
        time.sleep(2)


def run_bridge():
    """
    Tail COWRIE_LOCAL_LOG and append new lines to WINDOWS_LOG_PATH.
    Validates each line is valid JSON before forwarding.
    """
    forwarded = 0
    skipped   = 0

    with open(COWRIE_LOCAL_LOG, "r", encoding="utf-8", errors="replace") as src:
        # Seek to end — only forward NEW events
        src.seek(0, os.SEEK_END)
        logger.info("Bridge active — forwarding new Cowrie events to Windows path")
        logger.info("  Source : %s", COWRIE_LOCAL_LOG)
        logger.info("  Target : %s", WINDOWS_LOG_PATH)
        logger.info("  Press Ctrl+C to stop.")

        while _running:
            line = src.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                continue

            line = line.strip()
            if not line:
                continue

            # Validate JSON
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            # Append to Windows log
            try:
                with open(WINDOWS_LOG_PATH, "a", encoding="utf-8") as dst:
                    dst.write(line + "\n")
                    dst.flush()
                forwarded += 1

                # Pretty-print key events
                ev = obj.get("eventid", "")
                ip = obj.get("src_ip", "?")
                if "login" in ev:
                    usr = obj.get("username", "?")
                    pwd = obj.get("password", "?")
                    logger.info("[SSH] %-20s  LOGIN  user=%-12s pass=%s", ip, usr, pwd)
                elif "command" in ev:
                    cmd = obj.get("input", "")[:60]
                    logger.info("[SSH] %-20s  CMD    %s", ip, cmd)
                elif "connect" in ev:
                    logger.info("[SSH] %-20s  CONNECTED", ip)
                elif "download" in ev:
                    url = obj.get("url", "")
                    logger.info("[SSH] %-20s  DOWNLOAD  %s", ip, url)

            except OSError as e:
                logger.error("Failed to write to Windows log: %s", e)
                time.sleep(1)

    logger.info("Bridge stopped. Forwarded: %d lines, Skipped: %d invalid.", forwarded, skipped)


def main():
    print("\n  Cowrie → Windows Log Bridge")
    print("  ─────────────────────────────────────────")

    ensure_windows_log()
    wait_for_cowrie_log()

    try:
        run_bridge()
    except Exception as e:
        logger.error("Bridge crashed: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
