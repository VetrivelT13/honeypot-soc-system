#!/bin/bash
# =============================================================================
# stop_cowrie_wsl.sh — Gracefully stop Cowrie SSH Honeypot
# =============================================================================

PID_FILE="/opt/cowrie/var/run/cowrie.pid"
GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        sudo kill "$PID"
        sleep 1
        echo -e "${GREEN}✓ Cowrie stopped (PID $PID)${NC}"
    else
        echo -e "${RED}Cowrie process not running (stale PID file)${NC}"
    fi
    rm -f "$PID_FILE"
else
    echo -e "${RED}Cowrie PID file not found — may not be running${NC}"
fi
