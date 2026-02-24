# =============================================================================
# honeypots/web_honeypot.py — Flask Web Honeypot
# Serves fake login page + fake admin panel on WEB_HONEYPOT_PORT
# Detects SQLi, XSS, Command Injection, Credential Stuffing
# NOTE: This is NOT the SOC dashboard — it is solely an attacker trap.
# =============================================================================

import queue
import logging
import threading
from datetime import datetime
from functools import wraps

from flask import (Flask, request, render_template, redirect,
                   url_for, session, jsonify)

import sys
sys.path.insert(0, r"C:\Users\vetri\Desktop\FYProject")
import config

logger = logging.getLogger(__name__)


def create_web_honeypot(event_queue: queue.Queue) -> Flask:
    """Factory function — creates and returns the web honeypot Flask app."""

    app = Flask(
        __name__,
        template_folder=r"C:\Users\vetri\Desktop\FYProject\dashboard\templates\web_honeypot",
        static_folder=None,
    )
    app.secret_key = "web_honeypot_secret_key_2024"

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _put_event(event_type: str, payload: str, username: str = ""):
        ip = request.headers.get("X-Forwarded-For",
                                 request.remote_addr or "0.0.0.0").split(",")[0].strip()
        event = {
            "ip":         ip,
            "service":    "web",
            "event_type": event_type,
            "payload":    payload,
            "username":   username,
            "user_agent": request.headers.get("User-Agent", "")[:500],
            "timestamp":  datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        }
        try:
            event_queue.put_nowait(event)
        except queue.Full:
            logger.warning("Event queue full — dropping web event")

    # ── Routes ─────────────────────────────────────────────────────────────────

    @app.route("/", methods=["GET"])
    def index():
        _put_event("web_request", f"GET / UA:{request.headers.get('User-Agent','')[:100]}")
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")[:200]
            password = request.form.get("password", "")[:200]
            combined = f"username={username}&password={password}"

            _put_event("login_attempt", combined, username=username)

            # Always reject — but pretend to process
            error = "Invalid credentials. Please try again."

        return render_template("login.html", error=error)

    @app.route("/admin", methods=["GET"])
    def fake_admin():
        _put_event("web_request", f"GET /admin UA:{request.headers.get('User-Agent','')[:100]}")
        return render_template("admin.html")

    @app.route("/admin/login", methods=["POST"])
    def fake_admin_login():
        username = request.form.get("username", "")[:200]
        password = request.form.get("password", "")[:200]
        combined = f"username={username}&password={password}"
        _put_event("login_attempt", combined, username=username)
        return render_template("admin.html", error="Access Denied")

    @app.route("/search", methods=["GET", "POST"])
    def fake_search():
        query = request.args.get("q", "") or request.form.get("q", "")
        query = query[:1000]
        _put_event("web_request", f"SEARCH query={query}")
        return f"<html><body>Search results for: {query}</body></html>", 200

    @app.route("/wp-admin", methods=["GET", "POST"])
    @app.route("/wp-login.php", methods=["GET", "POST"])
    @app.route("/phpmyadmin", methods=["GET", "POST"])
    @app.route("/.env", methods=["GET"])
    @app.route("/config.php", methods=["GET"])
    @app.route("/shell.php", methods=["GET", "POST"])
    @app.route("/c99.php", methods=["GET", "POST"])
    @app.route("/backdoor.php", methods=["GET", "POST"])
    def honeypot_trap():
        path = request.path
        payload = f"PATH:{path} METHOD:{request.method}"
        if request.method == "POST":
            payload += f" BODY:{request.get_data(as_text=True)[:500]}"
        _put_event("web_request", payload)
        # Serve a fake 404 or fake page to keep attacker guessing
        return "<html><body><h2>Not Found</h2></body></html>", 404

    @app.route("/api/users", methods=["GET"])
    @app.route("/api/data", methods=["GET"])
    def fake_api():
        _put_event("web_request", f"API:{request.path} PARAMS:{str(request.args)[:200]}")
        return jsonify({"error": "Unauthorized"}), 401

    # ── SQL Injection probe paths ──────────────────────────────────────────────

    @app.route("/product", methods=["GET"])
    def fake_product():
        product_id = request.args.get("id", "")[:500]
        _put_event("web_request", f"PRODUCT id={product_id}")
        return f"<html><body>Product ID: {product_id}</body></html>", 200

    # ── Generic catch-all ──────────────────────────────────────────────────────

    @app.errorhandler(404)
    def not_found(e):
        path = request.path
        _put_event("web_request", f"404:{path}")
        return "<html><body><h2>404 Not Found</h2></body></html>", 404

    @app.errorhandler(500)
    def internal_error(e):
        return "<html><body><h2>500 Internal Server Error</h2></body></html>", 500

    return app
