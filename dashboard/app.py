# =============================================================================
# dashboard/app.py — SOC Analyst Dashboard (Flask + Flask-SocketIO)
# Includes: REST API, SocketIO, PDF report generation, MITRE stats
# =============================================================================

import os
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS

import sys
_DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_DASHBOARD_DIR))
import config

logger = logging.getLogger(__name__)

_db_manager = None
socketio: SocketIO = None
_flask_app: Flask = None


def create_dashboard(db_manager):
    global _db_manager, socketio, _flask_app

    _db_manager = db_manager

    app = Flask(
        __name__,
        template_folder=os.path.join(_DASHBOARD_DIR, "templates"),
        static_folder=os.path.join(_DASHBOARD_DIR, "static"),
    )
    app.secret_key = config.DASHBOARD_SECRET_KEY
    CORS(app)

    sio = SocketIO(
        app, cors_allowed_origins="*", async_mode="threading",
        logger=False, engineio_logger=False, allow_upgrades=True,
    )
    socketio   = sio
    _flask_app = app

    # ── REST API Routes ────────────────────────────────────────────────────────

    @app.route("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/api/stats")
    def api_stats():
        try:
            return jsonify({"status": "ok", "data": _db_manager.get_stats()})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/attacks")
    def api_attacks():
        try:
            limit = min(int(request.args.get("limit", 200)), config.ATTACK_HISTORY_LIMIT)
            return jsonify({"status": "ok", "data": _db_manager.get_recent_attacks(limit=limit)})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/attacks/<int:attack_id>")
    def api_attack_detail(attack_id):
        try:
            attack = _db_manager.get_attack_by_id(attack_id)
            if not attack:
                return jsonify({"status": "error", "message": "Not found"}), 404
            return jsonify({"status": "ok", "data": attack})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/map")
    def api_map():
        try:
            return jsonify({"status": "ok", "data": _db_manager.get_map_data()})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/actions")
    def api_actions():
        try:
            return jsonify({"status": "ok", "data": _db_manager.get_response_actions(limit=50)})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/health")
    def api_health():
        return jsonify({
            "status": "ok",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "2.0.0",
            "features": ["ssh","telnet","ftp","web","mitre","abuseipdb","pdf-reports"],
        })

    @app.route("/api/mitre")
    def api_mitre():
        """Return MITRE ATT&CK technique statistics."""
        try:
            from detection.mitre_mapping import MITRE_MAP
            stats = _db_manager.get_stats()
            return jsonify({
                "status": "ok",
                "data": {
                    "mitre_stats": stats.get("mitre_stats", []),
                    "technique_count": len(MITRE_MAP),
                }
            })
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/profiles")
    def api_profiles():
        """Return all attacker behaviour profiles."""
        try:
            from detection.attacker_profiler import profile_label, PROFILE_COLOR
            profiles = _db_manager.get_all_profiles()
            stats    = _db_manager.get_profile_stats()
            for p in profiles:
                p["label"] = profile_label(p["profile"])
                p["color"] = PROFILE_COLOR.get(p["profile"], "#64748b")
            return jsonify({
                "status": "ok",
                "data": {
                    "profiles": profiles,
                    "stats":    stats,
                }
            })
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/ip/<string:ip_address>")
    def api_ip_profile(ip_address):
        """Single IP: full history + attacker profile + kill chain + threat actor."""
        try:
            from detection.attacker_profiler import profile_label, PROFILE_COLOR
            from detection.killchain import get_ip_kill_chain_summary
            attacks = _db_manager.get_attacks_by_ip(ip_address)
            actions = [a for a in _db_manager.get_response_actions(limit=50)
                       if a["ip_address"] == ip_address]
            profile = _db_manager.get_attacker_profile(ip_address)
            if profile:
                profile["label"] = profile_label(profile["profile"])
                profile["color"] = PROFILE_COLOR.get(profile["profile"], "#64748b")
            # Kill chain summary
            kc_rows    = _db_manager.get_killchain_for_ip(ip_address)
            phase_nums = [r["phase_num"] for r in kc_rows]
            killchain  = get_ip_kill_chain_summary(phase_nums)
            # Threat actor
            threat_actor = _db_manager.get_threat_actor(ip_address)
            # Canary events for this IP
            canary_events = [e for e in _db_manager.get_canary_events(limit=200)
                             if e["ip_address"] == ip_address]
            return jsonify({
                "status": "ok",
                "data": {
                    "attacks":       attacks,
                    "actions":       actions,
                    "profile":       profile,
                    "killchain":     killchain,
                    "threat_actor":  threat_actor,
                    "canary_events": canary_events,
                    "summary": {
                        "total":        len(attacks),
                        "services":     list({a["service"] for a in attacks}),
                        "attack_types": list({a["attack_type"] for a in attacks}),
                        "max_risk":     max((a["risk_score"] for a in attacks), default=0),
                        "max_abuse":    max((a.get("abuse_score", 0) for a in attacks), default=0),
                        "mitre_techniques": list({a.get("mitre_technique","") for a in attacks if a.get("mitre_technique")}),
                    }
                }
            })
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/killchain")
    def api_killchain():
        """Kill chain summary across all IPs."""
        try:
            from detection.killchain import PHASES, get_ip_kill_chain_summary
            summary = _db_manager.get_killchain_summary()
            return jsonify({"status": "ok", "data": {"summary": summary, "phases": PHASES}})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/canary")
    def api_canary():
        """All canary trap events."""
        try:
            events = _db_manager.get_canary_events(limit=100)
            count  = _db_manager.get_canary_count()
            return jsonify({"status": "ok", "data": {"events": events, "total": count}})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/threat-actors")
    def api_threat_actors():
        """All threat actor fingerprints."""
        try:
            actors = _db_manager.get_all_threat_actors()
            return jsonify({"status": "ok", "data": {"actors": actors}})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/report")
    def api_generate_report():
        """Generate and download a PDF incident report."""
        try:
            from reports.pdf_generator import generate_report
            filepath = generate_report(_db_manager)
            return send_file(
                filepath,
                as_attachment=True,
                download_name=os.path.basename(filepath),
                mimetype="application/pdf",
            )
        except RuntimeError as e:
            return jsonify({"status": "error", "message": str(e)}), 500
        except Exception as e:
            logger.error("Report generation error: %s", e, exc_info=True)
            return jsonify({"status": "error", "message": str(e)}), 500

    # ── SocketIO Events ────────────────────────────────────────────────────────

    @sio.on("connect", namespace="/soc")
    def on_connect():
        logger.info("SOC analyst connected: %s", request.sid)
        try:
            stats = _db_manager.get_stats()
            emit("stats_update", stats)
        except Exception as e:
            logger.error("on_connect stats error: %s", e)

    @sio.on("disconnect", namespace="/soc")
    def on_disconnect():
        logger.info("SOC analyst disconnected: %s", request.sid)

    @sio.on("request_stats", namespace="/soc")
    def on_request_stats():
        try:
            emit("stats_update", _db_manager.get_stats())
        except Exception as e:
            logger.error("request_stats error: %s", e)

    @sio.on("request_map", namespace="/soc")
    def on_request_map():
        try:
            emit("map_data", {"markers": _db_manager.get_map_data()})
        except Exception as e:
            logger.error("request_map error: %s", e)

    return app, sio
