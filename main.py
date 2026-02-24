#!/usr/bin/env python3
# =============================================================================
# main.py — Master Entry Point for the Honeypot SOC System
# Services: SSH (Cowrie), Telnet, FTP, Web + SOC Dashboard
# =============================================================================

import sys, os, queue, logging, threading, time
import colorlog

PROJECT_ROOT = r"C:\Users\vetri\Desktop\FYProject"
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import config

def setup_logging():
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s [%(levelname)s] %(name)s: %(message)s%(reset)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={'DEBUG':'cyan','INFO':'green','WARNING':'yellow',
                    'ERROR':'red','CRITICAL':'bold_red,bg_white'}
    ))
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))
    for lib in ('werkzeug','engineio','socketio','urllib3'):
        logging.getLogger(lib).setLevel(logging.WARNING)

setup_logging()
logger = logging.getLogger("main")


def print_banner():
    banner = r"""
 ╔══════════════════════════════════════════════════════════════════════╗
 ║      ADVANCED MULTI-SERVICE HONEYPOT — SOC INTELLIGENCE PLATFORM    ║
 ║      Final Year Cybersecurity Project — Vetrivel                    ║
 ╠══════════════════════════════════════════════════════════════════════╣
 ║  SSH Honeypot (Cowrie)   → Port {}                                ║
 ║  Telnet Honeypot         → Port {}                               ║
 ║  FTP Honeypot            → Port {}                               ║
 ║  Web Honeypot            → Port {}                               ║
 ║  SOC Dashboard           → http://localhost:{}                   ║
 ╚══════════════════════════════════════════════════════════════════════╝
""".format(config.SSH_HONEYPOT_PORT, config.TELNET_HONEYPOT_PORT,
           config.FTP_HONEYPOT_PORT, config.WEB_HONEYPOT_PORT,
           config.SOC_DASHBOARD_PORT)
    print(banner)


def ensure_directories():
    dirs = [
        r"C:\Users\vetri\Desktop\FYProject\database",
        r"C:\Users\vetri\Desktop\FYProject\logs\cowrie",
        r"C:\Users\vetri\Desktop\FYProject\reports\output",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    logger.info("Directory structure verified.")


def main():
    print_banner()
    ensure_directories()

    event_queue = queue.Queue(maxsize=5000)

    from database.db_manager import DatabaseManager
    db = DatabaseManager()
    db.initialize()
    logger.info("Database ready at: %s", config.DB_PATH)

    from alerts.email_alert import EmailAlert
    from alerts.telegram_alert import TelegramAlert
    email_alert    = EmailAlert()
    telegram_alert = TelegramAlert()

    from dashboard.app import create_dashboard
    flask_app, socketio = create_dashboard(db_manager=db)

    from detection.engine import DetectionEngine
    engine = DetectionEngine(
        event_queue=event_queue, db_manager=db, socketio=socketio,
        email_alert=email_alert, telegram_alert=telegram_alert,
    )
    threading.Thread(target=engine.start, daemon=True, name="DetectionEngine").start()
    logger.info("Detection engine started.")

    from honeypots.telnet_honeypot import TelnetHoneypot
    telnet_hp = TelnetHoneypot(event_queue=event_queue)
    threading.Thread(target=telnet_hp.start, daemon=True, name="TelnetHoneypot").start()
    logger.info("Telnet honeypot started on port %d", config.TELNET_HONEYPOT_PORT)

    from honeypots.ftp_honeypot import FTPHoneypot
    ftp_hp = FTPHoneypot(event_queue=event_queue)
    threading.Thread(target=ftp_hp.start, daemon=True, name="FTPHoneypot").start()
    logger.info("FTP honeypot started on port %d", config.FTP_HONEYPOT_PORT)

    from honeypots.web_honeypot import create_web_honeypot
    web_app = create_web_honeypot(event_queue=event_queue)
    def run_web():
        try:
            web_app.run(host="0.0.0.0", port=config.WEB_HONEYPOT_PORT,
                        debug=False, use_reloader=False)
        except OSError as e:
            logger.error("Web honeypot failed: %s", e)
    threading.Thread(target=run_web, daemon=True, name="WebHoneypot").start()
    logger.info("Web honeypot started on port %d", config.WEB_HONEYPOT_PORT)

    from honeypots.cowrie_parser import CowrieLogParser, CowrieHistoryLoader
    def _load_history():
        CowrieHistoryLoader(event_queue=event_queue).load()
    threading.Thread(target=_load_history, daemon=True, name="CowrieHistory").start()
    cowrie_parser = CowrieLogParser(event_queue=event_queue)
    threading.Thread(target=cowrie_parser.start, daemon=True, name="CowrieParser").start()
    logger.info("Cowrie parser watching: %s", config.COWRIE_LOG_PATH)

    def stats_broadcast_loop():
        while True:
            time.sleep(15)
            try:
                stats = db.get_stats()
                socketio.emit("stats_update", stats, namespace="/soc")
            except Exception as e:
                logger.debug("Stats broadcast error: %s", e)
    threading.Thread(target=stats_broadcast_loop, daemon=True, name="StatsBroadcast").start()

    logger.info("=" * 60)
    logger.info("SOC Dashboard → http://localhost:%d", config.SOC_DASHBOARD_PORT)
    logger.info("Web Honeypot  → http://localhost:%d/login", config.WEB_HONEYPOT_PORT)
    logger.info("FTP Honeypot  → ftp://localhost:%d", config.FTP_HONEYPOT_PORT)
    logger.info("=" * 60)

    try:
        socketio.run(flask_app, host="0.0.0.0", port=config.SOC_DASHBOARD_PORT,
                     debug=False, use_reloader=False, log_output=False,
                     allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        logger.info("Shutting down honeypot SOC system...")
        engine.stop()
        telnet_hp.stop()
        ftp_hp.stop()
        cowrie_parser.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
