# =============================================================================
# reports/pdf_generator.py — Automated SOC Incident Report Generator
# Generates a professional PDF report from honeypot attack data
# Uses fpdf2 library (pip install fpdf2)
# =============================================================================

import os
import logging
from datetime import datetime
from collections import Counter

import sys
sys.path.insert(0, r"C:\Users\vetri\Desktop\FYProject")
import config

logger = logging.getLogger(__name__)

# Report output folder
REPORT_DIR = os.path.join(config.BASE_DIR, "reports", "output")
os.makedirs(REPORT_DIR, exist_ok=True)


def generate_report(db_manager) -> str:
    """
    Generate a PDF incident report from the current database state.
    Returns the file path of the generated PDF.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        logger.error("fpdf2 not installed. Run: pip install fpdf2")
        raise RuntimeError("fpdf2 library not found. Run: pip install fpdf2")

    from detection.mitre_mapping import get_technique_label

    # ── Gather data ────────────────────────────────────────────────────────────
    stats   = db_manager.get_stats()
    attacks = db_manager.get_recent_attacks(limit=500)
    actions = db_manager.get_response_actions(limit=50)
    now     = datetime.utcnow()
    ts      = now.strftime("%Y%m%d_%H%M%S")

    # Pre-compute top attackers
    ip_counter = Counter(a["ip_address"] for a in attacks)
    top_ips    = ip_counter.most_common(10)

    # Pre-compute MITRE techniques used
    mitre_counter = Counter(
        get_technique_label(a["attack_type"]) for a in attacks
    )
    top_mitre = mitre_counter.most_common(8)

    # ── Build PDF ──────────────────────────────────────────────────────────────
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ── COVER PAGE ─────────────────────────────────────────────────────────────
    pdf.add_page()
    _cover_page(pdf, now, stats)

    # ── EXECUTIVE SUMMARY ──────────────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "1. Executive Summary")
    summary_text = (
        f"This report covers honeypot activity captured by the Advanced Multi-Service "
        f"Honeypot SOC System. A total of {stats['total']} attack events were recorded "
        f"across SSH, Telnet, FTP, and Web honeypot services. "
        f"Of these, {stats['critical']} events were classified as Critical severity "
        f"and {stats['high']} as High severity, warranting immediate investigation. "
        f"The system successfully applied rule-based detection across 9 threat signatures "
        f"and performed geo-intelligence enrichment on all attacking IPs."
    )
    pdf.set_font("Arial", size=11)
    pdf.multi_cell(0, 7, summary_text)
    pdf.ln(5)

    # Key metrics table
    _section_subheader(pdf, "Key Metrics")
    metrics = [
        ("Total Events Detected",    str(stats["total"])),
        ("Critical Severity Events", str(stats["critical"])),
        ("High Severity Events",     str(stats["high"])),
        ("Unique Attacking IPs",     str(len(set(a["ip_address"] for a in attacks)))),
        ("Services Targeted",        str(len(stats["by_service"]))),
        ("Containment Actions Logged", str(len(actions))),
        ("Report Generated (UTC)",   now.strftime("%Y-%m-%d %H:%M:%S")),
    ]
    _draw_table(pdf, ["Metric", "Value"], metrics,
                col_widths=[130, 50])

    # ── ATTACK TIMELINE ────────────────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "2. Attack Distribution")

    _section_subheader(pdf, "Attacks by Severity")
    sev_data = [(_safe(r["severity"]), str(r["cnt"])) for r in stats["by_severity"]]
    _draw_table(pdf, ["Severity", "Count"], sev_data, col_widths=[130, 50])
    pdf.ln(5)

    _section_subheader(pdf, "Attacks by Service")
    svc_data = [(_safe(r["service"]).upper(), str(r["cnt"])) for r in stats["by_service"]]
    _draw_table(pdf, ["Service", "Count"], svc_data, col_widths=[130, 50])
    pdf.ln(5)

    _section_subheader(pdf, "Attacks by Type")
    type_data = [(_safe(r["attack_type"]), str(r["cnt"])) for r in stats["by_type"]]
    _draw_table(pdf, ["Attack Type", "Count"], type_data, col_widths=[130, 50])

    # ── TOP ATTACKERS ──────────────────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "3. Top Attacking IP Addresses")

    top_ip_rows = []
    for ip, count in top_ips:
        ip_attacks = [a for a in attacks if a["ip_address"] == ip]
        country    = _safe(ip_attacks[0]["country"]) if ip_attacks else "Unknown"
        max_sev    = max((a["severity"] for a in ip_attacks),
                         key=lambda s: {"Low":1,"Medium":2,"High":3,"Critical":4}.get(s,0))
        top_ip_rows.append((_safe(ip), country, str(count), _safe(max_sev)))

    _draw_table(pdf,
                ["IP Address", "Country", "Events", "Max Severity"],
                top_ip_rows,
                col_widths=[55, 55, 25, 45])

    # ── MITRE ATT&CK MAPPING ──────────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "4. MITRE ATT&CK Framework Mapping")

    pdf.set_font("Arial", size=11)
    pdf.multi_cell(0, 7,
        "The following MITRE ATT&CK techniques were observed based on detected "
        "attack patterns. These map honeypot detections to a globally recognised "
        "threat intelligence framework.")
    pdf.ln(5)

    _draw_table(pdf,
                ["MITRE Technique", "Occurrences"],
                [(_safe(t), str(c)) for t, c in top_mitre],
                col_widths=[140, 40])

    # ── RECENT CRITICAL/HIGH EVENTS ────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "5. Recent High & Critical Events")

    critical_attacks = [a for a in attacks if a["severity"] in ("Critical", "High")][:20]
    if critical_attacks:
        rows = []
        for a in critical_attacks:
            rows.append((
                _safe(a["timestamp"][:16]),
                _safe(a["ip_address"]),
                _safe(a["service"]).upper(),
                _safe(a["attack_type"]),
                _safe(a["severity"]),
            ))
        _draw_table(pdf,
                    ["Timestamp", "IP Address", "Service", "Attack Type", "Severity"],
                    rows,
                    col_widths=[35, 38, 20, 55, 22],
                    font_size=8)
    else:
        pdf.set_font("Arial", size=11)
        pdf.cell(0, 8, "No High/Critical events recorded.", ln=True)

    # ── CONTAINMENT ACTIONS ────────────────────────────────────────────────────
    if actions:
        pdf.add_page()
        _section_header(pdf, "6. Simulated Containment Actions")
        pdf.set_font("Arial", size=11)
        pdf.multi_cell(0, 7,
            "The following containment actions were automatically triggered for "
            "Critical severity events. These are simulated responses for educational "
            "purposes - in a production environment, these would execute real firewall rules.")
        pdf.ln(5)

        action_rows = [
            (_safe(a["timestamp"][:16]), _safe(a["ip_address"]),
             _safe(a["service"]).upper(), _safe(a["severity"]))
            for a in actions[:15]
        ]
        _draw_table(pdf,
                    ["Timestamp", "IP Address", "Service", "Severity"],
                    action_rows,
                    col_widths=[45, 50, 30, 45])

    # ── FOOTER / DISCLAIMER ────────────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "7. Disclaimer & Methodology")
    pdf.set_font("Arial", size=11)
    pdf.multi_cell(0, 7,
        "This report was automatically generated by the Advanced Multi-Service "
        "Honeypot SOC System, a Final Year Cybersecurity Project.\n\n"
        "METHODOLOGY:\n"
        "- SSH attacks captured via Cowrie honeypot (WSL2)\n"
        "- Telnet attacks captured via custom Python TCP socket server\n"
        "- FTP attacks captured via custom Python FTP socket server\n"
        "- Web attacks captured via Flask fake login/admin panel\n"
        "- All events processed through a 9-rule detection engine\n"
        "- Geo-intelligence provided by ip-api.com\n"
        "- MITRE ATT&CK mappings applied automatically per attack type\n\n"
        "DISCLAIMER:\n"
        "This honeypot system is designed for educational and research purposes only. "
        "All containment actions are simulated. No actual network changes are made. "
        "Data collected is for academic demonstration only."
    )

    # ── Save ───────────────────────────────────────────────────────────────────
    filename = f"SOC_Report_{ts}.pdf"
    filepath = os.path.join(REPORT_DIR, filename)
    pdf.output(filepath)
    logger.info("PDF report generated: %s", filepath)
    return filepath


# ── PDF Helper Functions ───────────────────────────────────────────────────────

def _safe(text: str) -> str:
    """
    Strip any characters that cannot be encoded in Latin-1 (the encoding
    used by fpdf2's built-in fonts like Arial/Helvetica).  This prevents
    UnicodeEncodeError when emoji or other Unicode glyphs appear in attack
    data fields (e.g. 'CANARY TRAP TRIGGERED' stored with a 🪤 prefix).
    Non-encodable characters are replaced with '?'.
    """
    if not isinstance(text, str):
        text = str(text)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _cover_page(pdf, now, stats):
    """Render the professional cover page."""
    pdf.set_fill_color(15, 23, 42)   # Dark navy
    pdf.rect(0, 0, 210, 297, "F")

    pdf.set_y(60)
    pdf.set_font("Arial", "B", 24)
    pdf.set_text_color(239, 68, 68)   # Red accent
    pdf.cell(0, 12, "SOC INCIDENT REPORT", ln=True, align="C")

    pdf.ln(5)
    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, "Advanced Multi-Service Honeypot", ln=True, align="C")
    pdf.cell(0, 10, "Threat Intelligence Platform", ln=True, align="C")

    pdf.ln(15)
    pdf.set_font("Arial", "", 13)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 8, f"Generated: {now.strftime('%Y-%m-%d %H:%M:%S')} UTC", ln=True, align="C")
    pdf.cell(0, 8, f"Total Events: {stats['total']}   |   "
                   f"Critical: {stats['critical']}   |   "
                   f"High: {stats['high']}", ln=True, align="C")

    pdf.ln(20)
    pdf.set_font("Arial", "I", 11)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 8, "Final Year Cybersecurity Project - Vetrivel", ln=True, align="C")

    # Reset colours for body pages
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(255, 255, 255)


def _section_header(pdf, title: str):
    pdf.set_font("Arial", "B", 14)
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, f"  {title}", ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)


def _section_subheader(pdf, title: str):
    pdf.set_font("Arial", "B", 12)
    pdf.set_text_color(239, 68, 68)
    pdf.cell(0, 8, title, ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)


def _draw_table(pdf, headers: list, rows: list,
                col_widths: list = None, font_size: int = 10):
    """Draw a simple bordered table with a header row."""
    n_cols = len(headers)
    if col_widths is None:
        total = 180
        col_widths = [total // n_cols] * n_cols

    row_height = 7

    # Header row
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", font_size)
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], row_height + 1, f" {h}", border=1, fill=True)
    pdf.ln()

    # Data rows
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", "", font_size)
    for idx, row in enumerate(rows):
        if pdf.get_y() > 270:
            pdf.add_page()
            # Re-draw header after page break
            pdf.set_fill_color(30, 41, 59)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Arial", "B", font_size)
            for i, h in enumerate(headers):
                pdf.cell(col_widths[i], row_height + 1, f" {h}", border=1, fill=True)
            pdf.ln()
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", "", font_size)

        fill = idx % 2 == 0
        pdf.set_fill_color(241, 245, 249) if fill else pdf.set_fill_color(255, 255, 255)
        for i, cell in enumerate(row):
            pdf.cell(col_widths[i], row_height, f" {str(cell)}", border=1, fill=fill)
        pdf.ln()

    pdf.ln(3)
