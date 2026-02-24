# 🕷️ Honeypot Cyber Attack Detection System

> A deception-based threat intelligence platform that lures, captures, and classifies real attackers in real time — built on a Raspberry Pi Zero W.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-green?logo=flask)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 🔍 What It Does

Most security tools try to block attackers. This system does the opposite — it lets them in on purpose and uses AI to profile them.

A honeypot sensor (Raspberry Pi Zero W) runs fake SSH, FTP, Telnet, and HTTP services. Real attackers probe these thinking they've found a real target. Every command, credential attempt, and session is silently captured, classified, and visualised on a live SOC dashboard.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🪤 **Canary Token Traps** | Fake AWS keys, credentials & URLs — triggers email alert in < 2 sec |
| 🗺️ **MITRE ATT&CK Mapping** | Every attack auto-mapped to technique IDs (14 tactics) |
| ⛓️ **Kill Chain Classification** | 7 Cyber Kill Chain phases tracked per session |
| 🤖 **K-Means AI Profiling** | Classifies attackers as APT / Script Kiddie / Opportunist / Targeted |
| 📊 **Live SOC Dashboard** | World attack map, heatmap, threat leaderboard, real-time feed |
| 📄 **Auto PDF Reports** | Daily incident reports — no analyst needed |
| 🌍 **Geo Intelligence** | Country, city, ASN lookup for every attacker IP |

---

## 🏗️ System Architecture

```
Real Attacker (Internet)
        │
        ▼
┌─────────────────────┐
│  Raspberry Pi Zero W │  ← SSH / FTP / Telnet / HTTP honeypots
│  (Edge Sensor)       │  ← Cowrie + custom honeypot services
└──────────┬──────────┘
           │  JSON logs
           ▼
┌─────────────────────┐
│  Detection Engine    │  ← MITRE mapping, Kill Chain, K-Means AI
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐     ┌──────────────────────┐
│  SQLite Database     │────▶│  SOC Dashboard        │
│  (Events + Profiles) │     │  (Flask + Socket.IO)  │
└─────────────────────┘     └──────────────────────┘
                                       │
                        ┌──────────────┼──────────────┐
                        ▼              ▼               ▼
                  Email Alert    Telegram Alert   PDF Report
```

---

## 🛠️ Tech Stack

- **Backend:** Python 3.10+, Flask, Flask-SocketIO, APScheduler
- **AI/ML:** scikit-learn (K-Means clustering)
- **Database:** SQLite
- **Frontend:** Leaflet.js, Chart.js, Socket.IO
- **Honeypot:** Cowrie (SSH/Telnet), custom FTP & HTTP honeypots
- **Threat Intel:** MITRE ATT&CK, AbuseIPDB, ip-api.com
- **Reporting:** fpdf2
- **Hardware:** Raspberry Pi Zero W

---

## 📊 Performance

| Metric | Value |
|---|---|
| Attack Detection Rate | > 95% |
| Canary Alert Speed | < 2 seconds |
| AI Profiler Accuracy | > 87% |
| MITRE Tactics Tracked | 14 |
| Total Hardware Cost | ₹3,500 (~$42 USD) |

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/honeypot-soc-system.git
cd honeypot-soc-system
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Set up environment variables
```bash
cp .env.example .env
# Edit .env and fill in your credentials
```

### 4. Run the dashboard
```bash
python main.py
```

Open `http://localhost:5000` in your browser.

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and set:

| Variable | Description |
|---|---|
| `EMAIL_SENDER` | Gmail address for sending alerts |
| `EMAIL_PASSWORD` | Gmail App Password (not your login password) |
| `EMAIL_RECIPIENT` | Where to receive alerts |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | Your Telegram chat ID |
| `ABUSEIPDB_API_KEY` | Free key from abuseipdb.com |
| `DASHBOARD_SECRET_KEY` | Any random secret string |

---

## 📁 Project Structure

```
honeypot-soc-system/
├── main.py                  # Entry point
├── config.py                # Configuration (reads from .env)
├── requirements.txt
├── .env.example             # Template — copy to .env
├── dashboard/               # Flask SOC dashboard
├── detection/               # MITRE mapping, Kill Chain, AI profiler
├── honeypots/               # SSH parser, FTP, Telnet, Web honeypots
├── database/                # SQLite DB manager
├── geo/                     # Geo IP lookup
├── alerts/                  # Email + Telegram alerting
├── intel/                   # AbuseIPDB threat intel
├── reports/                 # PDF report generator
└── cowrie_integration/      # Cowrie log bridge
```

---

## ⚠️ Legal Notice

This system is intended for **authorized security research and educational purposes only**. Deploy only on networks you own or have explicit written permission to monitor. Unauthorized interception of network traffic may be illegal in your jurisdiction.

---

## 👤 Author

**Vetrivel T** — Cybersecurity Enthusiast
Built from scratch. No commercial tools. Just Python and a $5 computer.

---

## 📄 License

MIT License — free to use, modify, and share with attribution.
