# Advanced Multi-Service Honeypot — SOC Intelligence Platform
## Complete Setup, Deployment & Viva Guide

---

## 1. SYSTEM REQUIREMENTS

| Component | Requirement |
|-----------|-------------|
| OS | Windows 10/11 or Ubuntu 20.04+ |
| Python | 3.9 or higher |
| RAM | Minimum 4 GB |
| Disk | 5 GB free space |
| Network | Lab/isolated network (recommended) |

---

## 2. QUICK START (Step-by-Step)

### Step 1 — Create the Project Folder

```
C:\Users\vetri\Desktop\FYProject\
```

Extract all project files into this exact directory.

### Step 2 — Install Python Dependencies

Open Command Prompt as Administrator inside the project folder:

```cmd
cd C:\Users\vetri\Desktop\FYProject
pip install -r requirements.txt
```

If `colorlog` fails:
```cmd
pip install colorlog --upgrade
```

### Step 3 — Edit Credentials (config.py)

Open `config.py` and fill in:

```python
EMAIL_SENDER    = "pract.8080@gmail.com"
EMAIL_PASSWORD  = "bvnxyhnlcfmfclfw"  # 16-char App Password, NOT Gmail password
EMAIL_RECIPIENT = "honey.checkpot@gmail.com"

TELEGRAM_BOT_TOKEN = "8505711160:AAHyOdTZWaeVPmP47cIC53OpAob-QWa7pvw"   # From BotFather
TELEGRAM_CHAT_ID   = "1135963247"       # Your chat or group ID
```

> **Note:** If you do not have email/Telegram yet, set `EMAIL_ENABLED = False` and `TELEGRAM_ENABLED = False` in config.py to disable them. The system runs fully without alerts.

### Step 4 — Run the System

```cmd
cd C:\Users\vetri\Desktop\FYProject
python main.py
```

You will see the startup banner. All three honeypots start automatically.

### Step 5 — Open the SOC Dashboard

Open your browser and navigate to:
```
http://localhost:5000
```

### Step 6 — Access the Web Honeypot (Attacker Trap)

```
http://localhost:8080/login
http://localhost:8080/admin
```

---

## 3. GMAIL APP PASSWORD SETUP

1. Go to your Google Account → Security
2. Enable 2-Step Verification
3. Go to App Passwords → Select "Mail" + "Windows Computer"
4. Copy the 16-character password
5. Paste it into `config.py` as `EMAIL_PASSWORD`

---

## 4. TELEGRAM BOT SETUP

1. Open Telegram → search `@BotFather`
2. Send `/newbot` and follow the prompts
3. Copy the Bot Token → paste into `config.py` as `TELEGRAM_BOT_TOKEN`
4. Start your bot (send it a message)
5. Visit `https://api.telegram.org/bot<TOKEN>/getUpdates`
6. Copy the `chat.id` value → paste as `TELEGRAM_CHAT_ID`

---

## 5. COWRIE SSH HONEYPOT SETUP (Linux/Kali)

> Cowrie runs best on Linux. On Windows, run it inside WSL or a Kali VM.

### Install Cowrie on Kali Linux:

```bash
sudo apt-get update
sudo apt-get install -y git python3-venv libssl-dev libffi-dev build-essential

git clone https://github.com/cowrie/cowrie.git /opt/cowrie
cd /opt/cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

### Configure Cowrie:

Edit `/opt/cowrie/etc/cowrie.cfg`:

```ini
[ssh]
listen_port = 2222

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json
```

### Start Cowrie:

```bash
cd /opt/cowrie
source cowrie-env/bin/activate
bin/cowrie start
```

### Link Cowrie logs to this project:

```bash
# Option 1: Symlink (Linux)
ln -sf /opt/cowrie/var/log/cowrie/cowrie.json \
  /mnt/c/Users/vetri/Desktop/FYProject/logs/cowrie/cowrie.json

# Option 2: Edit config.py to point to Cowrie's actual log path
COWRIE_LOG_PATH = "/opt/cowrie/var/log/cowrie/cowrie.json"
```

---

## 6. KALI LINUX ATTACK TESTING

Use these commands from your Kali attacker VM to generate realistic attack traffic.

### Test SSH Honeypot (Cowrie)

```bash
# Basic SSH brute force (5 attempts triggers detection)
for i in {1..10}; do
  sshpass -p "password$i" ssh -p 2222 -o StrictHostKeyChecking=no root@<HONEYPOT_IP>
done

# Automated brute force with hydra
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<HONEYPOT_IP>:2222
```

### Test Telnet Honeypot

```bash
# Manual Telnet
telnet <HONEYPOT_IP> 2323

# Automated Telnet brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://<HONEYPOT_IP>:2323
```

### Test Web Honeypot — SQL Injection

```bash
# SQLMap automated scan
sqlmap -u "http://<HONEYPOT_IP>:8080/product?id=1" --level=3 --risk=2

# Manual SQLi in browser
http://<HONEYPOT_IP>:8080/login
# Username: admin' OR 1=1 --
# Password: anything
```

### Test Web Honeypot — XSS

```bash
# In the login form username field, enter:
<script>alert('XSS')</script>

# Or via URL:
curl "http://<HONEYPOT_IP>:8080/search?q=<script>alert(1)</script>"
```

### Test Web Honeypot — Command Injection

```bash
curl "http://<HONEYPOT_IP>:8080/search?q=; ls -la /etc/passwd"
curl "http://<HONEYPOT_IP>:8080/search?q=&& cat /etc/shadow"
```

### Test Multi-Vector Attack (triggers Critical alert)

```bash
# Attack SSH AND Web simultaneously
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<HONEYPOT_IP>:2222 &
sqlmap -u "http://<HONEYPOT_IP>:8080/product?id=1" --batch &
telnet <HONEYPOT_IP> 2323 &
```

### Test DoS Simulation

```bash
# 20+ rapid requests → DoS detection
ab -n 100 -c 10 http://<HONEYPOT_IP>:8080/login

# Or with curl
for i in {1..30}; do
  curl -s "http://<HONEYPOT_IP>:8080/login" &
done
```

---

## 7. FOLDER STRUCTURE REFERENCE

```
C:\Users\vetri\Desktop\FYProject\
│
├── main.py                          ← START HERE
├── config.py                        ← Edit credentials
├── requirements.txt
│
├── database\
│   ├── __init__.py
│   ├── db_manager.py               ← SQLite operations
│   └── honeypot.db                 ← Auto-created on first run
│
├── geo\
│   ├── __init__.py
│   └── geo_lookup.py               ← ip-api geo lookup
│
├── detection\
│   ├── __init__.py
│   └── engine.py                   ← Rule-based threat detection
│
├── honeypots\
│   ├── __init__.py
│   ├── telnet_honeypot.py          ← Telnet trap server
│   ├── web_honeypot.py             ← Flask fake login + admin trap
│   └── cowrie_parser.py            ← Cowrie log parser
│
├── alerts\
│   ├── __init__.py
│   ├── email_alert.py              ← SMTP email alerts
│   └── telegram_alert.py          ← Telegram bot alerts
│
├── dashboard\
│   ├── __init__.py
│   ├── app.py                      ← Flask SOC dashboard + SocketIO
│   ├── templates\
│   │   ├── dashboard.html          ← SOC analyst UI
│   │   └── web_honeypot\
│   │       ├── login.html          ← Fake login page
│   │       └── admin.html          ← Fake admin panel
│   └── static\                     ← (CSS/JS served inline in HTML)
│
└── logs\
    └── cowrie\
        └── cowrie.json             ← Cowrie writes here
```

---

## 8. DETECTION RULES REFERENCE

| Rule | Trigger | Severity | Score |
|------|---------|----------|-------|
| R01 | 5+ login attempts in 10s (SSH/Telnet) | High | 8 |
| R02 | 20+ requests in 10s (DoS) | Critical | 10 |
| R03 | SQL keywords in payload | High/Critical | 7–9 |
| R04 | XSS pattern (`<script>`, etc.) | Medium | 5 |
| R05 | Command injection (`&&`, `;`, `/bin/`) | Critical | 9 |
| R06 | Path traversal (`../`) | Medium | 5 |
| R07 | Same IP targeting 2+ services | Critical | 9 |
| R08 | 3+ rapid web logins (credential stuffing) | High | 7 |
| R09 | Generic honeypot interaction | Low | 2 |

---

## 9. VIVA DEMONSTRATION SCRIPT

### Opening Statement
> "This project implements an Advanced Multi-Service Honeypot with a real-time SOC Analyst Dashboard. We deploy three honeypots — SSH via Cowrie, a custom Telnet socket server, and a Flask-based web honeypot — all feeding a central detection engine that scores, classifies, and displays threats in real time."

### Demo Sequence

1. **Show the running system** (`python main.py` output with all services started)
2. **Open SOC Dashboard** at `http://localhost:5000` — show dark theme, live counters, map
3. **Launch a Telnet brute force** from Kali:
   ```bash
   hydra -l admin -P rockyou.txt telnet://127.0.0.1:2323
   ```
   → Watch live feed update, map pin appear, High/Critical alert popup
4. **Launch SQLi against web honeypot**:
   ```bash
   curl "http://localhost:8080/login" -d "username=admin' OR 1=1--&password=x"
   ```
   → Show SQL Injection detected, Critical alert
5. **Click an attack in the feed** → Show Investigation Panel with full IP history
6. **Show Email / Telegram** received on your phone
7. **Open Database** (`honeypot.db`) in DB Browser for SQLite → show attacks table
8. **Explain the detection engine** (`engine.py`) — rules, scoring, containment logging

### Key Points to Emphasise
- No real firewall changes — all containment is simulated and logged
- Single SOC dashboard (not the web honeypot page)
- Real-time WebSocket (Socket.IO) — no page refresh needed
- Geo-cached lookup prevents rate limiting
- Modular design — each honeypot is independent and pluggable

---

## 10. TROUBLESHOOTING

| Problem | Solution |
|---------|----------|
| Port 5000 already in use | Change `SOC_DASHBOARD_PORT` in config.py |
| Port 2323 already in use | Change `TELNET_HONEYPOT_PORT` in config.py |
| Email not sending | Check App Password, enable "Less Secure" or use App Password |
| Telegram not sending | Verify BOT_TOKEN and CHAT_ID; send `/start` to bot first |
| Cowrie log not found | Set `COWRIE_LOG_PATH` to actual Cowrie log path in config.py |
| Map shows no pins | Check internet (ip-api.com requires outbound HTTP on port 80) |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` again |
| `eventlet` error | Run `pip install eventlet==0.36.1` |

---

## 11. DATABASE INSPECTION

Install DB Browser for SQLite:
https://sqlitebrowser.org/

Open: `C:\Users\vetri\Desktop\FYProject\database\honeypot.db`

Key tables:
- **attacks** — all detected attack events
- **response_actions** — simulated containment logs
- **geo_cache** — cached geo-location data

---

*Project by Vetrivel | Final Year Cybersecurity Project*
