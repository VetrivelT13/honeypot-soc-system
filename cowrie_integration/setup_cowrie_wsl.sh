#!/bin/bash
# =============================================================================
# setup_cowrie_wsl.sh — Automated Cowrie SSH Honeypot Setup for WSL
# Run this INSIDE WSL (Ubuntu): bash setup_cowrie_wsl.sh
# =============================================================================

set -e  # Exit immediately on any error

COWRIE_DIR="/opt/cowrie"
COWRIE_USER="cowrie"
WIN_LOG_PATH="/mnt/c/Users/vetri/Desktop/FYProject/logs/cowrie"
COWRIE_VENV="$COWRIE_DIR/cowrie-env"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() { echo -e "\n${CYAN}${BOLD}══ $1 ══${NC}\n"; }
ok()     { echo -e "${GREEN}✓ $1${NC}"; }
warn()   { echo -e "${YELLOW}⚠ $1${NC}"; }
fail()   { echo -e "${RED}✗ $1${NC}"; exit 1; }

# ── 0. Check WSL ─────────────────────────────────────────────────────────────
banner "Checking Environment"
if ! grep -qi microsoft /proc/version 2>/dev/null; then
    warn "Not running in WSL. This script is designed for WSL/Ubuntu."
    warn "Continuing anyway — may work on native Linux too."
fi
ok "Environment check passed"

# ── 1. System Dependencies ────────────────────────────────────────────────────
banner "Installing System Dependencies"
sudo apt-get update -qq
sudo apt-get install -y -qq \
    git \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    libssl-dev \
    libffi-dev \
    build-essential \
    authbind \
    virtualenv \
    2>/dev/null
ok "System dependencies installed"

# ── 2. Create cowrie system user (if not exists) ──────────────────────────────
banner "Setting Up Cowrie User"
if ! id "$COWRIE_USER" &>/dev/null; then
    sudo adduser --disabled-password --gecos "" "$COWRIE_USER"
    ok "Created user: $COWRIE_USER"
else
    ok "User $COWRIE_USER already exists"
fi

# ── 3. Clone Cowrie ───────────────────────────────────────────────────────────
banner "Cloning Cowrie Repository"
if [ -d "$COWRIE_DIR" ]; then
    warn "Cowrie already exists at $COWRIE_DIR — pulling latest updates"
    sudo git -C "$COWRIE_DIR" pull --quiet
else
    sudo git clone --quiet https://github.com/cowrie/cowrie.git "$COWRIE_DIR"
    ok "Cowrie cloned to $COWRIE_DIR"
fi
sudo chown -R "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_DIR"

# ── 4. Python Virtual Environment ─────────────────────────────────────────────
banner "Creating Python Virtual Environment"
sudo -u "$COWRIE_USER" python3 -m venv "$COWRIE_VENV"
ok "Virtual environment created at $COWRIE_VENV"

# ── 5. Install Python Dependencies ───────────────────────────────────────────
banner "Installing Cowrie Python Dependencies"
sudo -u "$COWRIE_USER" "$COWRIE_VENV/bin/pip" install --quiet --upgrade pip
sudo -u "$COWRIE_USER" "$COWRIE_VENV/bin/pip" install --quiet -r "$COWRIE_DIR/requirements.txt"
ok "Cowrie Python dependencies installed"

# ── 6. Windows Log Directory ──────────────────────────────────────────────────
banner "Setting Up Windows Log Directory"
if [ -d "$WIN_LOG_PATH" ]; then
    ok "Windows log directory already exists: $WIN_LOG_PATH"
else
    mkdir -p "$WIN_LOG_PATH" 2>/dev/null || {
        warn "Could not create $WIN_LOG_PATH — Windows drive may not be mounted"
        warn "Make sure your Windows C: drive is accessible at /mnt/c/"
        warn "Run: ls /mnt/c/Users/vetri/Desktop/ to verify"
    }
fi

# Make sure cowrie user can write to the Windows path
sudo chmod 777 "$WIN_LOG_PATH" 2>/dev/null || true
ok "Log directory ready: $WIN_LOG_PATH"

# ── 7. Deploy Cowrie Config ───────────────────────────────────────────────────
banner "Deploying Cowrie Configuration"
sudo cp /tmp/cowrie_fyproject.cfg "$COWRIE_DIR/etc/cowrie.cfg" 2>/dev/null || {
    # If the pre-generated config isn't there, write it inline
    sudo tee "$COWRIE_DIR/etc/cowrie.cfg" > /dev/null << 'COWRIE_CFG'
[honeypot]
hostname = corporate-server
log_path = ${honeypot:state_path}/log
download_path = ${honeypot:state_path}/downloads
share_path = ${honeypot:data_path}
state_path = var
etc_path = etc
data_path = data
contents_path = honeyfs

# Fake OS details
kernel_version = 5.15.0-91-generic
kernel_build_string = #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023
hardware_platform = x86_64
operating_system = GNU/Linux

[ssh]
# Listen on port 2222 (redirect 22->2222 via iptables if needed)
listen_port = 2222
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
rsa_public_key = data/ssh_host_rsa_key.pub
rsa_private_key = data/ssh_host_rsa_key
dsa_public_key = data/ssh_host_dsa_key.pub
dsa_private_key = data/ssh_host_dsa_key
ecdsa_public_key = data/ssh_host_ecdsa_key.pub
ecdsa_private_key = data/ssh_host_ecdsa_key

# Accept any username/password (full honey trap)
auth_class = UserDB
auth_class_parameters = userdb.txt

[output_jsonlog]
enabled = true
logfile = /mnt/c/Users/vetri/Desktop/FYProject/logs/cowrie/cowrie.json

[output_textlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.log

[shell]
filesystem = ${honeypot:data_path}/fs.pickle
fake_passwd = ${honeypot:data_path}/userdb.txt
COWRIE_CFG
    ok "cowrie.cfg written inline"
}
ok "Cowrie configuration deployed"

# ── 8. Create userdb (accept all logins) ─────────────────────────────────────
banner "Setting Up Credential Database"
sudo tee "$COWRIE_DIR/etc/userdb.txt" > /dev/null << 'USERDB'
# Cowrie UserDB — format: username:uid:password
# * means accept any value
root:0:*
admin:0:*
administrator:0:*
user:1000:*
ubuntu:1000:*
pi:1000:*
oracle:1000:*
test:1000:*
guest:1000:*
USERDB
sudo chown "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_DIR/etc/userdb.txt"
ok "Credential database set — honeypot accepts all logins"

# ── 9. Generate SSH Host Keys ─────────────────────────────────────────────────
banner "Generating SSH Host Keys"
cd "$COWRIE_DIR"
if [ ! -f "data/ssh_host_rsa_key" ]; then
    sudo -u "$COWRIE_USER" "$COWRIE_VENV/bin/python" bin/createfs 2>/dev/null || true
    sudo -u "$COWRIE_USER" ssh-keygen -t rsa -b 2048 \
        -f data/ssh_host_rsa_key -N "" -q 2>/dev/null || true
    sudo -u "$COWRIE_USER" ssh-keygen -t dsa -b 1024 \
        -f data/ssh_host_dsa_key -N "" -q 2>/dev/null || true
    sudo -u "$COWRIE_USER" ssh-keygen -t ecdsa -b 256 \
        -f data/ssh_host_ecdsa_key -N "" -q 2>/dev/null || true
    ok "SSH host keys generated"
else
    ok "SSH host keys already exist"
fi

# ── 10. Create startup script ─────────────────────────────────────────────────
banner "Creating Startup Script"
sudo tee /usr/local/bin/start-cowrie.sh > /dev/null << 'STARTUP'
#!/bin/bash
# Start Cowrie SSH Honeypot and tail its log
LOG=/mnt/c/Users/vetri/Desktop/FYProject/logs/cowrie/cowrie.json
touch "$LOG" 2>/dev/null || true
cd /opt/cowrie
source cowrie-env/bin/activate
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting Cowrie SSH Honeypot on port 2222..."
exec sudo -u cowrie /opt/cowrie/cowrie-env/bin/twistd \
    --umask=0022 \
    --pidfile=/opt/cowrie/var/run/cowrie.pid \
    --logger=cowrie.python.logfile.logger \
    cowrie
STARTUP
sudo chmod +x /usr/local/bin/start-cowrie.sh

# Also create a simple foreground runner for demo use
sudo tee /usr/local/bin/cowrie-fg.sh > /dev/null << 'FGSCRIPT'
#!/bin/bash
# Run Cowrie in foreground (shows live output — good for demos)
cd /opt/cowrie
sudo -u cowrie cowrie-env/bin/python -m cowrie.core.launch \
    -c etc/cowrie.cfg 2>&1 | \
    grep --line-buffered -E "(login|command|connect|download|cowrie)" | \
    while read line; do
        echo "[COWRIE] $line"
    done
FGSCRIPT
sudo chmod +x /usr/local/bin/cowrie-fg.sh

ok "Startup scripts created"

# ── 11. Port Redirect (optional, for port 22) ─────────────────────────────────
banner "Optional: Port 22 Redirect"
echo -e "${YELLOW}To redirect real SSH port 22 → Cowrie port 2222, run:${NC}"
echo "  sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222"
echo "  (Skip this if you are testing on localhost — port 2222 is fine)"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       COWRIE SETUP COMPLETE ✓                        ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  SSH Honeypot Port : 2222                            ║"
echo "║  Log Output        : Windows FYProject logs folder   ║"
echo "║  Start Command     : bash start_cowrie_wsl.sh        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${CYAN}Next step: Open a NEW WSL terminal and run:${NC}"
echo -e "  ${BOLD}cd /mnt/c/Users/vetri/Desktop/FYProject/cowrie_integration${NC}"
echo -e "  ${BOLD}bash start_cowrie_wsl.sh${NC}"
