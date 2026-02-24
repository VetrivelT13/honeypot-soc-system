#!/bin/bash
COWRIE_DIR="/opt/cowrie"
WIN_LOG_PATH="/mnt/c/Users/vetri/Desktop/FYProject/logs/cowrie"
LOG_FILE="$WIN_LOG_PATH/cowrie.json"

echo " +-------------------------------------------------+"
echo " |  COWRIE SSH HONEYPOT - Starting...              |"
echo " |  Port       : 2222                              |"
echo " +-------------------------------------------------+"

# --- Verify Cowrie installation ---
if [ ! -d "$COWRIE_DIR" ]; then
    echo "[ERROR] Cowrie not found at $COWRIE_DIR"
    echo "        Run setup_cowrie.bat first!"
    read -r -p "Press Enter to close..."
    exit 1
fi

# --- Prepare directories ---
mkdir -p "$WIN_LOG_PATH"
sudo -u cowrie mkdir -p "$COWRIE_DIR/var/run"
sudo -u cowrie mkdir -p "$COWRIE_DIR/var/log/cowrie"
sudo -u cowrie mkdir -p "$COWRIE_DIR/var/tty"
sudo -u cowrie mkdir -p "$COWRIE_DIR/var/lib/cowrie/downloads"
sudo -u cowrie mkdir -p "$COWRIE_DIR/var/lib/cowrie/tty"
sudo -u cowrie mkdir -p "$COWRIE_DIR/data"
touch "$LOG_FILE" 2>/dev/null
chmod 666 "$LOG_FILE" 2>/dev/null
sudo chown -R cowrie:cowrie "$COWRIE_DIR/var" 2>/dev/null

# --- Copy required data files if missing ---
[ ! -f "$COWRIE_DIR/data/fs.pickle" ] && sudo -u cowrie cp "$COWRIE_DIR/src/cowrie/data/fs.pickle" "$COWRIE_DIR/data/fs.pickle" 2>/dev/null
[ ! -f "$COWRIE_DIR/data/cmdoutput.json" ] && sudo -u cowrie cp "$COWRIE_DIR/src/cowrie/data/cmdoutput.json" "$COWRIE_DIR/data/cmdoutput.json" 2>/dev/null
[ ! -d "$COWRIE_DIR/data/txtcmds" ] && sudo -u cowrie cp -r "$COWRIE_DIR/src/cowrie/data/txtcmds" "$COWRIE_DIR/data/txtcmds" 2>/dev/null
[ ! -d "$COWRIE_DIR/data/arch" ] && sudo -u cowrie cp -r "$COWRIE_DIR/src/cowrie/data/arch" "$COWRIE_DIR/data/arch" 2>/dev/null

# --- Create userdb.txt in etc_path if missing (accepts any password) ---
if [ ! -f "$COWRIE_DIR/etc/userdb.txt" ]; then
    sudo bash -c "cat > $COWRIE_DIR/etc/userdb.txt << 'EOF'
root:x:*
admin:x:*
administrator:x:*
user:x:*
ubuntu:x:*
pi:x:*
guest:x:*
test:x:*
oracle:x:*
postgres:x:*
EOF"
    sudo chown cowrie:cowrie "$COWRIE_DIR/etc/userdb.txt"
fi

# --- Generate SSH host keys if missing ---
if [ ! -f "$COWRIE_DIR/data/ssh_host_rsa_key" ]; then
    sudo -u cowrie bash -c "cd /opt/cowrie && cowrie-env/bin/python3 -c 'from cowrie.ssh import keys; keys.getRSAKeys()'" 2>/dev/null
fi

# --- Stop existing instance ---
if [ -f "$COWRIE_DIR/var/run/cowrie.pid" ]; then
    OLD_PID=$(cat "$COWRIE_DIR/var/run/cowrie.pid" 2>/dev/null)
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        echo "[INFO] Stopping old Cowrie instance (PID $OLD_PID)..."
        sudo kill "$OLD_PID" 2>/dev/null
        sleep 2
    fi
    rm -f "$COWRIE_DIR/var/run/cowrie.pid"
fi

# --- Install Cowrie as Python package (registers twistd plugin) ---
echo "[INFO] Registering Cowrie with Twisted plugin system..."
sudo -u cowrie bash -c "
    source /opt/cowrie/cowrie-env/bin/activate
    pip install -e /opt/cowrie --quiet 2>/dev/null
" 2>/dev/null

# --- Clear Twisted plugin cache (forces re-discovery) ---
find "$COWRIE_DIR" -name "dropin.cache" -delete 2>/dev/null
find "$COWRIE_DIR/cowrie-env" -name "dropin.cache" -delete 2>/dev/null
echo "[OK] Plugin cache cleared."

# --- Write the startup script to a temp file ---
cat > /tmp/run_cowrie.sh << 'STARTSCRIPT'
#!/bin/bash
cd /opt/cowrie
source /opt/cowrie/cowrie-env/bin/activate
export PYTHONPATH=/opt/cowrie

# Verify cowrie plugin is discoverable
python -c "from cowrie.core import plugin" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[ERROR] Cowrie Python package not importable. Reinstalling..."
    pip install -e /opt/cowrie --quiet
fi

/opt/cowrie/cowrie-env/bin/twistd \
    --umask=0022 \
    --pidfile=/opt/cowrie/var/run/cowrie.pid \
    --logfile=/opt/cowrie/var/log/cowrie/twistd.log \
    cowrie
STARTSCRIPT

chmod +x /tmp/run_cowrie.sh
sudo chown cowrie:cowrie /tmp/run_cowrie.sh

# --- Start Cowrie ---
echo "[INFO] Starting Cowrie..."
sudo -u cowrie /tmp/run_cowrie.sh
sleep 3

# --- Check if started ---
if [ ! -f "$COWRIE_DIR/var/run/cowrie.pid" ]; then
    echo ""
    echo "[ERROR] Cowrie failed to start. Error details:"
    echo "---"
    cat "$COWRIE_DIR/var/log/cowrie/twistd.log" 2>/dev/null | tail -30
    echo "---"
    read -r -p "Press Enter to close..."
    exit 1
fi

PID=$(cat "$COWRIE_DIR/var/run/cowrie.pid")
echo "[OK] Cowrie is running! PID: $PID"
echo "[OK] JSON logs writing to: $LOG_FILE"
echo ""
echo "--- Live SSH Attack Feed (Ctrl+C stops viewing, Cowrie keeps running) ---"
echo ""

# --- Python display helper written to temp file ---
cat > /tmp/cowrie_display.py << 'PYEOF'
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
        ev  = d.get('eventid', '')
        ip  = d.get('src_ip', '?')
        ts  = d.get('timestamp', '')[:19]
        usr = d.get('username', '')
        cmd = d.get('input', '')
        url = d.get('url', '')
        if   'login.failed'  in ev: msg = '[FAIL] ' + ts + '  ' + ip.ljust(20) + '  LOGIN ATTEMPT  user=' + usr
        elif 'login.success' in ev: msg = '[PASS] ' + ts + '  ' + ip.ljust(20) + '  LOGIN SUCCESS  user=' + usr
        elif 'command.input' in ev: msg = '[CMD ] ' + ts + '  ' + ip.ljust(20) + '  ' + cmd[:60]
        elif 'connect'       in ev: msg = '[CONN] ' + ts + '  ' + ip.ljust(20) + '  CONNECTED'
        elif 'closed'        in ev: msg = '[DISC] ' + ts + '  ' + ip.ljust(20) + '  DISCONNECTED'
        elif 'download'      in ev: msg = '[FILE] ' + ts + '  ' + ip.ljust(20) + '  DOWNLOAD  ' + url
        else: msg = ''
        if msg:
            print(msg)
            sys.stdout.flush()
    except:
        pass
PYEOF

tail -F "$LOG_FILE" 2>/dev/null | python3 /tmp/cowrie_display.py
