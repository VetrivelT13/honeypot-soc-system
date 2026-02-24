# =============================================================================
# honeypots/telnet_honeypot.py — Python Telnet Honeypot Server
# Listens on TCP port 2323, logs all interactions, feeds detection engine
# =============================================================================

import socket
import threading
import logging
import queue
from datetime import datetime

import sys
sys.path.insert(0, r"C:\Users\vetri\Desktop\FYProject")
import config

logger = logging.getLogger(__name__)

# Fake terminal banner
_BANNER = (
    b"\r\n"
    b"Ubuntu 20.04.6 LTS\r\n"
    b"Kernel 5.15.0-91-generic on an x86_64\r\n"
    b"\r\n"
    b"login: "
)

_PASSWORD_PROMPT = b"Password: "

_FAKE_SHELL = b"$ "

_WELCOME_MSG = b"\r\nLast login: Mon Jan 15 09:32:11 2024 from 10.0.0.1\r\n"

# Commands that get a fake response (to keep attacker engaged longer)
_FAKE_RESPONSES = {
    "whoami":   b"root\r\n",
    "id":       b"uid=0(root) gid=0(root) groups=0(root)\r\n",
    "pwd":      b"/root\r\n",
    "uname -a": b"Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n",
    "ls":       b"bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\r\n",
    "ls -la":   b"total 64\r\ndrwxr-xr-x 19 root root 4096 Jan 15 09:00 .\r\ndrwxr-xr-x 19 root root 4096 Jan 15 09:00 ..\r\n",
    "cat /etc/passwd": b"root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n",
    "ifconfig": b"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 192.168.1.100  netmask 255.255.255.0\r\n",
    "ps aux":   b"USER       PID %CPU %MEM    VSZ   RSS TTY      STAT\r\nroot         1  0.0  0.1 225472  9136 ?        Ss\r\n",
}

_MAX_CMD_LEN = 512


class TelnetClientHandler(threading.Thread):
    """Handles a single Telnet client connection in its own thread."""

    def __init__(self, conn: socket.socket, addr: tuple,
                 event_queue: queue.Queue):
        super().__init__(daemon=True)
        self.conn        = conn
        self.addr        = addr
        self.ip          = addr[0]
        self.event_queue = event_queue
        self.authenticated = False

    def run(self):
        logger.info("Telnet connection from %s", self.ip)
        try:
            self._handle()
        except Exception as e:
            logger.debug("Telnet handler error for %s: %s", self.ip, e)
        finally:
            try:
                self.conn.close()
            except Exception:
                pass
            logger.info("Telnet session closed for %s", self.ip)

    def _handle(self):
        self.conn.settimeout(60)
        self.conn.sendall(_BANNER)

        username = self._readline(prompt=None)
        if not username:
            return

        self._log_event("login_attempt", f"USERNAME:{username}")
        self.conn.sendall(_PASSWORD_PROMPT)

        password = self._readline(prompt=None)
        if not password:
            return

        self._log_event("login_attempt", f"USERNAME:{username} PASSWORD:{password}")

        # Always pretend auth succeeded (honeypot behaviour)
        self.conn.sendall(_WELCOME_MSG)
        self.authenticated = True
        self.conn.sendall(_FAKE_SHELL)

        # Command loop
        cmd_count = 0
        while cmd_count < 50:
            cmd = self._readline(prompt=None)
            if cmd is None:
                break
            if cmd == "":
                self.conn.sendall(_FAKE_SHELL)
                continue

            self._log_event("command", cmd)
            cmd_count += 1

            if cmd.lower() in ("exit", "logout", "quit"):
                self.conn.sendall(b"logout\r\n")
                break

            response = _FAKE_RESPONSES.get(cmd.lower(),
                                           f"-bash: {cmd}: command not found\r\n".encode())
            self.conn.sendall(response)
            self.conn.sendall(_FAKE_SHELL)

    def _readline(self, prompt=None) -> str:
        """Read a line from the socket, character by character."""
        if prompt:
            self.conn.sendall(prompt)
        buf = b""
        try:
            while True:
                ch = self.conn.recv(1)
                if not ch:
                    return None
                if ch in (b"\r", b"\n"):
                    # echo newline
                    self.conn.sendall(b"\r\n")
                    break
                if ch == b"\x08":   # backspace
                    if buf:
                        buf = buf[:-1]
                        self.conn.sendall(b"\x08 \x08")
                elif ch == b"\x03":  # Ctrl+C
                    return None
                else:
                    buf += ch
                    self.conn.sendall(ch)   # echo char
                if len(buf) > _MAX_CMD_LEN:
                    break
        except socket.timeout:
            return None
        return buf.decode(errors="replace").strip()

    def _log_event(self, event_type: str, payload: str):
        """Put a normalised event onto the shared detection queue."""
        event = {
            "ip":         self.ip,
            "service":    "telnet",
            "event_type": event_type,
            "payload":    payload,
            "username":   "",
            "timestamp":  datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        }
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            logger.warning("Event queue full — dropping Telnet event from %s", self.ip)


class TelnetHoneypot:
    """
    TCP server that listens on TELNET_HONEYPOT_PORT and spawns a
    TelnetClientHandler thread per connection.
    """

    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue
        self.port        = config.TELNET_HONEYPOT_PORT
        self._stop_event = threading.Event()
        self._server_sock = None

    def start(self):
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._server_sock.bind(("0.0.0.0", self.port))
            self._server_sock.listen(50)
            self._server_sock.settimeout(1.0)
            logger.info("Telnet honeypot listening on port %d", self.port)

            while not self._stop_event.is_set():
                try:
                    conn, addr = self._server_sock.accept()
                    handler = TelnetClientHandler(conn, addr, self.event_queue)
                    handler.start()
                except socket.timeout:
                    continue
                except OSError:
                    break
        except OSError as e:
            logger.error("Telnet honeypot failed to bind port %d: %s", self.port, e)
        finally:
            if self._server_sock:
                self._server_sock.close()
            logger.info("Telnet honeypot stopped.")

    def stop(self):
        self._stop_event.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
