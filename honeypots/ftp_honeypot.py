# =============================================================================
# honeypots/ftp_honeypot.py — FTP Honeypot Service
# Simulates an FTP server to capture attacker credentials and commands
# Listens on port 2121 (real FTP is 21, requires root)
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


class FTPClientHandler:
    """Handles a single FTP client connection in a fake FTP session."""

    FAKE_FILES = [
        "-rw-r--r-- 1 root root  4096 Jan 15 09:23 passwords.txt",
        "-rw-r--r-- 1 root root 12800 Jan 15 09:23 backup.tar.gz",
        "-rw-r--r-- 1 root root  2048 Jan 10 14:11 config.ini",
        "drwxr-xr-x 2 root root  4096 Jan 08 08:00 private",
        "-rw-r--r-- 1 root root 51200 Jan 14 22:30 database_dump.sql",
        "-rw-r--r-- 1 root root  1024 Jan 12 11:05 id_rsa",
        "drwxr-xr-x 2 root root  4096 Jan 09 15:20 uploads",
    ]

    def __init__(self, conn: socket.socket, addr: tuple, event_queue: queue.Queue):
        self.conn        = conn
        self.addr        = addr
        self.ip          = addr[0]
        self.event_queue = event_queue
        self.username    = ""
        self.authenticated = False

    def _send(self, msg: str):
        try:
            self.conn.sendall((msg + "\r\n").encode("utf-8", errors="replace"))
        except Exception:
            pass

    def _put_event(self, event_type: str, payload: str = "", username: str = ""):
        try:
            self.event_queue.put_nowait({
                "ip":         self.ip,
                "service":    "ftp",
                "event_type": event_type,
                "payload":    payload,
                "username":   username or self.username,
                "timestamp":  datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            })
        except queue.Full:
            pass

    def handle(self):
        try:
            self.conn.settimeout(120)
            self._send("220 Microsoft FTP Service")
            self._put_event("connect", "FTP connection established")

            buffer = ""
            while True:
                try:
                    data = self.conn.recv(1024).decode("utf-8", errors="replace")
                    if not data:
                        break
                    buffer += data
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip().rstrip("\r")
                        if line:
                            self._handle_command(line)
                except socket.timeout:
                    break
                except (ConnectionResetError, BrokenPipeError):
                    break
        except Exception as e:
            logger.debug("FTP handler error for %s: %s", self.ip, e)
        finally:
            try:
                self.conn.close()
            except Exception:
                pass
            logger.info("FTP session ended for %s", self.ip)

    def _handle_command(self, line: str):
        parts = line.split(None, 1)
        cmd   = parts[0].upper() if parts else ""
        arg   = parts[1] if len(parts) > 1 else ""

        logger.debug("FTP [%s] CMD: %s %s", self.ip, cmd, arg)

        if cmd == "USER":
            self.username = arg
            self._put_event("login_attempt", f"USER {arg}", arg)
            self._send("331 Password required for " + arg)

        elif cmd == "PASS":
            # Accept all passwords — honeypot logs everything
            self._put_event("auth", f"PASS attempt for user={self.username} pass={arg}",
                            self.username)
            self.authenticated = True
            self._send("230 User logged in.")
            logger.warning("FTP LOGIN: %s with pass=%s from %s",
                           self.username, arg, self.ip)

        elif cmd == "SYST":
            self._send("215 Windows_NT")

        elif cmd == "FEAT":
            self._send("211-Features:")
            self._send(" UTF8")
            self._send(" MLSD")
            self._send("211 End")

        elif cmd == "PWD":
            self._send('257 "/" is current directory.')

        elif cmd in ("LIST", "NLST", "MLSD"):
            self._put_event("command", f"{cmd} {arg}".strip())
            self._send("150 Opening ASCII mode data connection.")
            self._send("226 Transfer complete.")
            # In a real implementation, we'd open a data channel
            # For simplicity, we just log the attempt

        elif cmd == "RETR":
            self._put_event("command", f"RETR {arg}")
            self._send("550 Permission denied.")
            logger.warning("FTP FILE DOWNLOAD ATTEMPT: %s from %s", arg, self.ip)

        elif cmd == "STOR":
            self._put_event("command", f"STOR {arg}")
            self._send("550 Permission denied.")
            logger.warning("FTP FILE UPLOAD ATTEMPT: %s from %s", arg, self.ip)

        elif cmd == "DELE":
            self._put_event("command", f"DELE {arg}")
            self._send("550 Permission denied.")

        elif cmd in ("CWD", "CDUP"):
            self._put_event("command", f"{cmd} {arg}".strip())
            self._send("250 Directory changed.")

        elif cmd == "MKD":
            self._put_event("command", f"MKD {arg}")
            self._send("550 Permission denied.")

        elif cmd == "TYPE":
            self._send("200 Type set to " + arg)

        elif cmd in ("PASV", "EPSV"):
            # Fake passive mode
            self._send("227 Entering Passive Mode (127,0,0,1,19,136).")

        elif cmd in ("PORT", "EPRT"):
            self._send("200 PORT command successful.")

        elif cmd == "NOOP":
            self._send("200 NOOP ok.")

        elif cmd == "QUIT":
            self._send("221 Goodbye.")
            raise ConnectionResetError("QUIT")

        elif cmd == "HELP":
            self._send("214 The following commands are recognized.")

        else:
            self._put_event("command", f"UNKNOWN: {line}")
            self._send("500 Unknown command.")


class FTPHoneypot:
    """
    Listens on FTP_HONEYPOT_PORT and spawns a handler thread per connection.
    """

    def __init__(self, event_queue: queue.Queue,
                 host: str = "0.0.0.0",
                 port: int = None):
        self.event_queue = event_queue
        self.host        = host
        self.port        = port or config.FTP_HONEYPOT_PORT
        self._stop_event = threading.Event()
        self._server_sock = None

    def start(self):
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.host, self.port))
            self._server_sock.listen(50)
            self._server_sock.settimeout(1.0)
            logger.info("FTP honeypot listening on %s:%d", self.host, self.port)

            while not self._stop_event.is_set():
                try:
                    conn, addr = self._server_sock.accept()
                    logger.info("FTP connection from %s:%d", addr[0], addr[1])
                    handler = FTPClientHandler(conn, addr, self.event_queue)
                    t = threading.Thread(
                        target=handler.handle,
                        daemon=True,
                        name=f"FTP-{addr[0]}",
                    )
                    t.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if not self._stop_event.is_set():
                        logger.error("FTP accept error: %s", e)

        except OSError as e:
            logger.error("FTP honeypot failed to bind port %d: %s", self.port, e)
        finally:
            if self._server_sock:
                try:
                    self._server_sock.close()
                except Exception:
                    pass

    def stop(self):
        self._stop_event.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
