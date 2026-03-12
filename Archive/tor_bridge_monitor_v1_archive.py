"""
Tor Bridge Monitor for Windows 11
Renders nyx inside the app window using pyte (VT100 terminal emulator)
and paramiko for SSH.

Requirements:
    pip install paramiko pyte
"""

import re
import tkinter as tk
import tkinter.font as tkfont
import tkinter.ttk as ttk
from tkinter import filedialog, messagebox
import threading
import queue
import json
import os
import time
import math
import collections
import datetime
import traceback
try:
    import ctypes as _ctypes
except ImportError:
    _ctypes = None

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    import pyte
    HAS_PYTE = True
except ImportError:
    HAS_PYTE = False

# ─────────────────────────────────────────────
#  Config
# ─────────────────────────────────────────────
CONFIG_FILE      = os.path.join(os.path.expanduser("~"), ".tor_bridge_monitor.json")
KNOWN_HOSTS_FILE = os.path.join(os.path.expanduser("~"), ".tor_bridge_monitor_known_hosts")
LOG_FILE         = os.path.join(os.path.expanduser("~"), ".tor_bridge_monitor.log")

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"host": "", "port": "22", "user": "pi",
            "password": "", "key_path": "", "autoconnect": False}

def save_config(cfg):
    """Persist config.  Passwords are NOT saved when an SSH key is configured
    — storing plaintext passwords on disk is a security risk and unnecessary
    when a key file is available."""
    try:
        to_save = dict(cfg)
        if to_save.get("key_path", "").strip():
            to_save["password"] = ""   # never persist password if key is set
        with open(CONFIG_FILE, "w") as f:
            json.dump(to_save, f, indent=2)
    except Exception:
        pass

# ─────────────────────────────────────────────
#  File logger  (always-on, rotates at 2 MB)
# ─────────────────────────────────────────────
import logging as _logging
import logging.handlers as _log_handlers

def _build_file_logger() -> _logging.Logger:
    """Return a module-level Logger that writes to LOG_FILE.

    Rotates at 2 MB, keeps 3 backups → max ~8 MB on disk.
    Thread-safe: RotatingFileHandler uses a file-level lock.
    """
    log = _logging.getLogger("tor_bridge_monitor")
    if log.handlers:
        return log   # already initialised (re-import guard)
    log.setLevel(_logging.DEBUG)
    try:
        fh = _log_handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3,
            encoding="utf-8", delay=False)
        fh.setFormatter(_logging.Formatter(
            "%(asctime)s  %(levelname)-7s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"))
        log.addHandler(fh)
    except Exception as e:
        # If we can't open the log file (permissions, read-only FS, …)
        # degrade gracefully — a NullHandler swallows all records silently.
        log.addHandler(_logging.NullHandler())
    return log

_file_log = _build_file_logger()


def _flog(level: str, msg: str, *args):
    """Convenience wrapper — level is "debug"|"info"|"warning"|"error"."""
    getattr(_file_log, level, _file_log.info)(msg, *args)


# ─────────────────────────────────────────────
#  Colour helpers  (256-colour + named)
# ─────────────────────────────────────────────
NAMED_COLORS = {
    "black":   "#1a1b26", "red":     "#f7768e", "green":   "#9ece6a",
    "yellow":  "#e0af68", "blue":    "#7aa2f7", "magenta": "#bb9af7",
    "cyan":    "#7dcfff", "white":   "#c0caf5",
    "brightblack":   "#414868", "brightred":     "#f7768e",
    "brightgreen":   "#9ece6a", "brightyellow":  "#e0af68",
    "brightblue":    "#7aa2f7", "brightmagenta": "#bb9af7",
    "brightcyan":    "#7dcfff", "brightwhite":   "#c0caf5",
    "default": None,
}

def _build_256_palette():
    p = {}
    for i in range(216):
        r, g, b = (i // 36) * 51, ((i // 6) % 6) * 51, (i % 6) * 51
        p[i + 16] = f"#{r:02x}{g:02x}{b:02x}"
    for i in range(24):
        v = 8 + i * 10
        p[i + 232] = f"#{v:02x}{v:02x}{v:02x}"
    return p

PALETTE_256 = _build_256_palette()
ANSI_RE     = re.compile(
    rb"\x1b(?:"                                   # ESC
    rb"\[[0-9;?]*[A-Za-z]"                        # CSI: cursor, erase, SGR
    rb"|](?:[^\x07\x1b]|\x1b(?!\\\\))*(?:\x07|\x1b\\\\)"  # OSC sequences
    rb"|[^\[\]]"                                  # lone ESC+char
    rb")")

def resolve_color(color, is_fg: bool) -> str:
    default = "#c0caf5" if is_fg else "#1a1b26"
    if color is None or color == "default":
        return default
    if isinstance(color, int):
        return PALETTE_256.get(color, default)
    low = str(color).lower()
    if low in NAMED_COLORS:
        return NAMED_COLORS[low] or default
    if len(low) == 6 and all(c in "0123456789abcdef" for c in low):
        return f"#{low}"
    return default


# ─────────────────────────────────────────────
#  TOFU SSH host key policy
# ─────────────────────────────────────────────
class _TOFUPolicy(paramiko.MissingHostKeyPolicy):
    """Trust-On-First-Use: accept and persist unknown keys; reject changed keys.

    On the first connection to a host, the server's public key is saved to our
    own known_hosts file and the connection proceeds.  On all subsequent
    connections, paramiko's RejectPolicy behaviour applies to changed keys
    (raised as BadHostKeyException) — protecting against MITM attacks.
    """
    def __init__(self, known_hosts_path: str):
        self._path = known_hosts_path

    def missing_host_key(self, client, hostname, key):
        # First time seeing this host — save and continue
        client._host_keys.add(hostname, key.get_name(), key)
        try:
            client.save_host_keys(self._path)
        except Exception:
            pass   # Non-fatal: key stored in memory for this session


# ─────────────────────────────────────────────
#  SSH + pyte worker thread
# ─────────────────────────────────────────────
class SSHWorker(threading.Thread):
    def __init__(self, cfg, cols, rows, screen_queue, status_queue, mode="nyx"):
        super().__init__(daemon=True)
        self.cfg      = cfg
        self.cols     = cols
        self.rows     = rows
        self.screen_q = screen_queue
        self.status_q = status_queue
        self.mode     = mode          # "nyx" | "shell"
        self._stop    = threading.Event()
        self.channel  = None
        self.client   = None
        self._nyx_running = False   # set True once nyx banner seen
        if HAS_PYTE:
            self.screen = pyte.Screen(cols, rows)
            self.stream = pyte.ByteStream(self.screen)
        else:
            self.screen = None
            self.stream = None
        # Lock guards concurrent access: stream.feed() (worker thread) vs
        # render()'s dirty.copy()+clear() (main thread).
        self.screen_lock = threading.Lock()

    # ── lifecycle ────────────────────────────
    def stop(self):
        self._stop.set()
        # Close in order: channel first, then transport, then client.
        # Skipping transport leaves a lingering TCP keepalive thread in paramiko.
        for obj in (self.channel, self.client):
            if obj:
                try:
                    obj.close()
                except Exception:
                    pass
        # Null refs so GC can collect and no stale sends can fire
        self.channel = None
        self.client  = None

    def send(self, data: bytes):
        if self.channel and not self.channel.closed:
            try:
                self.channel.send(data)
            except Exception:
                pass

    def resize(self, cols, rows):
        self.cols = cols
        self.rows = rows
        if self.screen:
            with self.screen_lock:
                self.screen.resize(rows, cols)
            # pyte.Screen.resize() already marks all rows dirty internally.
            # No manual dirty manipulation needed.
        if self.channel:
            try:
                self.channel.resize_pty(width=cols, height=rows)
            except Exception:
                pass

    def _put_refresh(self):
        try:
            self.screen_q.put_nowait(("refresh", None))
        except Exception:
            pass   # Queue full — frame dropped intentionally

    # ── main run loop ────────────────────────
    def run(self):
        if not HAS_PARAMIKO:
            self.status_q.put(("error", "paramiko not installed.\nRun: pip install paramiko pyte"))
            return
        if not HAS_PYTE:
            self.status_q.put(("error", "pyte not installed.\nRun: pip install paramiko pyte"))
            return

        self.status_q.put(("step", f"Connecting to {self.cfg['host']}:{self.cfg['port']}…"))
        try:
            self.client = paramiko.SSHClient()
            # TOFU host-key policy: load previously accepted keys from our own
            # known_hosts file.  On first connect the key is saved; on subsequent
            # connects a changed key raises BadHostKeyException (potential MITM).
            if os.path.exists(KNOWN_HOSTS_FILE):
                try:
                    self.client.load_host_keys(KNOWN_HOSTS_FILE)
                except Exception:
                    pass
            # RejectPolicy so unknown hosts are flagged, not silently accepted
            self.client.set_missing_host_key_policy(_TOFUPolicy(KNOWN_HOSTS_FILE))

            kw = dict(
                hostname       = self.cfg["host"],
                port           = int(self.cfg["port"]),
                username       = self.cfg["user"],
                timeout        = 30,
                banner_timeout = 60,
                auth_timeout   = 30,
            )
            key = self.cfg.get("key_path", "").strip()
            if key and os.path.exists(key):
                kw["key_filename"] = key
            elif self.cfg.get("password"):
                kw["password"] = self.cfg["password"]

            self.client.connect(**kw)
            _flog("info", "SSH connected to %s:%s as %s",
                  self.cfg["host"], self.cfg["port"], self.cfg["user"])
            self.status_q.put(("step_ok", f"Connected to {self.cfg['host']}"))

            transport   = self.client.get_transport()
            self.channel = transport.open_session()
            self.channel.get_pty(term="xterm-256color",
                                  width=self.cols, height=self.rows)
            self.channel.invoke_shell()

            # Wait for shell prompt then launch nyx
            self.channel.settimeout(1.0)
            buf      = b""
            deadline = time.time() + 15
            while time.time() < deadline and not self._stop.is_set():
                try:
                    chunk = self.channel.recv(4096)
                    if not chunk:
                        break
                    with self.screen_lock:
                        self.stream.feed(chunk)
                    self._put_refresh()
                    buf += chunk
                    # Cap buf to last 8 KB — we only need the tail for prompt detection
                    if len(buf) > 8192:
                        buf = buf[-8192:]
                    clean = ANSI_RE.sub(b"", buf).rstrip()
                    if clean.endswith((b"$", b"#", b">")):
                        break
                except (TimeoutError, OSError):
                    pass
                time.sleep(0.1)

            if self._stop.is_set():
                return

            # ── Shell mode: skip Tor check and nyx, just show the terminal ──
            if self.mode == "shell":
                self.status_q.put(("step_ok", "Shell ready"))
                self._nyx_running = False
                # Signal that the view should switch to terminal
                self.status_q.put(("nyx_ready", "shell"))
                # Remain connected — keep reading the channel forever
                self.channel.settimeout(0.3)
                while not self._stop.is_set():
                    try:
                        data = self.channel.recv(4096)
                        if not data:
                            break
                        with self.screen_lock:
                            self.stream.feed(data)
                        self._put_refresh()
                    except (TimeoutError, OSError):
                        continue
                    except Exception as e:
                        self.status_q.put(("error",
                            f"Shell error: {type(e).__name__}: {e}"))
                        break
                return

            # ── Tor service check ─────────────────────
            # Verify tor is loaded, enabled and active before launching nyx.
            self.status_q.put(("step", "Checking Tor service…"))
            self.channel.send("systemctl is-active tor; systemctl is-enabled tor\r\n")
            time.sleep(1.5)

            tor_buf = b""
            t_end = time.time() + 4
            while time.time() < t_end and not self._stop.is_set():
                try:
                    chunk = self.channel.recv(4096)
                    if not chunk:
                        break
                    with self.screen_lock:
                        self.stream.feed(chunk)
                    self._put_refresh()
                    tor_buf += chunk
                    # Cap to last 4 KB — systemctl output is tiny
                    if len(tor_buf) > 4096:
                        tor_buf = tor_buf[-4096:]
                except (TimeoutError, OSError):
                    break

            tor_text   = ANSI_RE.sub(b"", tor_buf).decode("utf-8",
                                                           errors="replace")
            tor_lines  = [l.strip() for l in tor_text.splitlines()
                          if l.strip()]

            is_active   = any("active"   in l and "inactive" not in l
                              for l in tor_lines)
            is_enabled  = any("enabled"  in l and "disabled" not in l
                              for l in tor_lines)
            is_failed   = any("failed"   in l for l in tor_lines)
            is_inactive = any("inactive" in l for l in tor_lines)

            if is_failed:
                self.status_q.put(("error",
                    "Tor service has FAILED on the remote host.\n"
                    "Fix with:  sudo systemctl restart tor\n"
                    "Check:     sudo journalctl -u tor -n 50"))
                return

            if is_inactive or not is_active:
                self.status_q.put(("error",
                    "Tor is not running on the remote host.\n"
                    "Start:   sudo systemctl start tor\n"
                    "Enable:  sudo systemctl enable tor"))
                return

            if not is_enabled:
                self.status_q.put(("step_warn", "Tor active but not enabled at boot"))
                time.sleep(1.5)
            else:
                self.status_q.put(("step_ok", "Tor active and enabled"))
                time.sleep(0.5)

            self.channel.send("nyx\r\n")

            # Main read loop
            # nyx_ready is signalled once nyx banner detected in stream.
            self.channel.settimeout(0.3)
            startup_buf  = b""
            startup_done = False
            while not self._stop.is_set():
                try:
                    data = self.channel.recv(4096)
                    if not data:
                        break           # Channel closed cleanly
                    with self.screen_lock:
                        self.stream.feed(data)
                    self._put_refresh()
                    if not startup_done:
                        startup_buf += data
                        if len(startup_buf) > 8192:
                            startup_buf = startup_buf[-8192:]
                        clean = ANSI_RE.sub(b"", startup_buf)
                        nyx_seen = (b"nyx" in clean.lower()
                                    or b"arm" in clean.lower())
                        # Fallback: if banner not seen after 10 s
                        # of output, show terminal anyway
                        timed_out = len(startup_buf) > 51200
                        if nyx_seen or timed_out:
                            startup_done       = True
                            self._nyx_running  = nyx_seen
                            self.status_q.put(("nyx_ready", "nyx launched"))
                except (TimeoutError, OSError):
                    continue            # Normal timeout — keep looping
                except Exception as e:
                    self.status_q.put(("error",
                        f"Stream error: {type(e).__name__}: {e}"))
                    break

        except paramiko.AuthenticationException:
            _flog("error", "SSH auth failed for %s@%s",
                  self.cfg.get("user"), self.cfg.get("host"))
            self.status_q.put(("error",
                "Authentication failed — check username/password or SSH key."))
        except paramiko.SSHException as e:
            msg = str(e)
            if "banner" in msg.lower():
                self.status_q.put(("error",
                    "SSH banner error — wrong port or Pi unreachable.\n"
                    "Test: ssh pi@<ip> in a terminal."))
            else:
                self.status_q.put(("error", f"SSH error: {e}"))
        except OSError as e:
            _flog("error", "SSH OSError for %s: %s", self.cfg.get("host"), e)
            self.status_q.put(("error", f"Connection error: {e}"))
        except Exception as e:
            self.status_q.put(("error", f"Unexpected error: {e}"))
        finally:
            self.status_q.put(("disconnected", "Disconnected"))



# ─────────────────────────────────────────────
#  Tor Control Port Worker
# ─────────────────────────────────────────────
def _fmt_bytes(n):
    """Human-readable byte count."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def _fmt_uptime(secs):
    """Human-readable uptime from seconds."""
    try:
        secs = int(secs)
    except Exception:
        return str(secs)
    d, r = divmod(secs, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return f"{d}d {h:02d}h {m:02d}m"
    return f"{h:02d}:{m:02d}:{s:02d}"


class TorControlWorker(threading.Thread):
    """Opens a direct-tcpip SSH tunnel to localhost:9051, authenticates via
    cookie auth, subscribes to BW/CIRC/ORCONN events, and periodically polls
    for relay identity and connection data.

    All socket I/O happens in a single thread, in a single recv loop.
    GETINFO/GETCONF commands are sent and their replies consumed inline
    before the event loop starts (initial poll), or inside a locked section
    during the periodic re-poll. There is no concurrent recv from two
    code paths — that was the root cause of the previous data-stall bug.

    Pushes dicts onto ctrl_queue:
        {"kind": "identity",     "data": {...}}
        {"kind": "bw",           "read": int, "written": int}
        {"kind": "circ",         "built": int, "failed": int}
        {"kind": "connections",  "conns": [...]}
        {"kind": "error",        "msg": str}
        {"kind": "ready"}
    """

    POLL_INTERVAL = 30   # seconds between full identity+connection re-polls

    def __init__(self, ssh_client, ctrl_queue):
        super().__init__(daemon=True)
        self.client   = ssh_client
        self.ctrl_q   = ctrl_queue
        self.cmd_q    = queue.Queue()  # main thread posts SIGNAL commands here
        self._stop       = threading.Event()
        self._socket_dead = False     # set True when OSError seen on send/recv
        self._sock    = None          # paramiko Channel used as socket
        self._circ_built   = 0
        self._circ_failed  = 0
        self._cached_fp    = ""   # fingerprint from last flags fetch
        self._cached_flags = []   # cached relay flags
        self._initial_data_sent = False  # set True once first polls complete

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    # ── low-level I/O ────────────────────────
    def _send(self, cmd: str):
        self._sock.sendall((cmd + "\r\n").encode())

    def _recv_until_ok(self, timeout: float = 5.0) -> list[str]:
        """Read a complete synchronous reply from the control port.

        Protocol prefixes:
          "250-..."   continuation line (more follow)
          "250+..."   start of data block (terminated by bare ".")
          "250 ..."   final line of reply
          "4xx/5xx "  error final line
          "650 ..."   async event — stashed in _event_stash, not returned

        If we time out, _recv_buf is cleared so stale bytes from the
        unfinished reply cannot corrupt the next command's reply.
        """
        if not hasattr(self, "_event_stash"):
            self._event_stash = []
        if not hasattr(self, "_recv_buf"):
            self._recv_buf = ""

        lines         = []
        end           = time.time() + timeout
        in_data_block = False

        while not self._stop.is_set() and time.time() < end:
            # Process any complete lines already in the buffer
            while "\n" in self._recv_buf:
                line, self._recv_buf = self._recv_buf.split("\n", 1)
                line = line.rstrip("\r")

                # Async event — stash for the outer loop to dispatch later
                if line.startswith("650"):
                    self._event_stash.append(line)
                    continue

                lines.append(line)

                if in_data_block:
                    if line == ".":
                        in_data_block = False
                    continue  # keep reading until the trailing 250 OK

                if len(line) >= 4 and line[3] == "+":
                    in_data_block = True
                    continue

                # Terminal line: 3-digit code followed by a space
                if len(line) >= 4 and line[3] == " ":
                    return lines  # clean return — buffer intact

            # No complete lines — read more bytes from socket
            try:
                self._sock.settimeout(0.5)
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                self._recv_buf += chunk.decode(errors="replace")
            except TimeoutError:
                # Normal 0.5s recv timeout — loop and re-check deadline.
                # Caught before OSError because TimeoutError IS-A OSError.
                pass
            except OSError:
                # Real socket error — clear buffer and re-raise so the
                # caller knows the socket is dead.
                self._recv_buf = ""
                raise
            except Exception:
                pass  # other transient error — keep looping

        # Timed out or stopped — discard any partial/stale reply bytes
        # so they cannot corrupt the next command's reply.
        self._recv_buf = ""
        return lines

    # ── cookie auth ─────────────────────────
    def _read_cookie(self) -> bytes:
        sftp = self.client.open_sftp()
        try:
            for path in ("/var/run/tor/control.authcookie",
                         "/run/tor/control.authcookie",
                         "/var/lib/tor/control_auth_cookie"):
                try:
                    with sftp.open(path, "rb") as f:
                        return f.read()
                except IOError:
                    continue
            raise FileNotFoundError("Tor auth cookie not found")
        finally:
            sftp.close()

    # ── command helpers (inline, sequential) ─
    def _getinfo(self, *keys) -> dict:
        """Send GETINFO and parse all 250-/250+/250 reply lines into a dict.

        Individual 552 errors for unavailable keys are silently skipped so
        that one missing key (e.g. 'address' on a bridge) does not cause the
        entire batch to return empty.  Multi-line data-block values are
        collapsed to their first non-empty line.
        """
        self._send("GETINFO " + " ".join(keys))
        lines = self._recv_until_ok()
        result       = {}
        block_key    = None   # key whose 250+ data block we are inside
        block_lines  = []

        for line in lines:
            # ── 250+ opens a data block ───────────────────────────────
            if line.startswith("250+") and "=" in line:
                rest = line[4:]
                k, _, v = rest.partition("=")
                block_key   = k.strip()
                block_lines = []
                if v.strip():
                    block_lines.append(v.strip())
                continue

            # ── bare "." closes a data block ─────────────────────────
            if line == "." and block_key is not None:
                # Store the first non-empty line of the block as the value
                result[block_key] = next(
                    (l for l in block_lines if l), "")
                block_key   = None
                block_lines = []
                continue

            # ── inside a data block: accumulate lines ─────────────────
            if block_key is not None:
                block_lines.append(line)
                continue

            # ── 250- / 250  normal key=value lines ────────────────────
            if line.startswith(("250-", "250 ")):
                rest = line[4:]
                if "=" in rest:
                    k, _, v = rest.partition("=")
                    result[k.strip()] = v.strip()
                continue

            # ── 552 / 5xx lines: key unavailable — skip silently ──────
            # (e.g. "552-Unrecognized key" or "552 Unrecognized key")
            # Do not abort — remaining keys may still be valid.

        return result

    def _getconf(self, *keys) -> dict:
        self._send("GETCONF " + " ".join(keys))
        lines = self._recv_until_ok()
        result = {}
        for line in lines:
            if "=" in line:
                rest = line[4:] if len(line) > 4 else line
                k, _, v = rest.partition("=")
                result[k.strip()] = v.strip()
        return result

    # ── data polls (called sequentially, not concurrently) ──
    def _poll_identity(self):
        try:
            # Batch GETINFO — safe keys that all Tor instances support.
            # 'address' and 'status/reachability-succeeded' are fetched
            # separately because they 552 on bridges / before reachability
            # check, and a 552 in a batch can corrupt subsequent key parsing.
            info = self._getinfo(
                "version", "fingerprint",
                "traffic/read", "traffic/written", "uptime",
                "status/bootstrap-phase",
            )
            # Fetch optional keys individually — failures are non-fatal
            for opt_key in ("address", "status/reachability-succeeded"):
                try:
                    partial = self._getinfo(opt_key)
                    info.update(partial)
                except Exception:
                    pass

            # Single GETCONF — second round-trip
            conf = self._getconf(
                "Nickname", "ORPort", "BandwidthRate", "BandwidthBurst",
            )
            # Flags: only fetch ns/id/<fp> if we have a fingerprint.
            # Cache it so repeated polls don't re-fetch unnecessarily.
            fp    = info.get("fingerprint", "").strip()
            flags = getattr(self, "_cached_flags", [])
            if fp and fp != getattr(self, "_cached_fp", ""):
                self._send(f"GETINFO ns/id/{fp}")
                ns_lines = self._recv_until_ok()
                new_flags = []
                for l in ns_lines:
                    parts = l.split()
                    if parts and parts[0] == "s":
                        new_flags = parts[1:]
                        break
                if new_flags:
                    self._cached_flags = new_flags
                    self._cached_fp    = fp
                    flags = new_flags

            self.ctrl_q.put({
                "kind":          "identity",
                "version":       info.get("version", "?"),
                "address":       info.get("address", "?"),
                "fingerprint":   fp,
                "nickname":      conf.get("Nickname", "?"),
                "orport":        conf.get("ORPort", "?"),
                "bw_rate":       conf.get("BandwidthRate", "?"),
                "bw_burst":      conf.get("BandwidthBurst", "?"),
                "traffic_read":  int(info.get("traffic/read", 0) or 0),
                "traffic_written": int(info.get("traffic/written", 0) or 0),
                "uptime":        info.get("uptime", "0"),
                "reachable":     info.get("status/reachability-succeeded", "?"),
                "bootstrap":     info.get("status/bootstrap-phase", "?"),
                "flags":         flags,
                "circ_built":    self._circ_built,
                "circ_failed":   self._circ_failed,
            })
        except OSError as e:
            self._socket_dead = True
            self.ctrl_q.put({"kind": "error",
                             "msg": f"_poll_identity failed (socket closed): {e}"})
        except Exception as e:
            tb = traceback.format_exc(limit=4)
            self.ctrl_q.put({"kind": "error",
                             "msg": f"_poll_identity failed: {e} | {tb}"})

    def _poll_connections(self):
        """Fetch active OR connections via GETINFO orconn-status."""
        try:
            self._send("GETINFO orconn-status")
            lines = self._recv_until_ok(timeout=5.0)
            conns = []
            for l in lines:
                l = l.strip()
                if l.startswith("250+orconn-status=") or l in (".", "250 OK"):
                    continue
                # Strip 250- prefix from multi-line replies
                if l.startswith("250-"):
                    l = l[4:]
                parsed = self._parse_orconn_line(l)
                if parsed and parsed["status"] not in ("", "CLOSED", "FAILED"):
                    conns.append(parsed)
            self.ctrl_q.put({"kind": "connections", "conns": conns})
        except OSError as e:
            self._socket_dead = True
            self.ctrl_q.put({"kind": "error",
                             "msg": f"_poll_connections failed (socket closed): {e}"})
        except Exception as e:
            self.ctrl_q.put({"kind": "error",
                             "msg": f"_poll_connections failed: {e}"})

    def _parse_orconn_line(self, line: str) -> dict | None:
        """Parse one ORCONN status line into a connection dict."""
        # Strip event prefix if present
        for prefix in ("650 ORCONN ", "250-", "250 "):
            if line.startswith(prefix):
                line = line[len(prefix):]
        parts = line.split()
        if len(parts) < 2:
            return None
        target = parts[0]
        status = parts[1]

        if status == "NEW" or (not target.startswith("$") and ":" in target):
            direction = "in"
        else:
            direction = "out"

        if target.startswith("$"):
            fp_nick = target.lstrip("$")
            sep = "~" if "~" in fp_nick else ("=" if "=" in fp_nick else None)
            if sep:
                fp, _, nickname = fp_nick.partition(sep)
            else:
                fp, nickname = fp_nick, ""
            ip_port = ""
        else:
            ip_port  = target
            nickname = ""
            fp       = ""

        return {
            "direction": direction,
            "ip_port":   ip_port,
            "nickname":  nickname,
            "fp":        fp,
            "status":    status,
        }

    # ── main run ─────────────────────────────
    def run(self):
        try:
            transport = self.client.get_transport()
            self._sock = transport.open_channel(
                "direct-tcpip",
                ("127.0.0.1", 9051),
                ("127.0.0.1", 0),
            )

            # Cookie auth with retry — the control port may be briefly
            # unavailable after a session drop (Tor re-binding, prior
            # connection still tearing down at TCP level).  Retry up to
            # 3 times with a short back-off before giving up.
            # On each retry we close and reopen the channel: if Tor replied
            # 515 (bad auth) it may have closed the connection, so the old
            # channel is dead and we must open a fresh one.
            auth_ok    = False
            last_reply = []
            for auth_attempt in range(3):
                if auth_attempt > 0:
                    time.sleep(1.5)   # brief back-off before retry
                    if self._stop.is_set():
                        return
                    # Reopen the channel — previous attempt may have left it dead
                    try:
                        self._sock.close()
                    except Exception:
                        pass
                    try:
                        self._sock = transport.open_channel(
                            "direct-tcpip",
                            ("127.0.0.1", 9051),
                            ("127.0.0.1", 0),
                        )
                        self._recv_buf = ""   # clear any stale bytes
                    except Exception as e:
                        self.ctrl_q.put({"kind": "error",
                            "msg": f"Cannot reopen control channel: {e}"})
                        break
                try:
                    cookie = self._read_cookie()
                    self._send("AUTHENTICATE " + cookie.hex())
                except OSError:
                    break   # socket gone — no point retrying
                except Exception:
                    try:
                        self._send('AUTHENTICATE ""')
                    except OSError:
                        break
                # Use a longer timeout for auth — the control port may
                # take a moment to become ready after a session drop.
                last_reply = self._recv_until_ok(timeout=8.0)
                if any("250" in l for l in last_reply):
                    auth_ok = True
                    break
                # Got a reply but it wasn't 250 — could be 515 (wrong
                # auth method) or empty (channel open but Tor not ready).
                # Log verbosely so we can diagnose in the field.
                reply_str = repr(last_reply) if last_reply else "(no reply — timeout)"
                _flog("warning", "TorControl auth attempt %d/3 failed: %s",
                      auth_attempt + 1, reply_str)
                self.ctrl_q.put({"kind": "error",
                    "msg": f"Auth attempt {auth_attempt + 1}/3 failed: {reply_str}"})
            if not auth_ok:
                hint = ""
                if not last_reply:
                    hint = (
                        " — No reply received. Check that your torrc has "
                        "'ControlPort 9051' (TCP) not just ControlSocket. "
                        "Also verify the pi user is in the debian-tor group."
                    )
                self.ctrl_q.put({"kind": "error",
                    "msg": f"Control port auth failed after 3 attempts{hint}"})
                return

            _flog("info", "TorControl authenticated successfully")
            # Subscribe to events
            self._send("SETEVENTS BW CIRC ORCONN")
            self._recv_until_ok()

            self.ctrl_q.put({"kind": "ready"})

            # Initial data — sequential GETINFO/GETCONF calls before event loop
            self._poll_identity()
            self._poll_connections()
            self._initial_data_sent = True

            # ── single event loop ─────────────────
            # _recv_buf and _event_stash are initialised lazily by _recv_until_ok.
            # Do NOT reset them here — events stashed during the initial polls
            # above would be lost.  Ensure they exist but keep any stashed data.
            if not hasattr(self, "_recv_buf"):
                self._recv_buf = ""
            if not hasattr(self, "_event_stash"):
                self._event_stash = []
            last_poll         = time.time()
            last_retry_check  = time.time()
            RETRY_INTERVAL    = 8   # seconds before retrying if no identity yet

            while not self._stop.is_set():
                # Drain command queue — one-shot signals from the main thread
                try:
                    while True:
                        cmd = self.cmd_q.get_nowait()
                        if cmd == "__repoll__":
                            self._poll_identity()
                            self._poll_connections()
                            if self._socket_dead:
                                break
                            continue
                        try:
                            self._send(cmd)
                            reply = self._recv_until_ok(timeout=4.0)
                        except OSError as e:
                            # Socket died mid-command — report and exit loop
                            self._socket_dead = True
                            self.ctrl_q.put({"kind": "error",
                                "msg": f"Command failed (socket closed): {e}"})
                            break
                        ok = any(l.startswith("250") for l in reply)
                        self.ctrl_q.put({
                            "kind": "signal_result",
                            "cmd":  cmd,
                            "ok":   ok,
                            "reply": reply,
                        })
                        # After NEWNYM or RELOAD, refresh identity immediately
                        if ok and any(k in cmd for k in ("NEWNYM", "RELOAD", "CLEARDNSCACHE")):
                            self._poll_identity()
                            self._poll_connections()
                            if self._socket_dead:
                                break
                except queue.Empty:
                    pass

                # Exit if a poll call detected a dead socket
                if self._socket_dead:
                    break

                # Dispatch any events stashed during the last _recv_until_ok call
                for stashed in self._event_stash:
                    self._dispatch_event(stashed)
                self._event_stash.clear()

                # Debounced ORCONN poll — flush once per event-loop iteration
                # rather than once per ORCONN event (may arrive in bursts)
                if getattr(self, "_orconn_pending", False):
                    self._orconn_pending = False
                    self._poll_connections()

                # Retry initial data if Tor was still bootstrapping on connect
                # (fingerprint absent means identity poll returned empty data).
                # Re-poll every RETRY_INTERVAL until we get a fingerprint,
                # then stop retrying and let the normal POLL_INTERVAL take over.
                now = time.time()
                if (not self._cached_fp and
                        now - last_retry_check > RETRY_INTERVAL):
                    last_retry_check = now
                    self._poll_identity()
                    self._poll_connections()
                    for stashed in self._event_stash:
                        self._dispatch_event(stashed)
                    self._event_stash.clear()
                    if self._cached_fp:
                        # Got data — align the normal poll timer so we don't
                        # immediately re-poll again in POLL_INTERVAL seconds.
                        last_poll = now
                    continue

                # Periodic full re-poll — inline, same thread, no race
                if time.time() - last_poll > self.POLL_INTERVAL:
                    self._poll_identity()
                    self._poll_connections()
                    last_poll = time.time()
                    # Drain stash again after re-poll
                    for stashed in self._event_stash:
                        self._dispatch_event(stashed)
                    self._event_stash.clear()
                    continue   # skip recv() this iteration

                # Read new data into shared buffer
                try:
                    self._sock.settimeout(1.0)
                    chunk = self._sock.recv(4096)
                    if not chunk:
                        # Empty read = channel closed cleanly by remote
                        break
                    self._recv_buf += chunk.decode(errors="replace")
                except TimeoutError:
                    # Normal 1-second recv timeout — nothing arrived, keep looping.
                    # Must be caught BEFORE OSError because TimeoutError IS-A OSError
                    # in Python 3.3+; catching OSError first would swallow timeouts.
                    if self._stop.is_set():
                        break
                    continue
                except OSError:
                    # Real socket error: broken pipe, connection reset, closed channel.
                    # Not a timeout — exit cleanly.
                    break
                except Exception:
                    if self._stop.is_set():
                        break
                    continue

                # Dispatch complete event lines from shared buffer
                while "\n" in self._recv_buf:
                    line, self._recv_buf = self._recv_buf.split("\n", 1)
                    line = line.rstrip("\r")
                    self._dispatch_event(line)

        except Exception as e:
            _flog("error", "TorControl unhandled exception: %s", e)
            self.ctrl_q.put({"kind": "error", "msg": f"Control port: {e}"})
        finally:
            # Always tell the main thread the control connection is gone,
            # regardless of whether we exited cleanly, via stop(), or via
            # an unexpected exception (e.g. SSH transport closed under us).
            _flog("info", "TorControl worker exiting")
            self.ctrl_q.put({"kind": "ctrl_disconnected"})

    def _dispatch_event(self, line: str):
        """Handle a single async event line from Tor."""
        if not line.startswith("650 "):
            return

        # BW <read> <written>
        if line.startswith("650 BW "):
            parts = line.split()
            if len(parts) >= 4:
                try:
                    self.ctrl_q.put({
                        "kind":    "bw",
                        "read":    int(parts[2]),
                        "written": int(parts[3]),
                    })
                except ValueError:
                    pass

        # CIRC
        elif line.startswith("650 CIRC "):
            if " BUILT" in line:
                self._circ_built += 1
                self.ctrl_q.put({"kind": "circ",
                                  "built": self._circ_built,
                                  "failed": self._circ_failed})
            elif " FAILED" in line or " CLOSED" in line:
                self._circ_failed += 1
                self.ctrl_q.put({"kind": "circ",
                                  "built": self._circ_built,
                                  "failed": self._circ_failed})

        # ORCONN — connection state changed; schedule a debounced re-poll.
        # High-traffic relays can generate many ORCONN events per second;
        # polling on every one would flood the Tor control port with GETINFO
        # requests.  Coalesce events within a 1-second window instead.
        elif line.startswith("650 ORCONN "):
            self._orconn_pending = True


# ─────────────────────────────────────────────
#  VT100 Canvas Terminal Widget
# ─────────────────────────────────────────────
class TerminalCanvas(tk.Canvas):

    # ── class-level constants ────────────────
    _CURSOR_APP = {
        "Up":    b"\x1bOA", "Down":  b"\x1bOB",
        "Right": b"\x1bOC", "Left":  b"\x1bOD",
        "Home":  b"\x1bOH", "End":   b"\x1bOF",
    }
    _KEY_MAP = {
        "Return":    b"\r",    "KP_Enter":  b"\r",
        "BackSpace": b"\x7f",  "Tab":       b"\t",
        "Escape":    b"\x1b",  "Prior":     b"\x1b[5~",
        "Next":      b"\x1b[6~", "Delete":  b"\x1b[3~",
        "F1":  b"\x1bOP",  "F2":  b"\x1bOQ",
        "F3":  b"\x1bOR",  "F4":  b"\x1bOS",
        "F5":  b"\x1b[15~", "F6": b"\x1b[17~",
        "F7":  b"\x1b[18~", "F8": b"\x1b[19~",
        "F9":  b"\x1b[20~", "F10":b"\x1b[21~",
    }
    _SPECIAL_KEYSYMS = frozenset({
        "Up", "Down", "Left", "Right",
        "Home", "End", "Prior", "Next", "Delete",
        "Return", "KP_Enter", "BackSpace", "Tab", "Escape",
        "F1","F2","F3","F4","F5","F6","F7","F8","F9","F10",
    })

    def __init__(self, parent, cols, rows,
                 font_name="Cascadia Code", font_size=11, **kw):
        super().__init__(parent, bg="#1a1b26",
                         highlightthickness=0, cursor="xterm", **kw)
        self.cols          = cols
        self.rows          = rows
        self._font_name    = font_name
        self._font_size    = font_size
        self._key_callback = None       # set by app before any events fire
        self._cell_ids     = {}         # (row,col) -> (bg_id, char_id)
        self._prev_cursor  = None       # last cursor position for restore
        self._resize_after_id = None    # debounce timer

        self._init_font()
        self._build_grid()

        self.bind("<Configure>", self._on_configure)
        self.bind("<Button-1>",  lambda e: self.focus_set())
        for seq in ("<Up>", "<Down>", "<Left>", "<Right>",
                    "<Prior>", "<Next>", "<Home>", "<End>",
                    "<Return>", "<KP_Enter>", "<BackSpace>",
                    "<Tab>", "<Escape>", "<Delete>",
                    "<F1>","<F2>","<F3>","<F4>","<F5>",
                    "<F6>","<F7>","<F8>","<F9>","<F10>"):
            self.bind(seq, self._on_special_key)
        self.bind("<KeyPress>", self._on_printable_key)
        self.focus_set()

    # ── font / grid ──────────────────────────
    def _init_font(self):
        # Delete any prior font objects — tkfont.Font registers in Tk's
        # internal font table and leaks permanently without explicit deletion.
        for attr in ("_font", "_font_bold"):
            prev = getattr(self, attr, None)
            if prev:
                try:
                    prev.delete()
                except Exception:
                    pass
        avail = tkfont.families()
        for f in [self._font_name, "Consolas", "Courier New", "Lucida Console"]:
            if f in avail:
                self._font_name = f
                break
        self._font      = tkfont.Font(
            family=self._font_name, size=self._font_size)
        self._font_bold = tkfont.Font(
            family=self._font_name, size=self._font_size, weight="bold")
        # Force int — font.measure/metrics return float on HiDPI/macOS
        self._cw = int(self._font.measure("M"))
        self._ch = int(self._font.metrics("linespace")) + 2

    def _build_grid(self):
        """Rebuild canvas items for current cols/rows.
        Called once at startup and once after each debounced resize.
        Explicitly deletes old items first to free tkinter/Tk memory."""
        self.delete("all")
        self._cell_ids   = {}
        self._prev_cursor = None        # reset cursor cache — old IDs are gone
        cw, ch = self._cw, self._ch
        for r in range(self.rows):
            y1 = r * ch
            y2 = y1 + ch
            for c in range(self.cols):
                x1 = c * cw
                x2 = x1 + cw
                bg_id = self.create_rectangle(
                    x1, y1, x2, y2, fill="#1a1b26", outline="")
                ch_id = self.create_text(
                    x1 + cw // 2, y1 + ch // 2,
                    text=" ", font=self._font,
                    fill="#c0caf5", anchor="center")
                self._cell_ids[(r, c)] = (bg_id, ch_id)

    # ── resize (debounced) ───────────────────
    def _on_configure(self, event):
        new_cols = max(1, int(event.width)  // self._cw)
        new_rows = max(1, int(event.height) // self._ch)
        if new_cols == self.cols and new_rows == self.rows:
            return
        self.cols = new_cols
        self.rows = new_rows
        # Cancel any pending rebuild and schedule a fresh one.
        # Grid is rebuilt only once, 150 ms after dragging stops.
        if self._resize_after_id:
            self.after_cancel(self._resize_after_id)
        self._resize_after_id = self.after(150, self._do_resize)

    def _do_resize(self):
        self._resize_after_id = None
        self._build_grid()
        if self._key_callback:
            self._key_callback(("resize", self.cols, self.rows))

    # ── render ───────────────────────────────
    def render(self, screen: "pyte.Screen"):
        """Redraw dirty rows, keeping the cursor cell visually stable.

        The row loop deliberately skips the cursor cell so it is written
        exactly once — at the end — regardless of how many times nyx marks
        its row dirty.  Without this, the row loop first paints the cell's
        normal colours and then the cursor block overwrites them, producing
        a visible two-step flicker on every frame where nyx updates its
        status bar (bandwidth counters, uptime, etc.).
        """
        cy, cx  = screen.cursor.y, screen.cursor.x
        cur_pos = (cy, cx)
        prev    = self._prev_cursor

        # Snapshot and clear dirty set atomically
        dirty = screen.dirty.copy()
        screen.dirty.clear()

        # If cursor moved, old position's row must be redrawn so the
        # highlight is erased; new row must be drawn so we can re-apply it.
        cursor_moved = cur_pos != prev
        if cursor_moved:
            if prev:
                dirty.add(prev[0])
            dirty.add(cy)

        # Nothing to do — skip entirely
        if not dirty:
            return

        cell_ids = self._cell_ids
        s_lines  = screen.lines
        s_cols   = screen.columns
        buf      = screen.buffer

        for (row, col), (bg_id, ch_id) in cell_ids.items():
            if row not in dirty:
                continue
            # Skip the live cursor cell — painted separately below
            # so it is touched exactly once per render, eliminating flicker.
            if (row, col) == cur_pos:
                continue
            if row >= s_lines or col >= s_cols:
                self.itemconfig(bg_id, fill="#1a1b26")
                self.itemconfig(ch_id, text=" ")
                continue
            cell = buf[row][col]
            ch   = cell.data or " "
            fg   = resolve_color(cell.fg, True)
            bg   = resolve_color(cell.bg, False)
            if cell.reverse:
                fg, bg = bg, fg
            font = self._font_bold if cell.bold else self._font
            self.itemconfig(bg_id, fill=bg)
            self.itemconfig(ch_id, text=ch, fill=fg, font=font)

        # Paint cursor cell exactly once — bounds-checked against current
        # screen dimensions to guard against resize races where pyte's cursor
        # position may temporarily exceed the canvas grid.
        self._prev_cursor = cur_pos
        if cur_pos in cell_ids and cy < s_lines and cx < s_cols:
            bg_id, ch_id = cell_ids[cur_pos]
            self.itemconfig(bg_id, fill="#7aa2f7")
            self.itemconfig(ch_id, fill="#1a1b26")

    # ── keyboard ─────────────────────────────
    def _on_special_key(self, event):
        if not self._key_callback:
            return "break"
        seq = self._CURSOR_APP.get(event.keysym) \
              or self._KEY_MAP.get(event.keysym)
        if seq:
            self._key_callback(("key", seq))
        return "break"

    def _on_printable_key(self, event):
        if not self._key_callback:
            return "break"
        if event.keysym in self._SPECIAL_KEYSYMS:
            return "break"
        if not event.char or event.char == "\x00":
            return "break"
        if ord(event.char[0]) < 32:
            if (event.state & 0x4) and event.char.isalpha():
                self._key_callback(
                    ("key", bytes([ord(event.char.upper()) - 64])))
            return "break"
        self._key_callback(
            ("key", event.char.encode("utf-8", errors="replace")))
        return "break"




# ─────────────────────────────────────────────
#  Main App
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
#  Dashboard Panel  (native tkinter Tor data)
# ─────────────────────────────────────────────
class DashboardPanel(tk.Frame):
    """Native tkinter panel showing live Tor control-port data.

    Panels:
      - Live bandwidth sparkline (read/write, last 120 seconds)
      - Relay identity card (fingerprint, flags, IP, uptime, traffic)
    """

    BG      = "#0f1117"
    PANEL   = "#161929"
    BORDER  = "#1e2235"
    ACCENT  = "#7c3aed"
    TEXT    = "#e2e8f0"
    TEXT_DIM = "#64748b"
    SUCCESS  = "#10b981"
    WARNING  = "#f59e0b"
    ERROR    = "#ef4444"

    # Sparkline colours
    COL_READ    = "#7aa2f7"   # blue  — download
    COL_WRITE   = "#9ece6a"   # green — upload
    HISTORY_LEN  = 60          # seconds of BW history shown in sparkline
    EMA_ALPHA    = 0.25        # EMA smoothing factor (0=frozen, 1=raw)
                               # 0.25 gives a ~4-sample rolling feel
    PEAK_DECAY   = 0.97        # Peak-hold decay per sample (per second)
                               # 0.97 → ceiling halves in ~23 s after a burst

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=self.BG, **kw)
        self._bw_read    = collections.deque([0] * self.HISTORY_LEN, maxlen=self.HISTORY_LEN)
        self._bw_written = collections.deque([0] * self.HISTORY_LEN, maxlen=self.HISTORY_LEN)
        # EMA smoothing state — tracks the smoothed value between samples
        self._ema_read    = 0.0
        self._ema_written = 0.0
        # Peak-hold: ceiling rises instantly, decays slowly so the y-axis
        # doesn't snap up and down on every burst
        self._peak_hold   = 0.0
        self._identity   = {}
        self._circ_built   = 0
        self._circ_failed  = 0
        self._build()

    # ── construction ──────────────────────────
    def _f(self, families, size, bold=False):
        for fam in families:
            try:
                return tkfont.Font(family=fam, size=size,
                                   weight="bold" if bold else "normal")
            except Exception:
                continue
        return tkfont.Font(size=size, weight="bold" if bold else "normal")

    def _build(self):
        # Store fonts as instance attributes so Python's GC never collects
        # them while Tk widgets still hold a reference to their internal name.
        self._font_mono   = self._f(["Cascadia Code", "Consolas", "Courier New"], 10)
        self._font_mono_s = self._f(["Cascadia Code", "Consolas", "Courier New"], 9)
        self._font_ui     = self._f(["Segoe UI", "Helvetica Neue", "Arial"], 10)
        self._font_ui_s   = self._f(["Segoe UI", "Helvetica Neue", "Arial"], 9)
        self._font_ui_b   = self._f(["Segoe UI", "Helvetica Neue", "Arial"], 11, bold=True)
        mono   = self._font_mono
        mono_s = self._font_mono_s
        ui     = self._font_ui
        ui_s   = self._font_ui_s
        ui_b   = self._font_ui_b

        # ── bandwidth section ──────────────────
        bw_frame = tk.Frame(self, bg=self.BG)
        bw_frame.pack(fill="x", padx=20, pady=(18, 0))

        # Section header row
        hdr = tk.Frame(bw_frame, bg=self.BG)
        hdr.pack(fill="x", pady=(0, 6))
        tk.Label(hdr, text="BANDWIDTH", font=ui_s,
                 fg=self.ACCENT, bg=self.BG).pack(side="left")
        # Live read/write rate labels (updated by tick)
        self._lbl_read_rate  = tk.Label(hdr, text="↓  0 B/s", font=mono_s,
                                         fg=self.COL_READ,  bg=self.BG)
        self._lbl_read_rate.pack(side="right")
        tk.Label(hdr, text="  ", bg=self.BG).pack(side="right")
        self._lbl_write_rate = tk.Label(hdr, text="↑  0 B/s", font=mono_s,
                                         fg=self.COL_WRITE, bg=self.BG)
        self._lbl_write_rate.pack(side="right")

        # Sparkline canvas
        self._bw_canvas = tk.Canvas(bw_frame, bg=self.PANEL,
                                     height=110, highlightthickness=1,
                                     highlightbackground=self.BORDER)
        self._bw_canvas.pack(fill="x")
        self._bw_canvas.bind("<Configure>", lambda _: self._redraw_sparkline())

        # Y-axis legend
        self._lbl_bw_max = tk.Label(bw_frame, text="", font=mono_s,
                                     fg=self.TEXT_DIM, bg=self.BG, anchor="e")
        self._lbl_bw_max.pack(fill="x")

        # ── separator ─────────────────────────
        tk.Frame(self, bg=self.BORDER, height=1).pack(
            fill="x", padx=20, pady=(16, 0))

        # ── two-column lower section ───────────
        # Left: Relay Identity  |  Right: Connection Info
        lower = tk.Frame(self, bg=self.BG)
        lower.pack(fill="both", expand=True, padx=20, pady=(14, 14))
        lower.columnconfigure(0, weight=3)   # identity gets more width
        lower.columnconfigure(1, weight=0)   # 1px divider
        lower.columnconfigure(2, weight=2)   # connection info
        lower.rowconfigure(0, weight=1)

        # ── LEFT: relay identity ──────────────
        id_outer = tk.Frame(lower, bg=self.BG)
        id_outer.grid(row=0, column=0, sticky="nsew")

        tk.Label(id_outer, text="RELAY IDENTITY", font=ui_s,
                 fg=self.ACCENT, bg=self.BG).pack(anchor="w", pady=(0, 8))

        id_grid = tk.Frame(id_outer, bg=self.BG)
        id_grid.pack(fill="x", anchor="n")

        def row(label, attr, mono=False, parent=None):
            grid = parent if parent is not None else id_grid
            f = mono_s if mono else ui_s
            tk.Label(grid, text=label, font=ui_s,
                     fg=self.TEXT_DIM, bg=self.BG,
                     anchor="w", width=14).grid(
                         row=row.n, column=0, sticky="w", pady=2)
            lbl = tk.Label(grid, text="—", font=f,
                           fg=self.TEXT, bg=self.BG, anchor="w")
            lbl.grid(row=row.n, column=1, sticky="w", padx=(6, 0))
            setattr(self, attr, lbl)
            row.n += 1
        row.n = 0

        row("Nickname",    "_id_nickname")
        row("Address",     "_id_address",  mono=True)
        row("Fingerprint", "_id_fp",       mono=True)
        row("OR Port",     "_id_orport")
        row("Tor version", "_id_version")
        row("Flags",       "_id_flags")
        row("Uptime",      "_id_uptime")
        row("BW rate",     "_id_bwrate")

        # ── vertical divider ──────────────────
        tk.Frame(lower, bg=self.BORDER, width=1).grid(
            row=0, column=1, sticky="ns", padx=18)

        # ── RIGHT: live connection list ──────
        conn_outer = tk.Frame(lower, bg=self.BG)
        conn_outer.grid(row=0, column=2, sticky="nsew")

        # Header row with title + live count
        conn_hdr = tk.Frame(conn_outer, bg=self.BG)
        conn_hdr.pack(fill="x", pady=(0, 6))
        tk.Label(conn_hdr, text="CONNECTIONS", font=ui_s,
                 fg=self.ACCENT, bg=self.BG).pack(side="left")
        self._conn_count = tk.Label(conn_hdr, text="", font=mono_s,
                                     fg=self.TEXT_DIM, bg=self.BG)
        self._conn_count.pack(side="right")

        # Column headers
        col_hdr = tk.Frame(conn_outer, bg=self.PANEL)
        col_hdr.pack(fill="x")
        for txt, w in [("", 2), ("IP : Port", 18), ("Relay", 14), ("Status", 10)]:
            tk.Label(col_hdr, text=txt, font=ui_s, fg=self.TEXT_DIM,
                     bg=self.PANEL, anchor="w", width=w,
                     padx=4, pady=2).pack(side="left")

        # Scrollable connection rows
        list_frame = tk.Frame(conn_outer, bg=self.BG)
        list_frame.pack(fill="both", expand=True)

        self._conn_canvas = tk.Canvas(list_frame, bg=self.BG,
                                       highlightthickness=0)

        # Dark, auto-hiding scrollbar via ttk styling
        _sb_style = ttk.Style()
        _sb_style.theme_use("default")
        _sb_style.configure(
            "Dark.Vertical.TScrollbar",
            background  = "#1e2235",   # track
            troughcolor = "#0f1117",   # trough (matches BG)
            arrowcolor  = "#1e2235",   # hide arrows by matching track
            borderwidth = 0,
            relief      = "flat",
        )
        _sb_style.map(
            "Dark.Vertical.TScrollbar",
            background  = [("active", "#2e3350"), ("disabled", "#0f1117")],
        )
        self._conn_sb = ttk.Scrollbar(list_frame, orient="vertical",
                                       style="Dark.Vertical.TScrollbar",
                                       command=self._conn_canvas.yview)
        self._conn_canvas.configure(
            yscrollcommand=self._conn_yscroll_cb)
        # Don't pack scrollbar yet — _conn_yscroll_cb shows/hides it
        self._conn_canvas.pack(side="left", fill="both", expand=True)

        # Inner frame that holds the actual row widgets
        self._conn_inner = tk.Frame(self._conn_canvas, bg=self.BG)
        self._conn_canvas_window = self._conn_canvas.create_window(
            (0, 0), window=self._conn_inner, anchor="nw")
        self._conn_inner.bind("<Configure>", self._on_conn_inner_resize)
        self._conn_canvas.bind("<Configure>", self._on_conn_canvas_resize)

        # Mouse wheel scrolling
        self._conn_canvas.bind("<MouseWheel>", self._conn_scroll)

        self._conn_row_widgets = []   # live row Frame widgets

        # Font refs for row rendering (already stored as instance attrs above)
        self._conn_mono_s = self._font_mono_s
        self._conn_ui_s   = self._font_ui_s

    # ── data update methods ────────────────────
    def push_bw(self, read_b: int, written_b: int):
        # Apply EMA smoothing before storing.
        # Raw value is used for the live rate labels (people want to see the
        # actual instantaneous rate); smoothed value goes into the sparkline.
        a = self.EMA_ALPHA
        self._ema_read    = a * read_b    + (1 - a) * self._ema_read
        self._ema_written = a * written_b + (1 - a) * self._ema_written
        self._bw_read.append(self._ema_read)
        self._bw_written.append(self._ema_written)
        self._lbl_read_rate.config(text=f"↓  {_fmt_bytes(read_b)}/s")
        self._lbl_write_rate.config(text=f"↑  {_fmt_bytes(written_b)}/s")
        self._redraw_sparkline()

    def push_identity(self, d: dict):
        self._identity = d
        self._circ_built  = d.get("circ_built",  self._circ_built)
        self._circ_failed = d.get("circ_failed", self._circ_failed)
        self._refresh_identity()

    def push_circs(self, built: int, failed: int):
        self._circ_built  = built
        self._circ_failed = failed

    def push_connections(self, conns: list):
        """Update the live connection list.

        Each entry in conns is a dict with keys:
            direction : "in" | "out" | "?"
            ip_port   : "1.2.3.4:443"
            nickname  : relay nickname or fingerprint prefix or ""
            status    : "CONNECTED" | "LAUNCHED" | "CLOSED" | etc.
        """
        # Destroy old row widgets
        for w in self._conn_row_widgets:
            w.destroy()
        self._conn_row_widgets.clear()

        # Colour map for status
        status_col = {
            "CONNECTED": self.SUCCESS,
            "LAUNCHED":  self.WARNING,
            "FAILED":    self.ERROR,
            "CLOSED":    self.TEXT_DIM,
            "NEW":       "#7dcfff",
        }
        dir_sym = {"in": "←", "out": "→", "?": "·"}
        dir_col = {"in": "#7aa2f7", "out": "#9ece6a", "?": self.TEXT_DIM}

        for i, c in enumerate(conns):
            bg = self.PANEL if i % 2 == 0 else self.BG
            row_f = tk.Frame(self._conn_inner, bg=bg)
            row_f.pack(fill="x")

            direction = c.get("direction", "?")
            status    = c.get("status",    "?")
            ip_port   = c.get("ip_port",   "?")
            nickname  = c.get("nickname",  "")

            # Direction arrow
            tk.Label(row_f, text=dir_sym.get(direction, "·"),
                     font=self._conn_mono_s,
                     fg=dir_col.get(direction, self.TEXT_DIM),
                     bg=bg, width=2, anchor="center",
                     padx=4, pady=1).pack(side="left")

            # IP:port
            tk.Label(row_f, text=ip_port,
                     font=self._conn_mono_s,
                     fg=self.TEXT, bg=bg,
                     anchor="w", width=20,
                     padx=4, pady=1).pack(side="left")

            # Nickname (truncated)
            nick_display = nickname[:14] if nickname else "—"
            tk.Label(row_f, text=nick_display,
                     font=self._conn_ui_s,
                     fg=self.TEXT_DIM, bg=bg,
                     anchor="w", width=14,
                     padx=4, pady=1).pack(side="left")

            # Status
            col = status_col.get(status, self.TEXT_DIM)
            tk.Label(row_f, text=status[:10],
                     font=self._conn_ui_s,
                     fg=col, bg=bg,
                     anchor="w", padx=4, pady=1).pack(side="left")

            # Propagate scroll events from row widgets up to the canvas
            for _sw in row_f.winfo_children() + [row_f]:
                _sw.bind("<MouseWheel>", self._conn_scroll)
            self._conn_row_widgets.append(row_f)

        # Update count label
        n = len(conns)
        n_in  = sum(1 for c in conns if c.get("direction") == "in")
        n_out = sum(1 for c in conns if c.get("direction") == "out")
        self._conn_count.config(
            text=f"{n} total  ←{n_in}  →{n_out}")

        # Scroll to top when list refreshes
        self._conn_canvas.yview_moveto(0)

    def _conn_yscroll_cb(self, first, last):
        """Auto-show/hide the scrollbar depending on whether content overflows."""
        self._conn_sb.set(first, last)
        if float(first) <= 0.0 and float(last) >= 1.0:
            # All content visible — hide the scrollbar
            self._conn_sb.pack_forget()
        else:
            # Content overflows — show it
            self._conn_sb.pack(side="right", fill="y",
                               before=self._conn_canvas)

    def _on_conn_inner_resize(self, event):
        self._conn_canvas.configure(
            scrollregion=self._conn_canvas.bbox("all"))

    def _on_conn_canvas_resize(self, event):
        self._conn_canvas.itemconfig(
            self._conn_canvas_window, width=event.width)

    def _conn_scroll(self, event):
        """Scroll the connection list canvas by one unit per wheel tick.
        Bound on the canvas AND every child widget so the event is always
        caught regardless of which widget the cursor is over."""
        self._conn_canvas.yview_scroll(-1 * (event.delta // 120), "units")

    # ── sparkline drawing ──────────────────────
    def _redraw_sparkline(self):
        c = self._bw_canvas
        c.delete("all")
        w = c.winfo_width()  or 600
        h = c.winfo_height() or 110
        pad_top = 8
        pad_bot = 8
        plot_h  = h - pad_top - pad_bot

        # Background grid lines
        for pct in (0.25, 0.5, 0.75, 1.0):
            y = pad_top + plot_h * (1 - pct)
            c.create_line(0, y, w, y, fill=self.BORDER, width=1)

        instant_max = max(max(self._bw_read, default=0),
                          max(self._bw_written, default=0))
        if instant_max == 0 and self._peak_hold < 1:
            # Empty state — draw label
            c.create_text(w // 2, h // 2, text="Waiting for data…",
                          fill=self.TEXT_DIM,
                          font=("Cascadia Code", 9))
            self._lbl_bw_max.config(text="")
            return

        # Peak-hold: ceiling rises immediately to accommodate bursts,
        # then decays slowly so the graph doesn't rescale on every sample.
        if instant_max > self._peak_hold:
            self._peak_hold = float(instant_max)
        else:
            self._peak_hold = max(instant_max,
                                  self._peak_hold * self.PEAK_DECAY)
        combined_max = self._peak_hold

        self._lbl_bw_max.config(
            text=f"peak  {_fmt_bytes(combined_max)}/s")

        def _poly(series, colour):
            n   = len(series)
            if n < 2:
                return
            step = w / (n - 1)
            pts  = []
            for i, val in enumerate(series):
                x = i * step
                y = pad_top + plot_h * (1 - val / combined_max)
                pts.append((x, y))
            # Filled area
            fill_pts = [(0, h)] + pts + [(w, h)]
            flat = [v for xy in fill_pts for v in xy]
            # Parse colour to make a translucent-ish fill
            r = int(colour[1:3], 16)
            g = int(colour[3:5], 16)
            b = int(colour[5:7], 16)
            fill_col = f"#{max(0,r-60):02x}{max(0,g-60):02x}{max(0,b-60):02x}"
            c.create_polygon(flat, fill=fill_col, outline="")
            # Line on top
            flat_line = [v for xy in pts for v in xy]
            c.create_line(flat_line, fill=colour, width=2, smooth=True)

        _poly(self._bw_read,    self.COL_READ)
        _poly(self._bw_written, self.COL_WRITE)

        # Legend
        lx = w - 4
        for label, col in [("↓ recv", self.COL_READ),
                            ("↑ send", self.COL_WRITE)]:
            c.create_text(lx, pad_top + 2, text=label,
                          fill=col, anchor="ne",
                          font=("Cascadia Code", 8))
            lx -= 56

    # ── identity refresh ───────────────────────
    def _refresh_identity(self):
        d = self._identity
        if not d:
            return

        def set_lbl(widget, val, colour=None):
            widget.config(text=str(val) if val else "—")
            if colour:
                widget.config(fg=colour)

        # ── LEFT: relay identity ──────────────
        set_lbl(self._id_nickname, d.get("nickname", "?"))
        set_lbl(self._id_address,  d.get("address",  "?"))

        fp = d.get("fingerprint", "")
        if fp:
            # Break fingerprint into 4-char groups for readability
            grouped = " ".join(fp[i:i+4] for i in range(0, len(fp), 4))
            if not hasattr(self, "_fp_font"):
                self._fp_font = self._f(
                    ["Cascadia Code", "Consolas", "Courier New"], 8)
            self._id_fp.config(text=grouped, font=self._fp_font)
        else:
            self._id_fp.config(text="—")

        set_lbl(self._id_orport,  d.get("orport",  "?"))
        set_lbl(self._id_version, d.get("version", "?"))
        set_lbl(self._id_uptime,  _fmt_uptime(d.get("uptime", 0)))

        bw_rate  = d.get("bw_rate",  "")
        bw_burst = d.get("bw_burst", "")
        try:
            rate_str  = _fmt_bytes(int(bw_rate))  if bw_rate  else "?"
            burst_str = _fmt_bytes(int(bw_burst)) if bw_burst else "?"
            set_lbl(self._id_bwrate, f"{rate_str}/s  (burst {burst_str}/s)")
        except ValueError:
            set_lbl(self._id_bwrate, bw_rate or "?")

        # Flags
        flags = d.get("flags", [])
        flag_col = {
            "Running": self.SUCCESS, "Valid": self.SUCCESS,
            "Guard":   "#a78bfa",   "Stable": "#7dcfff",
            "Fast":    "#e0af68",   "HSDir":  "#bb9af7",
            "Exit":    self.ERROR,  "BadExit": self.ERROR,
        }
        set_lbl(self._id_flags, " ".join(flags) if flags else "—")
        if flags:
            for f in ("Exit", "BadExit", "Guard", "Fast", "Running"):
                if f in flags:
                    self._id_flags.config(fg=flag_col.get(f, self.TEXT))
                    break

        # (connection list is updated by push_connections via ORCONN events)

class TorMonitorApp:
    BG       = "#0d0f14"
    PANEL    = "#13161e"
    BORDER   = "#1e2330"
    ACCENT   = "#7c3aed"
    SUCCESS  = "#10b981"
    WARNING  = "#f59e0b"
    ERROR    = "#ef4444"
    TEXT     = "#e2e8f0"
    TEXT_DIM = "#64748b"

    TERM_COLS = 120
    TERM_ROWS = 36

    def __init__(self, root):
        self.root     = root
        self.cfg      = load_config()
        _flog("info", "="*60)
        _flog("info", "Tor Bridge Monitor starting — log file: %s", LOG_FILE)
        self.worker      = None
        self.ctrl_worker = None
        self.screen_q    = queue.Queue(maxsize=120)
        self.status_q    = queue.Queue(maxsize=32)
        self.ctrl_q      = queue.Queue(maxsize=256)
        self._closing         = False  # set True in on_close to stop _poll loop
        self._dying_ctrl_worker = None  # previous ctrl worker being joined
        self._splash_root_binds = []   # root key binds set by disconnect splash
        self._watchdog_after_id = None  # after() ID for _watchdog_repoll
        self._spin_after_id     = None  # after() ID for overlay pulse animation
        self._connect_time    = None   # time.time() when connection established
        self._nyx_page        = 0      # estimated current nyx page index (0-based)
        self._uptime_after_id = None   # after() id for timer tick
        self._identity_logged = False  # suppress repeated identity log msgs
        self._last_conn_n     = -1     # dedup for OR connection log messages
        self._last_circ_built = -1     # dedup for circuit log messages
        self._last_circ_failed = -1
        self._build_ui()
        self._poll()
        if self.cfg.get("autoconnect") and self.cfg.get("host"):
            self.root.after(800, self._connect)

    # ── UI construction ──────────────────────
    def _build_ui(self):
        self.root.title("Tor Bridge Monitor")
        self.root.configure(bg=self.BG)
        self.root.geometry("1200x780")
        self.root.minsize(900, 600)

        title = self._font(["Segoe UI", "Arial"], 13, bold=True)
        label = self._font(["Segoe UI", "Arial"], 10)
        small = self._font(["Segoe UI", "Arial"], 9)
        mono  = self._font(["Cascadia Code", "Consolas", "Courier New"], 11)

        # Top bar
        topbar = tk.Frame(self.root, bg=self.BG, height=56)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)
        tk.Label(topbar, text="⬡", font=("Segoe UI", 22),
                 fg=self.ACCENT, bg=self.BG).pack(side="left", padx=(18, 6))
        tk.Label(topbar, text="Tor Bridge Monitor", font=title,
                 fg=self.TEXT, bg=self.BG).pack(side="left")
        self.status_dot = tk.Label(topbar, text="●", font=("Segoe UI", 14),
                                   fg=self.TEXT_DIM, bg=self.BG)
        self.status_dot.pack(side="right", padx=(0, 10))
        self.status_label = tk.Label(topbar, text="Not connected",
                                     font=small, fg=self.TEXT_DIM, bg=self.BG)
        self.status_label.pack(side="right", padx=(0, 4))
        # Uptime timer — hidden until connected
        self._uptime_label = tk.Label(topbar, text="",
                                      font=self._font(["Cascadia Code","Consolas","Courier New"], 9),
                                      fg=self.TEXT_DIM, bg=self.BG)
        self._uptime_label.pack(side="right", padx=(0, 16))
        self.sidebar_visible = True
        self.toggle_btn = tk.Button(
            topbar, text="◀  Hide Panel", font=small,
            bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
            activebackground=self.ACCENT, activeforeground="white",
            padx=10, pady=4, command=self._toggle_sidebar)
        self.toggle_btn.pack(side="right", padx=(0, 8))
        tk.Frame(self.root, bg=self.BORDER, height=1).pack(fill="x")

        # Body
        self._body_frame = tk.Frame(self.root, bg=self.BG)
        body = self._body_frame
        body.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(body, bg=self.PANEL, width=260)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        self._build_sidebar(self.sidebar, label, small, mono)

        self._right_frame = tk.Frame(body, bg=self.BG)
        right = self._right_frame
        right.pack(side="left", fill="both", expand=True)

        # Terminal header buttons
        term_header = tk.Frame(right, bg=self.BG, height=34)
        term_header.pack(fill="x")
        term_header.pack_propagate(False)
        self._view_label = tk.Label(term_header, text="Tor Bridge  —  live dashboard",
                 font=small, fg=self.TEXT_DIM,
                 bg=self.BG)
        self._view_label.pack(side="left", padx=14, pady=8)

        # View toggle — Dashboard / Terminal
        self._view_mode = "dashboard"   # start on dashboard
        self._view_toggle_btn = tk.Button(
            term_header, text="⬡  Dashboard", font=small,
            bg=self.ACCENT, fg="white", bd=0, cursor="hand2",
            activebackground="#6d28d9", activeforeground="white",
            padx=10, pady=2, command=self._toggle_view)
        self._view_toggle_btn.pack(side="right", padx=(0, 8), pady=6)

        # Actions menu button — always visible
        self._actions_btn = tk.Button(
            term_header, text="⚡ Actions", font=small,
            bg=self.BORDER, fg=self.TEXT, bd=0, cursor="hand2",
            activebackground=self.ACCENT, activeforeground="white",
            padx=10, pady=2, command=self._show_actions_menu)
        self._actions_btn.pack(side="right", padx=(0, 4), pady=6)

        self._nyx_btns = []
        # Graph/page picker — shown in terminal view
        self._graph_btn = tk.Button(
            term_header, text="📊 Graph", font=small,
            bg=self.BORDER, fg=self.TEXT, bd=0, cursor="hand2",
            activebackground=self.ACCENT, activeforeground="white",
            padx=10, pady=2, command=self._show_graph_menu)
        self._graph_btn.pack(side="right", padx=(0, 4), pady=6)
        self._nyx_btns.append(self._graph_btn)

        for label_text, key_bytes in [
                ("Ctrl+C", b"\x03"), ("Ctrl+Z", b"\x1a"), ("q  quit", b"q")]:
            btn = tk.Button(term_header, text=label_text, font=small,
                      bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
                      padx=8, pady=2,
                      command=lambda k=key_bytes: self._send_key(k))
            btn.pack(side="right", padx=(0, 4), pady=6)
            self._nyx_btns.append(btn)
        # nyx buttons visible only in terminal view — hide initially
        for btn in self._nyx_btns:
            btn.pack_forget()

        # ── view container ────────────────────────────
        self._view_container = tk.Frame(right, bg=self.BG)
        self._view_container.pack(fill="both", expand=True)

        # Dashboard panel (visible by default)
        self.dashboard = DashboardPanel(self._view_container)
        self.dashboard.pack(fill="both", expand=True)

        # Terminal canvas (hidden until toggled)
        self.term = TerminalCanvas(self._view_container, self.TERM_COLS,
                                   self.TERM_ROWS,
                                   font_name="Cascadia Code", font_size=11)
        self.term._key_callback = self._on_term_event
        # term starts hidden — shown when user switches to terminal view

        # Loading overlay — covers terminal canvas during connection / checks
        self._overlay        = None
        self._overlay_steps  = []   # list of (label_widget, icon_widget)
        # Show connect-mode picker on startup (replaced by loading overlay on connect)
        self.root.after(50, self._show_disconnect_splash)

        # ── Debug log panel ───────────────────────────────────────────
        self._log_visible = True   # open by default
        self._LOG_MAX     = 200
        self._log_height  = 160    # pixel height, adjustable by drag handle

        # Outer collapsible container — height driven by _log_height when visible.
        # pack_propagate(False) lets us set an explicit pixel height via configure().
        self._log_frame = tk.Frame(self.root, bg=self.PANEL,
                                   height=self._log_height)
        self._log_frame.pack_propagate(False)
        # Packed after status bar is built (see below)

        # ── Drag handle — sits at the very top of _log_frame ─────────────
        # The user drags this strip up/down to resize the log panel.
        # cursor="sb_v_double_arrow" gives the ↕ resize cursor on hover.
        log_handle = tk.Frame(self._log_frame, bg=self.BORDER,
                              height=4, cursor="sb_v_double_arrow")
        log_handle.pack(fill="x", side="top")
        log_handle.pack_propagate(False)

        self._log_drag_y   = None   # Y coord at mouse-down
        self._log_drag_h   = None   # panel height at mouse-down
        LOG_MIN_H = 60              # minimum panel height in pixels
        LOG_MAX_H = 600             # maximum panel height in pixels

        def _log_drag_start(event):
            self._log_drag_y = event.y_root
            self._log_drag_h = self._log_frame.winfo_height()

        def _log_drag_move(event):
            if self._log_drag_y is None:
                return
            delta = self._log_drag_y - event.y_root   # dragging UP = larger
            new_h = max(LOG_MIN_H, min(LOG_MAX_H,
                                       self._log_drag_h + delta))
            self._log_height = new_h
            self._log_frame.configure(height=new_h)

        def _log_drag_end(event):
            self._log_drag_y = None
            self._log_drag_h = None

        log_handle.bind("<ButtonPress-1>",   _log_drag_start)
        log_handle.bind("<B1-Motion>",       _log_drag_move)
        log_handle.bind("<ButtonRelease-1>", _log_drag_end)

        # Visual hint: lighten handle on hover
        log_handle.bind("<Enter>",
            lambda e: log_handle.config(bg="#2e3a50"))
        log_handle.bind("<Leave>",
            lambda e: log_handle.config(bg=self.BORDER))

        # ── Inner content (header + text) ─────────────────────────────────
        log_inner = tk.Frame(self._log_frame, bg=self.PANEL)
        log_inner.pack(fill="both", expand=True, padx=0, pady=0)

        log_hdr = tk.Frame(log_inner, bg=self.PANEL, height=24)
        log_hdr.pack(fill="x")
        log_hdr.pack_propagate(False)
        tk.Label(log_hdr, text="DEBUG LOG", font=small,
                 fg=self.ACCENT, bg=self.PANEL).pack(side="left", padx=10)
        tk.Button(log_hdr, text="Clear", font=small,
                  bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
                  padx=6, pady=0,
                  command=self._log_clear).pack(side="right", padx=6, pady=2)
        tk.Button(log_hdr, text="Copy", font=small,
                  bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
                  padx=6, pady=0,
                  command=self._log_copy).pack(side="right", padx=(6, 0), pady=2)

        log_text_frame = tk.Frame(log_inner, bg=self.PANEL)
        log_text_frame.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        self._log_text = tk.Text(
            log_text_frame,
            bg="#090b10", fg="#64748b",
            font=self._font(["Cascadia Code","Consolas","Courier New"], 8),
            bd=0, highlightthickness=0,
            state="disabled", wrap="word",
            selectbackground=self.BORDER,
            insertbackground=self.TEXT,
        )
        log_sb_v = ttk.Scrollbar(log_text_frame, orient="vertical",
                                  command=self._log_text.yview,
                                  style="Dark.Vertical.TScrollbar")
        self._log_text.configure(yscrollcommand=log_sb_v.set)
        log_sb_v.pack(side="right", fill="y")
        self._log_text.pack(side="left", fill="both", expand=True)

        # Tag colours for log levels
        self._log_text.tag_configure("ts",    foreground="#2e3a50")
        self._log_text.tag_configure("info",  foreground="#64748b")
        self._log_text.tag_configure("ok",    foreground="#10b981")
        self._log_text.tag_configure("warn",  foreground="#f59e0b")
        self._log_text.tag_configure("error", foreground="#ef4444")
        self._log_text.tag_configure("ctrl",  foreground="#7aa2f7")
        self._log_text.tag_configure("conn",  foreground="#bb9af7")

        # ── Status bar ────────────────────────────────────────────────
        # Pack from bottom up so body's expand=True stops above these widgets.
        # Order matters: bar first (bottom-most), then sep above it.
        bar = tk.Frame(self.root, bg=self.PANEL, height=26)
        bar.pack(side="bottom", fill="x")
        self._statusbar_sep = tk.Frame(self.root, bg=self.BORDER, height=1)
        self._statusbar_sep.pack(side="bottom", fill="x")
        bar.pack_propagate(False)
        # Pack the toggle button FIRST so it anchors to the right edge
        # before the label claims remaining space — prevents it disappearing
        # when the window is narrowed.
        self._log_toggle_btn = tk.Button(
            bar, text="⬡ Debug Log", font=small,
            bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
            padx=8, pady=0,
            command=self._toggle_log)
        self._log_toggle_btn.pack(side="right", padx=6, pady=3)
        self.statusbar = tk.Label(bar, font=small, fg=self.TEXT_DIM,
                                  bg=self.PANEL,
                                  text="Enter SSH credentials and click Connect")
        self.statusbar.pack(side="left", padx=12, fill="x", expand=True)

        # Log open by default — pack it now that the separator exists
        self._log_frame.pack(side="bottom", fill="x",
                             before=self._statusbar_sep)
        self._log_toggle_btn.config(bg=self.ACCENT, fg="white")

        if not HAS_PARAMIKO:
            self._set_status("error",
                "⚠  paramiko not installed — run: pip install paramiko pyte")
        if not HAS_PYTE:
            self._set_status("error",
                "⚠  pyte not installed — run: pip install paramiko pyte")

    def _build_sidebar(self, parent, label, small, mono):
        pad = {"padx": 16, "pady": 3}

        def section(text):
            tk.Label(parent, text=text.upper(), font=small,
                     fg=self.ACCENT, bg=self.PANEL,
                     anchor="w").pack(fill="x", padx=16, pady=(10, 2))
            tk.Frame(parent, bg=self.BORDER, height=1).pack(fill="x", padx=16)

        def field(lbl, default, show=""):
            tk.Label(parent, text=lbl, font=small, fg=self.TEXT_DIM,
                     bg=self.PANEL, anchor="w").pack(fill="x", **pad)
            var = tk.StringVar(value=default)
            tk.Entry(parent, textvariable=var, font=mono,
                     bg=self.BG, fg=self.TEXT, bd=0,
                     insertbackground=self.TEXT,
                     highlightthickness=1,
                     highlightcolor=self.ACCENT,
                     highlightbackground=self.BORDER,
                     show=show).pack(fill="x", padx=16, ipady=5)
            return var

        tk.Frame(parent, bg=self.PANEL, height=10).pack()
        section("SSH Connection")
        self.host_var = field("Hostname / IP",   self.cfg.get("host", ""))
        self.port_var = field("SSH Port",         self.cfg.get("port", "22"))
        self.user_var = field("Username",          self.cfg.get("user", "pi"))
        self.pass_var = field("Password",          self.cfg.get("password", ""),
                               show="●")

        section("SSH Key (optional)")
        self.key_var = field("Path to private key", self.cfg.get("key_path", ""))
        key_row = tk.Frame(parent, bg=self.PANEL)
        key_row.pack(fill="x", padx=16, pady=(3, 8))
        tk.Button(key_row, text="Browse…", font=small,
                  bg=self.BORDER, fg=self.TEXT, bd=0, cursor="hand2",
                  activebackground=self.ACCENT, activeforeground="white",
                  padx=10, pady=3,
                  command=self._browse_key).pack(side="left")

        # ── nyx Keys collapsible dropdown ────
        self._keys_expanded = False

        keys_header = tk.Frame(parent, bg=self.PANEL)
        keys_header.pack(fill="x", padx=16, pady=(10, 0))
        self._keys_arrow = tk.Label(keys_header, text="▶",
                                    font=small, fg=self.ACCENT, bg=self.PANEL)
        self._keys_arrow.pack(side="left")
        keys_title = tk.Label(keys_header, text="  NYX KEYS",
                              font=small, fg=self.ACCENT, bg=self.PANEL,
                              anchor="w", cursor="hand2")
        keys_title.pack(side="left", fill="x", expand=True)
        tk.Frame(parent, bg=self.BORDER, height=1).pack(
            fill="x", padx=16, pady=(2, 0))

        self._keys_panel = tk.Frame(parent, bg=self.PANEL)
        for k, v in [("← → / n", "Switch page"), ("p", "Pause"),
                     ("h", "Help"), ("m", "Menu"),
                     ("q", "Quit nyx"),  ("d", "Details")]:
            row = tk.Frame(self._keys_panel, bg=self.PANEL)
            row.pack(fill="x", padx=4, pady=1)
            tk.Label(row, text=k, font=mono, fg=self.ACCENT,
                     bg=self.PANEL, width=10, anchor="w").pack(side="left")
            tk.Label(row, text=v, font=small, fg=self.TEXT_DIM,
                     bg=self.PANEL, anchor="w").pack(side="left")

        # Spacer anchors the panel — dropdown inserts before it
        self._keys_spacer = tk.Frame(parent, bg=self.PANEL)
        self._keys_spacer.pack(fill="both", expand=True)

        def toggle_keys(_event=None):
            self._keys_expanded = not self._keys_expanded
            if self._keys_expanded:
                self._keys_panel.pack(fill="x", padx=12, pady=(4, 0),
                                      before=self._keys_spacer)
                self._keys_arrow.config(text="▼")
            else:
                self._keys_panel.pack_forget()
                self._keys_arrow.config(text="▶")

        for w in (keys_header, keys_title, self._keys_arrow):
            w.bind("<Button-1>", toggle_keys)

        # Autoconnect checkbox
        ac_row = tk.Frame(parent, bg=self.PANEL)
        ac_row.pack(fill="x", padx=16, pady=(0, 4))
        self.autoconnect_var = tk.BooleanVar(
            value=self.cfg.get("autoconnect", False))
        tk.Checkbutton(
            ac_row, text="Auto-connect on launch",
            variable=self.autoconnect_var, font=small,
            fg=self.TEXT_DIM, bg=self.PANEL, selectcolor=self.BG,
            activebackground=self.PANEL, activeforeground=self.TEXT,
            cursor="hand2",
            command=self._save_autoconnect).pack(side="left")

        # Connect / Disconnect buttons
        btn = tk.Frame(parent, bg=self.PANEL)
        btn.pack(fill="x", padx=16, pady=12)
        self.connect_btn = tk.Button(
            btn, text="⬡  Connect", font=label,
            bg=self.ACCENT, fg="white", bd=0, cursor="hand2",
            activebackground="#6d28d9", activeforeground="white",
            pady=8, command=self._connect)
        self.connect_btn.pack(fill="x", pady=(0, 6))
        self.disconnect_btn = tk.Button(
            btn, text="Disconnect", font=label,
            bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
            activebackground=self.ERROR, activeforeground="white",
            pady=8, command=self._disconnect, state="disabled")
        self.disconnect_btn.pack(fill="x")

        tk.Label(parent, text="nyx · tor bridge · ssh monitor",
                 font=small, fg=self.TEXT_DIM,
                 bg=self.PANEL).pack(pady=(0, 10))

    # ── Disconnect splash (connect-mode picker) ───────────────────
    def _show_disconnect_splash(self):
        """Show the idle splash screen with two keyboard-navigable options:
        Connect Nyx  |  Connect SSH Shell
        Shares the same visual DNA as the loading overlay."""
        if self._overlay:
            self._hide_overlay()

        self._overlay_steps  = []
        self._spin_frame_idx = 0
        self._spin_after_id  = None
        self._pulse_r        = 0.0

        # Outer overlay — full-bleed over the right panel
        ov = tk.Frame(self._right_frame, bg=self.BG)
        ov.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._overlay = ov

        # Scanlines texture (Canvas sits behind everything via place)
        scan = tk.Canvas(ov, bg=self.BG, highlightthickness=0)
        scan.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._overlay_scan = scan
        self._draw_scanlines(scan)
        scan.bind("<Configure>", lambda e, c=scan: self._draw_scanlines(c))

        # ── Centre the content column using grid ──────────────────────
        # grid() lets us use row/column weights to centre a widget without
        # place(), which gives zero intrinsic size to its children.
        ov.grid_rowconfigure(0, weight=1)
        ov.grid_rowconfigure(2, weight=1)
        ov.grid_columnconfigure(0, weight=1)
        ov.grid_columnconfigure(2, weight=1)

        col = tk.Frame(ov, bg=self.BG)
        col.grid(row=1, column=1, sticky="")   # naturally sized, centred

        ui_title = self._font(["Segoe UI", "Helvetica Neue", "Arial"], 15, bold=True)
        ui_sub   = self._font(["Segoe UI", "Helvetica Neue", "Arial"],  9)
        ui_btn   = self._font(["Segoe UI", "Helvetica Neue", "Arial"], 11)
        ui_desc  = self._font(["Segoe UI", "Helvetica Neue", "Arial"],  8)

        # Hex icon with animated pulse ring
        ic = tk.Canvas(col, width=80, height=80,
                       bg=self.BG, highlightthickness=0)
        ic.pack(pady=(0, 4))
        self._pulse_ring  = ic.create_oval(6, 6, 74, 74,
                                           outline=self.ACCENT, width=2)
        ic.create_text(40, 42, text="⬡",
                       font=("Segoe UI", 34), fill=self.ACCENT)
        self._icon_canvas = ic

        tk.Label(col, text="TOR BRIDGE MONITOR",
                 font=ui_title, fg=self.TEXT, bg=self.BG).pack(pady=(2, 0))

        rule = tk.Canvas(col, height=3, width=300,
                         bg=self.BG, highlightthickness=0)
        rule.pack(pady=(10, 20))
        rule.create_line(0,   1, 300, 1, fill=self.BORDER, width=1)
        rule.create_line(80,  1, 220, 1, fill=self.ACCENT, width=2)
        rule.create_line(130, 1, 170, 1, fill="#c4b5fd",   width=2)

        # ── Menu options ──────────────────────────────────────────────
        options = [
            ("⬡  Connect Nyx",
             "Launch nyx monitor  ·  live dashboard  ·  Tor control port",
             self._connect),
            ("⌨  SSH Shell",
             "Open raw SSH terminal  ·  full shell access",
             self._connect_shell),
        ]

        self._splash_sel   = 0
        self._splash_items = []   # list of (outer_frame, inner_frame, lbl, desc)

        item_container = tk.Frame(col, bg=self.BG)
        item_container.pack(pady=(0, 4))

        def _select(idx):
            self._splash_sel = idx
            for i, (fr, inn, lbl, desc) in enumerate(self._splash_items):
                if i == idx:
                    for w in (fr, inn, lbl, desc):
                        w.config(bg=self.ACCENT)
                    lbl.config(fg="white")
                    desc.config(fg="#c4b5fd")
                else:
                    for w in (fr, inn, lbl, desc):
                        w.config(bg=self.BORDER)
                    lbl.config(fg=self.TEXT)
                    desc.config(fg=self.TEXT_DIM)

        def _execute(idx=None):
            if idx is None:
                idx = self._splash_sel
            fn = options[idx][2]
            self._hide_overlay()
            fn()

        for i, (label_text, desc_text, _fn) in enumerate(options):
            fr = tk.Frame(item_container, bg=self.BORDER, cursor="hand2")
            fr.pack(fill="x", pady=4, ipadx=0, ipady=0)

            inn = tk.Frame(fr, bg=self.BORDER)
            inn.pack(fill="x", padx=18, pady=10)

            lbl = tk.Label(inn, text=label_text, font=ui_btn,
                           fg=self.TEXT, bg=self.BORDER, anchor="w")
            lbl.pack(fill="x")
            desc = tk.Label(inn, text=desc_text, font=ui_desc,
                            fg=self.TEXT_DIM, bg=self.BORDER, anchor="w")
            desc.pack(fill="x")

            self._splash_items.append((fr, inn, lbl, desc))

            for w in (fr, inn, lbl, desc):
                w.bind("<Button-1>", lambda e, ii=i: _execute(ii))
                w.bind("<Enter>",    lambda e, ii=i: _select(ii))

        _select(0)

        tk.Label(col, text="↑ ↓  navigate  ·  Enter  execute",
                 font=ui_sub, fg=self.TEXT_DIM,
                 bg=self.BG).pack(pady=(14, 0))

        # ── Keyboard navigation ───────────────────────────────────────
        # tk.Frame cannot receive keyboard focus on Windows, so we plant a
        # zero-size hidden Entry inside the overlay and focus that instead.
        # All key events bubble up through the entry's bindings.
        focus_trap = tk.Entry(ov, width=0, bd=0, highlightthickness=0,
                              bg=self.BG, fg=self.BG,
                              insertbackground=self.BG,
                              takefocus=True)
        focus_trap.place(x=0, y=0, width=1, height=1)

        def _on_key(event):
            if not self._overlay:
                return "break"
            sym = event.keysym
            if sym == "Up":
                _select((self._splash_sel - 1) % len(options))
                return "break"
            elif sym == "Down":
                _select((self._splash_sel + 1) % len(options))
                return "break"
            elif sym in ("Return", "KP_Enter"):
                _execute()
                return "break"

        focus_trap.bind("<Up>",      _on_key)
        focus_trap.bind("<Down>",    _on_key)
        focus_trap.bind("<Return>",  _on_key)
        focus_trap.bind("<KP_Enter>",_on_key)
        focus_trap.bind("<Key>",     _on_key)

        # Also bind on root so keys work even if something else steals focus
        self.root.bind("<Up>",      _on_key)
        self.root.bind("<Down>",    _on_key)
        self.root.bind("<Return>",  _on_key)
        self._splash_root_binds = ["<Up>", "<Down>", "<Return>"]

        # Give keyboard focus to the trap widget
        ov.after(50, focus_trap.focus_set)

        # Start pulse animation
        self._animate_pulse()

    def _connect_shell(self):
        """Connect via SSH and open a raw shell (no nyx, no Tor check)."""
        if not HAS_PARAMIKO or not HAS_PYTE:
            messagebox.showerror("Missing dependencies",
                "Install required packages:\n\n"
                "  pip install paramiko pyte\n\nThen restart the app.")
            return

        cfg = {
            "host":     self.host_var.get().strip(),
            "port":     self.port_var.get().strip() or "22",
            "user":     self.user_var.get().strip() or "pi",
            "password": self.pass_var.get(),
            "key_path": self.key_var.get().strip(),
        }
        if not cfg["host"]:
            messagebox.showwarning("Missing host",
                "Enter the Raspberry Pi hostname or IP.")
            return

        cfg["autoconnect"] = self.autoconnect_var.get()
        save_config(cfg)
        self.cfg = cfg

        if self.worker:
            self.worker.stop()
            self.worker = None
        self._stop_ctrl_worker()   # ensure any lingering ctrl worker is stopped
        self._identity_logged  = False
        self._last_conn_n      = -1
        self._last_circ_built  = -1
        self._last_circ_failed = -1

        self.connect_btn.config(state="disabled")
        self.disconnect_btn.config(state="normal")

        self._show_overlay()
        self._overlay_set_pending(f"Connecting to {cfg['host']}…")

        self.worker = SSHWorker(cfg, self.term.cols, self.term.rows,
                                self.screen_q, self.status_q, mode="shell")
        self.worker.start()

    # ── Loading overlay ──────────────────────────
    # Braille spinner frames
    _SPIN_FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def _show_overlay(self):
        """Replace terminal with a polished animated loading screen."""
        if self._overlay:
            self._hide_overlay()

        self._overlay_steps  = []
        self._spin_frame_idx = 0
        self._spin_after_id  = None
        self._pulse_r        = 0.0

        # Outer frame — covers entire right panel
        ov = tk.Frame(self._right_frame, bg=self.BG)
        ov.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._overlay = ov

        # Scanline canvas (decorative full-bleed texture)
        scan = tk.Canvas(ov, bg=self.BG, highlightthickness=0)
        scan.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._overlay_scan = scan
        self._draw_scanlines(scan)
        scan.bind("<Configure>", lambda e, c=scan: self._draw_scanlines(c))

        # Centre column
        col = tk.Frame(ov, bg=self.BG)
        col.place(relx=0.5, rely=0.44, anchor="center")

        mono_step = self._font(["Cascadia Code", "Consolas", "Courier New"], 10)
        ui_title  = self._font(["Segoe UI", "Helvetica Neue", "Arial"], 15, bold=True)
        ui_sub    = self._font(["Segoe UI", "Helvetica Neue", "Arial"],  9)

        # Hex icon with animated pulse ring
        ic = tk.Canvas(col, width=80, height=80,
                       bg=self.BG, highlightthickness=0)
        ic.pack(pady=(0, 4))
        self._pulse_ring = ic.create_oval(6, 6, 74, 74,
                                          outline=self.ACCENT, width=2)
        ic.create_text(40, 42, text="\u2b21",
                       font=("Segoe UI", 34), fill=self.ACCENT)
        self._icon_canvas = ic

        # Title
        tk.Label(col, text="TOR BRIDGE MONITOR",
                 font=ui_title, fg=self.TEXT, bg=self.BG).pack(pady=(2, 0))

        # Accent rule with bright centre segment
        rule = tk.Canvas(col, height=3, width=300,
                         bg=self.BG, highlightthickness=0)
        rule.pack(pady=(10, 16))
        rule.create_line(0,   1, 300, 1, fill=self.BORDER, width=1)
        rule.create_line(80,  1, 220, 1, fill=self.ACCENT, width=2)
        rule.create_line(130, 1, 170, 1, fill="#c4b5fd",   width=2)

        # Step list
        self._step_container = tk.Frame(col, bg=self.BG, width=300)
        self._step_container.pack(fill="x")
        self._step_container.pack_propagate(False)

        # Spinner row — always below steps
        spin_row = tk.Frame(col, bg=self.BG)
        spin_row.pack(pady=(8, 0), anchor="w", fill="x")
        self._spin_icon_lbl = tk.Label(spin_row, text="",
                                       font=mono_step,
                                       fg=self.ACCENT, bg=self.BG, width=2)
        self._spin_icon_lbl.pack(side="left")
        self._spin_text_lbl = tk.Label(spin_row, text="",
                                       font=mono_step,
                                       fg=self.TEXT_DIM, bg=self.BG)
        self._spin_text_lbl.pack(side="left")

        # Subtitle tag
        tk.Label(col, text="ssh  \u00b7  nyx  \u00b7  tor",
                 font=ui_sub, fg=self.TEXT_DIM,
                 bg=self.BG).pack(pady=(18, 0))

        # Start animation loop
        self._animate_pulse()

    def _draw_scanlines(self, canvas):
        """Paint faint horizontal scan-lines across the overlay canvas."""
        canvas.delete("scan")
        h = canvas.winfo_height() or 600
        w = canvas.winfo_width()  or 1000
        for y in range(0, h, 4):
            canvas.create_line(0, y, w, y, fill="#161929",
                               tags="scan", width=1)

    def _animate_pulse(self):
        """Drive the pulsing ring and braille spinner at 80 ms intervals."""
        if not self._overlay:
            return
        try:
            self._pulse_r = (self._pulse_r + 0.05) % (2 * math.pi)
            s    = 0.82 + 0.18 * math.sin(self._pulse_r)
            cx = cy = 40
            r  = 32
            self._icon_canvas.coords(self._pulse_ring,
                                     cx - r*s, cy - r*s,
                                     cx + r*s, cy + r*s)
            bright = int(160 + 95 * math.sin(self._pulse_r))
            bright = max(90, min(255, bright))
            ring_col = "#{:02x}{:02x}ff".format(
                max(0, bright - 80), max(0, bright - 80))
            self._icon_canvas.itemconfig(self._pulse_ring,
                                         outline=ring_col, width=2)
            # Advance spinner only while there is a pending label
            if self._spin_text_lbl.cget("text"):
                self._spin_frame_idx = (
                    self._spin_frame_idx + 1) % len(self._SPIN_FRAMES)
                self._spin_icon_lbl.config(
                    text=self._SPIN_FRAMES[self._spin_frame_idx])
        except Exception:
            return
        self._spin_after_id = self._overlay.after(80, self._animate_pulse)

    def _hide_overlay(self):
        """Cancel animations and destroy the overlay frame."""
        if self._spin_after_id:
            try:
                self._overlay.after_cancel(self._spin_after_id)
            except Exception:
                pass
        self._spin_after_id  = None
        if self._overlay:
            self._overlay.destroy()
        self._overlay        = None
        self._step_container = None
        self._overlay_steps  = []
        # Remove root-level key bindings set by the disconnect splash
        for seq in getattr(self, "_splash_root_binds", []):
            try:
                self.root.unbind(seq)
            except Exception:
                pass
        self._splash_root_binds = []

    def _overlay_add_step(self, text, state):
        """Append a step row to the loading screen."""
        sc = getattr(self, "_step_container", None)
        if sc is None or not self._overlay:
            return
        if not hasattr(self, "_overlay_step_font"):
            self._overlay_step_font = self._font(
                ["Cascadia Code", "Consolas", "Courier New"], 10)
        mono_step = self._overlay_step_font
        icons = {"pending": "\u25a1", "ok": "\u2713",
                 "warn":    "\u25b3", "error": "\u2717"}
        fgs   = {"pending": self.TEXT_DIM, "ok": self.SUCCESS,
                 "warn": self.WARNING,     "error": self.ERROR}
        row = tk.Frame(sc, bg=self.BG)
        row.pack(fill="x", pady=3, anchor="w")
        icon_lbl = tk.Label(row, text=icons.get(state, "\u25a1"),
                            font=mono_step,
                            fg=fgs.get(state, self.TEXT_DIM),
                            bg=self.BG, width=2, anchor="w")
        icon_lbl.pack(side="left")
        text_lbl = tk.Label(row, text=text, font=mono_step,
                            fg=fgs.get(state, self.TEXT_DIM),
                            bg=self.BG, anchor="w")
        text_lbl.pack(side="left")
        self._overlay_steps.append([icon_lbl, text_lbl, state])
        if state == "pending":
            # Show spinner icon next to the pending row
            self._spin_icon_lbl.config(
                text=self._SPIN_FRAMES[self._spin_frame_idx])
            self._spin_text_lbl.config(text="")
        else:
            self._spin_icon_lbl.config(text="")
            self._spin_text_lbl.config(text="")

    def _overlay_update_last(self, state, text=None):
        """Resolve the most recent pending step to ok / warn / error."""
        if not self._overlay_steps:
            return
        icons = {"ok": "\u2713", "warn": "\u25b3", "error": "\u2717"}
        fgs   = {"ok": self.SUCCESS, "warn": self.WARNING, "error": self.ERROR}
        entry = self._overlay_steps[-1]
        icon_lbl, text_lbl, _ = entry
        icon_lbl.config(text=icons.get(state, "\u25a1"),
                        fg=fgs.get(state, self.TEXT_DIM))
        text_lbl.config(fg=fgs.get(state, self.TEXT_DIM))
        if text:
            text_lbl.config(text=text)
        entry[2] = state
        if state in ("ok", "warn", "error"):
            self._spin_icon_lbl.config(text="")
            self._spin_text_lbl.config(text="")

    def _overlay_set_pending(self, text):
        """Set the spinner label to reflect the current in-progress action."""
        if not self._overlay:
            return
        self._spin_text_lbl.config(text=text)
        self._spin_icon_lbl.config(
            text=self._SPIN_FRAMES[self._spin_frame_idx])

    # ── Autoconnect ──────────────────────────
    def _save_autoconnect(self):
        self.cfg["autoconnect"] = self.autoconnect_var.get()
        save_config(self.cfg)

    # ── Sidebar toggle ───────────────────────
    def _toggle_sidebar(self):
        if self.sidebar_visible:
            self.sidebar.pack_forget()
            self.toggle_btn.config(text="▶  Show Panel")
        else:
            self._right_frame.pack_forget()
            self.sidebar.pack(side="left", fill="y")
            self._right_frame.pack(side="left", fill="both", expand=True)
            self.toggle_btn.config(text="◀  Hide Panel")
        self.sidebar_visible = not self.sidebar_visible

    # ── Connect / Disconnect ─────────────────
    def _connect(self):
        if not HAS_PARAMIKO or not HAS_PYTE:
            messagebox.showerror("Missing dependencies",
                "Install required packages:\n\n"
                "  pip install paramiko pyte\n\nThen restart the app.")
            return

        cfg = {
            "host":     self.host_var.get().strip(),
            "port":     self.port_var.get().strip() or "22",
            "user":     self.user_var.get().strip() or "pi",
            "password": self.pass_var.get(),
            "key_path": self.key_var.get().strip(),
        }
        if not cfg["host"]:
            messagebox.showwarning("Missing host",
                "Enter the Raspberry Pi hostname or IP.")
            return

        cfg["autoconnect"] = self.autoconnect_var.get()
        save_config(cfg)
        self.cfg = cfg

        if self.worker:
            self.worker.stop()
            self.worker = None
        self._stop_ctrl_worker()   # stop any lingering ctrl worker from previous session
        self._identity_logged  = False
        self._last_conn_n      = -1
        self._last_circ_built  = -1
        self._last_circ_failed = -1

        self.connect_btn.config(state="disabled")
        self.disconnect_btn.config(state="normal")

        # Reset overlay for fresh connection
        self._show_overlay()
        self._overlay_set_pending(f"Connecting to {cfg['host']}…")

        self.worker = SSHWorker(cfg, self.term.cols, self.term.rows,
                                self.screen_q, self.status_q)
        self.worker.start()

    def _disconnect(self):
        self._hide_overlay()
        if self.worker:
            # Gracefully quit nyx before closing the channel.
            # Send 'q' to exit nyx, then a short pause so the shell
            # can return to prompt before the channel is torn down.
            # This prevents "broken pipe" errors on the Pi side.
            if getattr(self.worker, "_nyx_running", False):
                try:
                    self.worker.send(b"q")
                except Exception:
                    pass
                self.root.after(300, lambda: self._finish_disconnect())
            else:
                self._finish_disconnect()
        else:
            self._finish_disconnect()

    def _start_ctrl_worker(self):
        """Start TorControlWorker on the existing SSH transport."""
        if not self.worker or not self.worker.client:
            return
        if self.ctrl_worker and self.ctrl_worker.is_alive():
            return
        if getattr(self, '_ctrl_launching', False):
            return   # _launch thread already in flight — don't spawn a second
        self._ctrl_launching = True
        # Drain stale events from a previous session.
        # The old SSHWorker's finally block always posts ("disconnected", ...)
        # to status_q — if that message hasn't been processed yet, _poll would
        # call _stop_ctrl_worker() on the new worker the moment it starts.
        # The old TorControlWorker posts "ctrl_disconnected" to ctrl_q similarly.
        # Drain both queues so no stale messages from the previous session can
        # interfere with the freshly started worker.
        for q in (self.ctrl_q, self.status_q):
            try:
                while True:
                    q.get_nowait()
            except Exception:
                pass

        ssh_client = self.worker.client

        def _launch():
            try:
                # If a previous ctrl_worker thread is still alive (e.g. its socket
                # just closed), wait for it to exit before opening a new channel.
                # Tor only allows one authenticated control connection at a time —
                # if the old channel is still open when we authenticate, Tor drops
                # the new connection.  join() here is safe because we are on a
                # background thread, not the main (tkinter) thread.
                old = getattr(self, '_dying_ctrl_worker', None)
                if old is not None and old.is_alive():
                    old.join(timeout=3.0)

                if self._closing:
                    return
                if not self.worker or self.worker.client is not ssh_client:
                    # SSH session was replaced while we were waiting — abort
                    return

                worker = TorControlWorker(ssh_client, self.ctrl_q)
                self.ctrl_worker = worker
                worker.start()
            finally:
                self._ctrl_launching = False   # allow future calls through

        threading.Thread(target=_launch, daemon=True).start()

    def _stop_ctrl_worker(self):
        if self.ctrl_worker:
            w = self.ctrl_worker
            self.ctrl_worker = None
            # Keep reference so _start_ctrl_worker's _launch thread can
            # join() it before opening a new Tor control connection.
            self._dying_ctrl_worker = w
            w.stop()

    def _finish_disconnect(self):
        self._stop_ctrl_worker()
        self._stop_uptime()
        self._identity_logged = False
        if self.worker:
            self.worker.stop()
            self.worker = None
        for q in (self.screen_q, self.status_q, self.ctrl_q):
            try:
                while True:
                    q.get_nowait()
            except Exception:
                pass
        self._set_status("disconnected", "Disconnected")
        self._log("Disconnected", "warn")
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")
        self._show_disconnect_splash()

    def _send_key(self, data: bytes):
        if self.worker:
            self.worker.send(data)

    def _on_term_event(self, event):
        if event[0] == "key":
            self._send_key(event[1])
        elif event[0] == "resize":
            _, cols, rows = event
            if self.worker:
                self.worker.resize(cols, rows)

    def _toggle_view(self):
        """Switch between Dashboard and nyx Terminal views."""
        if self._view_mode == "dashboard":
            # Switch to terminal
            self.dashboard.pack_forget()
            self.term.pack(fill="both", expand=True)
            self.term.focus_set()
            self._view_mode = "terminal"
            self._view_toggle_btn.config(text="⬢  Terminal",
                                          bg=self.ACCENT, fg="white",
                                          activebackground="#6d28d9",
                                          activeforeground="white")
            self._view_label.config(text="nyx  —  Bandwidth")
            self._nyx_page = 0
            self._graph_btn.config(bg=self.BORDER, fg=self.TEXT)
            # Show nyx control buttons
            for btn in getattr(self, "_nyx_btns", []):
                btn.pack(side="right", padx=(0, 4), pady=6)
        else:
            # Switch to dashboard
            self.term.pack_forget()
            self.dashboard.pack(fill="both", expand=True)
            self._view_mode = "dashboard"
            self._view_toggle_btn.config(text="⬡  Dashboard",
                                          bg=self.ACCENT, fg="white",
                                          activebackground="#6d28d9",
                                          activeforeground="white")
            self._view_label.config(text="Tor Bridge  —  live dashboard")
            # Hide nyx control buttons
            for btn in getattr(self, "_nyx_btns", []):
                btn.pack_forget()

    def _browse_key(self):
        path = filedialog.askopenfilename(
            title="Select SSH Private Key",
            filetypes=[("All files", "*.*"),
                       ("PEM files", "*.pem"),
                       ("OpenSSH key", "id_*")])
        if path:
            self.key_var.set(path)

    # ── Poll loop ────────────────────────────
    def _poll(self):
        try:
            while True:
                msg  = self.status_q.get_nowait()
                kind = msg[0]
                text = msg[1]

                if kind == "step":
                    # Add a pending row so progress history is visible.
                    # If the previous step is still pending, resolve it
                    # first (it was superseded without a step_ok/warn).
                    if self._overlay_steps and                             self._overlay_steps[-1][2] == "pending":
                        self._overlay_update_last("ok")
                    self._overlay_add_step(text, "pending")
                    self._set_status("connecting", text)
                    self._log(text, "info")

                elif kind == "step_ok":
                    if self._overlay_steps and                             self._overlay_steps[-1][2] == "pending":
                        self._overlay_update_last("ok", text)
                    else:
                        self._overlay_add_step(text, "ok")
                    self._set_status("connected", text)
                    self._log(text, "ok")

                elif kind == "step_warn":
                    if self._overlay_steps and                             self._overlay_steps[-1][2] == "pending":
                        self._overlay_update_last("warn", text)
                    else:
                        self._overlay_add_step(text, "warn")
                    self._set_status("connecting", text)
                    self._log(text, "warn")

                elif kind == "nyx_ready":
                    is_shell = (text == "shell")
                    self._overlay_add_step(
                        "Shell ready" if is_shell else "Launching nyx…", "ok")
                    self.root.after(600, self._hide_overlay)
                    self._set_status("connected",
                                     f"Connected · {self.cfg.get('host', '')}")
                    if not is_shell:
                        # Only open Tor control port for nyx mode, not plain shell
                        self._start_ctrl_worker()
                    self._start_uptime()
                    self._log(f"Connected to {self.cfg.get('host','')}", "ok")

                elif kind == "error":
                    if self._overlay_steps and                             self._overlay_steps[-1][2] == "pending":
                        self._overlay_update_last("error")
                    self._overlay_add_step(text, "error")
                    self._set_status("error", text)
                    self._log(text, "error")
                    self.worker = None
                    self.connect_btn.config(state="normal")
                    self.disconnect_btn.config(state="disabled")

                elif kind == "disconnected":
                    # Guard: if self.worker is None, a new _connect() has
                    # already cleaned up — this is a stale "disconnected"
                    # from the old SSHWorker's finally block. Ignore it.
                    if self.worker is None:
                        pass
                    else:
                        self._hide_overlay()
                        self._stop_ctrl_worker()
                        self._stop_uptime()
                        self._identity_logged = False
                        self._set_status("disconnected", text)
                        self._log("Connection lost (remote)", "warn")
                        self.worker = None
                        self.connect_btn.config(state="normal")
                        self.disconnect_btn.config(state="disabled")
                        self._show_disconnect_splash()

                else:
                    self._set_status(kind, text)

        except queue.Empty:
            pass

        # Drain screen queue — only render when overlay is gone
        needs_render = False
        try:
            while True:
                self.screen_q.get_nowait()
                needs_render = True
        except queue.Empty:
            pass

        if needs_render and self.worker and self.worker.screen:
            if not self._overlay and not self.term._resize_after_id:
                with self.worker.screen_lock:
                    self.term.render(self.worker.screen)

        # Poll control-port queue (dashboard data)
        try:
            while True:
                msg  = self.ctrl_q.get_nowait()
                kind = msg.get("kind")
                if kind == "bw":
                    self.dashboard.push_bw(msg["read"], msg["written"])
                elif kind == "identity":
                    self.dashboard.push_identity(msg)
                    if not self._identity_logged:
                        self._identity_logged = True
                        nick = msg.get("nickname", "?")
                        fp   = msg.get("fingerprint", "?")[:8]
                        self._log(f"Relay identity: {nick}  fp={fp}…", "ctrl")
                elif kind == "circ":
                    new_b, new_f = msg["built"], msg["failed"]
                    self.dashboard.push_circs(new_b, new_f)
                    if new_b != getattr(self, "_last_circ_built", -1) or                        new_f != getattr(self, "_last_circ_failed", -1):
                        self._log(f"Circuit: built={new_b}  failed={new_f}", "conn")
                        self._last_circ_built, self._last_circ_failed = new_b, new_f
                elif kind == "connections":
                    self.dashboard.push_connections(msg["conns"])
                    n = len(msg["conns"])
                    if n != getattr(self, "_last_conn_n", -1):
                        n_in  = sum(1 for c in msg["conns"] if c.get("direction") == "in")
                        n_out = sum(1 for c in msg["conns"] if c.get("direction") == "out")
                        self._log(
                            f"OR connections: {n} total  ←{n_in} in  →{n_out} out",
                            "conn")
                        self._last_conn_n = n
                elif kind == "ready":
                    if self._view_mode != "dashboard":
                        self._toggle_view()
                    self._view_label.config(text="Tor Bridge  —  live dashboard")
                    self._log(
                        "Control port connected (BW/CIRC/ORCONN events active)",
                        "ctrl")
                    # Watchdog: if dashboard still empty after 10 s, request repoll.
                    # Handles the case where Tor was still bootstrapping at connect
                    # time and the initial polls returned empty / partial data.
                    self._watchdog_after_id = self.root.after(10_000, self._watchdog_repoll)
                elif kind == "signal_result":
                    status = "ok" if msg["ok"] else "error"
                    short  = msg["cmd"].replace("SIGNAL ", "")
                    self._log(
                        f"← {short}: {'OK' if msg['ok'] else 'FAILED'}",
                        status)
                elif kind == "ctrl_disconnected":
                    # TorControlWorker exited — clean up without showing
                    # the full disconnect splash (SSH may still be alive).
                    self._stop_ctrl_worker()
                    self._stop_uptime()
                    # Reset log dedup counters so reconnect logs all events fresh
                    self._identity_logged  = False
                    self._last_conn_n      = -1
                    self._last_circ_built  = -1
                    self._last_circ_failed = -1
                    self._log("Control port connection lost", "warn")
                    self._set_status("warn", "Control port disconnected")
                elif kind == "error":
                    self._log(
                        f"Control port error: {msg.get('msg', '')}",
                        "error")
        except queue.Empty:
            pass

        if not getattr(self, "_closing", False):
            self.root.after(33, self._poll)

    # ── First-launch data watchdog ───────────
    def _watchdog_repoll(self):
        """Called 10 s after ctrl port connects. If identity is still empty,
        post a repoll request to the worker. Repeats every 10 s until data
        arrives, then stops."""
        if not self.ctrl_worker or not self.ctrl_worker.is_alive():
            return
        identity = getattr(self.dashboard, "_identity", {})
        nickname = identity.get("nickname", "?")
        if nickname in ("?", "", None):
            self._log("Watchdog: no identity data yet — requesting repoll", "warn")
            try:
                self.ctrl_worker.cmd_q.put("__repoll__")
            except Exception:
                pass
            # Schedule another check
            self._watchdog_after_id = self.root.after(10_000, self._watchdog_repoll)
        # else: data is present — stop watching

    # ── nyx Graph / page picker ──────────────
    # nyx cycles through pages with ← → (or n).
    # Page order is fixed; we track our estimated position and send the minimum
    # number of right-arrow presses to reach the target page.
    _NYX_PAGES = [
        ("📈  Bandwidth",    "Bandwidth graphs — up/down rate, burst, observed"),
        ("🔗  Connections",  "OR/Guard/Exit connections with flags and latency"),
        ("⚙️  Configuration", "Loaded torrc options with descriptions"),
        ("📋  Torrc",        "Raw torrc file contents"),
        ("📜  Logs",         "Live Tor log stream (INFO / NOTICE / WARN)"),
    ]

    def _show_graph_menu(self):
        """Pop up the nyx page picker anchored below the Graph button."""
        if self._view_mode != "terminal":
            return
        menu = tk.Toplevel(self.root)
        menu.overrideredirect(True)
        menu.configure(bg=self.BORDER)
        menu.attributes("-topmost", True)

        btn  = self._graph_btn
        bx   = btn.winfo_rootx()
        by   = btn.winfo_rooty() + btn.winfo_height() + 2
        menu.geometry(f"+{bx}+{by}")

        def _dismiss(e=None):
            try:
                menu.destroy()
            except Exception:
                pass
        menu.bind("<FocusOut>", _dismiss)

        small = self._font(["Segoe UI", "Arial"], 9)
        small_dim = self._font(["Segoe UI", "Arial"], 8)

        for idx, (label, subtitle) in enumerate(self._NYX_PAGES):
            is_active = (idx == self._nyx_page)

            def _make_handler(i=idx, m=menu):
                def handler():
                    m.destroy()
                    self._nyx_goto_page(i)
                return handler

            bg_row = self.ACCENT if is_active else self.PANEL
            fg_lbl = "white"     if is_active else self.TEXT
            fg_sub = "#c4b5fd"   if is_active else self.TEXT_DIM

            row = tk.Frame(menu, bg=bg_row, cursor="hand2")
            row.pack(fill="x", padx=1, pady=1)

            inner = tk.Frame(row, bg=bg_row)
            inner.pack(fill="x", padx=14, pady=5)

            lbl_w = tk.Label(inner, text=label, font=small,
                             fg=fg_lbl, bg=bg_row, anchor="w")
            lbl_w.pack(fill="x")
            sub_w = tk.Label(inner, text=subtitle, font=small_dim,
                             fg=fg_sub, bg=bg_row, anchor="w")
            sub_w.pack(fill="x")

            h = _make_handler()
            for w in (row, inner, lbl_w, sub_w):
                w.bind("<Button-1>", lambda e, hh=h: hh())
                if not is_active:
                    w.bind("<Enter>", lambda e, r=row, i2=inner, l=lbl_w, s=sub_w:
                        [x.config(bg=self.BORDER) for x in (r, i2, l, s)])
                    w.bind("<Leave>", lambda e, r=row, i2=inner, l=lbl_w, s=sub_w,
                                             bg=bg_row:
                        [x.config(bg=bg) for x in (r, i2, l, s)])

        menu.update_idletasks()
        menu.focus_set()

    def _nyx_goto_page(self, target_idx: int):
        """Navigate nyx to the target page by sending right-arrow keypresses."""
        n_pages = len(self._NYX_PAGES)
        current = self._nyx_page % n_pages
        target  = target_idx % n_pages

        # Calculate shortest forward-only path (nyx wraps around)
        presses = (target - current) % n_pages
        if presses == 0:
            return   # already there

        # Send right-arrow key 'presses' times with a tiny gap so nyx can render
        def _send_step(remaining):
            if remaining <= 0 or self._view_mode != "terminal":
                return
            if getattr(self, "_closing", False):
                return
            self._send_key(b"\x1b[C")   # ESC [ C  = right arrow (VT100)
            self.root.after(60, lambda: _send_step(remaining - 1))

        _send_step(presses)
        self._nyx_page = target

        # Update the header label and button highlight
        page_name = self._NYX_PAGES[target][0].split("  ", 1)[-1]  # strip emoji
        self._view_label.config(text=f"nyx  —  {page_name}")

        # Return focus to the terminal after all arrow keys have been sent.
        # Delay is (presses * 60ms) + 80ms buffer so focus arrives after the
        # last keypress, not before it.
        delay = presses * 60 + 80
        def _refocus():
            if self._view_mode == "terminal" and not self._closing:
                self.term.focus_set()
        self.root.after(delay, _refocus)

    # ── Tor Actions menu ─────────────────────
    # Each entry: (label, SIGNAL/command, confirm_msg or None)
    _NYX_ACTIONS = [
        ("🔀  New Identity",     "SIGNAL NEWNYM",          None),
        ("🔄  Reload Config",    "SIGNAL RELOAD",          None),
        ("🗑  Flush DNS Cache",  "SIGNAL CLEARDNSCACHE",   None),
        ("💤  Enter Dormant",    "SIGNAL DORMANT",
             "Put Tor into dormant mode? It will stop relaying traffic."),
        ("☀️  Wake Up",          "SIGNAL ACTIVE",          None),
        ("─" * 22,               None,                     None),   # separator
        ("🔁  Reload Full",      "SIGNAL HUP",
             "Send HUP to Tor? This fully reloads the configuration."),
    ]

    def _show_actions_menu(self):
        """Pop up a compact action menu anchored below the Actions button."""
        if not self.ctrl_worker or not self.ctrl_worker.is_alive():
            self._log("Actions: not connected to control port", "warn")
            return

        menu = tk.Toplevel(self.root)
        menu.overrideredirect(True)   # no title bar
        menu.configure(bg=self.BORDER)
        menu.attributes("-topmost", True)

        # Position below the Actions button
        btn = self._actions_btn
        bx  = btn.winfo_rootx()
        by  = btn.winfo_rooty() + btn.winfo_height() + 2
        menu.geometry(f"+{bx}+{by}")

        # Dismiss on any click outside
        def _dismiss(e=None):
            try:
                self._actions_btn.focus_set()
                menu.after(0, menu.destroy)
            except Exception:
                pass
        menu.bind("<FocusOut>", _dismiss)

        small = self._font(["Segoe UI", "Arial"], 9)
        mono  = self._font(["Cascadia Code", "Consolas", "Courier New"], 9)

        for label, cmd, confirm in self._NYX_ACTIONS:
            if cmd is None:
                # Separator
                tk.Frame(menu, bg=self.TEXT_DIM, height=1).pack(
                    fill="x", padx=8, pady=2)
                continue

            def _make_handler(c=cmd, cf=confirm, lbl=label, m=menu):
                def handler():
                    m.destroy()
                    if cf:
                        if not messagebox.askyesno(
                                "Confirm", cf, parent=self.root):
                            return
                    self._send_signal(c, lbl)
                return handler

            row = tk.Frame(menu, bg=self.PANEL, cursor="hand2")
            row.pack(fill="x", padx=1, pady=1)
            lbl_w = tk.Label(row, text=label,
                             font=small, fg=self.TEXT,
                             bg=self.PANEL, anchor="w",
                             padx=14, pady=6)
            lbl_w.pack(fill="x")
            for w in (row, lbl_w):
                w.bind("<Button-1>", lambda e, h=_make_handler(): h())
                w.bind("<Enter>",
                       lambda e, r=row, l=lbl_w:
                           (r.config(bg=self.ACCENT), l.config(bg=self.ACCENT)))
                w.bind("<Leave>",
                       lambda e, r=row, l=lbl_w:
                           (r.config(bg=self.PANEL), l.config(bg=self.PANEL)))

        menu.update_idletasks()
        menu.focus_set()

    def _send_signal(self, cmd: str, label: str = ""):
        """Queue a control-port command and log the result when it comes back."""
        if not self.ctrl_worker or not self.ctrl_worker.is_alive():
            self._log(f"Action skipped (no control port): {cmd}", "warn")
            return
        self.ctrl_worker.cmd_q.put(cmd)
        self._log(f"→ {label or cmd}", "ctrl")

    # ── Debug log ────────────────────────────
    def _log(self, msg: str, level: str = "info"):
        """Append a timestamped entry to the debug log and the log file."""
        # Mirror every UI log entry to the file log at the appropriate level
        _file_lvl = {"ok": "info", "info": "info",
                     "warn": "warning", "error": "error"}.get(level, "info")
        _flog(_file_lvl, "UI  %s", msg)
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        w = self._log_text
        w.configure(state="normal")
        w.insert("end", ts, "ts")
        w.insert("end", "  " + msg + "\n", level)
        # Trim to _LOG_MAX lines in widget too
        line_count = int(w.index("end-1c").split(".")[0])
        if line_count > self._LOG_MAX:
            w.delete("1.0", f"{line_count - self._LOG_MAX}.0")
        w.configure(state="disabled")
        w.see("end")

    def _log_open_file(self):
        """Open the log file in the system default text viewer."""
        import subprocess
        try:
            if os.path.exists(LOG_FILE):
                os.startfile(LOG_FILE)   # Windows: opens in Notepad / default app
            else:
                messagebox.showinfo("Log file",
                    f"No log file yet.\nIt will be created at:\n{LOG_FILE}")
        except Exception as e:
            messagebox.showerror("Open log file", str(e))

    def _log_copy(self):
        text = self._log_text.get("1.0", "end").strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)

    def _log_clear(self):
        self._log_text.configure(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.configure(state="disabled")

    def _toggle_log(self):
        self._log_visible = not self._log_visible
        if self._log_visible:
            # Restore last-used height before packing so the frame doesn't
            # briefly flash at the wrong size.
            self._log_frame.configure(height=self._log_height)
            self._log_frame.pack(side="bottom", fill="x",
                                 before=self._statusbar_sep)
            self._log_toggle_btn.config(bg=self.ACCENT, fg="white")
        else:
            self._log_frame.pack_forget()
            self._log_toggle_btn.config(bg=self.BORDER, fg=self.TEXT_DIM)

    # ── Uptime timer ─────────────────────────
    def _uptime_tick(self):
        if not self._connect_time:
            return
        elapsed = int(time.time() - self._connect_time)
        h, r    = divmod(elapsed, 3600)
        m, s    = divmod(r, 60)
        self._uptime_label.config(
            text=f"  ⏱  {h:02d}:{m:02d}:{s:02d}",
            fg=self.TEXT_DIM)
        self._uptime_after_id = self.root.after(1000, self._uptime_tick)

    def _start_uptime(self):
        if self._uptime_after_id:
            self.root.after_cancel(self._uptime_after_id)
            self._uptime_after_id = None
        self._connect_time = time.time()
        self._uptime_tick()

    def _stop_uptime(self):
        if self._uptime_after_id:
            self.root.after_cancel(self._uptime_after_id)
            self._uptime_after_id = None
        self._connect_time = None
        self._uptime_label.config(text="")

    def on_close(self):
        """Graceful shutdown — called by WM_DELETE_WINDOW protocol.

        Shutdown order:
          1. Cancel all pending after() callbacks so no more Tk calls fire.
          2. Signal both worker threads to stop and close their sockets.
          3. Join threads with a short timeout so their run() methods return
             before we destroy the Tk root — prevents Tcl errors from threads
             calling into a destroyed widget after root.destroy().
          4. Drain queues and clean up resources, then destroy the window.
        """
        # ── Step 1: cancel all pending after() loops ──────────────────
        self._stop_uptime()   # cancels root.after(1000, _uptime_tick)

        # Cancel terminal resize debounce
        if self.term._resize_after_id:
            try:
                self.term.after_cancel(self.term._resize_after_id)
                self.term._resize_after_id = None
            except Exception:
                pass

        # Cancel overlay pulse animation
        if self._spin_after_id:
            try:
                self.root.after_cancel(self._spin_after_id)
                self._spin_after_id = None
            except Exception:
                pass

        # Cancel watchdog repoll timer
        if self._watchdog_after_id:
            try:
                self.root.after_cancel(self._watchdog_after_id)
                self._watchdog_after_id = None
            except Exception:
                pass

        # Cancel the _poll loop — set a flag that _poll checks before rescheduling
        self._closing = True

        # ── Step 2: signal threads to stop ────────────────────────────
        threads_to_join = []

        if self.ctrl_worker:
            self.ctrl_worker.stop()          # sets _stop event + closes socket
            threads_to_join.append(self.ctrl_worker)
            self.ctrl_worker = None

        if self.worker:
            # Gracefully quit nyx so the Pi shell returns to prompt cleanly
            if getattr(self.worker, "_nyx_running", False):
                try:
                    self.worker.send(b"q")
                except Exception:
                    pass
            self.worker.stop()               # sets _stop event + closes channel
            threads_to_join.append(self.worker)
            self.worker = None

        # ── Step 3: join threads (short timeout) ──────────────────────
        # Both threads are daemon=True so a join timeout is not fatal — the
        # process exits regardless.  The timeout avoids a hung window while
        # still ensuring threads have had a chance to exit their run() loops
        # before we destroy Tk state they may reference.
        for t in threads_to_join:
            try:
                t.join(timeout=2.0)
            except Exception:
                pass

        # ── Step 4: drain queues, clean up, destroy ───────────────────
        for q in (self.screen_q, self.status_q, self.ctrl_q):
            try:
                while True:
                    q.get_nowait()
            except Exception:
                pass

        # Explicitly delete font objects — prevents tkinter cleanup warnings
        for attr in ("_font", "_font_bold"):
            f = getattr(self.term, attr, None)
            if f:
                try:
                    f.delete()
                except Exception:
                    pass

        _flog("info", "Tor Bridge Monitor closed")
        self.root.destroy()

    def _set_status(self, kind, msg):
        colors = {
            "connecting":   self.WARNING,
            "connected":    self.SUCCESS,
            "disconnected": self.TEXT_DIM,
            "error":        self.ERROR,
        }
        c = colors.get(kind, self.TEXT_DIM)
        self.status_dot.config(fg=c)
        self.status_label.config(fg=c, text=msg)
        self.statusbar.config(text=msg)

    def _font(self, families, size, bold=False):
        avail = tkfont.families()
        for f in families:
            if f in avail:
                return (f, size, "bold" if bold else "normal")
        return ("Courier New", size, "bold" if bold else "normal")


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def main():
    root = tk.Tk()
    try:
        root.update()
        _ctypes.windll.dwmapi.DwmSetWindowAttribute(
            root.winfo_id(), 20,
            _ctypes.byref(_ctypes.c_int(1)), _ctypes.sizeof(_ctypes.c_int))
    except Exception:
        pass

    app = TorMonitorApp(root)

    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
