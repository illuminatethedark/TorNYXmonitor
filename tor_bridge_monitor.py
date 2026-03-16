"""
Tor NYX Monitor v0.2.3
======================================
Two worker threads (SSH + Tor control port) post events onto a single queue.
The main tkinter thread drains that queue every 50 ms and updates the UI.
No shared state survives a disconnect.

Requirements:
    pip install paramiko pyte
"""

# ─────────────────────────────────────────────────────────────────────────────
#  Standard library
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations

__version__ = "0.2.3"

import base64
import collections
import datetime
import json
import logging
import logging.handlers
import os
import queue
import re
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import tkinter.ttk as ttk
import traceback
from tkinter import filedialog, messagebox

# ─────────────────────────────────────────────────────────────────────────────
#  Optional dependencies
# ─────────────────────────────────────────────────────────────────────────────
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

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as _crypto_hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ─────────────────────────────────────────────────────────────────────────────
#  Paths
# ─────────────────────────────────────────────────────────────────────────────
_HOME            = os.path.expanduser("~")
CONFIG_FILE      = os.path.join(_HOME, ".tor_bridge_monitor.json")
KNOWN_HOSTS_FILE = os.path.join(_HOME, ".tor_bridge_monitor_known_hosts")
LOG_FILE         = os.path.join(_HOME, ".tor_bridge_monitor.log")
PROFILES_FILE    = os.path.join(_HOME, ".tor_bridge_monitor_profiles.json")

# ─────────────────────────────────────────────────────────────────────────────
#  File logger  (always-on, rotates at 2 MB, keeps 3 backups)
# ─────────────────────────────────────────────────────────────────────────────
def _make_logger() -> logging.Logger:
    log = logging.getLogger("tbm")
    if log.handlers:
        return log
    log.setLevel(logging.DEBUG)
    try:
        fh = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3,
            encoding="utf-8", delay=False)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-7s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"))
        log.addHandler(fh)
    except Exception:
        log.addHandler(logging.NullHandler())
    return log

_log = _make_logger()


# ─────────────────────────────────────────────────────────────────────────────
#  UI scale  (resolution-aware sizing)
# ─────────────────────────────────────────────────────────────────────────────
def _compute_ui_scale(root: tk.Tk) -> float:
    """Return a UI scale factor derived from the screen resolution.

    Baseline: 1920×1080 → 1.0.
    Smaller screens get a factor < 1.0 so the UI shrinks to fit.
    Larger / HiDPI screens get a factor > 1.0 for better readability.
    Clamped to [0.65, 1.8] to prevent extremes.

    tkinter reports *logical* pixels, so Windows DPI scaling (e.g. 150 %)
    is already factored in — no extra DPI query needed.
    """
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    scale = min(sw / 1920.0, sh / 1080.0)
    scale = max(0.65, min(1.8, scale))
    _log.info("Screen %dx%d → UI scale %.2f", sw, sh, scale)
    return scale


# ─────────────────────────────────────────────────────────────────────────────
#  Config
# ─────────────────────────────────────────────────────────────────────────────
def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"host": "", "port": "22", "user": "gambit",
            "password": "", "key_path": "", "autoconnect": False}

def save_config(cfg: dict):
    """Persist config — password never saved when a key file is set.

    Writes to a .tmp sidecar then atomically renames it via os.replace()
    so a crash mid-write never leaves a corrupt config file.
    """
    try:
        to_save = dict(cfg)
        if to_save.get("key_path", "").strip():
            to_save["password"] = ""
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(to_save, f, indent=2)
        os.replace(tmp, CONFIG_FILE)
    except Exception as exc:
        _log.error("save_config failed: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
#  Connection profiles — data layer
# ─────────────────────────────────────────────────────────────────────────────
def load_profiles() -> dict:
    """Return the raw profiles file dict — may be plaintext or encrypted wrapper."""
    if os.path.exists(PROFILES_FILE):
        try:
            with open(PROFILES_FILE, encoding="utf-8") as fh:
                data = json.load(fh)
            if data.get("encrypted") or isinstance(data.get("profiles"), dict):
                return data
        except Exception as exc:
            _log.warning("load_profiles failed (corrupt file?): %s", exc)
    return {"version": 1, "encrypted": False, "profiles": {}, "last": ""}


def save_profiles(data: dict):
    """Atomically write the profiles file."""
    try:
        tmp = PROFILES_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, PROFILES_FILE)
    except Exception as exc:
        _log.error("save_profiles failed: %s", exc)


_PBKDF2_ITERS = 480_000

def _profiles_derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from password + salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(algorithm=_crypto_hashes.SHA256(),
                     length=32, salt=salt, iterations=_PBKDF2_ITERS)
    return kdf.derive(password.encode("utf-8"))


def _profiles_encrypt(inner: dict, key: bytes, salt: bytes) -> dict:
    """Encrypt the inner profiles dict. Returns the outer wrapper suitable for save_profiles()."""
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, json.dumps(inner).encode("utf-8"), None)
    return {
        "version":    1,
        "encrypted":  True,
        "salt":       base64.b64encode(salt).decode(),
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }


def _profiles_decrypt(outer: dict, key: bytes) -> dict | None:
    """Decrypt and return the inner dict, or None on auth failure."""
    try:
        nonce = base64.b64decode(outer["nonce"])
        ct    = base64.b64decode(outer["ciphertext"])
        pt    = AESGCM(key).decrypt(nonce, ct, None)
        return json.loads(pt.decode("utf-8"))
    except Exception:
        return None


class SecureCredStore:
    """Stores connection-profile passwords in the OS credential manager.

    Priority:
      1. ``keyring``  (pip install keyring) — Windows Credential Manager,
                       macOS Keychain, or Linux SecretService / GNOME Keyring.
      2. Windows DPAPI via ctypes — no extra dependency; data is bound to the
                       current Windows user account and machine.
      3. Plaintext inside the profiles JSON file + a log warning.

    Passwords are kept *outside* the profiles JSON file whenever a secure
    backend is available.  For DPAPI the encrypted blob is embedded in the
    profile entry so the file remains self-contained.
    """

    _SERVICE = "TorNYXMonitor"
    _cached_backend: str = ""

    # ── backend detection ─────────────────────────────────────────────────
    @classmethod
    def _detect_backend(cls) -> str:
        if cls._cached_backend:
            return cls._cached_backend
        # 1. keyring
        try:
            import keyring as _kr   # type: ignore[import-not-found]
            _kr.get_password(cls._SERVICE, "__probe__")
            cls._cached_backend = "keyring"
            _log.info("SecureCredStore: using keyring backend")
            return cls._cached_backend
        except Exception:
            pass
        # 2. DPAPI (Windows)
        try:
            if cls._dpapi_protect("probe") is not None:
                cls._cached_backend = "dpapi"
                _log.info("SecureCredStore: using Windows DPAPI backend")
                return cls._cached_backend
        except Exception:
            pass
        # 3. Plaintext fallback
        _log.warning(
            "SecureCredStore: no secure credential store found — "
            "passwords will be stored in plaintext in %s", PROFILES_FILE)
        cls._cached_backend = "plain"
        return cls._cached_backend

    # ── Windows DPAPI ─────────────────────────────────────────────────────
    @classmethod
    def _dpapi_protect(cls, plaintext: str) -> str | None:
        """Encrypt *plaintext* with DPAPI; return base64 str or None."""
        try:
            import ctypes as _c
            import ctypes.wintypes as _w

            class _BLOB(_c.Structure):
                _fields_ = [("cbData", _w.DWORD),
                             ("pbData", _c.POINTER(_c.c_char))]

            data  = plaintext.encode("utf-8")
            buf   = (_c.c_char * len(data))(*data)
            b_in  = _BLOB(len(data), buf)
            b_out = _BLOB()
            ok = _c.windll.crypt32.CryptProtectData(
                _c.byref(b_in), None, None, None, None, 0, _c.byref(b_out))
            if not ok:
                return None
            raw = bytes(_c.string_at(b_out.pbData, b_out.cbData))
            _c.windll.kernel32.LocalFree(b_out.pbData)
            return base64.b64encode(raw).decode("ascii")
        except Exception:
            return None

    @classmethod
    def _dpapi_unprotect(cls, b64: str) -> str | None:
        """Decrypt a DPAPI base64 blob; return plaintext or None."""
        try:
            import ctypes as _c
            import ctypes.wintypes as _w

            class _BLOB(_c.Structure):
                _fields_ = [("cbData", _w.DWORD),
                             ("pbData", _c.POINTER(_c.c_char))]

            data  = base64.b64decode(b64)
            buf   = (_c.c_char * len(data))(*data)
            b_in  = _BLOB(len(data), buf)
            b_out = _BLOB()
            ok = _c.windll.crypt32.CryptUnprotectData(
                _c.byref(b_in), None, None, None, None, 0, _c.byref(b_out))
            if not ok:
                return None
            raw = _c.string_at(b_out.pbData, b_out.cbData)
            _c.windll.kernel32.LocalFree(b_out.pbData)
            return raw.decode("utf-8")
        except Exception:
            return None

    # ── public API ────────────────────────────────────────────────────────
    @classmethod
    def store(cls, profile_name: str, password: str) -> dict:
        """Persist *password* for *profile_name*.

        Returns a metadata dict that must be merged into the profile entry
        before the caller calls ``save_profiles()``.
        """
        if not password:
            return {"_pwd_backend": "none"}

        backend = cls._detect_backend()

        if backend == "keyring":
            try:
                import keyring as _kr   # type: ignore[import-not-found]
                _kr.set_password(cls._SERVICE, profile_name, password)
                return {"_pwd_backend": "keyring"}
            except Exception as exc:
                _log.warning("keyring store failed (%s) — falling back", exc)
                backend = "dpapi"

        if backend == "dpapi":
            enc = cls._dpapi_protect(password)
            if enc:
                return {"_pwd_backend": "dpapi", "_pwd_enc": enc}
            backend = "plain"

        _log.warning("Storing password in plaintext for profile '%s'",
                     profile_name)
        return {"_pwd_backend": "plain", "_pwd_plain": password}

    @classmethod
    def load(cls, profile: dict, profile_name: str) -> str:
        """Retrieve the password for *profile_name*.

        *profile* is the dict stored under that name in the profiles file.
        """
        backend = profile.get("_pwd_backend", "none")
        if backend == "keyring":
            try:
                import keyring as _kr   # type: ignore[import-not-found]
                return _kr.get_password(cls._SERVICE, profile_name) or ""
            except Exception:
                return ""
        if backend == "dpapi":
            enc = profile.get("_pwd_enc", "")
            return cls._dpapi_unprotect(enc) or "" if enc else ""
        if backend == "plain":
            return profile.get("_pwd_plain", "")
        return ""

    @classmethod
    def delete(cls, profile: dict, profile_name: str):
        """Remove any OS-side credential for *profile_name*."""
        if profile.get("_pwd_backend") == "keyring":
            try:
                import keyring as _kr   # type: ignore[import-not-found]
                _kr.delete_password(cls._SERVICE, profile_name)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
#  TOFU SSH host-key policy
# ─────────────────────────────────────────────────────────────────────────────
_TOFUBase: type = object
if HAS_PARAMIKO:
    _TOFUBase = paramiko.MissingHostKeyPolicy

class _TOFUPolicy(_TOFUBase):
    """Trust-on-first-use: save unknown keys; reject changed keys."""
    def __init__(self, path: str):
        self._path = path

    def missing_host_key(self, client, hostname, key):
        client._host_keys.add(hostname, key.get_name(), key)
        try:
            client.save_host_keys(self._path)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
#  Colour helpers  (VT100 / 256-colour palette)
# ─────────────────────────────────────────────────────────────────────────────
NAMED_COLORS = {
    "black":         "#1a1b26", "red":           "#f7768e",
    "green":         "#9ece6a", "yellow":        "#e0af68",
    "blue":          "#7aa2f7", "magenta":       "#bb9af7",
    "cyan":          "#7dcfff", "white":         "#c0caf5",
    "brightblack":   "#414868", "brightred":     "#f7768e",
    "brightgreen":   "#9ece6a", "brightyellow":  "#e0af68",
    "brightblue":    "#7aa2f7", "brightmagenta": "#bb9af7",
    "brightcyan":    "#7dcfff", "brightwhite":   "#c0caf5",
    "default":       None,
}

def _build_256_palette() -> dict:
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
    rb"\x1b(?:"
    rb"\[[0-9;?]*[A-Za-z]"
    rb"|](?:[^\x07\x1b]|\x1b(?!\\\\))*(?:\x07|\x1b\\\\)"
    rb"|[^\[\]]"
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


# ─────────────────────────────────────────────────────────────────────────────
#  Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────
def fmt_bytes(n: int) -> str:
    v: float = n
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024:
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} TB"


# ─────────────────────────────────────────────────────────────────────────────
#  SSHWorker
#  ─ Connects via paramiko, opens a PTY shell, optionally launches nyx.
#  ─ Feeds all PTY output through pyte and posts ("screen", None) events.
#  ─ Also owns the paramiko.SSHClient so CtrlWorker can borrow the transport.
# ─────────────────────────────────────────────────────────────────────────────
class SSHWorker(threading.Thread):

    def __init__(self, cfg: dict, cols: int, rows: int,
                 event_q: queue.Queue, mode: str = "nyx",
                 session_id: int = 0):
        super().__init__(daemon=True)
        self.cfg        = cfg
        self.cols       = cols
        self.rows       = rows
        self.event_q    = event_q
        self.mode       = mode          # "nyx" | "shell"
        self.session_id = session_id

        self._stop    = threading.Event()
        self.client   = None          # paramiko.SSHClient — set once connected
        self._channel = None

        if HAS_PYTE:
            self.screen      = pyte.Screen(cols, rows)       # type: ignore[possibly-undefined]
            self.stream      = pyte.ByteStream(self.screen)  # type: ignore[possibly-undefined]
            self.screen_lock = threading.Lock()
        else:
            self.screen = self.stream = self.screen_lock = None

    # ── public API ──────────────────────────────────────────────────────────
    def stop(self):
        self._stop.set()
        for obj in (self._channel, self.client):
            if obj:
                try:
                    obj.close()
                except Exception:
                    pass

    def send(self, data: bytes):
        try:
            if self._channel:
                self._channel.send(data)
        except Exception:
            pass

    def resize(self, cols: int, rows: int):
        self.cols = cols
        self.rows = rows
        try:
            if self._channel:
                self._channel.resize_pty(width=cols, height=rows)
            if self.screen:
                with self.screen_lock:
                    self.screen.resize(rows, cols)
        except Exception:
            pass

    # ── helpers ─────────────────────────────────────────────────────────────
    def _post(self, *args):
        try:
            self.event_q.put_nowait((self.session_id,) + args)
        except queue.Full:
            pass

    def _feed(self, data: bytes):
        if self.screen_lock:
            with self.screen_lock:
                self.stream.feed(data)
        self._post("screen", None)

    def _wait_for_prompt(self, timeout: float = 15.0) -> bool:
        """Read until shell prompt detected or timeout.  Returns True on prompt."""
        buf      = b""
        deadline = time.time() + timeout
        self._channel.settimeout(0.5)
        while time.time() < deadline and not self._stop.is_set():
            try:
                chunk = self._channel.recv(4096)
                if not chunk:
                    break
                self._feed(chunk)
                buf += chunk
                if len(buf) > 8192:
                    buf = buf[-8192:]
                if ANSI_RE.sub(b"", buf).rstrip().endswith((b"$", b"#", b">")):
                    return True
            except TimeoutError:
                pass
            except OSError:
                break
        return False

    # ── run ─────────────────────────────────────────────────────────────────
    def run(self):
        if not HAS_PARAMIKO:
            self._post("status", "error",
                       "paramiko not installed.\nRun: pip install paramiko pyte")
            return
        if not HAS_PYTE:
            self._post("status", "error",
                       "pyte not installed.\nRun: pip install paramiko pyte")
            return

        host = self.cfg["host"]
        try:
            self._post("status", "connecting", f"Connecting to {host}…")
            _log.info("SSH connecting to %s:%s", host, self.cfg["port"])

            self.client = paramiko.SSHClient()
            if os.path.exists(KNOWN_HOSTS_FILE):
                try:
                    self.client.load_host_keys(KNOWN_HOSTS_FILE)
                except Exception:
                    pass
            self.client.set_missing_host_key_policy(_TOFUPolicy(KNOWN_HOSTS_FILE))

            kw = dict(
                hostname       = host,
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
            _log.info("SSH connected to %s as %s", host, self.cfg["user"])
            self._post("status", "connecting", f"Connected to {host} — opening terminal…")

            transport      = self.client.get_transport()
            # Send SSH keepalives every 30 s so the server never drops an
            # idle transport (fixes disconnects caused by sshd ClientAliveInterval).
            transport.set_keepalive(30)
            self._channel  = transport.open_session()
            self._channel.get_pty(term="xterm-256color",
                                   width=self.cols, height=self.rows)
            self._channel.invoke_shell()

            if not self._wait_for_prompt():
                if self._stop.is_set():
                    return

            if self._stop.is_set():
                return

            # ── shell mode ──────────────────────────────────────────────────
            if self.mode == "shell":
                self._post("status", "connected", f"Shell — {host}")
                self._post("ssh_ready", "shell")
                _log.info("Shell mode ready")
                self._read_loop()
                return

            # ── check Tor service ────────────────────────────────────────────
            self._post("status", "connecting", "Checking Tor service…")
            self._channel.send("systemctl is-active tor; systemctl is-enabled tor\r\n")
            time.sleep(1.5)

            tor_buf  = b""
            deadline = time.time() + 4
            self._channel.settimeout(0.5)
            while time.time() < deadline and not self._stop.is_set():
                try:
                    chunk = self._channel.recv(4096)
                    if not chunk:
                        break
                    self._feed(chunk)
                    tor_buf += chunk
                    if len(tor_buf) > 4096:
                        tor_buf = tor_buf[-4096:]
                except TimeoutError:
                    pass
                except OSError:
                    break

            if self._stop.is_set():
                return

            tor_text  = ANSI_RE.sub(b"", tor_buf).decode("utf-8", errors="replace")
            tor_lines = [l.strip() for l in tor_text.splitlines() if l.strip()]

            is_active   = any("active"   in l and "inactive" not in l for l in tor_lines)
            is_enabled  = any("enabled"  in l and "disabled" not in l for l in tor_lines)
            is_failed   = any("failed"   in l for l in tor_lines)
            is_inactive = any("inactive" in l for l in tor_lines)

            if is_failed:
                self._post("status", "error",
                    "Tor service has FAILED.\n"
                    "Fix:  sudo systemctl restart tor\n"
                    "Logs: sudo journalctl -u tor -n 50")
                return

            if is_inactive or not is_active:
                self._post("status", "error",
                    "Tor is not running.\n"
                    "Start:  sudo systemctl start tor\n"
                    "Enable: sudo systemctl enable tor")
                return

            if not is_enabled:
                _log.warning("Tor active but not enabled at boot")
                self._post("status", "connecting", "Tor active (not enabled at boot)")
            else:
                self._post("status", "connecting", "Tor active and enabled")

            # ── launch nyx ──────────────────────────────────────────────────
            self._post("status", "connecting", "Launching nyx…")
            self._channel.send("nyx\r\n")
            self._channel.settimeout(0.3)

            startup_buf  = b""
            startup_done = False
            while not self._stop.is_set():
                try:
                    data = self._channel.recv(4096)
                    if not data:
                        break
                    self._feed(data)
                    if not startup_done:
                        startup_buf += data
                        if len(startup_buf) > 51200:
                            startup_buf = startup_buf[-51200:]
                        clean = ANSI_RE.sub(b"", startup_buf)
                        if (b"nyx" in clean.lower()
                                or b"arm" in clean.lower()
                                or len(startup_buf) > 40960):
                            startup_done      = True
                            _log.info("nyx detected and running")
                            self._post("ssh_ready", "nyx")
                except TimeoutError:
                    continue
                except OSError:
                    break
                except Exception as e:
                    _log.error("SSH stream error: %s", e)
                    break

        except paramiko.AuthenticationException:
            _log.error("SSH auth failed for %s@%s", self.cfg.get("user"), host)
            self._post("status", "error",
                       "Authentication failed — check username / password or key.")
        except paramiko.SSHException as e:
            msg = str(e)
            if "banner" in msg.lower():
                self._post("status", "error",
                    "SSH banner error — wrong port or host unreachable.")
            else:
                self._post("status", "error", f"SSH error: {e}")
            _log.error("SSH exception: %s", e)
        except OSError as e:
            _log.error("SSH OSError: %s", e)
            self._post("status", "error", f"Connection error: {e}")
        except Exception as e:
            _log.error("SSH unexpected: %s", traceback.format_exc())
            self._post("status", "error", f"Unexpected error: {e}")
        finally:
            self._post("ssh_down", None)

    def _read_loop(self):
        """Bare read loop used for shell mode and nyx after startup."""
        self._channel.settimeout(0.3)
        while not self._stop.is_set():
            try:
                data = self._channel.recv(4096)
                if not data:
                    break
                self._feed(data)
            except TimeoutError:
                continue
            except OSError:
                break
            except Exception as e:
                _log.error("Read loop error: %s", e)
                break


# ─────────────────────────────────────────────────────────────────────────────
#  CtrlWorker
#  ─ Opens a direct-tcpip channel to 127.0.0.1:9051 on the Pi.
#  ─ Authenticates, subscribes to BW/CIRC/ORCONN events.
#  ─ Single recv loop processes events and runs periodic polls.
#  ─ All state is local — nothing survives between instances.
# ─────────────────────────────────────────────────────────────────────────────
class CtrlWorker(threading.Thread):

    POLL_INTERVAL  = 30   # full identity + connections re-poll interval (s)
    RETRY_INTERVAL = 8    # retry if fingerprint missing (Tor bootstrapping)
    ORCONN_DEBOUNCE = 1.0 # seconds to coalesce ORCONN events before polling

    def __init__(self, ssh_client, event_q: queue.Queue,
                 session_id: int = 0):
        super().__init__(daemon=True)
        self.client     = ssh_client
        self.event_q    = event_q
        self.session_id = session_id
        self.cmd_q      = queue.Queue()   # main thread posts signal commands here
        self._stop      = threading.Event()

        # All per-session state — initialised fresh every run()
        self._sock        = None
        self._buf         = ""         # line-accumulation buffer
        self._circ_built  = 0
        self._circ_failed = 0
        self._fp          = ""         # cached fingerprint

    # ── public API ──────────────────────────────────────────────────────────
    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def send_signal(self, cmd: str):
        """Queue a SIGNAL command from the main thread."""
        try:
            self.cmd_q.put_nowait(cmd)
        except queue.Full:
            pass

    # ── internal helpers ────────────────────────────────────────────────────
    def _post(self, *args):
        try:
            self.event_q.put_nowait((self.session_id,) + args)
        except queue.Full:
            pass

    def _send(self, line: str):
        if self._sock is None:
            raise OSError("control socket is not connected")
        self._sock.sendall((line + "\r\n").encode())

    def _read_cookie(self, cookie_path: str) -> str:
        """Return the Tor auth cookie as a hex string, or "" on failure.

        Tries three methods in order:
          1. SSH exec_command with sudo (works on Pi OS without group membership)
          2. SSH exec_command with xxd (hex dump — avoids binary stdout issues)
          3. SFTP open (works if pi is in the debian-tor group)
        """
        # Method 1: sudo cat — raw bytes via stdout
        try:
            _, stdout, _ = self.client.exec_command(
                f"sudo cat {cookie_path}", timeout=5)
            data = stdout.read()
            if len(data) == 32:
                _log.debug("Cookie read via sudo cat (%d bytes)", len(data))
                return data.hex()
        except Exception as e:
            _log.debug("Cookie sudo cat failed: %s", e)

        # Method 2: xxd hex dump — avoids any binary/encoding issues
        try:
            _, stdout, _ = self.client.exec_command(
                f"sudo xxd -p {cookie_path} | tr -d '\\n'", timeout=5)
            hexdata = stdout.read().decode(errors="replace").strip()
            if len(hexdata) == 64 and all(c in "0123456789abcdefABCDEF"
                                           for c in hexdata):
                _log.debug("Cookie read via xxd (%d hex chars)", len(hexdata))
                return hexdata
        except Exception as e:
            _log.debug("Cookie xxd failed: %s", e)

        # Method 3: SFTP (requires pi to be in debian-tor group)
        try:
            sftp = self.client.open_sftp()
            with sftp.open(cookie_path, "rb") as cf:
                data = cf.read()
            sftp.close()
            if len(data) == 32:
                _log.debug("Cookie read via SFTP (%d bytes)", len(data))
                return data.hex()
        except Exception as e:
            _log.debug("Cookie SFTP failed: %s", e)

        _log.warning("All cookie read methods failed for %s", cookie_path)
        return ""

    def _recv_reply(self, timeout: float = 6.0) -> list[str]:
        """Read a complete synchronous reply (250/4xx/5xx terminal line).

        Async 650 events seen during a synchronous exchange are dispatched
        immediately rather than stashed — they are informational and safe to
        process out-of-order with respect to the reply we are waiting for.
        """
        lines    = []
        deadline = time.time() + timeout
        in_block = False

        while not self._stop.is_set() and time.time() < deadline:
            # Process buffered complete lines first
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                line = line.rstrip("\r")

                if line.startswith("650"):
                    # Async event during a synchronous exchange — dispatch now
                    self._dispatch(line)
                    continue

                lines.append(line)

                if in_block:
                    if line == ".":
                        in_block = False
                    continue

                if len(line) >= 4 and line[3] == "+":
                    in_block = True
                    continue

                if len(line) >= 4 and line[3] == " ":
                    return lines   # terminal line — reply complete

            # Need more bytes
            try:
                self._sock.settimeout(0.5)
                chunk = self._sock.recv(4096)
                if not chunk:
                    raise OSError("control channel closed")
                self._buf += chunk.decode(errors="replace")
                if len(self._buf) > 65536:
                    _log.warning("_recv_reply: _buf exceeded 64 KB — truncating")
                    self._buf = self._buf[-32768:]
            except TimeoutError:
                continue   # normal — loop and check deadline
            except OSError:
                raise      # real socket error — propagate

        self._buf = ""   # timed out — discard partial reply
        return lines

    def _ok(self, lines: list[str]) -> bool:
        return any(l.startswith("250") for l in lines)

    # ── polls ───────────────────────────────────────────────────────────────
    def _poll_identity(self):
        try:
            info = {}

            self._send("GETINFO version")
            for l in self._recv_reply():
                if l.startswith("250-version=") or l.startswith("250 version="):
                    info["version"] = l.split("=", 1)[1].strip()

            self._send("GETINFO address")
            for l in self._recv_reply():
                if "address=" in l:
                    info["address"] = l.split("=", 1)[1].strip()

            self._send("GETCONF Nickname ORPort BandwidthRate BandwidthBurst")
            for l in self._recv_reply():
                for key in ("Nickname", "ORPort", "BandwidthRate", "BandwidthBurst"):
                    if l.lower().startswith(f"250-{key.lower()}=") or \
                       l.lower().startswith(f"250 {key.lower()}="):
                        info[key.lower()] = l.split("=", 1)[1].strip()

            self._send("GETINFO fingerprint")
            for l in self._recv_reply():
                if "fingerprint=" in l.lower():
                    fp = l.split("=", 1)[1].strip()
                    info["fingerprint"] = fp
                    self._fp = fp

            # Flags from ns/id
            if self._fp:
                self._send(f"GETINFO ns/id/{self._fp}")
                flags = []
                for l in self._recv_reply():
                    if l.startswith("s "):
                        flags = l[2:].split()
                        break
                info["flags"] = flags

            self._send("GETINFO uptime")
            for l in self._recv_reply():
                if "uptime=" in l.lower():
                    try:
                        info["uptime"] = int(l.split("=", 1)[1].strip())
                    except ValueError:
                        pass

            # Only post when at least one meaningful field was received.
            # An all-empty dict (every GETINFO timed out) must not overwrite
            # the displayed identity fields with dashes.
            if info and ("fingerprint" in info or "version" in info):
                self._post("identity", info)
                _log.debug("Identity polled: fp=%s, keys=%s",
                           self._fp, list(info.keys()))

        except OSError:
            raise
        except Exception as e:
            _log.warning("Identity poll error: %s", e)

    @staticmethod
    def _parse_orconn_line(line: str) -> dict | None:
        """Parse one orconn-status line.

        Actual Tor format (two tokens):
          Outbound:  $FP~NICKNAME STATUS
          Inbound:   IP:PORT STATUS
        """
        parts = line.split()
        if len(parts) < 2:
            return None
        target = parts[0]
        status = parts[1]

        # Inbound connection: target is an IP:PORT (no $ prefix, contains : or .)
        if not target.startswith("$") and (":" in target or "." in target):
            return {
                "direction": "in",
                "ip_port":   target,
                "nickname":  "",
                "status":    status,
            }

        # Outbound connection: target is $FP or $FP~nickname
        if target.startswith("$") or re.match(r'^[0-9A-Fa-f]+$', target):
            fp_nick = target.lstrip("$")
            if "~" in fp_nick:
                fp, _, nickname = fp_nick.partition("~")
            else:
                fp, nickname = fp_nick, ""
            return {
                "direction": "out",
                "ip_port":   "",
                "nickname":  nickname or fp[:8],
                "status":    status,
            }
        return None

    def _poll_connections(self):
        try:
            self._send("GETINFO orconn-status")
            lines = self._recv_reply()
            _log.debug("orconn-status raw (%d lines): %s", len(lines), lines)
            conns = []
            for l in lines:
                # Normalise: strip any 250[-+ ] status prefix (handles both
                # 250+ data-block format and 250- continuation-line format)
                stripped = re.sub(r'^250[-+ ]', '', l).strip()
                stripped = re.sub(r'^orconn-status=', '', stripped).strip()
                if not stripped or stripped in ("OK", "."):
                    continue
                conn = self._parse_orconn_line(stripped)
                if conn:
                    conns.append(conn)
                else:
                    _log.debug("orconn-status unmatched line: %r", stripped)
            _log.debug("orconn-status parsed %d connections", len(conns))
            # Always post — even empty list clears stale rows on disconnect
            self._post("conns", conns)
        except OSError:
            raise
        except Exception as e:
            _log.warning("Connections poll error: %s", e)

    # ── event dispatch ──────────────────────────────────────────────────────
    def _dispatch(self, line: str):
        if not line.startswith("650 "):
            return

        # BW — too noisy for the event log, handle silently
        if line.startswith("650 BW "):
            parts = line.split()
            if len(parts) >= 4:
                try:
                    self._post("bw", int(parts[2]), int(parts[3]))
                except ValueError:
                    pass
            return

        # CIRC
        if line.startswith("650 CIRC "):
            if " BUILT" in line:
                self._circ_built += 1
            elif " FAILED" in line or " CLOSED" in line:
                self._circ_failed += 1
            else:
                self._post("event", line[4:])
                return
            self._post("circ", self._circ_built, self._circ_failed)
            self._post("event", line[4:])
            return

        # ORCONN — set flag, debounced poll happens in main loop
        if line.startswith("650 ORCONN "):
            self._orconn_dirty = True
            self._post("event", line[4:])
            return

        # STREAM / ADDRMAP / anything else — forward to event log
        self._post("event", line[4:])

    # ── main run ────────────────────────────────────────────────────────────
    def run(self):
        try:
            transport    = self.client.get_transport()
            self._sock   = transport.open_channel(
                "direct-tcpip", ("127.0.0.1", 9051), ("127.0.0.1", 0))
            self._buf    = ""
            self._orconn_dirty = False

            # ── authenticate ────────────────────────────────────────────────
            # Try cookie auth first, fall back to empty string.
            # Retry up to 3 times; reopen channel between attempts in case
            # Tor closed it after a failed attempt.
            auth_ok = False
            for attempt in range(3):
                if attempt > 0:
                    if self._stop.is_set():
                        return
                    time.sleep(1.5)
                    try:
                        self._sock.close()
                    except Exception:
                        pass
                    try:
                        self._sock = transport.open_channel(
                            "direct-tcpip", ("127.0.0.1", 9051), ("127.0.0.1", 0))
                        self._buf = ""
                    except Exception as e:
                        _log.error("Cannot reopen control channel: %s", e)
                        break

                try:
                    cookie_path = "/var/run/tor/control.authcookie"
                    self._send("PROTOCOLINFO 1")
                    info_lines = self._recv_reply(timeout=4.0)
                    for il in info_lines:
                        if "COOKIEFILE=" in il:
                            m = re.search(r'COOKIEFILE="([^"]+)"', il)
                            if m:
                                cookie_path = m.group(1)

                    cookie_hex = self._read_cookie(cookie_path)
                    if cookie_hex:
                        self._send("AUTHENTICATE " + cookie_hex)
                    else:
                        self._send('AUTHENTICATE ""')
                except OSError:
                    break

                reply = self._recv_reply(timeout=8.0)
                _log.debug("Auth attempt %d reply: %s", attempt + 1, reply)
                if self._ok(reply):
                    auth_ok = True
                    break
                _log.warning("Auth attempt %d failed: %s", attempt + 1, reply)
                self._post("status", "warn",
                           f"Control auth attempt {attempt+1}/3 failed")

            if not auth_ok:
                self._post("status", "error",
                    "Tor control auth failed after 3 attempts.\n"
                    "Check torrc has 'ControlPort 9051' and "
                    "'CookieAuthentication 1'.\n"
                    "Also: sudo usermod -aG debian-tor <username>")
                _log.error("Tor control auth failed")
                return

            _log.info("Tor control authenticated")

            # ── subscribe + initial poll ─────────────────────────────────────
            self._send("SETEVENTS BW CIRC ORCONN STREAM ADDRMAP")
            self._recv_reply()
            self._post("ctrl_up", None)

            self._poll_identity()
            self._poll_connections()

            # ── event loop ───────────────────────────────────────────────────
            last_poll         = time.time()
            last_retry        = time.time()
            last_orconn_event = 0.0

            while not self._stop.is_set():
                # ── drain command queue ──────────────────────────────────────
                try:
                    while True:
                        cmd = self.cmd_q.get_nowait()
                        self._send(cmd)
                        reply = self._recv_reply(timeout=4.0)
                        ok    = self._ok(reply)
                        self._post("signal_result", cmd, ok, reply)
                        if ok and any(k in cmd for k in
                                      ("NEWNYM", "RELOAD", "CLEARDNSCACHE")):
                            self._poll_identity()
                            self._poll_connections()
                except queue.Empty:
                    pass

                # ── debounced ORCONN poll ────────────────────────────────────
                now = time.time()
                if self._orconn_dirty and \
                        now - last_orconn_event > self.ORCONN_DEBOUNCE:
                    self._orconn_dirty  = False
                    last_orconn_event   = now
                    self._poll_connections()

                # ── retry if bootstrapping (no fingerprint yet) ──────────────
                if not self._fp and now - last_retry > self.RETRY_INTERVAL:
                    last_retry = now
                    self._poll_identity()
                    self._poll_connections()
                    if self._fp:
                        last_poll = now   # align normal timer

                # ── periodic full re-poll ────────────────────────────────────
                if now - last_poll > self.POLL_INTERVAL:
                    last_poll = time.time()
                    self._poll_identity()
                    self._poll_connections()

                # ── receive events ───────────────────────────────────────────
                try:
                    self._sock.settimeout(1.0)
                    chunk = self._sock.recv(4096)
                    if not chunk:
                        _log.info("CtrlWorker: control channel EOF — Tor may have restarted")
                        break   # channel closed cleanly (Tor restart / reload)
                    self._buf += chunk.decode(errors="replace")
                    if len(self._buf) > 65536:
                        _log.warning("CtrlWorker: _buf exceeded 64 KB — truncating")
                        self._buf = self._buf[-32768:]
                except TimeoutError:
                    continue
                except OSError:
                    break

                # Dispatch all complete lines
                while "\n" in self._buf:
                    line, self._buf = self._buf.split("\n", 1)
                    self._dispatch(line.rstrip("\r"))

        except OSError as e:
            _log.error("CtrlWorker OSError: %s", e)
            self._post("status", "warn", f"Control port error: {e}")
        except Exception as e:
            _log.error("CtrlWorker unexpected: %s", traceback.format_exc())
            self._post("status", "warn", f"Control port: {e}")
        finally:
            _log.info("CtrlWorker exiting")
            self._post("ctrl_down", None)


# ─────────────────────────────────────────────────────────────────────────────
#  TerminalCanvas  (unchanged from v1 — this part works)
# ─────────────────────────────────────────────────────────────────────────────
class TerminalCanvas(tk.Canvas):

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

    def __init__(self, parent, cols: int, rows: int,
                 font_name: str = "Cascadia Code", font_size: int = 11, **kw):
        super().__init__(parent, bg="#1a1b26", highlightthickness=0,
                         cursor="xterm", **kw)
        self.cols           = cols
        self.rows           = rows
        self._font_name     = font_name
        self._font_size     = font_size
        self._key_callback  = None
        self._cell_ids      = {}
        self._prev_cursor   = None
        self._resize_id     = None

        self._init_font()
        self._build_grid()

        self.bind("<Configure>", self._on_configure)
        self.bind("<Button-1>",  lambda e: self.focus_set())
        for seq in ("<Up>","<Down>","<Left>","<Right>","<Prior>","<Next>",
                    "<Home>","<End>","<Return>","<KP_Enter>","<BackSpace>",
                    "<Tab>","<Escape>","<Delete>",
                    "<F1>","<F2>","<F3>","<F4>","<F5>",
                    "<F6>","<F7>","<F8>","<F9>","<F10>"):
            self.bind(seq, self._on_special_key)
        self.bind("<KeyPress>", self._on_printable_key)
        self.focus_set()

    def _init_font(self):
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
        self._font      = tkfont.Font(family=self._font_name, size=self._font_size)
        self._font_bold = tkfont.Font(family=self._font_name, size=self._font_size,
                                       weight="bold")
        self._cw = int(self._font.measure("M"))
        self._ch = int(self._font.metrics("linespace")) + 2

    def _build_grid(self):
        self.delete("all")
        self._cell_ids    = {}
        self._prev_cursor = None
        cw, ch = self._cw, self._ch
        for r in range(self.rows):
            y1, y2 = r * ch, r * ch + ch
            for c in range(self.cols):
                x1, x2 = c * cw, c * cw + cw
                bg_id = self.create_rectangle(x1, y1, x2, y2,
                                               fill="#1a1b26", outline="")
                ch_id = self.create_text(x1 + cw // 2, y1 + ch // 2,
                                          text=" ", font=self._font,
                                          fill="#c0caf5", anchor="center")
                self._cell_ids[(r, c)] = (bg_id, ch_id)

    def _on_configure(self, event):
        new_cols = max(1, int(event.width)  // self._cw)
        new_rows = max(1, int(event.height) // self._ch)
        if new_cols == self.cols and new_rows == self.rows:
            return
        self.cols, self.rows = new_cols, new_rows
        if self._resize_id:
            self.after_cancel(self._resize_id)
        self._resize_id = self.after(150, self._do_resize)

    def _do_resize(self):
        self._resize_id = None
        self._build_grid()
        if self._key_callback:
            self._key_callback(("resize", self.cols, self.rows))

    def render(self, screen):
        cy, cx  = screen.cursor.y, screen.cursor.x
        cur_pos = (cy, cx)
        prev    = self._prev_cursor

        dirty = screen.dirty.copy()
        screen.dirty.clear()

        if cur_pos != prev:
            if prev:
                dirty.add(prev[0])
            dirty.add(cy)

        if not dirty:
            return

        cell_ids = self._cell_ids
        s_lines  = screen.lines
        s_cols   = screen.columns
        buf      = screen.buffer

        for (row, col), (bg_id, ch_id) in cell_ids.items():
            if row not in dirty:
                continue
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

        self._prev_cursor = cur_pos
        if cur_pos in cell_ids and cy < s_lines and cx < s_cols:
            bg_id, ch_id = cell_ids[cur_pos]
            self.itemconfig(bg_id, fill="#7aa2f7")
            self.itemconfig(ch_id, fill="#1a1b26")

    def _on_special_key(self, event):
        if not self._key_callback:
            return "break"
        seq = self._CURSOR_APP.get(event.keysym) or self._KEY_MAP.get(event.keysym)
        if seq:
            self._key_callback(("key", seq))
        return "break"

    def _on_printable_key(self, event):
        if not self._key_callback:
            return "break"
        if event.keysym in self._CURSOR_APP or event.keysym in self._KEY_MAP:
            return "break"
        if event.char and event.state & 0x4:   # Ctrl held
            c = ord(event.char) & 0x1f
            self._key_callback(("key", bytes([c])))
            return "break"
        if event.char and ord(event.char) >= 32:
            self._key_callback(("key", event.char.encode("utf-8", errors="replace")))
        return "break"


# ─────────────────────────────────────────────────────────────────────────────
#  DashboardPanel
# ─────────────────────────────────────────────────────────────────────────────
class DashboardPanel(tk.Frame):

    BG       = "#0f1117"
    PANEL    = "#161929"
    BORDER   = "#1e2235"
    ACCENT   = "#7c3aed"
    TEXT     = "#e2e8f0"
    TEXT_DIM = "#64748b"
    SUCCESS  = "#10b981"
    WARNING  = "#f59e0b"
    ERROR    = "#ef4444"
    COL_READ  = "#7aa2f7"
    COL_WRITE = "#9ece6a"

    HISTORY_LEN = 60
    EMA_ALPHA   = 0.25
    PEAK_DECAY  = 0.97

    # Graph modes
    GRAPH_MODES = ["Bandwidth", "Connections", "Resources"]

    def __init__(self, parent, scale: float = 1.0, **kw):
        super().__init__(parent, bg=self.BG, **kw)
        self._scale       = scale
        self._lower_drag_y = None
        self._lower_drag_h = None
        # Bandwidth history
        self._bw_read    = collections.deque([0] * self.HISTORY_LEN,
                                              maxlen=self.HISTORY_LEN)
        self._bw_written = collections.deque([0] * self.HISTORY_LEN,
                                              maxlen=self.HISTORY_LEN)
        self._ema_r  = 0.0
        self._ema_w  = 0.0
        self._peak   = 0.0
        # Connections history (total connection count over time)
        self._conn_hist  = collections.deque([0] * self.HISTORY_LEN,
                                              maxlen=self.HISTORY_LEN)
        self._conn_in_hist  = collections.deque([0] * self.HISTORY_LEN,
                                                 maxlen=self.HISTORY_LEN)
        self._conn_out_hist = collections.deque([0] * self.HISTORY_LEN,
                                                 maxlen=self.HISTORY_LEN)
        # Resources: circuit counts over time
        self._circ_built_hist  = collections.deque([0] * self.HISTORY_LEN,
                                                    maxlen=self.HISTORY_LEN)
        self._circ_failed_hist = collections.deque([0] * self.HISTORY_LEN,
                                                    maxlen=self.HISTORY_LEN)
        self._identity    = {}
        self._circ_built  = 0
        self._circ_failed = 0
        self._last_conns     = []
        self._conn_sig_last  = None    # fingerprint of last rendered conn list
        self._conn_sort      = "direction"  # active sort: direction|status|name|none
        self._graph_mode  = "Bandwidth"   # "Bandwidth" | "Connections" | "Resources"
        self._graph_dirty = False          # coalesces push_bw() redraws to one per poll tick
        self._build()

    # ── font helper ─────────────────────────────────────────────────────────
    def _f(self, families, size, bold=False):
        for fam in families:
            try:
                return tkfont.Font(family=fam, size=size,
                                   weight="bold" if bold else "normal")
            except Exception:
                continue
        return tkfont.Font(size=size, weight="bold" if bold else "normal")

    def _s(self, n: int) -> int:
        return max(1, round(n * self._scale))

    def _sf(self, n: int) -> int:
        return max(7, round(n * self._scale))

    # ── construction ────────────────────────────────────────────────────────
    def _build(self):
        # Store all font objects as instance attrs — prevents GC from
        # deleting them while Tk widgets still hold a reference.
        self._fmono_s = self._f(["Cascadia Code", "Consolas", "Courier New"], self._sf(9))
        self._fui_s   = self._f(["Segoe UI", "Helvetica Neue", "Arial"], self._sf(9))
        self._ffp     = self._f(["Cascadia Code", "Consolas", "Courier New"], self._sf(8))

        # ── top-level grid: fixed rows for bw + identity, events row expands ──
        # row 0 = bandwidth, row 1 = sep, row 2 = identity/connections,
        # row 3 = sep, row 4 = events (weight=1, minsize guarantees visibility)
        # grid_propagate(False): parent controls our size; we distribute it.
        # Without this, tkinter sizes the frame to fit children and the
        # weight/minsize system never activates when the window shrinks.
        self.grid_propagate(False)
        self.rowconfigure(0, weight=0)
        self.rowconfigure(1, weight=0)
        self.rowconfigure(2, weight=0)
        self.rowconfigure(3, weight=0)
        self.rowconfigure(4, weight=1, minsize=self._s(80))
        self.rowconfigure(5, weight=0)
        self.columnconfigure(0, weight=1)

        # ── bandwidth section ─────────────────────────────────────────────
        bw_frame = tk.Frame(self, bg=self.BG)
        bw_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 0))

        hdr = tk.Frame(bw_frame, bg=self.BG)
        hdr.pack(fill="x", pady=(0, 6))
        self._graph_title_lbl = tk.Label(hdr, text="BANDWIDTH", font=self._fui_s,
                                          fg=self.ACCENT, bg=self.BG)
        self._graph_title_lbl.pack(side="left")
        self._lbl_read  = tk.Label(hdr, text="↓  0 B/s", font=self._fmono_s,
                                    fg=self.COL_READ,  bg=self.BG)
        self._lbl_read.pack(side="right")
        tk.Label(hdr, text="  ", bg=self.BG).pack(side="right")
        self._lbl_write = tk.Label(hdr, text="↑  0 B/s", font=self._fmono_s,
                                    fg=self.COL_WRITE, bg=self.BG)
        self._lbl_write.pack(side="right")

        self._bw_canvas = tk.Canvas(bw_frame, bg=self.PANEL, height=self._s(110),
                                     highlightthickness=1,
                                     highlightbackground=self.BORDER)
        self._bw_canvas.pack(fill="x")
        self._bw_canvas.bind("<Configure>", lambda _: self._redraw_graph())

        self._lbl_bw_max = tk.Label(bw_frame, text="", font=self._fmono_s,
                                     fg=self.TEXT_DIM, bg=self.BG, anchor="e")
        self._lbl_bw_max.pack(fill="x")

        tk.Frame(self, bg=self.BORDER, height=1).grid(row=1, column=0, sticky="ew", padx=20, pady=(16, 0))

        # ── two-column middle section (identity + connections) ────────────
        # height=240: large enough for all 8 relay-identity rows at scale=1.0
        lower = tk.Frame(self, bg=self.BG, height=self._s(240))
        lower.grid(row=2, column=0, sticky="ew", padx=20, pady=(14, 0))
        lower.pack_propagate(False)
        lower.grid_propagate(False)
        self._lower = lower   # referenced by the top drag handle
        lower.columnconfigure(0, weight=3)
        lower.columnconfigure(1, weight=0)
        lower.columnconfigure(2, weight=2)
        lower.rowconfigure(0, weight=1)

        # LEFT: relay identity
        left_col = tk.Frame(lower, bg=self.BG)
        left_col.grid(row=0, column=0, sticky="nsew")
        id_outer = tk.Frame(left_col, bg=self.BG)
        id_outer.pack(fill="x", anchor="n")
        tk.Label(id_outer, text="RELAY IDENTITY", font=self._fui_s,
                 fg=self.ACCENT, bg=self.BG).pack(anchor="w", pady=(0, 8))
        id_grid = tk.Frame(id_outer, bg=self.BG)
        id_grid.pack(fill="x", anchor="n")

        def id_row(label, attr, font=None):
            f = font or self._fui_s
            tk.Label(id_grid, text=label, font=self._fui_s,
                     fg=self.TEXT_DIM, bg=self.BG,
                     anchor="w", width=14).grid(
                         row=id_row.n, column=0, sticky="w", pady=2)
            lbl = tk.Label(id_grid, text="—", font=f,
                           fg=self.TEXT, bg=self.BG, anchor="w")
            lbl.grid(row=id_row.n, column=1, sticky="w", padx=(6, 0))
            setattr(self, attr, lbl)
            id_row.n += 1
        id_row.n = 0

        id_row("Nickname",    "_id_nick")
        id_row("Address",     "_id_addr",   font=self._fmono_s)
        id_row("Fingerprint", "_id_fp",     font=self._ffp)
        id_row("OR Port",     "_id_port")
        id_row("Tor version", "_id_ver")
        id_row("Uptime",      "_id_uptime")
        id_row("Flags",       "_id_flags")
        id_row("BW rate",     "_id_bwrate")

        # Vertical divider between identity and connections
        tk.Frame(lower, bg=self.BORDER, width=1).grid(
            row=0, column=1, sticky="ns", padx=18)

        # RIGHT: connections
        conn_outer = tk.Frame(lower, bg=self.BG)
        conn_outer.grid(row=0, column=2, sticky="nsew")

        conn_hdr = tk.Frame(conn_outer, bg=self.BG)
        conn_hdr.pack(fill="x", pady=(0, 6))
        tk.Label(conn_hdr, text="CONNECTIONS", font=self._fui_s,
                 fg=self.ACCENT, bg=self.BG).pack(side="left")
        self._conn_count = tk.Label(conn_hdr, text="", font=self._fmono_s,
                                     fg=self.TEXT_DIM, bg=self.BG)
        self._conn_count.pack(side="right")
        _sort_labels = {"direction": "↕ Direction", "status": "↕ Status",
                        "name": "↕ Name", "none": "↕ Default"}
        self._conn_sort_btn = tk.Button(
            conn_hdr, text=_sort_labels[self._conn_sort],
            font=self._fui_s, fg=self.TEXT_DIM, bg=self.BG,
            relief="flat", bd=0, cursor="hand2",
            activeforeground=self.ACCENT, activebackground=self.BG,
            command=self._cycle_conn_sort)
        self._conn_sort_btn.pack(side="right", padx=(0, 8))

        col_hdr = tk.Frame(conn_outer, bg=self.PANEL)
        col_hdr.pack(fill="x")
        for txt, w in [("", 2), ("IP : Port", 18), ("Relay", 14), ("Status", 10)]:
            tk.Label(col_hdr, text=txt, font=self._fui_s,
                     fg=self.TEXT_DIM, bg=self.PANEL,
                     anchor="w", width=w, padx=4, pady=2).pack(side="left")

        list_frame = tk.Frame(conn_outer, bg=self.BG)
        list_frame.pack(fill="both", expand=True)

        self._conn_canvas = tk.Canvas(list_frame, bg=self.BG, highlightthickness=0)

        _sb_style = ttk.Style()
        _sb_style.theme_use("default")
        _sb_style.configure("Dark.Vertical.TScrollbar",
            background="#1e2235", troughcolor="#0f1117",
            arrowcolor="#1e2235", borderwidth=0, relief="flat")
        _sb_style.map("Dark.Vertical.TScrollbar",
            background=[("active", "#2e3350"), ("disabled", "#0f1117")])

        self._conn_sb = ttk.Scrollbar(list_frame, orient="vertical",
                                       style="Dark.Vertical.TScrollbar",
                                       command=self._conn_canvas.yview)
        self._conn_canvas.configure(yscrollcommand=self._conn_scroll_cb)
        self._conn_canvas.pack(side="left", fill="both", expand=True)

        self._conn_inner  = tk.Frame(self._conn_canvas, bg=self.BG)
        self._conn_win    = self._conn_canvas.create_window(
            (0, 0), window=self._conn_inner, anchor="nw")
        self._conn_inner.bind("<Configure>",
            lambda e: self._conn_canvas.configure(
                scrollregion=self._conn_canvas.bbox("all")))
        self._conn_canvas.bind("<Configure>",
            lambda e: self._conn_canvas.itemconfig(
                self._conn_win, width=e.width))
        self._conn_canvas.bind("<MouseWheel>", self._conn_scroll)

        self._conn_rows = []

        # ── full-width events section ─────────────────────────────────────
        # Top drag handle: drag up/down to resize the identity section vs events
        ev_top_handle = tk.Frame(self, bg=self.BORDER,
                                  height=self._s(6), cursor="sb_v_double_arrow")
        ev_top_handle.grid(row=3, column=0, sticky="ew", padx=20, pady=(10, 0))
        ev_top_handle.bind("<Enter>",
                           lambda _: ev_top_handle.config(bg="#2e3a50"))
        ev_top_handle.bind("<Leave>",
                           lambda _: ev_top_handle.config(bg=self.BORDER))
        ev_top_handle.bind("<ButtonPress-1>",   self._ev_top_drag_start)
        ev_top_handle.bind("<B1-Motion>",       self._ev_top_drag_move)
        ev_top_handle.bind("<ButtonRelease-1>", self._ev_top_drag_end)

        ev_section = tk.Frame(self, bg=self.BG)
        ev_section.grid(row=4, column=0, sticky="nsew", padx=20, pady=(6, 0))

        # Bottom drag handle: drag up to open/grow the debug log below
        self._bottom_handle = tk.Frame(self, bg=self.BORDER,
                                        height=self._s(5), cursor="sb_v_double_arrow")
        self._bottom_handle.grid(row=5, column=0, sticky="ew")
        self._bottom_handle.bind("<Enter>",
                                  lambda _: self._bottom_handle.config(bg="#2e3a50"))
        self._bottom_handle.bind("<Leave>",
                                  lambda _: self._bottom_handle.config(bg=self.BORDER))
        ev_section.rowconfigure(1, weight=1)
        ev_section.columnconfigure(0, weight=1)

        tk.Label(ev_section, text="EVENTS", font=self._fui_s,
                 fg=self.ACCENT, bg=self.BG).grid(
                     row=0, column=0, sticky="w", pady=(0, 4))

        ev_list = tk.Frame(ev_section, bg=self.BG)
        ev_list.grid(row=1, column=0, sticky="nsew")
        ev_list.rowconfigure(0, weight=1)
        ev_list.columnconfigure(0, weight=1)

        self._ev_text = tk.Text(ev_list, bg=self.PANEL, fg=self.TEXT,
            font=self._fmono_s, relief="flat", bd=0, state="disabled",
            wrap="none", highlightthickness=0, selectbackground=self.BORDER,
            width=1, height=1)  # suppress natural size request; grid controls size
        self._ev_text.grid(row=0, column=0, sticky="nsew")

        _ev_sb_style = ttk.Style()
        _ev_sb_style.configure("EvDark.Vertical.TScrollbar",
            background="#1e2235", troughcolor="#0f1117",
            arrowcolor="#1e2235", borderwidth=0, relief="flat")
        _ev_sb_style.map("EvDark.Vertical.TScrollbar",
            background=[("active", "#2e3350"), ("disabled", "#0f1117")])
        ev_sb = ttk.Scrollbar(ev_list, orient="vertical",
            style="EvDark.Vertical.TScrollbar", command=self._ev_text.yview)
        self._ev_text.configure(yscrollcommand=ev_sb.set)
        ev_sb.grid(row=0, column=1, sticky="ns")

        self._ev_text.tag_configure("ts",     foreground=self.TEXT_DIM)
        self._ev_text.tag_configure("circ",   foreground="#7dd3fc")
        self._ev_text.tag_configure("orcon",  foreground="#86efac")
        self._ev_text.tag_configure("stream", foreground="#fcd34d")
        self._ev_text.tag_configure("addr",   foreground="#c4b5fd")
        self._ev_text.tag_configure("other",  foreground=self.TEXT)
        self._EV_MAX = 200

    # ── top drag handle (identity ↔ events boundary) ─────────────────────────
    def _ev_top_drag_start(self, event):
        self._lower_drag_y = event.y_root
        self._lower_drag_h = self._lower.winfo_height()

    def _ev_top_drag_move(self, event):
        if self._lower_drag_y is None:
            return
        delta  = event.y_root - self._lower_drag_y
        new_h  = self._lower_drag_h + delta
        # Clamp: at least enough to show a few rows; at most 80 % of panel height
        panel_h = self.winfo_height()
        min_h   = self._s(80)
        max_h   = max(min_h, int(panel_h * 0.75)) if panel_h > 0 else self._s(400)
        new_h   = max(min_h, min(max_h, new_h))
        self._lower.configure(height=new_h)

    def _ev_top_drag_end(self, *_):
        self._lower_drag_y = None
        self._lower_drag_h = None

    # ── scroll helpers ───────────────────────────────────────────────────────
    def _conn_scroll(self, event):
        self._conn_canvas.yview_scroll(-1 * (event.delta // 120), "units")

    def _conn_scroll_cb(self, first, last):
        self._conn_sb.set(first, last)
        if float(first) <= 0.0 and float(last) >= 1.0:
            self._conn_sb.pack_forget()
        else:
            self._conn_sb.pack(side="right", fill="y",
                               before=self._conn_canvas)

    # ── data update methods ──────────────────────────────────────────────────
    def push_event(self, line: str):
        """Append a raw Tor control event line to the Events panel."""
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        u = line.upper()
        if u.startswith("CIRC "):       tag = "circ"
        elif u.startswith("ORCONN "):   tag = "orcon"
        elif u.startswith("STREAM "):   tag = "stream"
        elif u.startswith("ADDRMAP "): tag = "addr"
        else:                           tag = "other"
        w = self._ev_text
        w.configure(state="normal")
        w.insert("end", ts + "  ", "ts")
        w.insert("end", line.rstrip() + "\n", tag)
        n = int(w.index("end-1c").split(".")[0])
        if n > self._EV_MAX:
            w.delete("1.0", f"{n - self._EV_MAX}.0")
        w.configure(state="disabled")
        w.see("end")

    def push_bw(self, read_b: int, written_b: int):
        a = self.EMA_ALPHA
        self._ema_r = a * read_b    + (1 - a) * self._ema_r
        self._ema_w = a * written_b + (1 - a) * self._ema_w
        self._bw_read.append(self._ema_r)
        self._bw_written.append(self._ema_w)
        if self._graph_mode == "Bandwidth":
            self._lbl_read.config(text=f"↓  {fmt_bytes(read_b)}/s")
            self._lbl_write.config(text=f"↑  {fmt_bytes(written_b)}/s")
        # BW events fire every second — set a dirty flag so the main poll
        # loop redraws once per 50 ms tick regardless of BW event rate.
        self._graph_dirty = True

    def push_identity(self, d: dict):
        self._identity = d
        self._refresh_identity()

    def push_circs(self, built: int, failed: int):
        # Store per-event deltas, not cumulative totals.  Cumulative values
        # cause the history to fill with near-identical large numbers, making
        # the graph appear flat regardless of circuit activity.
        delta_b = max(0, built  - self._circ_built)
        delta_f = max(0, failed - self._circ_failed)
        self._circ_built  = built
        self._circ_failed = failed
        self._circ_built_hist.append(delta_b)
        self._circ_failed_hist.append(delta_f)
        if self._graph_mode == "Resources":
            self._redraw_graph()

    @staticmethod
    def _conn_sig(conns: list) -> tuple:
        """Cheap structural fingerprint — used to skip redundant widget rebuilds."""
        return tuple(
            (c.get("direction",""), c.get("ip_port",""),
             c.get("nickname",""),  c.get("status",""))
            for c in conns
        )

    def push_connections(self, conns: list):
        n     = len(conns)
        n_in  = sum(1 for c in conns if c.get("direction") == "in")
        n_out = sum(1 for c in conns if c.get("direction") == "out")

        # Always update history deques and graph regardless of widget state.
        self._conn_hist.append(n)
        self._conn_in_hist.append(n_in)
        self._conn_out_hist.append(n_out)
        if self._graph_mode == "Connections":
            self._redraw_graph()

        # Skip the expensive destroy-and-recreate cycle when visible data
        # hasn't changed. ORCONN events fire on every state transition and
        # many don't affect the displayed list at all.
        sig = self._conn_sig(conns)
        if sig == self._conn_sig_last:
            return
        self._conn_sig_last = sig

        for w in self._conn_rows:
            w.destroy()
        self._conn_rows.clear()

        status_col = {
            "CONNECTED": self.SUCCESS,  "LAUNCHED": self.WARNING,
            "FAILED":    self.ERROR,    "CLOSED":   self.TEXT_DIM,
            "NEW":       "#7dcfff",
        }

        for i, c in enumerate(self._sorted_conns(conns)):
            bg    = self.PANEL if i % 2 == 0 else self.BG
            row_f = tk.Frame(self._conn_inner, bg=bg)
            row_f.pack(fill="x")

            direction = c.get("direction", "out")
            status    = c.get("status",    "?")
            ip_port   = c.get("ip_port",   "")
            nickname  = c.get("nickname",  "")
            # Outbound conns identify by $FP~nickname; inbound by IP:PORT.
            # Show whichever is available in the address column.
            display_addr = ip_port or nickname or "?"

            dir_sym = {"in": "←", "out": "→", "?": "·"}.get(direction, "·")
            dir_col = {"in": "#7aa2f7", "out": "#9ece6a",
                       "?": self.TEXT_DIM}.get(direction, self.TEXT_DIM)

            widgets = [
                tk.Label(row_f, text=dir_sym, font=self._fmono_s,
                         fg=dir_col, bg=bg, width=2, anchor="center",
                         padx=4, pady=1),
                tk.Label(row_f, text=display_addr, font=self._fmono_s,
                         fg=self.TEXT, bg=bg, anchor="w", width=20,
                         padx=4, pady=1),
                tk.Label(row_f, text=(nickname[:14] if nickname else "—"),
                         font=self._fui_s, fg=self.TEXT_DIM, bg=bg,
                         anchor="w", width=14, padx=4, pady=1),
                tk.Label(row_f, text=status[:10],
                         font=self._fui_s,
                         fg=status_col.get(status, self.TEXT_DIM),
                         bg=bg, anchor="w", padx=4, pady=1),
            ]
            for w in widgets:
                w.pack(side="left")
                w.bind("<MouseWheel>", self._conn_scroll)
            row_f.bind("<MouseWheel>", self._conn_scroll)

            self._conn_rows.append(row_f)

        self._conn_count.config(text=f"{n} total  ←{n_in}  →{n_out}")
        self._conn_canvas.yview_moveto(0)
        self._last_conns = conns

    # ── connection sort ──────────────────────────────────────────────────────
    _SORT_MODES   = ["direction", "status", "name", "none"]
    _SORT_LABELS  = {"direction": "↕ Direction", "status": "↕ Status",
                     "name":      "↕ Name",       "none":  "↕ Default"}
    _STATUS_ORDER = {"CONNECTED": 0, "LAUNCHED": 1, "NEW": 2,
                     "FAILED": 3, "CLOSED": 4}

    def _sorted_conns(self, conns: list) -> list:
        mode = self._conn_sort
        if mode == "direction":
            # Inbound (←) first, then outbound; ties broken by display name
            return sorted(conns, key=lambda c: (
                0 if c.get("direction") == "in" else 1,
                (c.get("ip_port") or c.get("nickname") or "").lower()))
        if mode == "status":
            return sorted(conns, key=lambda c: (
                self._STATUS_ORDER.get(c.get("status", ""), 5),
                (c.get("ip_port") or c.get("nickname") or "").lower()))
        if mode == "name":
            return sorted(conns, key=lambda c: (
                c.get("nickname") or c.get("ip_port") or "").lower())
        return list(conns)  # "none" — preserve Tor's order

    def _cycle_conn_sort(self):
        idx = self._SORT_MODES.index(self._conn_sort)
        self._conn_sort = self._SORT_MODES[(idx + 1) % len(self._SORT_MODES)]
        self._conn_sort_btn.config(text=self._SORT_LABELS[self._conn_sort])
        # Re-render immediately with new sort using cached data
        self._conn_sig_last = None
        self.push_connections(self._last_conns)

    def reset(self):
        """Clear all data — called on disconnect."""
        for deq in (self._bw_read, self._bw_written,
                    self._conn_hist, self._conn_in_hist, self._conn_out_hist,
                    self._circ_built_hist, self._circ_failed_hist):
            deq.clear()
            deq.extend([0] * self.HISTORY_LEN)
        self._ema_r = self._ema_w = self._peak = 0.0
        self._identity    = {}
        self._circ_built  = self._circ_failed = 0
        self._last_conns     = []
        self._conn_sig_last  = None
        self._lbl_read.config(text="↓  0 B/s")
        self._lbl_write.config(text="↑  0 B/s")
        self._lbl_bw_max.config(text="")
        self._ev_text.configure(state="normal")
        self._ev_text.delete("1.0", "end")
        self._ev_text.configure(state="disabled")
        for attr in ("_id_nick","_id_addr","_id_fp","_id_port","_id_ver",
                     "_id_flags","_id_bwrate"):
            getattr(self, attr).config(text="—")
        self.push_connections([])
        self._redraw_graph()

    def reset_layout(self):
        """Restore all draggable panel sizes to their defaults."""
        self._lower.configure(height=self._s(240))

    # ── graph mode control ────────────────────────────────────────────────
    def set_graph_mode(self, mode: str):
        """Switch the sparkline between Bandwidth, Connections, Resources."""
        if mode not in self.GRAPH_MODES:
            return
        self._graph_mode = mode
        titles = {
            "Bandwidth":   "BANDWIDTH",
            "Connections": "CONNECTIONS",
            "Resources":   "RESOURCES  (circuits)",
        }
        self._graph_title_lbl.config(text=titles[mode])
        # Update rate labels to match mode
        if mode == "Bandwidth":
            self._lbl_write.config(fg=self.COL_WRITE)
            self._lbl_read.config(fg=self.COL_READ)
            self._lbl_read.config(text="↓  0 B/s")
            self._lbl_write.config(text="↑  0 B/s")
        elif mode == "Connections":
            self._lbl_write.config(fg="#9ece6a")
            self._lbl_read.config(fg="#7aa2f7")
            self._lbl_read.config(text="←  in: 0")
            self._lbl_write.config(text="→  out: 0")
        elif mode == "Resources":
            self._lbl_write.config(fg=self.ERROR)
            self._lbl_read.config(fg=self.SUCCESS)
            self._lbl_read.config(text="✓  built: 0")
            self._lbl_write.config(text="✗  failed: 0")
        self._lbl_bw_max.config(text="")
        self._redraw_graph()

        # Immediately populate buffered data so the new view is live on switch.
        if mode == "Connections" and self._last_conns:
            self._conn_sig_last = None        # force list rebuild from cache
            self.push_connections(self._last_conns)
        elif mode == "Resources":
            self._lbl_read.config(text=f"✓  built: {self._circ_built}")
            self._lbl_write.config(text=f"✗  failed: {self._circ_failed}")

    # ── sparkline ─────────────────────────────────────────────────────────
    def _redraw_graph(self):
        """Redraw the sparkline canvas for the current graph mode."""
        if self._graph_mode == "Bandwidth":
            self._redraw_bandwidth()
        elif self._graph_mode == "Connections":
            self._redraw_connections_graph()
        elif self._graph_mode == "Resources":
            self._redraw_resources_graph()

    def _canvas_base(self):
        """Clear canvas and return (canvas, w, h, pt, pb, ph)."""
        c  = self._bw_canvas
        c.delete("all")
        w  = c.winfo_width()  if c.winfo_width()  > 1 else 600
        h  = c.winfo_height() if c.winfo_height() > 1 else 110
        pt, pb = 8, 8
        ph = h - pt - pb
        for frac in (0.25, 0.5, 0.75):
            y = pt + ph * (1 - frac)
            c.create_line(0, y, w, y, fill=self.BORDER, width=1)
        return c, w, h, pt, pb, ph

    def _series_pts(self, series, w, pt, ph, ceiling):
        n   = self.HISTORY_LEN
        out = []
        for i, v in enumerate(series):
            x = int(i / (n - 1) * w) if n > 1 else w // 2
            y = pt + int(ph * (1 - min(v, ceiling) / ceiling))
            out.extend([x, y])
        return out

    def _draw_poly(self, c, series, w, h, pt, ph, ceiling, fill, stipple=""):
        if len(series) < 2:
            return
        xs_ys    = self._series_pts(series, w, pt, ph, ceiling)
        poly_pts = [xs_ys[0], h] + xs_ys + [xs_ys[-2], h]
        kw = dict(fill=fill, outline="")
        if stipple:
            kw["stipple"] = stipple
        c.create_polygon(poly_pts, **kw)
        c.create_line(xs_ys, fill=fill, width=2, smooth=True)

    def _redraw_bandwidth(self):
        c, w, h, pt, pb, ph = self._canvas_base()
        all_v   = list(self._bw_read) + list(self._bw_written)
        raw_max = max(all_v) if all_v else 0
        self._peak = max(raw_max, self._peak * self.PEAK_DECAY)
        ceiling    = max(self._peak, 1024)
        self._draw_poly(c, self._bw_written, w, h, pt, ph, ceiling,
                        self.COL_WRITE, "gray50")
        self._draw_poly(c, self._bw_read,    w, h, pt, ph, ceiling,
                        self.COL_READ,  "gray50")
        self._lbl_bw_max.config(text=f"↑ {fmt_bytes(int(ceiling))}/s")

    def _redraw_connections_graph(self):
        c, w, h, pt, pb, ph = self._canvas_base()
        all_v   = list(self._conn_hist)
        raw_max = max(all_v) if any(all_v) else 0
        ceiling = max(raw_max, 1)
        self._draw_poly(c, self._conn_out_hist, w, h, pt, ph, ceiling,
                        "#9ece6a", "gray50")
        self._draw_poly(c, self._conn_in_hist,  w, h, pt, ph, ceiling,
                        "#7aa2f7", "gray50")
        n_in  = self._conn_in_hist[-1]  if self._conn_in_hist  else 0
        n_out = self._conn_out_hist[-1] if self._conn_out_hist else 0
        self._lbl_read.config(text=f"←  in: {n_in}")
        self._lbl_write.config(text=f"→  out: {n_out}")
        self._lbl_bw_max.config(text=f"↑ {int(ceiling)} total")

    def _redraw_resources_graph(self):
        c, w, h, pt, pb, ph = self._canvas_base()
        all_v   = list(self._circ_built_hist) + list(self._circ_failed_hist)
        raw_max = max(all_v) if any(all_v) else 0
        ceiling = max(raw_max, 1)
        self._draw_poly(c, self._circ_failed_hist, w, h, pt, ph, ceiling,
                        self.ERROR,   "gray50")
        self._draw_poly(c, self._circ_built_hist,  w, h, pt, ph, ceiling,
                        self.SUCCESS, "gray50")
        # Labels show cumulative session totals; graph bars show per-event deltas.
        self._lbl_read.config(text=f"✓  built: {self._circ_built}")
        self._lbl_write.config(text=f"✗  failed: {self._circ_failed}")
        self._lbl_bw_max.config(text=f"↑ {int(ceiling)} peak/event")

    # ── identity refresh ──────────────────────────────────────────────────
    def _refresh_identity(self):
        d = self._identity
        if not d:
            return

        def sl(widget, val, fg=None):
            widget.config(text=str(val) if val else "—")
            if fg:
                widget.config(fg=fg)

        sl(self._id_nick,   d.get("nickname", "?"))
        sl(self._id_addr,   d.get("address",  "?"))
        sl(self._id_port,   d.get("orport",   "?"))
        sl(self._id_ver,    d.get("version",  "?"))

        fp = d.get("fingerprint", "")
        if fp:
            grouped = " ".join(fp[i:i+4] for i in range(0, len(fp), 4))
            self._id_fp.config(text=grouped, font=self._ffp)
        else:
            self._id_fp.config(text="—")

        secs = d.get("uptime")
        if isinstance(secs, int):
            d_  = secs // 86400
            h_  = (secs % 86400) // 3600
            m_  = (secs % 3600)  // 60
            sl(self._id_uptime,
               f"{d_}d {h_}h {m_}m" if d_ else f"{h_}h {m_}m")
        else:
            sl(self._id_uptime, "—")

        bwr  = d.get("bandwidthrate",  "")
        bwb  = d.get("bandwidthburst", "")
        try:
            rs = f"{fmt_bytes(int(bwr))}/s"  if bwr else "?"
            bs = f"{fmt_bytes(int(bwb))}/s"  if bwb else "?"
            sl(self._id_bwrate, f"{rs}  (burst {bs})")
        except ValueError:
            sl(self._id_bwrate, bwr or "?")

        flags    = d.get("flags", [])
        flag_col = {
            "Running": self.SUCCESS, "Valid":   self.SUCCESS,
            "Guard":   "#a78bfa",    "Stable":  "#7dcfff",
            "Fast":    "#e0af68",    "HSDir":   "#bb9af7",
            "Exit":    self.ERROR,   "BadExit": self.ERROR,
        }
        sl(self._id_flags, " ".join(flags) if flags else "—")
        for f in ("Exit", "BadExit", "Guard", "Fast", "Running"):
            if f in flags:
                self._id_flags.config(fg=flag_col.get(f, self.TEXT))
                break


# ─────────────────────────────────────────────────────────────────────────────
#  TorMonitorApp  (main window)
# ─────────────────────────────────────────────────────────────────────────────
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

    # Dashboard graph mode options
    _GRAPH_MODES = [
        ("📈  Bandwidth",    "Inbound / outbound bandwidth rate over time"),
        ("🔗  Connections",  "Active OR connection counts over time"),
        ("⚙️  Resources",    "Circuit build successes and failures over time"),
    ]

    _NYX_ACTIONS = [
        ("🔀  New Identity",    "SIGNAL NEWNYM",        None),
        ("🔄  Reload Config",   "SIGNAL RELOAD",        None),
        ("🗑  Flush DNS Cache", "SIGNAL CLEARDNSCACHE", None),
        (None, None, None),  # separator
        ("⏹  Shutdown Tor",    "SIGNAL SHUTDOWN",
         "This will stop the Tor process on the Pi. Continue?"),
        ("🔁  Halt & Restart",  "SIGNAL HALT",
         "This will kill and restart Tor on the Pi. Continue?"),
    ]

    def __init__(self, root: tk.Tk):
        self.root = root
        self.cfg  = load_config()
        self._sc  = _compute_ui_scale(root)   # resolution scale factor

        # Load profiles and merge last-used profile into cfg so the sidebar
        # is pre-populated before _build_ui() runs.
        self._profiles_data = load_profiles()
        self._master_key  : bytes | None = None   # AES-256 key derived from master password
        self._master_salt : bytes | None = None   # PBKDF2 salt (stored in profiles file)
        self._profiles_locked : bool = False      # encrypted file not yet decrypted

        if self._profiles_data.get("encrypted"):
            # File is encrypted — can't pre-populate until unlocked.
            # Store raw encrypted blob; schedule unlock prompt after UI is built.
            self._profiles_raw_enc = self._profiles_data
            self._profiles_data    = {"version": 1, "encrypted": False, "profiles": {}, "last": ""}
            self._profiles_locked  = True
        else:
            self._profiles_raw_enc = None

        _last_prof = self._profiles_data.get("last", "")
        if not self._profiles_locked:
            if _last_prof and _last_prof in self._profiles_data.get("profiles", {}):
                _pd = self._profiles_data["profiles"][_last_prof]
                for _k, _v in _pd.items():
                    if not _k.startswith("_"):
                        self.cfg[_k] = _v
                self.cfg["password"] = SecureCredStore.load(_pd, _last_prof)

        # Worker handles — always None when not running
        self._ssh : SSHWorker  | None = None
        self._ctrl: CtrlWorker | None = None

        # Single event queue — both workers post here
        self._eq  = queue.Queue(maxsize=512)

        # Generation counter — incremented on each connect so stale events
        # from a dying previous worker are silently discarded.
        self._session = 0

        # UI state
        self._view_mode      = "dashboard"
        self._graph_mode     = "Bandwidth"   # active dashboard graph mode
        self._closing        = False
        self._ctrl_retry_count  = 0           # reconnect attempt counter
        self._ctrl_retry_id     = None        # pending after() id for retry
        self._ctrl_reconnecting = False       # True while a retry is in progress
        self._ctrl_down_rounds  = 0           # consecutive ctrl_down-while-SSH-alive cycles
        self._ctrl_update_hint  = False       # True once the "may be updates" msg is shown
        self._ssh_retry_count   = 0
        self._ssh_retry_id      = None
        self._ssh_retry_cfg     = None
        self._ssh_retry_mode    = "nyx"
        self._spin_id     = None
        self._spin_lbl    = None
        self._overlay_lbl = None
        self._log_height  = self._s(160)
        self._last_poll_time = time.time()   # for sleep-wake detection

        _log.info("=" * 60)
        _log.info("Tor NYX Monitor v%s starting — log: %s", __version__, LOG_FILE)

        self._build_ui()

        # Populate profile combo now that the widget exists
        _last_prof2 = self._profiles_data.get("last", "")
        self._refresh_profile_combo(select=_last_prof2)
        if _last_prof2:
            self.profile_name_var.set(_last_prof2)

        self._update_lock_btn()

        if self._profiles_locked:
            self.root.after(300, self._prompt_unlock_profiles)

        self._poll()

        if self.cfg.get("autoconnect") and self.cfg.get("host"):
            self.root.after(800, self._connect)

    # ─────────────────────────────────────────────────────────────────────────
    #  UI construction
    # ─────────────────────────────────────────────────────────────────────────
    def _font(self, families, size, bold=False):
        avail = tkfont.families()
        for f in families:
            if f in avail:
                return (f, size, "bold" if bold else "normal")
        return ("Courier New", size, "bold" if bold else "normal")

    def _s(self, n: int) -> int:
        """Scale a pixel dimension by the screen resolution factor."""
        return max(1, round(n * self._sc))

    def _sf(self, n: int) -> int:
        """Scale a font point size (minimum 7 pt)."""
        return max(7, round(n * self._sc))

    def _build_ui(self):
        self.root.title(f"Tor NYX Monitor  v{__version__}")

        # Load window icon — works both when running as a script and as a
        # PyInstaller --onefile exe (where _MEIPASS holds extracted resources).
        try:
            import sys
            _base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
            _ico  = os.path.join(_base, "icon.ico")
            if os.path.exists(_ico):
                self.root.iconbitmap(_ico)
        except Exception:
            pass
        self.root.configure(bg=self.BG)
        self.root.geometry(f"{self._s(1200)}x{self._s(780)}")
        self.root.minsize(self._s(900), self._s(680))

        # Dark styling for the ttk.Combobox popup listbox
        self.root.option_add("*TCombobox*Listbox*Background",       "#090b10")
        self.root.option_add("*TCombobox*Listbox*Foreground",       self.TEXT)
        self.root.option_add("*TCombobox*Listbox*selectBackground", self.ACCENT)
        self.root.option_add("*TCombobox*Listbox*selectForeground", "white")

        title = self._font(["Segoe UI", "Arial"], self._sf(13), bold=True)
        label = self._font(["Segoe UI", "Arial"], self._sf(10))
        small = self._font(["Segoe UI", "Arial"], self._sf(9))
        mono  = self._font(["Cascadia Code", "Consolas", "Courier New"], self._sf(11))

        # ── top bar ──────────────────────────────────────────────────────────
        topbar = tk.Frame(self.root, bg=self.BG, height=self._s(56))
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        tk.Label(topbar, text="⬡", font=("Segoe UI", self._sf(22)),
                 fg=self.ACCENT, bg=self.BG).pack(side="left", padx=(18, 6))
        tk.Label(topbar, text="Tor NYX Monitor", font=title,
                 fg=self.TEXT, bg=self.BG).pack(side="left")

        self._status_dot   = tk.Label(topbar, text="●", font=("Segoe UI", self._sf(14)),
                                       fg=self.TEXT_DIM, bg=self.BG)
        self._status_dot.pack(side="right", padx=(0, 10))
        self._status_lbl   = tk.Label(topbar, text="Not connected",
                                       font=small, fg=self.TEXT_DIM, bg=self.BG)
        self._status_lbl.pack(side="right", padx=(0, 4))

        self._sidebar_vis = True
        self._hide_btn = tk.Button(
            topbar, text="◀  Hide Panel", font=small,
            bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
            activebackground=self.ACCENT, activeforeground="white",
            padx=10, pady=4, command=self._toggle_sidebar)
        self._hide_btn.pack(side="right", padx=(0, 8))

        tk.Frame(self.root, bg=self.BORDER, height=1).pack(fill="x")

        # ── status bar ───────────────────────────────────────────────────────
        # Must be packed BEFORE the body so pack reserves its space first.
        # If packed after expand=True body, it gets squeezed to zero at min height.
        self._statusbar_sep = tk.Frame(self.root, bg=self.BORDER, height=1)
        self._statusbar_sep.pack(side="bottom", fill="x")
        bar = tk.Frame(self.root, bg=self.PANEL, height=self._s(26))
        bar.pack(side="bottom", fill="x")
        bar.pack_propagate(False)

        # ── body ─────────────────────────────────────────────────────────────
        self._body = tk.Frame(self.root, bg=self.BG)
        self._body.pack(fill="both", expand=True)

        self._sidebar = tk.Frame(self._body, bg=self.PANEL, width=self._s(260))
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)
        self._build_sidebar(self._sidebar, label, small, mono)

        self._right = tk.Frame(self._body, bg=self.BG)
        self._right.pack(side="left", fill="both", expand=True)
        self._build_right(self._right, small)

        self._log_toggle_btn = tk.Button(
            bar, text="⬡ Debug Log", font=small,
            bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
            padx=8, pady=0, command=self._toggle_log)
        self._log_toggle_btn.pack(side="right", padx=6, pady=3)
        self._restart_tor_btn = tk.Button(
            bar, text="⟳ Restart Tor", font=small,
            bg="#7c3aed", fg="white", bd=0, cursor="hand2",
            activebackground="#6d28d9", activeforeground="white",
            padx=8, pady=0, command=self._restart_tor)
        # Shown only when ctrl port is down — hidden by default
        self._maintenance_btn = tk.Button(
            bar, text="⬆ Update System", font=small,
            bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
            activebackground=self.ACCENT, activeforeground="white",
            padx=8, pady=0, command=self._run_maintenance)
        # Shown when SSH is connected — hidden by default
        self.statusbar = tk.Label(bar, font=small, fg=self.TEXT_DIM,
                                   bg=self.PANEL,
                                   text="Enter SSH credentials and click Connect")
        self.statusbar.pack(side="left", padx=12, fill="x", expand=True)

        # ── debug log (hidden by default) ─────────────────────────────────────
        self._LOG_MAX   = 150
        self._log_vis   = False
        self._log_frame = tk.Frame(self._right, bg=self.PANEL,
                                    height=self._log_height)
        self._log_frame.pack_propagate(False)

        # Drag handle
        self._log_drag_y = None
        self._log_drag_h = None
        log_handle = tk.Frame(self._log_frame, bg=self.BORDER, height=self._s(4),
                               cursor="sb_v_double_arrow")
        log_handle.pack(fill="x", side="top")
        log_handle.pack_propagate(False)
        log_handle.bind("<ButtonPress-1>",
            lambda e: self._log_drag_start(e))
        log_handle.bind("<B1-Motion>",
            lambda e: self._log_drag_move(e))
        log_handle.bind("<ButtonRelease-1>",
            lambda e: self._log_drag_end(e))
        log_handle.bind("<Enter>", lambda e: log_handle.config(bg="#2e3a50"))
        log_handle.bind("<Leave>", lambda e: log_handle.config(bg=self.BORDER))

        log_inner = tk.Frame(self._log_frame, bg=self.PANEL)
        log_inner.pack(fill="both", expand=True)

        log_hdr = tk.Frame(log_inner, bg=self.PANEL, height=self._s(24))
        log_hdr.pack(fill="x")
        log_hdr.pack_propagate(False)
        tk.Label(log_hdr, text="DEBUG LOG", font=small,
                 fg=self.ACCENT, bg=self.PANEL).pack(side="left", padx=10)
        for txt, cmd in [("Clear", self._log_clear),
                         ("Copy",  self._log_copy),
                         ("Open log file", self._log_open)]:
            tk.Button(log_hdr, text=txt, font=small,
                      bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
                      padx=6, pady=0,
                      command=cmd).pack(side="right", padx=(0, 4), pady=2)

        log_tf = tk.Frame(log_inner, bg=self.PANEL)
        log_tf.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        self._log_text = tk.Text(
            log_tf, bg="#090b10", fg="#64748b",
            font=self._font(["Cascadia Code","Consolas","Courier New"], self._sf(8)),
            bd=0, highlightthickness=0, state="disabled", wrap="word",
            selectbackground=self.BORDER, insertbackground=self.TEXT)
        log_sb = ttk.Scrollbar(log_tf, orient="vertical",
                                command=self._log_text.yview,
                                style="Dark.Vertical.TScrollbar")
        self._log_text.configure(yscrollcommand=log_sb.set)
        log_sb.pack(side="right", fill="y")
        self._log_text.pack(side="left", fill="both", expand=True)

        for tag, fg in [("ts","#2e3a50"),("info","#64748b"),("ok","#10b981"),
                        ("warn","#f59e0b"),("error","#ef4444"),
                        ("ctrl","#7aa2f7"),("conn","#bb9af7")]:
            self._log_text.tag_configure(tag, foreground=fg)

        # Log starts hidden — user opens it via the Debug Log button

        # ── loading overlay ───────────────────────────────────────────────────
        self._overlay       = None
        self._overlay_lbl   = None
        self._ctrl_wait_lbl = None
        self._ctrl_wait_t0  = 0.0

        # Show splash on startup
        self.root.after(50, self._show_splash)

    def _build_right(self, right: tk.Frame, small):
        # Header bar
        hdr = tk.Frame(right, bg=self.BG, height=self._s(34))
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        self._view_lbl = tk.Label(hdr, text="Tor Bridge  —  live dashboard",
                                   font=small, fg=self.TEXT_DIM, bg=self.BG)
        self._view_lbl.pack(side="left", padx=14, pady=8)

        # View toggle button
        self._view_btn = tk.Button(
            hdr, text="⬡  Dashboard", font=small,
            bg=self.ACCENT, fg="white", bd=0, cursor="hand2",
            activebackground="#6d28d9", activeforeground="white",
            padx=10, pady=2, command=self._toggle_view)
        self._view_btn.pack(side="right", padx=(0, 8), pady=6)

        # Actions menu button
        self._actions_btn = tk.Button(
            hdr, text="⚡ Actions", font=small,
            bg=self.BORDER, fg=self.TEXT, bd=0, cursor="hand2",
            activebackground=self.ACCENT, activeforeground="white",
            padx=10, pady=2, command=self._show_actions_menu)
        self._actions_btn.pack(side="right", padx=(0, 4), pady=6)

        # Graph / page picker — terminal view only
        self._graph_btn = tk.Button(
            hdr, text="📊 Graph", font=small,
            bg=self.BORDER, fg=self.TEXT, bd=0, cursor="hand2",
            activebackground=self.ACCENT, activeforeground="white",
            padx=10, pady=2, command=self._show_graph_menu)
        self._graph_btn.pack(side="right", padx=(0, 4), pady=6)

        # nyx control buttons
        # _nyx_btns = terminal-only buttons (Ctrl+C, Ctrl+Z, q).
        # _graph_btn stays always visible so users can pick a page from either view.
        self._nyx_btns = []
        for txt, key in [("Ctrl+C", b"\x03"), ("Ctrl+Z", b"\x1a"), ("q  quit", b"q")]:
            btn = tk.Button(hdr, text=txt, font=small,
                            bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
                            padx=8, pady=2,
                            command=lambda k=key: self._send_key(k))
            btn.pack(side="right", padx=(0, 4), pady=6)
            self._nyx_btns.append(btn)
        # Hide terminal-only buttons initially; graph button stays packed
        for btn in self._nyx_btns:
            btn.pack_forget()

        # View container
        self._view_container = tk.Frame(right, bg=self.BG)
        self._view_container.pack(fill="both", expand=True)

        self.dashboard = DashboardPanel(self._view_container, scale=self._sc)
        self.dashboard.pack(fill="both", expand=True)

        # Wire the dashboard's bottom handle to the log-panel resize logic
        bh = self.dashboard._bottom_handle
        bh.bind("<ButtonPress-1>",   self._dashboard_bottom_drag_start)
        bh.bind("<B1-Motion>",       self._log_drag_move)
        bh.bind("<ButtonRelease-1>", self._log_drag_end)

        self.term = TerminalCanvas(self._view_container, self.TERM_COLS,
                                    self.TERM_ROWS,
                                    font_name="Cascadia Code",
                                    font_size=self._sf(11))
        self.term._key_callback = self._on_term_event

    # ─────────────────────────────────────────────────────────────────────────
    #  Connection profile management
    # ─────────────────────────────────────────────────────────────────────────
    def _refresh_profile_combo(self, select: str = ""):
        """Rebuild the profile list and optionally pre-select one."""
        names = sorted(self._profiles_data.get("profiles", {}).keys())
        self._profile_names = names
        if select and select in names:
            self.profile_var.set(select)
        elif names:
            self.profile_var.set(names[0])
        else:
            self.profile_var.set("")

    def _on_profile_select(self, *_):
        """Load the chosen profile into the connection fields."""
        name = self.profile_var.get()
        if not name:
            return
        self.profile_name_var.set(name)
        self._populate_from_profile(name)

    def _show_profile_menu(self):
        """Open a custom flat dropdown to select a saved connection profile."""
        names = self._profile_names
        if not names:
            return

        menu = tk.Toplevel(self.root)
        menu.overrideredirect(True)
        menu.configure(bg=self.BORDER)
        menu.attributes("-topmost", True)

        btn = self._profile_btn
        bx  = btn.winfo_rootx()
        by  = btn.winfo_rooty() + btn.winfo_height() + 2
        bw  = btn.winfo_width()
        menu.geometry(f"{bw}x1+{bx}+{by}")   # width matches button; height set after fill

        _selected = [False]

        def _dismiss(e=None):
            if _selected[0]:
                return
            try:
                menu.destroy()
            except Exception:
                pass
            try:
                self.root.unbind("<Button-1>", _dismiss_id[0])
            except Exception:
                pass

        _dismiss_id = [None]
        def _bind_dismiss():
            _dismiss_id[0] = self.root.bind("<Button-1>",
                lambda e: _dismiss() if not _menu_contains(e.x_root, e.y_root) else None,
                add="+")
        menu.after(1, _bind_dismiss)

        def _menu_contains(rx, ry):
            try:
                mx = menu.winfo_rootx(); my = menu.winfo_rooty()
                mw = menu.winfo_width(); mh = menu.winfo_height()
                return mx <= rx <= mx + mw and my <= ry <= my + mh
            except Exception:
                return False

        menu.bind("<Escape>", _dismiss)
        menu.bind("<FocusOut>", lambda e: menu.after(50, lambda: _dismiss()
                                                     if not _menu_contains(
                                                         self.root.winfo_pointerx(),
                                                         self.root.winfo_pointery()) else None))

        current = self.profile_var.get()
        small   = self._font(["Segoe UI", "Arial"], self._sf(9))

        for name in names:
            active = (name == current)
            bg_row = self.ACCENT if active else self.PANEL
            fg_lbl = "white"     if active else self.TEXT

            row = tk.Frame(menu, bg=bg_row, cursor="hand2")
            row.pack(fill="x", padx=1, pady=1)
            lw  = tk.Label(row, text=f"  {name}", font=small,
                           fg=fg_lbl, bg=bg_row, anchor="w", padx=6, pady=5)
            lw.pack(fill="x")

            def _go(n=name, mn=menu):
                _selected[0] = True
                try:
                    self.root.unbind("<Button-1>", _dismiss_id[0])
                except Exception:
                    pass
                mn.destroy()
                self.profile_var.set(n)
                self._on_profile_select()

            for w in (row, lw):
                w.bind("<Button-1>", lambda e, fn=_go: fn())
                if not active:
                    w.bind("<Enter>", lambda e, r=row, l=lw:
                           [x.config(bg=self.BORDER) for x in (r, l)])
                    w.bind("<Leave>", lambda e, r=row, l=lw, bg=bg_row:
                           [x.config(bg=bg) for x in (r, l)])

        menu.update_idletasks()
        menu.geometry(f"{bw}x{menu.winfo_reqheight()}+{bx}+{by}")
        menu.focus_set()

    def _populate_from_profile(self, name: str):
        """Fill all sidebar connection fields from a saved profile."""
        p = self._profiles_data.get("profiles", {}).get(name, {})
        self.host_var.set(p.get("host", ""))
        self.port_var.set(p.get("port", "22"))
        self.user_var.set(p.get("user", ""))
        self.key_var.set(p.get("key_path", ""))
        self.autoconnect_var.set(bool(p.get("autoconnect", False)))
        self.pass_var.set(SecureCredStore.load(p, name))

    def _save_profile(self):
        """Save the current connection fields as a named profile."""
        name = self.profile_name_var.get().strip()
        if not name:
            messagebox.showwarning("Save Profile",
                                   "Enter a name for this profile.")
            return

        profiles = self._profiles_data.setdefault("profiles", {})

        # If this is the very first profile and no master key is set yet, offer encryption
        is_first_profile = len(profiles) == 0 or (len(profiles) == 1 and name in profiles)
        if HAS_CRYPTO and self._master_key is None and is_first_profile and not self._profiles_locked:
            if messagebox.askyesno(
                    "Master Password",
                    "Protect your profiles with a master password?\n\n"
                    "If you decline, profiles are saved without encryption "
                    "(individual SSH passwords remain protected by the OS credential store).",
                    icon="question"):
                self._set_master_password_dialog()

        # If the user renamed an existing profile, remove the old credential
        old_name = self.profile_var.get()
        if old_name and old_name != name and old_name in profiles:
            SecureCredStore.delete(profiles[old_name], old_name)
            del profiles[old_name]

        p = {
            "host":        self.host_var.get().strip(),
            "port":        self.port_var.get().strip() or "22",
            "user":        self.user_var.get().strip() or "gambit",
            "key_path":    self.key_var.get().strip(),
            "autoconnect": self.autoconnect_var.get(),
        }
        pwd_meta = SecureCredStore.store(name, self.pass_var.get())
        p.update(pwd_meta)

        profiles[name] = p
        self._profiles_data["last"] = name
        self._save_profiles_to_disk()

        self._refresh_profile_combo(select=name)
        backend = pwd_meta.get("_pwd_backend", "none")
        self._ui_log(f"Profile '{name}' saved  ·  credential store: {backend}",
                     "ok")

    def _delete_profile(self):
        """Delete the currently selected profile after confirmation."""
        name = self.profile_var.get()
        if not name:
            return
        profiles = self._profiles_data.get("profiles", {})
        if name not in profiles:
            return
        if not messagebox.askyesno(
                "Delete Profile",
                f"Delete profile '{name}'?\n\nThis cannot be undone.",
                icon="warning"):
            return
        SecureCredStore.delete(profiles[name], name)
        del profiles[name]
        remaining = list(profiles.keys())
        new_last   = remaining[0] if remaining else ""
        self._profiles_data["last"] = new_last
        self._save_profiles_to_disk()
        self._refresh_profile_combo(select=new_last)
        self.profile_name_var.set(new_last)
        self._ui_log(f"Profile '{name}' deleted", "warn")

    def _save_profiles_to_disk(self):
        """Write profiles to disk, encrypting if a master key is set."""
        inner = {
            "version":  self._profiles_data.get("version", 1),
            "profiles": self._profiles_data.get("profiles", {}),
            "last":     self._profiles_data.get("last", ""),
        }
        if self._master_key and self._master_salt and HAS_CRYPTO:
            outer = _profiles_encrypt(inner, self._master_key, self._master_salt)
        else:
            outer = {"encrypted": False, **inner}
        save_profiles(outer)

    def _update_lock_btn(self):
        if not hasattr(self, "_lock_btn"):
            return
        if not HAS_CRYPTO:
            self._lock_btn.config(text="🔒 (no cryptography pkg)", state="disabled")
        elif self._master_key:
            self._lock_btn.config(text="🔒 Change Password",
                                  fg=self.ACCENT, state="normal")
        else:
            self._lock_btn.config(text="🔓 Set Password",
                                  fg=self.TEXT_DIM, state="normal")

    def _on_lock_btn(self):
        if not HAS_CRYPTO:
            messagebox.showwarning("Master Password",
                "The 'cryptography' package is not installed.\n"
                "Run:  pip install cryptography")
            return
        self._set_master_password_dialog()

    def _ask_master_password(self, title: str = "Master Password",
                             prompt: str = "Enter master password:") -> str | None:
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.resizable(False, False)
        dlg.configure(bg=self.BG)
        dlg.grab_set()
        dlg.transient(self.root)

        result = [None]

        tk.Label(dlg, text=prompt, bg=self.BG, fg=self.TEXT,
                 font=self._font(["Segoe UI", "Arial"], self._sf(10)),
                 wraplength=300).pack(padx=20, pady=(20, 6))

        pw_var = tk.StringVar()
        pw_entry = tk.Entry(dlg, textvariable=pw_var, show="•",
                            bg="#090b10", fg=self.TEXT,
                            insertbackground=self.TEXT,
                            font=self._font(["Cascadia Code", "Consolas", "Courier New"], self._sf(11)),
                            relief="flat", bd=6, width=30)
        pw_entry.pack(padx=20, pady=(0, 16))
        pw_entry.focus_set()

        btn_row = tk.Frame(dlg, bg=self.BG)
        btn_row.pack(pady=(0, 16))

        def _ok(*_):
            result[0] = pw_var.get()
            dlg.destroy()

        def _cancel(*_):
            dlg.destroy()

        tk.Button(btn_row, text="Cancel", bg=self.BORDER, fg=self.TEXT_DIM,
                  bd=0, padx=12, pady=4, cursor="hand2",
                  command=_cancel).pack(side="left", padx=6)
        tk.Button(btn_row, text="Unlock", bg=self.ACCENT, fg="white",
                  bd=0, padx=12, pady=4, cursor="hand2",
                  command=_ok).pack(side="left", padx=6)

        pw_entry.bind("<Return>", _ok)
        dlg.bind("<Escape>", _cancel)

        # Centre over main window
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width()  - dlg.winfo_reqwidth())  // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dlg.winfo_reqheight()) // 2
        dlg.geometry(f"+{x}+{y}")

        self.root.wait_window(dlg)
        return result[0]

    def _prompt_unlock_profiles(self):
        if not HAS_CRYPTO:
            self._ui_log("Profiles file is encrypted but 'cryptography' package is missing — profiles unavailable", "warn")
            return

        raw = self._profiles_raw_enc
        if not raw:
            return

        pwd = self._ask_master_password(
            title="Unlock Profiles",
            prompt="Profiles are protected by a master password.\nEnter password to unlock:")
        if pwd is None:
            self._ui_log("Profiles locked — password not provided.", "warn")
            self._profiles_locked = True
            return

        # Derive key and attempt decryption (PBKDF2 — brief pause is intentional)
        try:
            salt  = base64.b64decode(raw["salt"])
            key   = _profiles_derive_key(pwd, salt)
            inner = _profiles_decrypt(raw, key)
        except Exception as exc:
            messagebox.showerror("Unlock Profiles", f"Decryption error: {exc}")
            return

        if inner is None:
            if messagebox.askyesno("Unlock Profiles",
                                   "Incorrect password.\nTry again?", icon="warning"):
                self.root.after(100, self._prompt_unlock_profiles)
            else:
                self._ui_log("Profiles locked — incorrect password.", "warn")
            return

        self._master_key      = key
        self._master_salt     = salt
        self._profiles_locked = False
        self._profiles_raw_enc = None
        self._profiles_data   = inner

        last = inner.get("last", "")
        self._refresh_profile_combo(select=last)
        if last:
            self.profile_name_var.set(last)
            self._populate_from_profile(last)
        self._update_lock_btn()
        self._ui_log("Profiles unlocked ✓", "ok")

    def _set_master_password_dialog(self):
        changing = self._master_key is not None
        dlg = tk.Toplevel(self.root)
        dlg.title("Change Master Password" if changing else "Set Master Password")
        dlg.resizable(False, False)
        dlg.configure(bg=self.BG)
        dlg.grab_set()
        dlg.transient(self.root)

        fnt     = self._font(["Segoe UI", "Arial"], self._sf(10))
        fnt_sm  = self._font(["Segoe UI", "Arial"], self._sf(9))
        fnt_mono= self._font(["Cascadia Code", "Consolas", "Courier New"], self._sf(11))

        header_text = ("Change or remove the master password that encrypts your profiles file."
                       if changing else
                       "Set a master password to encrypt your saved profiles.\n"
                       "⚠  If you forget this password, your profiles cannot be recovered.")
        tk.Label(dlg, text=header_text, bg=self.BG, fg=self.TEXT,
                 font=fnt_sm, wraplength=340, justify="left").pack(padx=20, pady=(18, 10))

        def _row(label_text):
            f = tk.Frame(dlg, bg=self.BG)
            f.pack(fill="x", padx=20, pady=2)
            tk.Label(f, text=label_text, bg=self.BG, fg=self.TEXT_DIM,
                     font=fnt_sm, width=12, anchor="w").pack(side="left")
            v = tk.StringVar()
            e = tk.Entry(f, textvariable=v, show="•", bg="#090b10", fg=self.TEXT,
                         insertbackground=self.TEXT, font=fnt_mono,
                         relief="flat", bd=4, width=24)
            e.pack(side="left")
            return v, e

        pw1_var, pw1_ent = _row("New password:")
        pw2_var, _       = _row("Confirm:")

        note = tk.Label(dlg, text="Leave both fields blank to remove master password protection.",
                        bg=self.BG, fg=self.TEXT_DIM, font=fnt_sm, wraplength=340)
        note.pack(padx=20, pady=(6, 4))

        status_lbl = tk.Label(dlg, text="", bg=self.BG, fg=self.WARNING, font=fnt_sm)
        status_lbl.pack(pady=2)

        btn_row = tk.Frame(dlg, bg=self.BG)
        btn_row.pack(pady=(4, 18))

        def _ok(*_):
            p1 = pw1_var.get()
            p2 = pw2_var.get()
            if p1 != p2:
                status_lbl.config(text="Passwords do not match.")
                return
            ok_btn.config(state="disabled", text="Working…")
            dlg.update()
            if p1 == "":
                # Remove encryption
                self._master_key  = None
                self._master_salt = None
            else:
                salt = os.urandom(16)
                key  = _profiles_derive_key(p1, salt)
                self._master_key  = key
                self._master_salt = salt
            self._save_profiles_to_disk()
            self._update_lock_btn()
            action = "removed" if p1 == "" else ("changed" if changing else "set")
            self._ui_log(f"Profiles master password {action}.", "ok")
            dlg.destroy()

        def _cancel(*_):
            dlg.destroy()

        tk.Button(btn_row, text="Cancel", bg=self.BORDER, fg=self.TEXT_DIM,
                  bd=0, padx=12, pady=4, cursor="hand2",
                  command=_cancel).pack(side="left", padx=6)
        ok_btn = tk.Button(btn_row,
                           text="Change Password" if changing else "Set Password",
                           bg=self.ACCENT, fg="white",
                           bd=0, padx=12, pady=4, cursor="hand2",
                           command=_ok)
        ok_btn.pack(side="left", padx=6)

        pw1_ent.focus_set()
        dlg.bind("<Escape>", _cancel)

        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width()  - dlg.winfo_reqwidth())  // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dlg.winfo_reqheight()) // 2
        dlg.geometry(f"+{x}+{y}")

        self.root.wait_window(dlg)

    def _build_sidebar(self, sidebar: tk.Frame, label, small, mono):
        pad = dict(padx=14, pady=3)

        # Section label helper
        def section(text):
            tk.Label(sidebar, text=text, font=small,
                     fg=self.ACCENT, bg=self.PANEL,
                     anchor="w").pack(fill="x", padx=14, pady=(14, 4))
            tk.Frame(sidebar, bg=self.BORDER, height=1).pack(
                fill="x", padx=14, pady=(0, 6))

        def lbl(text):
            tk.Label(sidebar, text=text, font=small,
                     fg=self.TEXT_DIM, bg=self.PANEL,
                     anchor="w").pack(fill="x", **pad)

        def entry(var, show=None):
            kw = dict(textvariable=var, font=mono,
                      bg="#090b10", fg=self.TEXT,
                      insertbackground=self.TEXT,
                      relief="flat", bd=4)
            if show:
                kw["show"] = show
            e = tk.Entry(sidebar, **kw)
            e.pack(fill="x", padx=14, pady=(0, 4))
            return e

        # ── profiles section ──────────────────────────────────────────────────
        section("PROFILES")

        # Custom flat profile selector (replaces ttk.Combobox for consistent theming)
        self.profile_var   = tk.StringVar()
        self._profile_names = []
        self._profile_btn  = tk.Button(
            sidebar, text="  — select profile —  ▾",
            font=small,
            bg="#090b10", fg=self.TEXT,
            activebackground=self.BORDER, activeforeground=self.TEXT,
            bd=0, relief="flat", cursor="hand2",
            anchor="w", padx=8, pady=4,
            command=self._show_profile_menu)
        self._profile_btn.pack(fill="x", padx=14, pady=(0, 4))

        def _sync_profile_btn(*_):
            name = self.profile_var.get()
            self._profile_btn.config(
                text=f"  {name}  ▾" if name else "  — select profile —  ▾")
        self.profile_var.trace_add("write", _sync_profile_btn)

        # Name entry + Save button on the same row
        _pn_row = tk.Frame(sidebar, bg=self.PANEL)
        _pn_row.pack(fill="x", padx=14, pady=(0, 4))
        self.profile_name_var = tk.StringVar()
        tk.Entry(_pn_row, textvariable=self.profile_name_var, font=mono,
                 bg="#090b10", fg=self.TEXT, insertbackground=self.TEXT,
                 relief="flat", bd=4).pack(side="left", fill="x", expand=True)
        tk.Button(_pn_row, text="Save", font=small,
                  bg=self.ACCENT, fg="white", bd=0, cursor="hand2",
                  activebackground="#6d28d9", activeforeground="white",
                  padx=8, pady=2,
                  command=self._save_profile).pack(side="right", padx=(4, 0))

        # Delete button (right-aligned, subtle)
        tk.Button(sidebar, text="Delete Profile", font=small,
                  bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
                  activebackground=self.ERROR, activeforeground="white",
                  padx=8, pady=2,
                  command=self._delete_profile).pack(
                      anchor="e", padx=14, pady=(0, 8))

        self._lock_btn = tk.Button(
            sidebar, text="🔓 Set Password", font=small,
            bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
            activebackground=self.ACCENT, activeforeground="white",
            padx=8, pady=2,
            command=self._on_lock_btn)
        self._lock_btn.pack(anchor="e", padx=14, pady=(0, 8))

        # ── connection fields ──────────────────────────────────────────────
        section("CONNECTION")

        lbl("Host / IP")
        self.host_var = tk.StringVar(value=self.cfg.get("host", ""))
        entry(self.host_var)

        lbl("SSH Port")
        self.port_var = tk.StringVar(value=self.cfg.get("port", "22"))
        entry(self.port_var)

        lbl("Username")
        self.user_var = tk.StringVar(value=self.cfg.get("user", "gambit"))
        entry(self.user_var)

        lbl("Password")
        self.pass_var = tk.StringVar(value=self.cfg.get("password", ""))
        entry(self.pass_var, show="●")

        lbl("SSH Key (optional)")
        key_row = tk.Frame(sidebar, bg=self.PANEL)
        key_row.pack(fill="x", padx=14, pady=(0, 4))
        self.key_var = tk.StringVar(value=self.cfg.get("key_path", ""))
        tk.Entry(key_row, textvariable=self.key_var, font=mono,
                 bg="#090b10", fg=self.TEXT,
                 insertbackground=self.TEXT,
                 relief="flat", bd=4).pack(side="left", fill="x", expand=True)
        tk.Button(key_row, text="…", font=small, bg=self.BORDER,
                  fg=self.TEXT_DIM, bd=0, cursor="hand2", padx=6,
                  command=self._browse_key).pack(side="right", padx=(4, 0))

        # Autoconnect toggle
        ac_row = tk.Frame(sidebar, bg=self.PANEL)
        ac_row.pack(fill="x", padx=14, pady=(4, 8))
        self.autoconnect_var = tk.BooleanVar(value=self.cfg.get("autoconnect", False))
        tk.Checkbutton(ac_row, text="Autoconnect on launch",
                       variable=self.autoconnect_var,
                       font=small, fg=self.TEXT_DIM, bg=self.PANEL,
                       selectcolor=self.BORDER, activebackground=self.PANEL,
                       bd=0).pack(side="left")

        # Connect / Disconnect buttons
        btn_row = tk.Frame(sidebar, bg=self.PANEL)
        btn_row.pack(fill="x", padx=14, pady=(0, 8))
        self.connect_btn = tk.Button(
            btn_row, text="Connect Nyx", font=small,
            bg=self.ACCENT, fg="white", bd=0, cursor="hand2",
            activebackground="#6d28d9", activeforeground="white",
            padx=10, pady=6, command=self._connect)
        self.connect_btn.pack(side="left", fill="x", expand=True)
        tk.Frame(btn_row, bg=self.PANEL, width=6).pack(side="left")
        self.shell_btn = tk.Button(
            btn_row, text="Shell", font=small,
            bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
            padx=10, pady=6, command=self._connect_shell)
        self.shell_btn.pack(side="left")

        self.disconnect_btn = tk.Button(
            sidebar, text="Disconnect", font=small,
            bg=self.BORDER, fg=self.TEXT_DIM, bd=0, cursor="hand2",
            padx=10, pady=6, state="disabled", command=self._disconnect)
        self.disconnect_btn.pack(fill="x", padx=14, pady=(0, 12))

    # ─────────────────────────────────────────────────────────────────────────
    #  Event poll loop  (main thread only)
    # ─────────────────────────────────────────────────────────────────────────
    def _poll(self):
        if self._closing:
            return

        now = time.time()
        gap = now - self._last_poll_time
        self._last_poll_time = now
        # A gap much larger than the 50 ms schedule means the system was
        # suspended.  5 s is conservative — normal jitter is < 500 ms.
        if gap > 5.0 and (self._ssh or self._ctrl or self._ssh_retry_cfg):
            self._on_wake_from_sleep()

        try:
            for _ in range(32):   # drain up to 32 messages per tick
                msg = self._eq.get_nowait()
                # First element is the session_id; discard stale events from
                # workers that belonged to a previous connection attempt.
                if msg[0] != self._session:
                    continue
                self._handle(msg[1:])
        except queue.Empty:
            pass

        # Coalesced graph redraw — at most once per 50 ms poll tick.
        _dash = getattr(self, "_dash", None)
        if _dash is not None and _dash._graph_dirty:
            _dash._redraw_graph()
            _dash._graph_dirty = False

        # Guard against rescheduling after root.destroy() has been queued
        # from the background join thread — winfo_exists() is False by then.
        try:
            if self.root.winfo_exists():
                self.root.after(50, self._poll)
        except Exception:
            pass

    def _handle(self, msg: tuple):
        kind = msg[0]

        if kind == "status":
            _, level, text = msg
            self._set_status(level, text)
            self._ui_log(text, "warn" if level in ("error","warn") else "info")

        elif kind == "screen":
            if self._ssh and self._ssh.screen_lock:
                with self._ssh.screen_lock:
                    self.term.render(self._ssh.screen)

        elif kind == "bw":
            _, r, w = msg
            self.dashboard.push_bw(r, w)

        elif kind == "identity":
            _, d = msg
            self.dashboard.push_identity(d)

        elif kind == "conns":
            _, conns = msg
            self.dashboard.push_connections(conns)

        elif kind == "circ":
            _, built, failed = msg
            self.dashboard.push_circs(built, failed)

        elif kind == "ctrl_up":
            if getattr(self, "_ctrl_reconnecting", False):
                self._ctrl_reconnecting = False
                self._ui_log("Tor control port reconnected ✓", "ok")
            else:
                self._ui_log("Tor control port connected", "ctrl")
            self._ctrl_down_rounds = 0
            self._ctrl_update_hint = False
            self._hide_overlay()
            self._restart_tor_btn.pack_forget()
            self._set_status("connected",
                             f"Connected · {self.cfg.get('host', '')}")

        elif kind == "ctrl_down":
            self._ui_log("Tor control port disconnected", "warn")
            self._ctrl = None
            self._ctrl_reconnecting = False
            # Cancel any already-pending retry before scheduling a new one
            if getattr(self, "_ctrl_retry_id", None):
                try:
                    self.root.after_cancel(self._ctrl_retry_id)
                except Exception:
                    pass
                self._ctrl_retry_id = None
            # If the SSH transport is still alive, Tor may have just restarted.
            # Attempt to reconnect the control channel automatically.
            if self._ssh and self._ssh.is_alive() and self._ssh.client:
                transport = self._ssh.client.get_transport()
                if transport and transport.is_active():
                    self._ctrl_down_rounds += 1
                    self._ui_log("Will attempt to reconnect control port…", "info")
                    # After 2 consecutive failed reconnect cycles while SSH stays
                    # alive, Tor is likely mid-restart due to system updates.
                    # Show a one-time explanatory message so the user isn't alarmed.
                    if self._ctrl_down_rounds >= 2 and not self._ctrl_update_hint:
                        self._ctrl_update_hint = True
                        self._ui_log(
                            "Tor is taking longer than expected to reconnect — "
                            "this often happens when the host is running system "
                            "updates (e.g. apt upgrade). Still retrying…", "warn")
                    self._set_status("warn",
                                     f"Control port down · {self.cfg.get('host', '')} — reconnecting…")
                    self._ctrl_retry_count = 0
                    self._ctrl_retry_id = self.root.after(3000, self._retry_ctrl)
                    self._restart_tor_btn.pack(side="right", padx=(0, 4), pady=3,
                                               before=self._log_toggle_btn)

        elif kind == "ssh_ready":
            mode = msg[1]
            if self._ssh_retry_id:
                try: self.root.after_cancel(self._ssh_retry_id)
                except Exception: pass
                self._ssh_retry_id = None
            self._ssh_retry_count = 0
            self._ui_log(f"SSH ready — mode: {mode}", "ok")
            self._maintenance_btn.pack(side="right", padx=(0, 4), pady=3,
                                       before=self._log_toggle_btn)
            if mode == "shell":
                # Shell mode: overlay done, switch to terminal view.
                self._set_status("connected",
                                  f"Connected · {self.cfg.get('host','')}")
                self._hide_overlay()
                if self._view_mode == "dashboard":
                    self._toggle_view()
            else:
                # Nyx mode: keep the overlay alive but show a progress screen
                # so the user knows we're waiting for the Tor control port.
                # The overlay is hidden when ctrl_up fires.
                self._set_status("connecting",
                                  f"SSH connected · {self.cfg.get('host','')} "
                                  f"— awaiting Tor control port…")
                self._show_ctrl_wait_overlay(self.cfg.get("host", ""))
                # Small delay lets nyx finish starting and Tor's control socket settle.
                if self._ssh:
                    _sid = self._session
                    self.root.after(2000,
                        lambda: self._start_ctrl() if self._session == _sid else None)

        elif kind == "ssh_down":
            self._ssh = None
            if self._ssh_retry_cfg:
                self._ssh_retry_count = 0
                self._ui_log("Connection lost — attempting to reconnect...", "warn")
                self._set_status("disconnected", "Reconnecting...")
                if self._ssh_retry_id:
                    try: self.root.after_cancel(self._ssh_retry_id)
                    except Exception: pass
                self._ssh_retry_id = self.root.after(3000, self._retry_ssh)
            else:
                self._on_disconnected()

        elif kind == "event":
            _, line = msg
            self.dashboard.push_event(line)

        elif kind == "signal_result":
            _, cmd, ok, reply = msg
            level = "ok" if ok else "warn"
            self._ui_log(f"Signal {cmd}: {'OK' if ok else 'FAILED'} {reply}", level)

    # ─────────────────────────────────────────────────────────────────────────
    #  Connection management
    # ─────────────────────────────────────────────────────────────────────────
    def _cfg_from_ui(self) -> dict | None:
        cfg = {
            "host":        self.host_var.get().strip(),
            "port":        self.port_var.get().strip() or "22",
            "user":        self.user_var.get().strip() or "gambit",
            "password":    self.pass_var.get(),
            "key_path":    self.key_var.get().strip(),
            "autoconnect": self.autoconnect_var.get(),
        }
        if not cfg["host"]:
            messagebox.showwarning("Tor NYX Monitor", "Enter a host / IP address.")
            return None
        save_config(cfg)
        self.cfg = cfg
        return cfg

    def _stop_workers(self):
        """Signal both workers to stop.  Does NOT join — returns immediately."""
        for w in (self._ctrl, self._ssh):
            if w:
                try:
                    w.stop()
                except Exception:
                    pass
        self._ssh  = None
        self._ctrl = None

    def _on_wake_from_sleep(self):
        """Called when the poll-gap detector identifies a system resume.

        SSH sockets are always dead after sleep.  Kill the stale workers,
        bump the session counter so their queued events are discarded, then
        schedule a fresh SSH reconnect after a short delay to let the NIC
        re-establish before we attempt to connect.
        """
        _log.info("Wake from sleep detected (poll gap > 5 s) — reconnecting")
        self._ui_log("System resumed from sleep — reconnecting…", "warn")
        self._set_status("connecting", "Resumed from sleep — reconnecting…")

        # Cancel any in-flight retry timers from the previous session.
        for attr in ("_ctrl_retry_id", "_ssh_retry_id"):
            aid = getattr(self, attr, None)
            if aid:
                try:
                    self.root.after_cancel(aid)
                except Exception:
                    pass
                setattr(self, attr, None)

        cfg  = self._ssh_retry_cfg   # preserve before _stop_workers clears it
        mode = self._ssh_retry_mode

        self._session += 1           # discard all queued events from dead workers
        self._stop_workers()

        if cfg:
            # Restore retry context so _retry_ssh knows what to connect to.
            self._ssh_retry_cfg   = cfg
            self._ssh_retry_mode  = mode
            self._ssh_retry_count = 0
            self._ctrl_retry_count = 0
            # Wait 4 s for the NIC to come back before attempting SSH.
            self._ssh_retry_id = self.root.after(4000, self._retry_ssh)
        else:
            self._on_disconnected()

    def _connect(self, mode: str = "nyx"):
        cfg = self._cfg_from_ui()
        if not cfg:
            return
        self._stop_workers()
        self.dashboard.reset()
        self.connect_btn.config(state="disabled")
        self.shell_btn.config(state="disabled")
        self.disconnect_btn.config(state="normal")
        self._show_overlay(f"Connecting to {cfg['host']}…")

        self._session += 1
        self._ctrl_retry_count  = 0
        self._ctrl_retry_id     = None
        self._ctrl_reconnecting = False
        self._ctrl_down_rounds  = 0
        self._ctrl_update_hint  = False
        self._ssh_retry_count   = 0
        self._ssh_retry_id      = None
        self._ssh_retry_cfg     = cfg
        self._ssh_retry_mode    = mode
        self._ssh = SSHWorker(cfg, self.TERM_COLS, self.TERM_ROWS,
                               self._eq, mode=mode,
                               session_id=self._session)
        self._ssh.start()
        _log.info("SSHWorker started for %s (mode=%s) session=%d",
                  cfg["host"], mode, self._session)

    def _connect_shell(self):
        self._connect(mode="shell")

    def _disconnect(self):
        self._ssh_retry_cfg  = None
        self._ssh_retry_mode = "nyx"
        if self._ssh_retry_id:
            try: self.root.after_cancel(self._ssh_retry_id)
            except Exception: pass
            self._ssh_retry_id = None
        self._stop_workers()
        self._on_disconnected()

    def _start_ctrl(self):
        """Start CtrlWorker on the existing SSH transport."""
        if not self._ssh or not self._ssh.client:
            return
        self._ctrl = CtrlWorker(self._ssh.client, self._eq,
                                session_id=self._session)
        self._ctrl.start()
        _log.info("CtrlWorker started session=%d", self._session)

    # Backoff delays (seconds) for successive control-port reconnect attempts:
    # 3s, 6s, 12s, 24s, 48s, 60s, 60s, 60s, 60s, 60s  (max 10 attempts ≈ 8 min)
    _CTRL_BACKOFF = [3, 6, 12, 24, 48, 60, 60, 60, 60, 60]

    def _retry_ctrl(self):
        """Attempt to reconnect the Tor control channel after a drop.

        Called via root.after() with exponential back-off.  Gives up after
        len(_CTRL_BACKOFF) attempts so we don't loop forever if Tor is gone.
        """
        # Abort if the session changed (user disconnected / reconnected)
        # or if ctrl already came back up (race)
        if not self._ssh or not self._ssh.is_alive():
            _log.info("_retry_ctrl: SSH gone — giving up")
            return
        if self._ctrl and self._ctrl.is_alive():
            _log.info("_retry_ctrl: ctrl already alive — skipping")
            return

        # Check SSH transport still active
        transport = self._ssh.client.get_transport() if self._ssh.client else None
        if not transport or not transport.is_active():
            _log.info("_retry_ctrl: SSH transport dead — giving up")
            self._ui_log("Control port: SSH transport lost, cannot reconnect", "warn")
            return

        attempt = getattr(self, "_ctrl_retry_count", 0)
        max_att = len(self._CTRL_BACKOFF)

        _log.info("_retry_ctrl: attempt %d/%d", attempt + 1, max_att)
        self._ui_log(
            f"Reconnecting control port… (attempt {attempt + 1}/{max_att})",
            "info")

        # Try to open a test channel to 9051 to see if Tor is back
        try:
            test_ch = transport.open_channel(
                "direct-tcpip", ("127.0.0.1", 9051), ("127.0.0.1", 0))
            test_ch.close()
            tor_up = True
        except Exception as e:
            _log.debug("_retry_ctrl: port 9051 not reachable yet: %s", e)
            tor_up = False

        if tor_up:
            # Tor is back — start a fresh CtrlWorker.
            # The "reconnected ✓" message is logged by the ctrl_up handler
            # once authentication actually succeeds, not here.
            self._ctrl_reconnecting = True
            self._start_ctrl()
            _log.info("_retry_ctrl: CtrlWorker restarted, awaiting auth")
            return

        # Not up yet — schedule next attempt if retries remain
        self._ctrl_retry_count = attempt + 1
        if self._ctrl_retry_count < max_att:
            delay_ms = self._CTRL_BACKOFF[self._ctrl_retry_count] * 1000
            _log.info("_retry_ctrl: Tor not ready, retrying in %ds", delay_ms // 1000)
            self._ctrl_retry_id = self.root.after(delay_ms, self._retry_ctrl)
        else:
            self._ui_log(
                f"Control port unreachable after {max_att} attempts — "
                "attempting automatic Tor restart…", "warn")
            _log.warning("_retry_ctrl: gave up after %d attempts — auto-restarting Tor",
                         max_att)
            self._restart_tor(auto=True)

    def _run_ssh_cmd(self, cmd: str, on_done=None):
        """Run a shell command over the current SSH session (non-blocking).

        Executes via paramiko exec_command on a daemon thread so the UI never
        blocks.  on_done(ok, stdout, stderr) is called on the main thread when
        the command finishes.  No-ops if SSH is not connected.
        """
        if not self._ssh or not self._ssh.client:
            self._ui_log("SSH not connected — cannot run remote command", "warn")
            return

        client = self._ssh.client

        def _worker():
            try:
                # Open a fresh exec channel — completely independent of the PTY.
                # get_pty=False (default) ensures output never touches the nyx channel.
                transport = client.get_transport()
                if transport is None or not transport.is_active():
                    raise OSError("SSH transport is no longer active")
                chan = transport.open_session()
                chan.exec_command(cmd)
                stdout = b""
                stderr_bytes = b""
                while not chan.exit_status_ready():
                    if chan.recv_ready():
                        stdout += chan.recv(4096)
                    if chan.recv_stderr_ready():
                        stderr_bytes += chan.recv_stderr(4096)
                # drain remaining
                while chan.recv_ready():
                    stdout += chan.recv(4096)
                while chan.recv_stderr_ready():
                    stderr_bytes += chan.recv_stderr(4096)
                rc = chan.recv_exit_status()
                chan.close()
                ok = (rc == 0)
                stdout = stdout.decode(errors="replace").strip()
                stderr = stderr_bytes.decode(errors="replace").strip()
            except Exception as e:
                stdout = ""
                stderr = str(e)
                ok     = False
            if on_done:
                self.root.after(0, lambda: on_done(ok, stdout, stderr))

        threading.Thread(target=_worker, daemon=True).start()

    def _restart_tor(self, auto: bool = False):
        """Run sudo systemctl restart tor over SSH, then re-arm ctrl reconnect.

        Called automatically when ctrl-port reconnect exhausts all retries, or
        manually via the 'Restart Tor' button in the status bar.

        Immediately cancels any pending _retry_ctrl loop so the backoff timer
        does not race with the systemctl restart.  Control-port probing only
        resumes once we have confirmed Tor is active via is-active, mirroring
        what the SSHWorker does at initial connect time.
        """
        if not self._ssh or not self._ssh.client:
            self._ui_log("Cannot restart Tor: SSH not connected", "warn")
            return

        # ── Stop the ctrl retry loop immediately ────────────────────────────
        # Any pending _retry_ctrl after() must be cancelled NOW, before the
        # async restart begins.  Otherwise the backoff timer keeps firing and
        # attempts auth against a Tor process that is mid-restart.
        if getattr(self, "_ctrl_retry_id", None):
            try:
                self.root.after_cancel(self._ctrl_retry_id)
            except Exception:
                pass
            self._ctrl_retry_id = None
        # Stop any CtrlWorker that may still be running
        if self._ctrl:
            try:
                self._ctrl.stop()
            except Exception:
                pass
            self._ctrl = None
        self._ctrl_retry_count = 0

        prefix = "Auto-restarting" if auto else "Restarting"
        self._ui_log(f"{prefix} Tor via systemctl…", "info")
        self._set_status("warn", "Restarting Tor…")

        def _done_enable(ok2, stdout2, stderr2):
            if ok2:
                self._ui_log("systemctl enable tor: OK", "ok")
            else:
                msg = stderr2 or stdout2 or "(no output)"
                self._ui_log(f"systemctl enable tor failed: {msg}", "warn")

        def _done_active(ok, stdout, stderr):
            """Called after is-active check — only start ctrl if Tor is up."""
            text = (stdout + " " + stderr).lower()
            if ok or "active" in text:
                self._ui_log("Tor is active — reconnecting control port…", "ok")
                self._set_status("warn",
                                 f"Control port down · {self.cfg.get('host','')} — reconnecting…")
                # Kick off the normal ctrl reconnect loop from a clean slate
                self._ctrl_retry_count = 0
                self._ctrl_retry_id = self.root.after(500, self._retry_ctrl)
            else:
                self._ui_log(
                    f"Tor did not become active after restart "
                    f"(is-active: {stdout or stderr or 'no output'}) — "
                    "check journalctl -u tor on the Pi.", "warn")
                self._set_status("error", "Tor failed to start after restart")

        def _done_restart(ok, stdout, stderr):
            if ok:
                self._ui_log("systemctl restart tor: OK — confirming Tor is active…", "ok")
                # Enable at boot in parallel (best-effort)
                self._run_ssh_cmd("sudo systemctl enable tor", on_done=_done_enable)
                # Wait 3 s for Tor to initialise, then verify is-active before
                # attempting any control-port connection — same check as startup.
                self.root.after(
                    3000,
                    lambda: self._run_ssh_cmd(
                        "systemctl is-active tor", on_done=_done_active))
            else:
                msg = stderr or stdout or "(no output)"
                self._ui_log(f"systemctl restart tor FAILED: {msg}", "warn")
                self._ui_log(
                    "Check that the Pi user has passwordless sudo for systemctl, "
                    "or restart Tor manually.", "warn")
                self._set_status("error", "Tor restart failed — check sudo permissions")

        self._run_ssh_cmd("sudo systemctl restart tor", on_done=_done_restart)

    def _run_maintenance(self):
        """Run apt update && apt upgrade on the remote host, streaming output to the debug log.

        Uses a daemon thread with exec_command so the UI never blocks.  Output
        is posted line-by-line via root.after() so the log scrolls in real time.
        The button is disabled for the duration to prevent double-invocation.
        """
        if not self._ssh or not self._ssh.client:
            self._ui_log("Cannot run update: SSH not connected", "warn")
            return

        client = self._ssh.client
        self._maintenance_btn.config(state="disabled", text="⬆ Updating…")
        self._ui_log("Starting system update (apt update && apt upgrade)…", "info")

        def _worker():
            try:
                transport = client.get_transport()
                if transport is None or not transport.is_active():
                    raise OSError("SSH transport is no longer active")
                chan = transport.open_session()
                chan.exec_command(
                    "DEBIAN_FRONTEND=noninteractive sudo apt-get update -y"
                    " && DEBIAN_FRONTEND=noninteractive sudo apt-get upgrade -y"
                    " 2>&1")
                buf = b""
                while True:
                    chunk = chan.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    # Flush complete lines as they arrive
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        text = line.decode(errors="replace").rstrip("\r")
                        if text:
                            self.root.after(0, self._ui_log, text, "info")
                # Flush any remaining partial line
                if buf:
                    text = buf.decode(errors="replace").rstrip("\r\n")
                    if text:
                        self.root.after(0, self._ui_log, text, "info")
                rc = chan.recv_exit_status()
                chan.close()
                ok = (rc == 0)
            except Exception as exc:
                ok = False
                self.root.after(0, self._ui_log,
                                f"System update error: {exc}", "warn")

            def _finish():
                if ok:
                    self._ui_log("System update completed successfully ✓", "ok")
                else:
                    self._ui_log("System update finished with errors — check output above",
                                 "warn")
                try:
                    self._maintenance_btn.config(state="normal", text="⬆ Update System")
                except Exception:
                    pass

            self.root.after(0, _finish)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_disconnected(self):
        self.dashboard.reset()
        self.dashboard.reset_layout()
        # Collapse the debug log pane back to its default hidden state
        if self._log_vis:
            self._log_vis = False
            self._log_frame.pack_forget()
            self._log_toggle_btn.config(bg=self.BORDER, fg=self.TEXT_DIM)
        self._log_height = self._s(160)
        self.connect_btn.config(state="normal")
        self.shell_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")
        self._set_status("disconnected", "Disconnected")
        self._ui_log("Disconnected", "warn")
        self._restart_tor_btn.pack_forget()
        self._maintenance_btn.pack_forget()
        if self._view_mode == "terminal":
            self._toggle_view()
        self._show_splash()

    _SSH_BACKOFF = [3, 6, 12, 24, 48, 60, 60, 60, 60, 60]

    def _retry_ssh(self):
        """Reconnect SSH after an unexpected drop (VPN switch, network blip).

        Called via root.after() with exponential back-off. Gives up after
        len(_SSH_BACKOFF) attempts then falls back to splash.
        Aborted immediately if the user manually disconnects.
        """
        cfg  = self._ssh_retry_cfg
        mode = self._ssh_retry_mode
        if not cfg:
            return
        if self._ssh and self._ssh.is_alive():
            _log.info("_retry_ssh: SSH already alive")
            return

        attempt = self._ssh_retry_count
        max_att = len(self._SSH_BACKOFF)
        _log.info("_retry_ssh: attempt %d/%d to %s",
                  attempt + 1, max_att, cfg.get("host", "?"))
        self._ui_log(
            f"Reconnect attempt {attempt + 1}/{max_att} to {cfg['host']}…",
            "info")
        self._set_status("disconnected",
                         f"Reconnecting… ({attempt + 1}/{max_att})")
        self._show_overlay(
            f"Reconnecting to {cfg['host']}  (attempt {attempt + 1} of {max_att})")

        self._stop_workers()
        self._session += 1
        self._ctrl_retry_count  = 0
        self._ctrl_retry_id     = None
        self._ctrl_reconnecting = False
        self._ssh = SSHWorker(cfg, self.TERM_COLS, self.TERM_ROWS,
                               self._eq, mode=mode,
                               session_id=self._session)
        self._ssh.start()
        _log.info("_retry_ssh: SSHWorker started session=%d", self._session)

        self._ssh_retry_count = attempt + 1
        if self._ssh_retry_count < max_att:
            delay_ms = self._SSH_BACKOFF[self._ssh_retry_count] * 1000
            self._ssh_retry_id = self.root.after(delay_ms, self._retry_ssh)
        else:
            _log.warning("_retry_ssh: gave up after %d attempts", max_att)
            self._ssh_retry_id  = None
            self._ssh_retry_cfg = None

    # ─────────────────────────────────────────────────────────────────────────
    #  Overlay / splash
    # ─────────────────────────────────────────────────────────────────────────
    def _show_overlay(self, text: str = "Connecting…"):
        self._hide_overlay()
        ov = tk.Frame(self._right, bg=self.BG)
        ov.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._overlay = ov

        # Spinner + message
        self._spin_chars = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        self._spin_idx   = 0

        ov.grid_rowconfigure(0, weight=1)
        ov.grid_rowconfigure(2, weight=1)
        ov.grid_columnconfigure(0, weight=1)
        ov.grid_columnconfigure(2, weight=1)
        col = tk.Frame(ov, bg=self.BG)
        col.grid(row=1, column=1)

        tk.Label(col, text="⬡", font=("Segoe UI", self._sf(40)),
                 fg=self.ACCENT, bg=self.BG).pack(pady=(0, 16))

        self._spin_lbl = tk.Label(col, text="⠋",
                                   font=self._font(["Segoe UI","Arial"], self._sf(18)),
                                   fg=self.ACCENT, bg=self.BG)
        self._spin_lbl.pack()

        self._overlay_lbl = tk.Label(col, text=text,
                                      font=self._font(["Segoe UI","Arial"], self._sf(11)),
                                      fg=self.TEXT_DIM, bg=self.BG,
                                      wraplength=380, justify="center")
        self._overlay_lbl.pack(pady=(10, 0))
        self._spin_tick()

    def _show_ctrl_wait_overlay(self, host: str):
        """Transition the overlay to a 'waiting for Tor control port' state.

        Called after SSH+nyx are ready but before CtrlWorker has connected.
        Shows confirmed steps (SSH ✓, nyx ✓) and a live elapsed timer so
        the user knows the 15-20 s wait is normal.
        """
        self._hide_overlay()

        ov = tk.Frame(self._right, bg=self.BG)
        ov.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._overlay = ov

        self._spin_chars = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        self._spin_idx   = 0

        ov.grid_rowconfigure(0, weight=1)
        ov.grid_rowconfigure(2, weight=1)
        ov.grid_columnconfigure(0, weight=1)
        ov.grid_columnconfigure(2, weight=1)
        col = tk.Frame(ov, bg=self.BG)
        col.grid(row=1, column=1)

        tk.Label(col, text="⬡", font=("Segoe UI", self._sf(40)),
                 fg=self.ACCENT, bg=self.BG).pack(pady=(0, 10))
        tk.Label(col, text="ESTABLISHING CONNECTION",
                 font=self._font(["Segoe UI","Arial"], self._sf(11), bold=True),
                 fg=self.TEXT, bg=self.BG).pack()
        tk.Label(col, text=host,
                 font=self._font(["Cascadia Code","Consolas","Courier New"], self._sf(9)),
                 fg=self.TEXT_DIM, bg=self.BG).pack(pady=(2, 14))

        # Step indicator rows
        steps = tk.Frame(col, bg=self.BG)
        steps.pack(fill="x", pady=(0, 14))

        def _step(icon, text, color):
            row = tk.Frame(steps, bg=self.BG)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=icon,
                     font=self._font(["Segoe UI","Arial"], self._sf(10)),
                     fg=color, bg=self.BG, width=3, anchor="center").pack(side="left")
            tk.Label(row, text=text,
                     font=self._font(["Segoe UI","Arial"], self._sf(9)),
                     fg=color, bg=self.BG, anchor="w").pack(side="left")

        _step("✓", "SSH tunnel established", self.SUCCESS)
        _step("✓", "Nyx monitor launched",   self.SUCCESS)

        # Animated spinner row for ctrl port
        spin_row = tk.Frame(steps, bg=self.BG)
        spin_row.pack(fill="x", pady=2)
        self._spin_lbl = tk.Label(spin_row, text="⠋",
                                   font=self._font(["Segoe UI","Arial"], self._sf(10)),
                                   fg=self.ACCENT, bg=self.BG, width=3, anchor="center")
        self._spin_lbl.pack(side="left")
        tk.Label(spin_row, text="Connecting to Tor control port…",
                 font=self._font(["Segoe UI","Arial"], self._sf(9)),
                 fg=self.TEXT_DIM, bg=self.BG, anchor="w").pack(side="left")

        tk.Label(col,
                 text="This may take up to 30 s while nyx initializes",
                 font=self._font(["Segoe UI","Arial"], self._sf(8)),
                 fg=self.TEXT_DIM, bg=self.BG).pack(pady=(0, 8))

        self._ctrl_wait_t0  = time.time()
        self._ctrl_wait_lbl = tk.Label(
            col, text="elapsed  0:00",
            font=self._font(["Cascadia Code","Consolas","Courier New"], self._sf(8)),
            fg=self.TEXT_DIM, bg=self.BG)
        self._ctrl_wait_lbl.pack()

        self._spin_tick()
        self._ctrl_wait_tick()

    def _ctrl_wait_tick(self):
        """Update the elapsed-time label on the ctrl-wait overlay every second."""
        lbl = getattr(self, "_ctrl_wait_lbl", None)
        if not self._overlay or not lbl:
            return
        try:
            if not lbl.winfo_exists():
                return
        except Exception:
            return
        elapsed = int(time.time() - self._ctrl_wait_t0)
        m, s    = divmod(elapsed, 60)
        lbl.config(text=f"elapsed  {m}:{s:02d}")
        self.root.after(1000, self._ctrl_wait_tick)

    def _spin_tick(self):
        if not self._overlay or not self._spin_lbl or not self._spin_lbl.winfo_exists():
            return
        self._spin_lbl.config(text=self._spin_chars[
            self._spin_idx % len(self._spin_chars)])
        self._spin_idx += 1
        self._spin_id = self.root.after(100, self._spin_tick)

    def _update_overlay(self, text: str):
        if self._overlay_lbl:
            try:
                self._overlay_lbl.config(text=text)
            except Exception:
                pass

    def _hide_overlay(self):
        if self._spin_id:
            try:
                self.root.after_cancel(self._spin_id)
            except Exception:
                pass
            self._spin_id = None
        if self._overlay:
            try:
                self._overlay.destroy()
            except Exception:
                pass
            self._overlay      = None
            self._overlay_lbl  = None
            self._spin_lbl     = None
            self._ctrl_wait_lbl = None
            # Splash item refs are children of overlay — clear so _sel()
            # never calls .config() on already-destroyed widgets.
            self._splash_items = []

    def _show_splash(self):
        """Idle splash — keyboard-navigable connect picker."""
        self._hide_overlay()

        ov = tk.Frame(self._right, bg=self.BG)
        ov.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._overlay = ov

        small   = self._font(["Segoe UI","Arial"], self._sf(9))
        ui_btn  = self._font(["Segoe UI","Arial"], self._sf(11))
        ui_desc = self._font(["Segoe UI","Arial"], self._sf(8))
        ui_sub  = self._font(["Segoe UI","Arial"], self._sf(9))
        ui_ttl  = self._font(["Segoe UI","Arial"], self._sf(15), bold=True)

        ov.grid_rowconfigure(0, weight=1)
        ov.grid_rowconfigure(2, weight=1)
        ov.grid_columnconfigure(0, weight=1)
        ov.grid_columnconfigure(2, weight=1)

        col = tk.Frame(ov, bg=self.BG)
        col.grid(row=1, column=1)

        tk.Label(col, text="⬡", font=("Segoe UI", self._sf(40)),
                 fg=self.ACCENT, bg=self.BG).pack(pady=(0, 4))
        tk.Label(col, text="TOR NYX MONITOR",
                 font=ui_ttl, fg=self.TEXT, bg=self.BG).pack(pady=(2, 0))

        _rw = self._s(300)
        rule = tk.Canvas(col, height=3, width=_rw,
                          bg=self.BG, highlightthickness=0)
        rule.pack(pady=(10, 20))
        rule.create_line(0,           1, _rw,          1, fill=self.BORDER, width=1)
        rule.create_line(_rw*80//300, 1, _rw*220//300, 1, fill=self.ACCENT, width=2)
        rule.create_line(_rw*130//300,1, _rw*170//300, 1, fill="#c4b5fd",   width=2)

        options = [
            ("⬡  Connect Nyx",
             "Launch nyx monitor  ·  live dashboard  ·  Tor control port",
             self._connect),
            ("⌨  SSH Shell",
             "Open raw SSH terminal  ·  full shell access",
             self._connect_shell),
        ]

        self._splash_sel   = 0
        self._splash_items = []
        item_box = tk.Frame(col, bg=self.BG)
        item_box.pack(pady=(0, 4))

        def _sel(idx):
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

        def _run(idx=None):
            if idx is None:
                idx = self._splash_sel
            fn = options[idx][2]
            self._hide_overlay()
            fn()

        for i, (lt, dt, _fn) in enumerate(options):
            fr  = tk.Frame(item_box, bg=self.BORDER, cursor="hand2")
            fr.pack(fill="x", pady=4)
            inn = tk.Frame(fr, bg=self.BORDER)
            inn.pack(fill="x", padx=18, pady=10)
            lbl  = tk.Label(inn, text=lt, font=ui_btn,
                             fg=self.TEXT, bg=self.BORDER, anchor="w")
            lbl.pack(fill="x")
            desc = tk.Label(inn, text=dt, font=ui_desc,
                             fg=self.TEXT_DIM, bg=self.BORDER, anchor="w")
            desc.pack(fill="x")
            self._splash_items.append((fr, inn, lbl, desc))
            for w in (fr, inn, lbl, desc):
                w.bind("<Button-1>", lambda e, ii=i: _run(ii))
                w.bind("<Enter>",    lambda e, ii=i: _sel(ii))

        _sel(0)

        tk.Label(col, text="↑ ↓  navigate  ·  Enter  execute",
                 font=ui_sub, fg=self.TEXT_DIM, bg=self.BG).pack(pady=(14, 0))

        # Keyboard navigation via a hidden entry widget
        nav = tk.Entry(ov, width=0, bd=0, highlightthickness=0,
                       bg=self.BG, fg=self.BG, insertbackground=self.BG)
        nav.place(x=0, y=0, width=1, height=1)
        nav.focus_set()

        def _nav_key(e):
            if e.keysym == "Up":
                _sel((self._splash_sel - 1) % len(options))
            elif e.keysym == "Down":
                _sel((self._splash_sel + 1) % len(options))
            elif e.keysym in ("Return", "KP_Enter"):
                _run()
        nav.bind("<KeyPress>", _nav_key)
        ov.bind("<Button-1>", lambda e: nav.focus_set())


    # ─────────────────────────────────────────────────────────────────────────
    #  View toggle
    # ─────────────────────────────────────────────────────────────────────────
    def _toggle_view(self):
        if self._view_mode == "dashboard":
            self.dashboard.pack_forget()
            self.term.pack(fill="both", expand=True)
            self.term.focus_set()
            self._view_mode = "terminal"
            self._view_btn.config(text="⬢  Terminal",
                                   bg=self.ACCENT, fg="white",
                                   activebackground="#6d28d9")
            self._view_lbl.config(text="nyx  —  terminal")
            # Show terminal-only buttons (graph btn is always visible)
            for btn in self._nyx_btns:
                btn.pack(side="right", padx=(0, 4), pady=6)
        else:
            self.term.pack_forget()
            self.dashboard.pack(fill="both", expand=True)
            self._view_mode = "dashboard"
            self._view_btn.config(text="⬡  Dashboard",
                                   bg=self.ACCENT, fg="white",
                                   activebackground="#6d28d9")
            self._view_lbl.config(text="Tor Bridge  —  live dashboard")
            # Hide terminal-only buttons (graph btn stays visible)
            for btn in self._nyx_btns:
                btn.pack_forget()

    def _toggle_sidebar(self):
        if self._sidebar_vis:
            self._sidebar.pack_forget()
            self._hide_btn.config(text="▶  Show Panel")
        else:
            self._sidebar.pack(side="left", fill="y", before=self._right)
            self._hide_btn.config(text="◀  Hide Panel")
        self._sidebar_vis = not self._sidebar_vis

    # ─────────────────────────────────────────────────────────────────────────
    #  Dashboard graph mode picker
    # ─────────────────────────────────────────────────────────────────────────
    def _show_graph_menu(self):
        """Drop-down to switch the dashboard sparkline between graph modes."""
        menu = tk.Toplevel(self.root)
        menu.overrideredirect(True)
        menu.configure(bg=self.BORDER)
        menu.attributes("-topmost", True)

        btn = self._graph_btn
        bx  = btn.winfo_rootx()
        by  = btn.winfo_rooty() + btn.winfo_height() + 2
        menu.geometry(f"+{bx}+{by}")

        # Track whether a selection was made so dismiss doesn't double-fire
        _selected = [False]

        def _dismiss(e=None):
            if _selected[0]:
                return
            try:
                menu.destroy()
            except Exception:
                pass
            try:
                self.root.unbind("<Button-1>", _dismiss_id[0])
            except Exception:
                pass

        # Dismiss when clicking anywhere outside the menu
        # Use after(1) so this bind doesn't immediately fire on the button click
        _dismiss_id = [None]
        def _bind_dismiss():
            _dismiss_id[0] = self.root.bind("<Button-1>",
                lambda e: _dismiss() if not _menu_contains(e.x_root, e.y_root) else None,
                add="+")
        menu.after(1, _bind_dismiss)

        def _menu_contains(rx, ry):
            try:
                mx = menu.winfo_rootx()
                my = menu.winfo_rooty()
                mw = menu.winfo_width()
                mh = menu.winfo_height()
                return mx <= rx <= mx + mw and my <= ry <= my + mh
            except Exception:
                return False

        # Also dismiss on Escape
        menu.bind("<Escape>", _dismiss)
        menu.bind("<FocusOut>", lambda e: menu.after(50, lambda: _dismiss()
                                                     if not _menu_contains(
                                                         self.root.winfo_pointerx(),
                                                         self.root.winfo_pointery()) else None))

        small     = self._font(["Segoe UI","Arial"], self._sf(9))
        small_dim = self._font(["Segoe UI","Arial"], self._sf(8))

        for label, subtitle in self._GRAPH_MODES:
            mode_name = label.split("  ", 1)[-1]   # "Bandwidth" / "Connections" / "Resources"
            active    = (mode_name == self._graph_mode)
            bg_row    = self.ACCENT if active else self.PANEL
            fg_lbl    = "white"     if active else self.TEXT
            fg_sub    = "#c4b5fd"   if active else self.TEXT_DIM

            row = tk.Frame(menu, bg=bg_row, cursor="hand2")
            row.pack(fill="x", padx=1, pady=1)
            inn = tk.Frame(row, bg=bg_row)
            inn.pack(fill="x", padx=14, pady=5)
            lw  = tk.Label(inn, text=label,    font=small,
                            fg=fg_lbl, bg=bg_row, anchor="w")
            lw.pack(fill="x")
            sw  = tk.Label(inn, text=subtitle, font=small_dim,
                            fg=fg_sub, bg=bg_row, anchor="w")
            sw.pack(fill="x")

            def _go(m=mode_name, mn=menu):
                _selected[0] = True
                try:
                    self.root.unbind("<Button-1>", _dismiss_id[0])
                except Exception:
                    pass
                mn.destroy()
                self._set_graph_mode(m)

            for w in (row, inn, lw, sw):
                w.bind("<Button-1>", lambda e, fn=_go: fn())
                if not active:
                    w.bind("<Enter>", lambda e, r=row, i2=inn, l=lw, s=sw:
                        [x.config(bg=self.BORDER) for x in (r, i2, l, s)])
                    w.bind("<Leave>", lambda e, r=row, i2=inn, l=lw, s=sw,
                                             bg=bg_row:
                        [x.config(bg=bg) for x in (r, i2, l, s)])

        menu.update_idletasks()
        menu.focus_set()

    def _set_graph_mode(self, mode: str):
        """Switch the dashboard sparkline to the given mode."""
        self._graph_mode = mode
        self.dashboard.set_graph_mode(mode)
        _log.info("Graph mode set to: %s", mode)

    # ─────────────────────────────────────────────────────────────────────────
    #  Actions menu
    # ─────────────────────────────────────────────────────────────────────────
    def _show_actions_menu(self):
        if not self._ctrl or not self._ctrl.is_alive():
            self._ui_log("Actions: not connected to control port", "warn")
            return
        menu = tk.Toplevel(self.root)
        menu.overrideredirect(True)
        menu.configure(bg=self.BORDER)
        menu.attributes("-topmost", True)

        btn = self._actions_btn
        menu.geometry(f"+{btn.winfo_rootx()}+{btn.winfo_rooty()+btn.winfo_height()+2}")

        _selected = [False]

        def _dismiss(e=None):
            if _selected[0]:
                return
            try:
                self._actions_btn.focus_set()
                menu.after(0, menu.destroy)
            except Exception:
                pass
        menu.bind("<FocusOut>", _dismiss)

        small = self._font(["Segoe UI","Arial"], self._sf(9))
        mono  = self._font(["Cascadia Code","Consolas","Courier New"], self._sf(9))

        for label, cmd, confirm in self._NYX_ACTIONS:
            if cmd is None:
                tk.Frame(menu, bg=self.TEXT_DIM, height=1).pack(
                    fill="x", padx=8, pady=4)
                continue

            row = tk.Frame(menu, bg=self.PANEL, cursor="hand2")
            row.pack(fill="x", padx=1, pady=1)
            inner = tk.Frame(row, bg=self.PANEL)
            inner.pack(fill="x", padx=14, pady=6)
            lw = tk.Label(inner, text=label, font=small,
                           fg=self.TEXT, bg=self.PANEL, anchor="w")
            lw.pack(fill="x")
            cw = tk.Label(inner, text=cmd, font=mono,
                           fg=self.TEXT_DIM, bg=self.PANEL, anchor="w")
            cw.pack(fill="x")

            def _run(c=cmd, conf=confirm, m=menu):
                _selected[0] = True
                try:
                    m.destroy()
                except Exception:
                    pass
                if conf:
                    if not messagebox.askyesno("Confirm", conf):
                        return
                if self._ctrl:
                    self._ctrl.send_signal(c)

            for w in (row, inner, lw, cw):
                w.bind("<Button-1>", lambda e, fn=_run: fn())
                w.bind("<Enter>", lambda e, r=row, i=inner, l=lw, c=cw:
                    [x.config(bg=self.BORDER) for x in (r, i, l, c)])
                w.bind("<Leave>", lambda e, r=row, i=inner, l=lw, c=cw:
                    [x.config(bg=self.PANEL) for x in (r, i, l, c)])

        menu.update_idletasks()
        menu.focus_set()

    # ─────────────────────────────────────────────────────────────────────────
    #  Terminal input
    # ─────────────────────────────────────────────────────────────────────────
    def _send_key(self, data: bytes):
        if self._ssh:
            self._ssh.send(data)

    def _on_term_event(self, event):
        if event[0] == "key":
            self._send_key(event[1])
        elif event[0] == "resize":
            _, cols, rows = event
            if self._ssh:
                self._ssh.resize(cols, rows)

    # ─────────────────────────────────────────────────────────────────────────
    #  Status bar
    # ─────────────────────────────────────────────────────────────────────────
    def _set_status(self, kind: str, msg: str):
        colors = {
            "connecting":   self.WARNING,
            "connected":    self.SUCCESS,
            "disconnected": self.TEXT_DIM,
            "error":        self.ERROR,
            "warn":         self.WARNING,
        }
        c = colors.get(kind, self.TEXT_DIM)
        if self._overlay_lbl:
            self._update_overlay(msg)
        self._status_dot.config(fg=c)
        self._status_lbl.config(fg=c, text=msg)
        self.statusbar.config(text=msg)

    # ─────────────────────────────────────────────────────────────────────────
    #  Debug log
    # ─────────────────────────────────────────────────────────────────────────
    def _ui_log(self, msg: str, level: str = "info"):
        """Write to on-screen debug log and file log."""
        _lvl_map = {"ok":"info","info":"info","warn":"warning","error":"error",
                    "ctrl":"info","conn":"info"}
        _log.log(getattr(logging, _lvl_map.get(level,"info").upper(), logging.INFO),
                 "UI  %s", msg)
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        w  = self._log_text
        w.configure(state="normal")
        w.insert("end", ts,          "ts")
        w.insert("end", "  " + msg + "\n", level)
        n_lines = int(w.index("end-1c").split(".")[0])
        if n_lines > self._LOG_MAX:
            w.delete("1.0", f"{n_lines - self._LOG_MAX}.0")
        w.configure(state="disabled")
        w.see("end")

    def _log_clear(self):
        self._log_text.configure(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.configure(state="disabled")

    def _log_copy(self):
        text = self._log_text.get("1.0", "end").strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)

    def _log_open(self):
        try:
            if os.path.exists(LOG_FILE):
                os.startfile(LOG_FILE)
            else:
                messagebox.showinfo("Log file",
                    f"No log file yet.\nIt will appear at:\n{LOG_FILE}")
        except Exception as e:
            messagebox.showerror("Open log file", str(e))

    def _toggle_log(self):
        self._log_vis = not self._log_vis
        if self._log_vis:
            self._log_frame.configure(height=self._log_height)
            # Pack inside _right, below _view_container — pushes dashboard up
            self._log_frame.pack(side="bottom", fill="x",
                                  before=self._view_container)
            self._log_toggle_btn.config(bg=self.ACCENT, fg="white")
        else:
            self._log_frame.pack_forget()
            self._log_toggle_btn.config(bg=self.BORDER, fg=self.TEXT_DIM)

    def _dashboard_bottom_drag_start(self, event):
        """Bottom handle of the dashboard — shows the log if hidden, then drags."""
        if not self._log_vis:
            self._log_vis = True
            self._log_frame.configure(height=max(60, self._log_height))
            self._log_frame.pack(side="bottom", fill="x",
                                  before=self._view_container)
            self._log_toggle_btn.config(bg=self.ACCENT, fg="white")
        self._log_drag_start(event)

    def _log_drag_start(self, event):
        self._log_drag_y = event.y_root
        self._log_drag_h = self._log_frame.winfo_height()

    def _log_drag_move(self, event):
        if self._log_drag_y is None:
            return
        delta   = self._log_drag_y - event.y_root
        # Keep at least 200 px of vertical space for the dashboard above
        avail   = self._right.winfo_height()
        max_log = max(60, avail - 200) if avail > 0 else 600
        new_h   = max(60, min(max_log, self._log_drag_h + delta))
        self._log_height = new_h
        self._log_frame.configure(height=new_h)

    def _log_drag_end(self, event):
        self._log_drag_y = None
        self._log_drag_h = None

    # ─────────────────────────────────────────────────────────────────────────
    #  Sidebar helpers
    # ─────────────────────────────────────────────────────────────────────────
    def _browse_key(self):
        path = filedialog.askopenfilename(
            title="Select SSH Private Key",
            filetypes=[("All files", "*.*"), ("PEM files", "*.pem"),
                       ("OpenSSH key", "id_*")])
        if path:
            self.key_var.set(path)

    # ─────────────────────────────────────────────────────────────────────────
    #  Shutdown
    # ─────────────────────────────────────────────────────────────────────────
    def on_close(self):
        self._closing = True
        self._hide_overlay()

        # Cancel all pending after() callbacks before destroying workers
        for attr in ("_ctrl_retry_id", "_ssh_retry_id"):
            aid = getattr(self, attr, None)
            if aid:
                try:
                    self.root.after_cancel(aid)
                except Exception:
                    pass
                setattr(self, attr, None)

        if self.term._resize_id:
            try:
                self.term.after_cancel(self.term._resize_id)
            except Exception:
                pass

        # Signal workers and join briefly on a background thread
        workers = []
        for w in (self._ctrl, self._ssh):
            if w:
                w.stop()
                workers.append(w)
        self._ctrl = self._ssh = None

        def _join_and_destroy():
            for w in workers:
                try:
                    w.join(timeout=2.0)
                except Exception:
                    pass
            self.root.after(0, self.root.destroy)

        if workers:
            threading.Thread(target=_join_and_destroy, daemon=True).start()
        else:
            self.root.destroy()

        _log.info("Tor NYX Monitor closed")


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    root = tk.Tk()
    try:
        root.update()
        if _ctypes:
            hwnd = _ctypes.windll.user32.GetParent(root.winfo_id())
            for attr in (20, 19):   # 20 = Win10 1903+/Win11, 19 = older Win10
                _ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr,
                    _ctypes.byref(_ctypes.c_int(1)),
                    _ctypes.sizeof(_ctypes.c_int))
    except Exception:
        pass

    app = TorMonitorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
