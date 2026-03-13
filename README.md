# Tor NYX Monitor  v0.2.1

A desktop application for monitoring a remote Tor relay over SSH.
Runs on **Windows, Linux, and macOS**.
Connects to a Raspberry Pi (or any Linux host) running Tor, launches **nyx**
inside a PTY, streams the terminal to a canvas widget, and exposes a live
dashboard fed by the Tor control port.

## Features

- **Live dashboard** — bandwidth sparkline (read/write EMA), relay identity
  (nickname, address, fingerprint, OR port, Tor version, uptime, flags, BW rate),
  OR-connection list, circuit counters, event log
- **Three graph modes** — Bandwidth, Connections, Resources (circuits)
- **Tor control port** — cookie-authenticated, subscribes to BW / CIRC /
  ORCONN / STREAM / ADDRMAP events
- **Auto-reconnect** — exponential back-off for both SSH and control-port drops;
  automatic `systemctl restart tor` when the control port is unreachable
- **Sleep/wake recovery** — detects system suspend via poll-gap monitoring and
  automatically reconnects SSH after resume (4 s NIC settle delay)
- **SSH shell mode** — raw PTY shell as an alternative to nyx
- **TOFU host-key policy** — trust-on-first-use, stored in `~/.tor_bridge_monitor_known_hosts`
- **Debug log panel** — draggable, with Copy / Clear / Open-log-file actions
- Dark theme (TokyoNight palette)

## Requirements

### Host machine (Windows, Linux, or macOS)
- Python 3.9+
- `pip install paramiko pyte`
- **Linux only:** tkinter is not always bundled with Python — install it via your package manager if needed:
  ```
  sudo apt install python3-tk      # Debian/Ubuntu
  sudo dnf install python3-tkinter # Fedora
  brew install python-tk           # macOS (Homebrew)
  ```

### Raspberry Pi (or remote host)
```
# /etc/tor/torrc
ControlPort 9051
CookieAuthentication 1
```
The SSH user needs passwordless sudo for:
```
sudo systemctl restart tor
sudo systemctl enable tor
sudo systemctl is-active tor
sudo cat /var/run/tor/control.authcookie   # for cookie auth
```

## Running

```
python tor_bridge_monitor_v2.py
```

## Building (Windows, PyInstaller)

```
build_v2.bat
```
Produces `dist\Tor NYX Monitor v0.2.1.exe` (~17 MB, single file).

> **Linux/macOS:** `build_v2.bat` is Windows-only. You can build a native binary with PyInstaller directly:
> ```
> pip install pyinstaller
> pyinstaller --onefile tor_bridge_monitor_v2.py
> ```

## Cross-platform notes

The app runs on Windows, Linux, and macOS. All core functionality is platform-neutral. The only OS-specific code is a Windows DWM call (`DwmSetWindowAttribute`) that enables a dark native title bar — it uses `GetParent()` to obtain the correct top-level HWND and tries both attribute 20 (Windows 10 1903+/Windows 11) and attribute 19 (older Windows 10 builds) for maximum compatibility. This call is silently skipped on Linux and macOS.

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| Core monitoring & SSH | ✓ | ✓ | ✓ |
| Tor control port dashboard | ✓ | ✓ | ✓ |
| Dark title bar | ✓ | — | — |
| `.exe` build via `build_v2.bat` | ✓ | — | — |

## Config & logs

| File | Purpose |
|------|---------|
| `~/.tor_bridge_monitor.json` | SSH credentials (password stripped when key file is set) |
| `~/.tor_bridge_monitor_known_hosts` | TOFU SSH host keys |
| `~/.tor_bridge_monitor.log` | Rotating log (2 MB × 3 backups) |

## Architecture

Two daemon threads post events onto a single `queue.Queue(maxsize=512)`.
The main tkinter thread drains the queue every 50 ms via `root.after()`.
A session-ID counter on every event discards stale messages from previous
connections.

```
SSHWorker  ──┐
             ├──→  queue.Queue  ──→  _poll()  ──→  _handle()  ──→  UI
CtrlWorker ──┘
```

## Changelog

### v2.1 (current)
- **Relay identity uptime** — dashboard now shows formatted uptime (`Xd Xh Xm`)
  sourced from `GETINFO uptime`
- **Dark native title bar** — fixed DWM call to use `GetParent()` for the correct
  HWND; now tries attributes 20 and 19 for broad Windows 10/11 compatibility
- **Sleep/wake recovery** — poll-gap detector triggers automatic reconnect on
  system resume; no manual disconnect/reconnect needed
- Bug fix: `_show_actions_menu` closure no longer references `_selected` /
  `_dismiss_id` from the wrong scope; double-destroy race on menu click resolved

### v2 (initial release)
- Full rewrite — two-worker, single-queue architecture
- Live dashboard with graph mode switcher
- Auto-restart Tor on control-port exhaustion
- Exponential back-off for both SSH and control-port reconnect
- TOFU host-key policy
- Atomic config saves (`os.replace`)
- `from __future__ import annotations` for Python 3.9 compatibility
