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

### Windows
```bat
python tor_bridge_monitor.py
```

### Linux / macOS
1. Install system dependencies (if not already present):
   ```bash
   # Debian / Ubuntu
   sudo apt update
   sudo apt install python3 python3-pip python3-tk

   # Fedora
   sudo dnf install python3 python3-pip python3-tkinter

   # Arch
   sudo pacman -S python python-pip tk
   ```

2. Install Python dependencies:
   ```bash
   pip install paramiko pyte
   ```

3. Run:
   ```bash
   python3 tor_bridge_monitor.py
   ```
   Or use the launcher script directly:
   ```bash
   chmod +x linux/launch.sh
   ./linux/launch.sh
   ```

### Linux — Desktop shortcut (launchable icon)

Run the installer once from the app folder:
```bash
chmod +x linux/unix_install_desktop.sh
./linux/unix_install_desktop.sh
```

The installer handles everything in one step:

1. **System packages** — detects your package manager (`apt` / `dnf` / `pacman`),
   shows a confirmation dialog listing what will be installed, then prompts for
   your password via a GUI window (`pkexec` / `zenity`) to install
   `python3`, `python3-tk`, and `python3-venv` if any are missing
2. **Python dependencies** — creates a local `venv/` in the app folder and
   installs `paramiko` and `pyte` into it (no sudo required)
3. **Desktop shortcut** — writes `tor_bridge_monitor.desktop` with absolute
   paths, registers it in `~/.local/share/applications/` (applications menu),
   and places a trusted, clickable icon on `~/Desktop` if the folder exists

A completion dialog confirms when setup is done.

To uninstall the shortcut:
```bash
rm ~/.local/share/applications/tor_bridge_monitor.desktop
rm ~/Desktop/tor_bridge_monitor.desktop   # if created
```

## Building

### Windows
```bat
windows\windows_build.bat
```
Produces `dist\Tor NYX Monitor v0.2.1.exe` (~17 MB, single file).

### Linux (PyInstaller)

1. Install PyInstaller and all dependencies:
   ```bash
   pip install paramiko pyte pyinstaller PyNaCl cryptography
   ```

2. Build a single-file binary:
   ```bash
   pyinstaller --onefile \
       --name "Tor NYX Monitor" \
       --hidden-import paramiko \
       --hidden-import paramiko.transport \
       --hidden-import paramiko.auth_handler \
       --hidden-import paramiko.channel \
       --hidden-import paramiko.client \
       --hidden-import paramiko.pkey \
       --hidden-import paramiko.rsakey \
       --hidden-import paramiko.ecdsakey \
       --hidden-import paramiko.ed25519key \
       --hidden-import paramiko.sftp \
       --hidden-import paramiko.sftp_client \
       --hidden-import paramiko.packet \
       --hidden-import paramiko.compress \
       --hidden-import paramiko.kex_ecdh_nist \
       --hidden-import paramiko.kex_curve25519 \
       --hidden-import paramiko.kex_group14 \
       --hidden-import paramiko.kex_gex \
       --hidden-import pyte \
       --hidden-import pyte.modes \
       --hidden-import pyte.screens \
       --hidden-import pyte.streams \
       --hidden-import pyte.graphics \
       --hidden-import cryptography \
       --hidden-import cryptography.hazmat.primitives \
       --hidden-import cryptography.hazmat.backends \
       --hidden-import nacl \
       --hidden-import nacl.signing \
       --clean --noconfirm \
       tor_bridge_monitor.py
   ```

3. The binary is written to `dist/Tor NYX Monitor`.
   Make it executable and run it:
   ```bash
   chmod +x "dist/Tor NYX Monitor"
   "./dist/Tor NYX Monitor"
   ```

> **Note:** Some distributions require `python3-tk` to be installed system-wide
> even when using a virtualenv — it cannot be installed via pip.

## Cross-platform notes

The app runs on Windows, Linux, and macOS. All core functionality is platform-neutral. The only OS-specific code is a Windows DWM call (`DwmSetWindowAttribute`) that enables a dark native title bar — it uses `GetParent()` to obtain the correct top-level HWND and tries both attribute 20 (Windows 10 1903+/Windows 11) and attribute 19 (older Windows 10 builds) for maximum compatibility. This call is silently skipped on Linux and macOS.

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| Core monitoring & SSH | ✓ | ✓ | ✓ |
| Tor control port dashboard | ✓ | ✓ | ✓ |
| Dark title bar | ✓ | — | — |
| `.exe` build via `windows/windows_build.bat` | ✓ | — | — |

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
