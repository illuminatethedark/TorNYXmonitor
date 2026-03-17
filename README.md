# Tor NYX Monitor  v0.2.4

A desktop application for monitoring a remote Tor relay over SSH.
Runs on **Windows, Linux, and macOS**.
Connects to a Raspberry Pi (or any Linux host) running Tor, launches **nyx**
inside a PTY, streams the terminal to a canvas widget, and exposes a live
dashboard fed by the Tor control port.

---

## Features

- **Live dashboard** — bandwidth sparkline (read/write EMA), relay identity
  (nickname, address, fingerprint, OR port, Tor version, uptime, flags, BW rate),
  OR-connection list, circuit counters, event log
- **Live uptime counter** — dashboard uptime ticks every second, synced to the
  Tor control port `GETINFO uptime` value; no extra polling after the initial read
- **Three graph modes** — Bandwidth, Connections, Resources (circuits); all modes
  refresh at ~1 Hz clocked by BW events; Resources shows per-event deltas (not
  cumulative totals) so activity is always visible
- **Connections sort control** — cycle through Direction (inbound first), Status,
  Name (alphabetical), or Default (Tor order) via the `↕` button in the
  connections header
- **Connection profiles** — save multiple named SSH connection profiles; switch
  between them via a dropdown; credentials stored in the OS credential store
  (Windows DPAPI, macOS Keychain, Linux SecretService / keyring)
- **Master password protection** — optionally encrypt the entire profiles file
  with AES-256-GCM, key derived via PBKDF2-HMAC-SHA256 (480,000 iterations);
  requires the `cryptography` package; wrong password offers retry on startup
- **Resolution-aware UI scaling** — reads screen resolution on launch and scales
  all fonts, widgets, and layout proportionally (baseline 1920×1080 = 1.0×;
  clamped to 0.65×–1.8×)
- **Connection loading screen** — while waiting for the Tor control port to
  authenticate after SSH is ready, a full overlay shows SSH ✓, nyx ✓, and a
  live spinner + elapsed timer so users know the app is working
- **System-update detection** — after two consecutive failed Tor control-port
  reconnect cycles (while SSH stays alive), a one-time hint is shown explaining
  that host system updates (e.g. `apt upgrade`) commonly cause this pattern
- **Tor control port** — cookie-authenticated, subscribes to BW / CIRC /
  ORCONN / STREAM / ADDRMAP events
- **Auto-reconnect** — exponential back-off for both SSH and control-port drops;
  automatic `systemctl restart tor` when the control port is unreachable
- **Sleep/wake recovery** — detects system suspend via poll-gap monitoring and
  automatically reconnects SSH after resume (4 s NIC settle delay)
- **Layout reset on disconnect** — panel sizes (identity section, debug log)
  return to their defaults on each disconnect so every new connection starts fresh
- **Resizable panels** — drag the handle between Relay Identity and Events to
  resize vertically; drag the handle between the dashboard and debug log to
  reveal/resize the log pane
- **SSH shell mode** — raw PTY shell as an alternative to nyx
- **TOFU host-key policy** — trust-on-first-use, stored in `~/.tor_bridge_monitor_known_hosts`
- **Debug log panel** — draggable, with Copy / Clear / Open-log-file actions
- Dark theme (TokyoNight palette)

---

## Requirements

### Host machine (Windows, Linux, or macOS)

- Python 3.9+
- **Required:**
  ```
  pip install paramiko pyte
  ```
- **Optional — for master password profile encryption:**
  ```
  pip install cryptography
  ```
  Without this package the app runs normally; the `🔓 Set Password` button will
  show a disabled hint to install it.

- **Linux only:** tkinter is not always bundled with Python — install via your
  package manager if needed:
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

---

## Building

### Windows
```bat
windows\windows_build.bat
```
Produces `Tor NYX Monitor.exe` (~17 MB) placed directly on the Desktop.

**No Python required** — if Python is not found in PATH, the build script
automatically downloads the Python 3.12 full installer, uses it to run
PyInstaller, then removes it. No system-wide PATH changes, no admin rights needed.

To fully uninstall (exe, config files, saved passwords):
```bat
windows\windows_cleanup.bat
```
Deletes the Desktop exe, config files from `%USERPROFILE%`, and all saved
passwords from Windows Credential Manager.

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
       --hidden-import cryptography.hazmat.primitives.kdf.pbkdf2 \
       --hidden-import cryptography.hazmat.primitives.ciphers.aead \
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

### Linux — Desktop installer (launchable icon)

Run the installer once from the app folder:
```bash
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

To fully uninstall (shortcuts, venv, data files, and app folder):
```bash
./linux/unix_uninstall.sh
```
The uninstaller removes desktop shortcuts, the applications menu entry, the local
Python venv, user config/data files, and the app folder itself. System packages
(`python3`, `python3-tk`) are left in place as they may be shared.

---

## Running

### Windows (shell launch directly in python)
```bat
python tor_bridge_monitor.py
```

### Linux / macOS (manual installation+run)

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
   # Optional: pip install cryptography
   ```

3. Run:
   ```bash
   python3 tor_bridge_monitor.py
   ```
   Or use the launcher script directly:
   ```bash
   ./linux/launch.sh
   ```

---

## Cross-platform notes

The app runs on Windows, Linux, and macOS. All core functionality is
platform-neutral. The only OS-specific code is:

- A Windows DWM call (`DwmSetWindowAttribute`) that enables a dark native title
  bar — tries attributes 20 (Windows 11 / 10 1903+) and 19 (older Windows 10)
  for maximum compatibility; silently skipped on Linux/macOS.
- Credential storage uses Windows DPAPI on Windows, the system keyring on Linux/macOS
  (via the `keyring` package if installed), falling back to plaintext with a warning.

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| Core monitoring & SSH | ✓ | ✓ | ✓ |
| Tor control port dashboard | ✓ | ✓ | ✓ |
| Master password (AES-256-GCM) | ✓ | ✓ | ✓ |
| OS credential store | DPAPI | SecretService / keyring | Keychain |
| Dark title bar | ✓ | — | — |
| `.exe` build → Desktop via `windows/windows_build.bat` | ✓ | — | — |
| Cleanup / uninstall | `windows/windows_cleanup.bat` | `linux/unix_uninstall.sh` | — |

---

## Config & data files

| File | Purpose |
|------|---------|
| `~/.tor_bridge_monitor.json` | Last-used SSH connection (auto-saved) |
| `~/.tor_bridge_monitor_profiles.json` | Named connection profiles (plaintext or AES-256-GCM encrypted) |
| `~/.tor_bridge_monitor_known_hosts` | TOFU SSH host keys |
| `~/.tor_bridge_monitor.log` | Rotating log (2 MB × 3 backups) |

---

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

---

## Changelog

### v0.2.4
- **Graph render fix** — graphs were not repainting during active sessions; root
  cause was `_poll()` using `self._dash` (never assigned) instead of
  `self.dashboard` to trigger bandwidth redraws — the dirty-flag redraw path was
  completely dead. Fixed attribute reference.
- **Canvas dimension caching** — graph canvas now caches its size from
  `<Configure>` events (`event.width` / `event.height`) rather than calling
  `winfo_width()` at draw time, which returns 1 before the widget is fully
  realized and is unreliable on slow hardware (e.g. Raspberry Pi Zero 2W)
- **Live uptime counter** — dashboard uptime label now ticks every second using
  a `time.monotonic()` anchor set when the control port delivers `GETINFO uptime`;
  no additional control-port polling required
- **Uptime ticker resilience** — fixed a bug where the uptime ticker loop
  terminated permanently after the first disconnect; ticker now runs continuously
  and shows `—` while disconnected
- **Windows Python bootstrap** — `windows_build.bat` now auto-downloads the
  Python 3.12 full installer (not embeddable zip) when Python is absent from
  PATH; uses `/passive` flag so install failures are detected; bootstrapped
  Python is removed after the build completes
- **Windows cleanup script** — new `windows/windows_cleanup.bat` removes all app
  data: config/profile/log files from `%USERPROFILE%`, the Desktop shortcut, and
  all saved passwords from Windows Credential Manager (`TorNYXMonitor/*` entries)
- **Linux uninstaller** — new `linux/unix_uninstall.sh` fully removes the
  application: desktop shortcuts, applications menu entry, Python venv, user
  config/data files, and the app folder itself
- **Linux desktop icon** — `unix_install_desktop.sh` now references `icon.png`
  (256×256, included in the repo) instead of `icon.ico`; `.ico` files are not
  supported by LXDE/GNOME desktop environments

### v0.2.3
- **Custom profile selector** — replaced `ttk.Combobox` (OS-native popup that
  couldn't be themed) with a fully styled flat dropdown matching the app's dark
  palette; hover highlights, Escape-to-close, and outside-click dismiss
- **Graph hang fix** — bandwidth redraws coalesced to one per 50 ms poll tick
  via a dirty flag; eliminates UI stutter when BW events arrive faster than the
  canvas can flush
- **Instant view switching** — switching graph mode to Connections or Resources
  immediately populates from buffered data (cached connection list / circuit
  counts) rather than waiting for the next incoming event
- **System update module** — new "⬆ Update System" button in the status bar;
  runs `apt-get update && apt-get upgrade` on the remote host over SSH with
  streaming line-by-line output to the debug log; button visible only while SSH
  is connected, disabled during the run, restored on completion
- **Control-port wait timer** — label updated from "20 s" to "30 s" to match
  observed real-world nyx startup times
- **Bug fixes** — `save_config` and `load_profiles` silent failures now logged;
  `CtrlWorker._send()` guards against sending on a `None` socket; `_poll()`
  startup race fixed (`_dash` attribute guarded with `getattr` to handle early
  scheduler ticks before full init)

### v0.2.2
- **Master password protection** — optional AES-256-GCM encryption for the
  profiles file; key derived via PBKDF2-HMAC-SHA256 (480,000 iterations);
  prompted on first profile save; unlock dialog on startup if encrypted;
  `🔓 Set Password` / `🔒 Change Password` button in the Profiles sidebar;
  requires `pip install cryptography`
- **Connection profiles** — save, load, rename, and delete named SSH profiles;
  OS credential store integration (DPAPI / keyring / plaintext fallback) for
  SSH passwords within profiles
- **Connections sort control** — `↕` button in connections header cycles through
  Direction, Status, Name, and Default sort orders; applies instantly from cache
- **Resolution-aware UI scaling** — all sizes, fonts, and layout scale
  proportionally to the detected screen resolution (1920×1080 baseline)
- **Control-port loading overlay** — full-screen progress screen shown while
  waiting for Tor control port authentication after SSH connects; shows live
  spinner and elapsed timer
- **System-update detection** — after two consecutive failed reconnect cycles
  (Tor restarting with SSH still alive), a one-time explanatory message is shown
- **Graph fixes** — Resources graph now stores per-event circuit deltas (was
  cumulative totals that flatlined the chart); all three graph modes redraw at
  ~1 Hz via BW events (Connections and Resources no longer appear frozen)
- **Events section resize** — drag handle at top and bottom of the Events panel
  for vertical resizing
- **Layout reset on disconnect** — panel sizes reset to defaults on each
  disconnect so each new connection starts with a clean layout

### v0.2.1
- **Relay identity uptime** — dashboard now shows formatted uptime (`Xd Xh Xm`)
  sourced from `GETINFO uptime`
- **Dark native title bar** — fixed DWM call to use `GetParent()` for the correct
  HWND; now tries attributes 20 and 19 for broad Windows 10/11 compatibility
- **Sleep/wake recovery** — poll-gap detector triggers automatic reconnect on
  system resume; no manual disconnect/reconnect needed
- Bug fix: `_show_actions_menu` closure no longer references `_selected` /
  `_dismiss_id` from the wrong scope; double-destroy race on menu click resolved

### v0.2 (initial release)
- Full rewrite — two-worker, single-queue architecture
- Live dashboard with graph mode switcher
- Auto-restart Tor on control-port exhaustion
- Exponential back-off for both SSH and control-port reconnect
- TOFU host-key policy
- Atomic config saves (`os.replace`)
- `from __future__ import annotations` for Python 3.9 compatibility
