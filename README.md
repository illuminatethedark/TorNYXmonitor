# Tor NYX Monitor

An elegant Windows desktop application for monitoring a remote Tor relay over SSH.
Connects to a Raspberry Pi (or any Linux host) running Tor, launches **nyx**
inside a PTY, streams the terminal to a canvas widget, and exposes a live
dashboard fed by the Tor control port.

## Features

- **Live dashboard** — bandwidth sparkline (read/write EMA), relay identity,
  OR-connection list, circuit counters, event log
- **Three graph modes** — Bandwidth, Connections, Resources (circuits)
- **Tor control port** — cookie-authenticated, subscribes to BW / CIRC /
  ORCONN / STREAM / ADDRMAP events
- **Auto-reconnect** — exponential back-off for both SSH and control-port drops;
  automatic `systemctl restart tor` when the control port is unreachable
- **SSH shell mode** — raw PTY shell as an alternative to nyx
- **TOFU host-key policy** — trust-on-first-use, stored in `~/.tor_bridge_monitor_known_hosts`
- **Debug log panel** — draggable, with Copy / Clear / Open-log-file actions
- Dark theme (TokyoNight palette)

## Requirements

### Windows host
- Python 3.9+
- `pip install paramiko pyte`

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
Produces `dist\Tor NYX Monitor.exe` (~17 MB, single file).

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

### v2 (current)
- Full rewrite — two-worker, single-queue architecture
- Live dashboard with graph mode switcher
- Auto-restart Tor on control-port exhaustion
- Exponential back-off for both SSH and control-port reconnect
- TOFU host-key policy
- Atomic config saves (`os.replace`)
- `from __future__ import annotations` for Python 3.9 compatibility
