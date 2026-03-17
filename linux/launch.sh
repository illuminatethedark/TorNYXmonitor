#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Tor NYX Monitor — Linux / macOS launcher
#  Resolves its own directory so the shortcut works wherever it is placed.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="$(dirname "$SCRIPT_DIR")"
APP="$APP_ROOT/tor_bridge_monitor.py"
VENV_DIR="$SCRIPT_DIR/venv"

# ── Dependency check ──────────────────────────────────────────────────────────
_missing_deps=()

# Check python3
if [[ -x "$VENV_DIR/bin/python3" ]]; then
    PYTHON="$VENV_DIR/bin/python3"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
else
    _missing_deps+=("python3")
fi

# Check paramiko and pyte (only if python3 was found)
if [[ ${#_missing_deps[@]} -eq 0 ]]; then
    if ! "$PYTHON" -c "import paramiko, pyte" 2>/dev/null; then
        _missing_deps+=("paramiko / pyte  (run: pip install paramiko pyte)")
    fi
fi

if [[ ${#_missing_deps[@]} -gt 0 ]]; then
    MSG="Tor NYX Monitor cannot start.\n\nMissing dependencies:\n"
    for dep in "${_missing_deps[@]}"; do
        MSG+="  • $dep\n"
    done
    MSG+="\nRun linux/unix_install_desktop.sh to install everything automatically."

    if command -v zenity &>/dev/null; then
        zenity --error --title="Tor NYX Monitor" --text="$MSG" 2>/dev/null
    elif command -v notify-send &>/dev/null; then
        notify-send "Tor NYX Monitor" "$MSG"
    else
        echo -e "ERROR: $MSG" >&2
    fi
    exit 1
fi

exec "$PYTHON" "$APP"
