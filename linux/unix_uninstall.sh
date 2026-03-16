#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Tor NYX Monitor — uninstaller (Linux)
#
#  Removes desktop shortcuts, the local Python venv, user config/data files,
#  and the app folder itself.
#  Does NOT remove system packages (python3, python3-tk, etc.) as they may
#  be shared with other applications.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="$(dirname "$SCRIPT_DIR")"
APP_DIR="$HOME/.local/share/applications"
DESKTOP_DIR="$HOME/Desktop"
DEST_NAME="tor_bridge_monitor.desktop"
VENV_DIR="$SCRIPT_DIR/venv"

# ─────────────────────────────────────────────────────────────────────────────
#  GUI helpers (match installer style)
# ─────────────────────────────────────────────────────────────────────────────
_info() {
    if command -v zenity &>/dev/null; then
        zenity --info --title="Tor NYX Monitor Uninstall" --text="$1" \
               --width=380 2>/dev/null || true
    else
        echo "[i] $1"
    fi
}

_confirm() {
    if command -v zenity &>/dev/null; then
        zenity --question --title="Tor NYX Monitor Uninstall" --text="$1" \
               --width=420 2>/dev/null
    else
        read -r -p "[?] $1 [y/N] " _ans
        [[ "$_ans" =~ ^[Yy]$ ]]
    fi
}

echo ""
echo "================================================"
echo "  Tor NYX Monitor — Uninstall"
echo "================================================"
echo ""

_confirm "This will completely remove Tor NYX Monitor:\n\n  • Desktop shortcuts\n  • Applications menu entry\n  • Local Python virtual environment\n  • User config and data files\n  • App folder: $APP_ROOT\n\nSystem packages (python3, python3-tk) will NOT be removed.\n\nThis cannot be undone. Continue?" \
    || { echo "  Uninstall cancelled."; exit 0; }

# ─────────────────────────────────────────────────────────────────────────────
#  Step 1 — Remove applications menu entry
# ─────────────────────────────────────────────────────────────────────────────
if [[ -f "$APP_DIR/$DEST_NAME" ]]; then
    rm -f "$APP_DIR/$DEST_NAME"
    if command -v update-desktop-database &>/dev/null; then
        update-desktop-database "$APP_DIR" 2>/dev/null || true
    fi
    echo "  [✓] Removed applications menu entry"
else
    echo "  [i] Applications menu entry not found — skipping"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  Step 2 — Remove Desktop shortcut
# ─────────────────────────────────────────────────────────────────────────────
if [[ -f "$DESKTOP_DIR/$DEST_NAME" ]]; then
    rm -f "$DESKTOP_DIR/$DEST_NAME"
    echo "  [✓] Removed Desktop shortcut"
else
    echo "  [i] Desktop shortcut not found — skipping"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  Step 3 — Remove local .desktop file (written by installer into linux/)
# ─────────────────────────────────────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/$DEST_NAME" ]]; then
    rm -f "$SCRIPT_DIR/$DEST_NAME"
    echo "  [✓] Removed local $DEST_NAME"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  Step 4 — Remove Python virtual environment
# ─────────────────────────────────────────────────────────────────────────────
if [[ -d "$VENV_DIR" ]]; then
    rm -rf "$VENV_DIR"
    echo "  [✓] Removed Python virtual environment"
else
    echo "  [i] No virtual environment found — skipping"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  Step 5 — Remove user config and data files
# ─────────────────────────────────────────────────────────────────────────────
_removed_cfg=0
for f in \
    "$HOME/.tor_bridge_monitor.json" \
    "$HOME/.tor_bridge_monitor_profiles.json" \
    "$HOME/.tor_bridge_monitor_known_hosts" \
    "$HOME/.tor_bridge_monitor.log"
do
    if [[ -f "$f" ]]; then
        rm -f "$f"
        echo "  [✓] Removed $(basename "$f")"
        _removed_cfg=1
    fi
done
[[ $_removed_cfg -eq 0 ]] && echo "  [i] No user config files found — skipping"

# ─────────────────────────────────────────────────────────────────────────────
#  Done — show dialog before deleting the app folder
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================"
echo "  Uninstall complete."
echo "================================================"
echo ""

_info "Tor NYX Monitor has been fully uninstalled."

# ─────────────────────────────────────────────────────────────────────────────
#  Step 6 — Delete the app folder (must be last — script runs from inside it)
# ─────────────────────────────────────────────────────────────────────────────
APP_ROOT_TO_DELETE="$APP_ROOT"
rm -rf "$APP_ROOT_TO_DELETE"
