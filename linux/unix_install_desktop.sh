#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Tor NYX Monitor — desktop installer (Linux)
#
#  Run once after cloning or extracting the app folder.
#  Installs system packages (GUI sudo prompt), creates a local Python venv,
#  installs Python dependencies into it, then registers the desktop shortcut.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="$(dirname "$SCRIPT_DIR")"
APP_DIR="$HOME/.local/share/applications"
DESKTOP_DIR="$HOME/Desktop"
DEST_NAME="tor_bridge_monitor.desktop"
VENV_DIR="$SCRIPT_DIR/venv"

# ─────────────────────────────────────────────────────────────────────────────
#  GUI helpers
# ─────────────────────────────────────────────────────────────────────────────

_info() {
    # Show a non-blocking info notification
    if command -v zenity &>/dev/null; then
        zenity --info --title="Tor NYX Monitor Setup" --text="$1" \
               --width=380 2>/dev/null || true
    else
        echo "[i] $1"
    fi
}

_error() {
    if command -v zenity &>/dev/null; then
        zenity --error --title="Tor NYX Monitor Setup" --text="$1" \
               --width=420 2>/dev/null || true
    else
        echo "[!] $1" >&2
    fi
    exit 1
}

_progress() {
    # Run a command while showing a zenity progress spinner.
    # Usage: _progress "Label text" command [args...]
    local label="$1"; shift
    if command -v zenity &>/dev/null; then
        ("$@" 2>&1) | zenity --progress \
            --title="Tor NYX Monitor Setup" \
            --text="$label" \
            --pulsate --auto-close --auto-kill \
            --width=420 2>/dev/null || "$@"
    else
        echo "  --> $label"
        "$@"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  GUI sudo — tries pkexec, then zenity+sudo, then plain sudo
# ─────────────────────────────────────────────────────────────────────────────
_gui_sudo() {
    # Runs the given command string with elevated privileges via a GUI prompt.
    local cmd="$1"

    # Method 1: pkexec (PolicyKit — GNOME / KDE native dialog)
    if command -v pkexec &>/dev/null; then
        if pkexec bash -c "$cmd" 2>/dev/null; then
            return 0
        fi
    fi

    # Method 2: zenity password prompt → sudo -S
    if command -v zenity &>/dev/null; then
        local pass
        pass=$(zenity --password \
                      --title="Tor NYX Monitor Setup — Administrator Password" \
                      2>/dev/null) || true
        if [[ -n "$pass" ]]; then
            echo "$pass" | sudo -S bash -c "$cmd"
            return $?
        fi
        _error "Password not entered. Cannot install system dependencies.\n\nRun manually:\n  sudo bash -c \"$cmd\""
    fi

    # Method 3: plain sudo (terminal fallback)
    echo "  [i] No GUI sudo helper found — falling back to terminal sudo"
    sudo bash -c "$cmd"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Detect package manager
# ─────────────────────────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
elif command -v pacman &>/dev/null; then
    PKG_MANAGER="pacman"
else
    PKG_MANAGER="unknown"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  Step 1 — System packages
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================"
echo "  Tor NYX Monitor — Setup"
echo "================================================"
echo ""

_NEED_SYS=()

# Check python3
command -v python3 &>/dev/null || _NEED_SYS+=("python3")

# Check python3-tk (try importing tkinter)
python3 -c "import tkinter" 2>/dev/null || _NEED_SYS+=("tk")

# Check python3-venv
python3 -m venv --help &>/dev/null || _NEED_SYS+=("venv")

if [[ ${#_NEED_SYS[@]} -gt 0 ]]; then
    echo "  [i] Missing system packages: ${_NEED_SYS[*]}"

    case "$PKG_MANAGER" in
        apt)
            # Map generic names to apt package names
            APT_PKGS=""
            for p in "${_NEED_SYS[@]}"; do
                case "$p" in
                    python3) APT_PKGS+=" python3 python3-pip" ;;
                    tk)      APT_PKGS+=" python3-tk" ;;
                    venv)    APT_PKGS+=" python3-venv" ;;
                esac
            done
            if command -v zenity &>/dev/null; then
                zenity --question \
                    --title="Tor NYX Monitor Setup" \
                    --text="The following system packages need to be installed:\n<b>$APT_PKGS</b>\n\nYour password will be requested to continue." \
                    --width=420 2>/dev/null \
                    || _error "Installation cancelled by user."
            fi
            _gui_sudo "apt-get update -qq && apt-get install -y $APT_PKGS"
            ;;
        dnf)
            DNF_PKGS=""
            for p in "${_NEED_SYS[@]}"; do
                case "$p" in
                    python3) DNF_PKGS+=" python3 python3-pip" ;;
                    tk)      DNF_PKGS+=" python3-tkinter" ;;
                    venv)    DNF_PKGS+=" python3" ;;   # venv included in python3 on Fedora
                esac
            done
            if command -v zenity &>/dev/null; then
                zenity --question \
                    --title="Tor NYX Monitor Setup" \
                    --text="The following system packages need to be installed:\n<b>$DNF_PKGS</b>\n\nYour password will be requested to continue." \
                    --width=420 2>/dev/null \
                    || _error "Installation cancelled by user."
            fi
            _gui_sudo "dnf install -y $DNF_PKGS"
            ;;
        pacman)
            if command -v zenity &>/dev/null; then
                zenity --question \
                    --title="Tor NYX Monitor Setup" \
                    --text="The following system packages need to be installed:\n<b>python tk</b>\n\nYour password will be requested to continue." \
                    --width=420 2>/dev/null \
                    || _error "Installation cancelled by user."
            fi
            _gui_sudo "pacman -Sy --noconfirm python tk"
            ;;
        *)
            _error "Could not detect a supported package manager (apt / dnf / pacman).\n\nInstall Python 3, python3-tk, and python3-venv manually, then re-run this script."
            ;;
    esac
    echo "  [✓] System packages installed"
else
    echo "  [✓] System packages already present"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  Step 2 — Python virtualenv + pip dependencies
# ─────────────────────────────────────────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    echo "  [i] Creating Python virtual environment…"
    _progress "Creating Python virtual environment…" \
        python3 -m venv "$VENV_DIR"
    echo "  [✓] Virtual environment created: $VENV_DIR"
else
    echo "  [✓] Virtual environment already exists"
fi

# Check whether paramiko/pyte are already installed in the venv
if ! "$VENV_DIR/bin/python3" -c "import paramiko, pyte" 2>/dev/null; then
    echo "  [i] Installing Python dependencies into venv…"
    _progress "Installing Python dependencies (paramiko, pyte)…" \
        "$VENV_DIR/bin/pip" install --quiet paramiko pyte
    echo "  [✓] Python dependencies installed"
else
    echo "  [✓] Python dependencies already present"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  Step 3 — Make launcher executable
# ─────────────────────────────────────────────────────────────────────────────
chmod +x "$SCRIPT_DIR/launch.sh"
echo "  [✓] launch.sh marked executable"

# ─────────────────────────────────────────────────────────────────────────────
#  Step 4 — Write .desktop file with absolute paths
# ─────────────────────────────────────────────────────────────────────────────
ICON="$APP_ROOT/icon.png"

cat > "$SCRIPT_DIR/$DEST_NAME" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Tor NYX Monitor
GenericName=Tor Relay Monitor
Comment=Monitor a remote Tor relay over SSH
Exec=$SCRIPT_DIR/launch.sh
Icon=$ICON
Path=$APP_ROOT
Terminal=false
Categories=Network;Monitor;Security;
Keywords=tor;ssh;relay;monitor;nyx;
StartupNotify=true
EOF

echo "  [✓] $DEST_NAME written"

# ─────────────────────────────────────────────────────────────────────────────
#  Step 5 — Install to applications menu
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p "$APP_DIR"
cp "$SCRIPT_DIR/$DEST_NAME" "$APP_DIR/$DEST_NAME"
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "$APP_DIR" 2>/dev/null || true
fi
echo "  [✓] Installed to applications menu"

# ─────────────────────────────────────────────────────────────────────────────
#  Step 6 — Install to Desktop
# ─────────────────────────────────────────────────────────────────────────────
if [[ -d "$DESKTOP_DIR" ]]; then
    cp "$SCRIPT_DIR/$DEST_NAME" "$DESKTOP_DIR/$DEST_NAME"
    chmod +x "$DESKTOP_DIR/$DEST_NAME"
    if command -v gio &>/dev/null; then
        gio set "$DESKTOP_DIR/$DEST_NAME" metadata::trusted true 2>/dev/null || true
    fi
    echo "  [✓] Shortcut placed on Desktop"
else
    echo "  [i] No ~/Desktop folder — skipping desktop shortcut"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  Done
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "================================================"
echo "  Setup complete!"
echo "================================================"
echo ""

DONE_MSG="Tor NYX Monitor is ready!\n\nLaunch it from your applications menu"
[[ -d "$DESKTOP_DIR" ]] && DONE_MSG+=" or double-click the icon on your Desktop."
_info "$DONE_MSG"
