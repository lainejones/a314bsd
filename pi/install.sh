#!/usr/bin/env bash
# install.sh — Install the a314BSD bsdsocket.library Pi service
#
# Run this on the Raspberry Pi from the a314bsd/pi/ directory:
#   chmod +x install.sh
#   ./install.sh
#
# After installation the service starts automatically whenever the Amiga
# opens bsdsocket.library — no manual startup needed.

set -e

# Must run as root (writes to /opt/a314/ and /etc/)
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root."
    echo "       Try: sudo ./install.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
A314_DIR="/opt/a314"
CONF_FILE=""
PYTHON=""

# --------------------------------------------------------------------------
# 1. Locate a314d installation
# --------------------------------------------------------------------------

if [ ! -d "$A314_DIR" ]; then
    echo "ERROR: $A314_DIR not found."
    echo "       Install the A314 software first (a314d, a314fs, etc.)."
    exit 1
fi

# Prefer the venv Python that the rest of the A314 stack uses
if [ -x "$A314_DIR/venv/bin/python3" ]; then
    PYTHON="$A314_DIR/venv/bin/python3"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="$(command -v python3)"
else
    echo "ERROR: Python 3 not found."
    exit 1
fi

# Locate a314d.conf
for candidate in "$A314_DIR/a314d.conf" \
                 "/etc/opt/a314/a314d.conf" \
                 "/etc/a314d.conf" \
                 "/etc/a314/a314d.conf"; do
    if [ -f "$candidate" ]; then
        CONF_FILE="$candidate"
        break
    fi
done

# Last resort: search the filesystem
if [ -z "$CONF_FILE" ]; then
    CONF_FILE="$(find /etc /opt /home -name "a314d.conf" 2>/dev/null | head -1)"
fi

if [ -z "$CONF_FILE" ]; then
    echo "ERROR: a314d.conf not found."
    echo "  Pass it explicitly: CONF_FILE=/path/to/a314d.conf ./install.sh"
    exit 1
fi

echo "a314d config : $CONF_FILE"
echo "Python       : $PYTHON"
echo ""

# --------------------------------------------------------------------------
# 2. Install service script
# --------------------------------------------------------------------------

echo "[1/3] Installing bsdsocket.py -> $A314_DIR/bsdsocket.py"
cp "$SCRIPT_DIR/bsdsocket.py" "$A314_DIR/bsdsocket.py"
chmod 644 "$A314_DIR/bsdsocket.py"

# --------------------------------------------------------------------------
# 3. Register service in a314d.conf
# --------------------------------------------------------------------------

echo "[2/3] Updating $CONF_FILE"
if grep -q "^bsdsocket" "$CONF_FILE"; then
    echo "      'bsdsocket' entry already present — skipping (not modified)"
else
    # Backup, then append the new service line
    cp "$CONF_FILE" "${CONF_FILE}.bak"
    printf 'bsdsocket\t%s\t%s\n' "$PYTHON" "$A314_DIR/bsdsocket.py" >> "$CONF_FILE"
    echo "      Added entry (backup saved to ${CONF_FILE}.bak)"
fi

# --------------------------------------------------------------------------
# 4. Restart a314d so it picks up the new config
# --------------------------------------------------------------------------

echo "[3/3] Restarting a314d"
if systemctl is-active --quiet a314d 2>/dev/null; then
    sudo systemctl restart a314d
    echo "      a314d restarted OK"
elif systemctl list-unit-files 2>/dev/null | grep -q "a314d"; then
    echo "      a314d service exists but is not running — start with:"
    echo "        sudo systemctl start a314d"
else
    echo "      systemd service 'a314d' not found."
    echo "      Restart a314d manually for the new config to take effect."
fi

# --------------------------------------------------------------------------
# Done
# --------------------------------------------------------------------------

echo ""
echo "============================================================"
echo " Pi installation complete"
echo "============================================================"
echo ""
echo " The bsdsocket service will start automatically on demand"
echo " when the Amiga opens bsdsocket.library. No manual startup"
echo " needed after reboots."
echo ""
echo " To verify it is working:"
echo "   journalctl -u a314d -f"
echo "   (then open bsdsocket.library from the Amiga)"
echo ""
echo "------------------------------------------------------------"
echo " Amiga side (copy these files to the Amiga once only)"
echo "------------------------------------------------------------"
echo ""
echo "   bsdsocket.library  ->  LIBS:"
echo ""
echo " That is all. No Startup-Sequence changes are needed."
echo " Any software that uses bsdsocket.library (browsers, FTP"
echo " clients, SMB clients, etc.) will work immediately."
echo ""
echo " HTTPS/TLS is NOT in this base library. For https:// support add the"
echo " companion a314SSLlib project (its installer supersedes this one)."
echo "============================================================"
