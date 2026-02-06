#!/bin/bash
# nozyme-tap deployment script.
# Installs nozyme-tap on a Linux system (Raspberry Pi, Kali, Debian/Ubuntu).
#
# Usage: sudo ./install.sh --node-host <ip> [--interface wlan1] [--node-port 5590]
#
# Example:
#   sudo ./install.sh --node-host 10.0.3.15 --interface wlan1
#
# What it does:
# 1. Installs system dependencies (tshark, python3-pip, aircrack-ng)
# 2. Installs Python dependencies
# 3. Copies nozyme-tap to /home/tap
# 4. Generates tap_config.json with unique UUID and correct node address
# 5. Installs systemd service
# 6. Runs smoke test: starts service, verifies tshark args, frames flowing, ZMQ connected

set -e

INSTALL_DIR="/home/tap"
INTERFACE="wlan1"
NODE_HOST=""
NODE_PORT="5590"
INSTALL_SERVICE=true
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAP_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$TAP_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface) INTERFACE="$2"; shift 2 ;;
        --node-host) NODE_HOST="$2"; shift 2 ;;
        --node-port) NODE_PORT="$2"; shift 2 ;;
        --no-service) INSTALL_SERVICE=false; shift ;;
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# node-host is required — no silent fallback to localhost
if [ -z "$NODE_HOST" ]; then
    log_error "Missing required --node-host <ip>"
    echo ""
    echo "Usage: sudo ./install.sh --node-host <ip> [--interface wlan1] [--node-port 5590]"
    echo ""
    echo "Example:"
    echo "  sudo ./install.sh --node-host 10.0.3.15 --interface wlan1"
    exit 1
fi

# Check root
if [ "$EUID" -ne 0 ]; then
    log_error "Run as root: sudo ./install.sh"
    exit 1
fi

echo "================================"
echo "  nozyme-tap installer v0.2.0"
echo "================================"
echo ""
log_info "Install directory: $INSTALL_DIR"
log_info "WiFi interface: $INTERFACE"
log_info "Node: $NODE_HOST:$NODE_PORT"
log_info "Install systemd service: $INSTALL_SERVICE"
echo ""

# Step 1: System dependencies
log_info "Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections
apt-get update -qq

PACKAGES="tshark python3-pip python3-venv aircrack-ng iw wireless-tools libzmq-dev python3-dev build-essential git"
for pkg in $PACKAGES; do
    if ! dpkg -l "$pkg" &>/dev/null; then
        log_info "Installing $pkg..."
        apt-get install -y -qq "$pkg"
    else
        log_info "$pkg already installed"
    fi
done

# Step 2: Create install directory
log_info "Creating $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Step 3: Copy nozyme_tap package
log_info "Copying nozyme_tap..."
if [ -d "$INSTALL_DIR/nozyme_tap" ]; then
    if [ ! -f "$INSTALL_DIR/nozyme_tap/__init__.py" ]; then
        log_error "Refusing to rm: $INSTALL_DIR/nozyme_tap missing __init__.py sentinel"
        exit 1
    fi
    rm -rf "$INSTALL_DIR/nozyme_tap"
fi
cp -r "$TAP_DIR" "$INSTALL_DIR/nozyme_tap"

# Step 4: Install Python dependencies (in virtual environment)
VENV_DIR="$INSTALL_DIR/venv"
if [ ! -d "$VENV_DIR" ]; then
    log_info "Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
fi
log_info "Installing Python dependencies..."
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/nozyme_tap/deploy/requirements.txt" || exit 1

# Step 5: Generate config if not exists
CONFIG_FILE="$INSTALL_DIR/nozyme_tap/tap_config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    TAP_UUID=$(python3 -c "import uuid; print(uuid.uuid4())") || { log_error "UUID generation failed"; exit 1; }
    log_info "Generating tap_config.json (UUID: $TAP_UUID)..."
    cat > "$CONFIG_FILE" << CONF
{
    "tap_uuid": "$TAP_UUID",
    "tap_name": "$(hostname)-tap",
    "interface": "$INTERFACE",
    "auto_monitor": true,
    "channels_24ghz": [1, 6, 11],
    "channels_5ghz": [36, 40, 44, 48, 149, 153, 157, 161],
    "channels_6ghz": [],
    "channel_dwell_ms": 250,
    "node_host": "$NODE_HOST",
    "node_port": $NODE_PORT,
    "tshark_path": "/usr/bin/tshark",
    "log_level": "WARNING",
    "starvation_timeout_s": 30,
    "tshark_restart_delay_s": 1,
    "heartbeat_interval_s": 10,
    "zmq_buffer_size": 1000,
    "zmq_hwm": 1000,
    "memory_percent_threshold": 90.0
}
CONF
else
    log_warn "Config already exists, skipping: $CONFIG_FILE"
fi

# Step 6: Install systemd service
if [ "$INSTALL_SERVICE" = true ]; then
    log_info "Installing systemd service..."
    cp "$INSTALL_DIR/nozyme_tap/deploy/nozyme-tap.service" /etc/systemd/system/ || { log_error "Failed to copy service file"; exit 1; }
    systemctl daemon-reload
    systemctl enable nozyme-tap
    log_info "Service installed and enabled"
    log_info "Start with: sudo systemctl start nozyme-tap"
else
    log_info "Skipping systemd service installation"
fi

# Step 7: Smoke test — start service and verify frames are flowing
echo ""
echo "================================"
log_info "Installation complete, running smoke test..."
echo "================================"
echo ""

SMOKE_OK=true

if [ "$INSTALL_SERVICE" = true ]; then
    systemctl start nozyme-tap
    log_info "Service started, waiting 20s for frames..."
    sleep 20

    # Check 1: service is running
    if ! systemctl is-active --quiet nozyme-tap; then
        log_error "SMOKE TEST FAILED: service is not running"
        journalctl -u nozyme-tap --since "30 sec ago" --no-pager | tail -10
        SMOKE_OK=false
    else
        log_info "PASS: service is active"
    fi

    # Check 2: tshark has no -Y display filter
    TSHARK_CMD=$(ps -eo args | grep '[t]shark.*-i' | head -1)
    if echo "$TSHARK_CMD" | grep -q ' -Y '; then
        log_error "SMOKE TEST FAILED: tshark has a display filter (-Y)"
        log_error "  Command: $TSHARK_CMD"
        SMOKE_OK=false
    else
        log_info "PASS: no display filter (tshark: $TSHARK_CMD)"
    fi

    # Check 3: tshark has BPF capture filter 'type mgt'
    if echo "$TSHARK_CMD" | grep -q 'type mgt'; then
        log_info "PASS: BPF capture filter 'type mgt' present"
    else
        log_error "SMOKE TEST FAILED: missing BPF capture filter 'type mgt'"
        SMOKE_OK=false
    fi

    # Check 4: frames_parsed is not stuck at 0
    STATS_LINE=$(journalctl -u nozyme-tap --since "30 sec ago" --no-pager 2>/dev/null | grep "Stats:" | tail -1)
    if [ -n "$STATS_LINE" ]; then
        PARSED=$(echo "$STATS_LINE" | grep -oP '\d+ parsed' | grep -oP '\d+')
        if [ -n "$PARSED" ] && [ "$PARSED" -gt 0 ]; then
            log_info "PASS: frames_parsed=$PARSED (frames are flowing)"
        else
            log_warn "frames_parsed=0 (may need more time or no WiFi traffic yet)"
            log_warn "Re-check with: sudo journalctl -u nozyme-tap -f"
        fi
    else
        log_warn "No stats line yet — service may need more time"
        log_warn "Re-check with: sudo journalctl -u nozyme-tap -f"
    fi

    # Check 5: ZMQ connected to the right node
    ZMQ_LINE=$(journalctl -u nozyme-tap --since "30 sec ago" --no-pager 2>/dev/null | grep "ZMQ PUB connected" | tail -1)
    if echo "$ZMQ_LINE" | grep -q "$NODE_HOST"; then
        log_info "PASS: ZMQ connected to $NODE_HOST:$NODE_PORT"
    else
        log_error "SMOKE TEST FAILED: ZMQ not connected to $NODE_HOST"
        [ -n "$ZMQ_LINE" ] && log_error "  Got: $ZMQ_LINE"
        SMOKE_OK=false
    fi
fi

echo ""
if [ "$SMOKE_OK" = true ]; then
    echo "================================"
    log_info "ALL CHECKS PASSED"
    echo "================================"
else
    echo "================================"
    log_error "SMOKE TEST FAILED — check errors above"
    echo "================================"
    exit 1
fi

echo ""
echo "Files installed to: $INSTALL_DIR"
echo "Config: $CONFIG_FILE"
echo "Node: $NODE_HOST:$NODE_PORT"
echo ""
echo "Service control:"
echo "  sudo systemctl status nozyme-tap"
echo "  sudo journalctl -u nozyme-tap -f"
echo ""
