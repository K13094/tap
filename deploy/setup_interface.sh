#!/bin/bash
# Manual WiFi interface setup for nozyme-tap.
# Use this if auto_monitor is disabled in tap_config.json.
#
# Usage: sudo ./setup_interface.sh [interface] [channel]
# Example: sudo ./setup_interface.sh wlan1 6
#
# Note: nozyme-tap handles this automatically when auto_monitor=true.
# This script is for manual setup/debugging only.

set -e

INTERFACE="${1:-wlan1}"
CHANNEL="${2:-6}"
MON_INTERFACE="${INTERFACE}mon"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then
    log_error "Run as root: sudo ./setup_interface.sh"
    exit 1
fi

if ! ip link show "$INTERFACE" &>/dev/null; then
    log_error "Interface $INTERFACE not found"
    echo "Available wireless interfaces:"
    iw dev | grep Interface | awk '{print "  " $2}'
    exit 1
fi

log_info "Setting up $INTERFACE for monitor mode on channel $CHANNEL"

# Release interface from NetworkManager (keep NM running for other interfaces)
log_info "Releasing $INTERFACE from NetworkManager..."
nmcli device set "$INTERFACE" managed no 2>/dev/null || true
# Stop wpa_supplicant which interferes with monitor mode
systemctl stop wpa_supplicant 2>/dev/null || true
killall wpa_supplicant 2>/dev/null || true

# Check if already in monitor mode
CURRENT_TYPE=$(iw dev "$INTERFACE" info 2>/dev/null | grep type | awk '{print $2}')
if [ "$CURRENT_TYPE" = "monitor" ]; then
    log_info "$INTERFACE already in monitor mode"
    MON_INTERFACE="$INTERFACE"
else
    if ip link show "$MON_INTERFACE" &>/dev/null; then
        ip link set "$MON_INTERFACE" down 2>/dev/null || true
        iw dev "$MON_INTERFACE" del 2>/dev/null || true
    fi

    ip link set "$INTERFACE" down

    if iw dev "$INTERFACE" set type monitor 2>/dev/null; then
        MON_INTERFACE="$INTERFACE"
    else
        log_warn "Direct mode set failed, trying airmon-ng..."
        if command -v airmon-ng &>/dev/null; then
            airmon-ng start "$INTERFACE" 2>/dev/null
            if ip link show "${INTERFACE}mon" &>/dev/null; then
                MON_INTERFACE="${INTERFACE}mon"
            fi
        else
            log_error "Cannot set monitor mode. Install aircrack-ng: sudo apt install aircrack-ng"
            exit 1
        fi
    fi

    ip link set "$MON_INTERFACE" up
fi

# Set channel
log_info "Setting channel $CHANNEL..."
iw dev "$MON_INTERFACE" set channel "$CHANNEL"

# Verify
VERIFY_TYPE=$(iw dev "$MON_INTERFACE" info 2>/dev/null | grep type | awk '{print $2}')
VERIFY_CHANNEL=$(iw dev "$MON_INTERFACE" info 2>/dev/null | grep channel | head -1 | awk '{print $2}')

if [ "$VERIFY_TYPE" = "monitor" ]; then
    log_info "Monitor mode: OK"
else
    log_error "Monitor mode verification FAILED (type=$VERIFY_TYPE)"
    exit 1
fi

if [ "$VERIFY_CHANNEL" = "$CHANNEL" ]; then
    log_info "Channel $CHANNEL: OK"
else
    log_warn "Channel verification: expected $CHANNEL, got $VERIFY_CHANNEL"
fi

echo ""
log_info "Interface ready: $MON_INTERFACE (channel $CHANNEL, monitor mode)"
echo ""
echo "Start nozyme-tap with:"
echo "  sudo python3 -m nozyme_tap --interface $MON_INTERFACE --config tap_config.json"
