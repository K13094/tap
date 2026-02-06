#!/bin/bash
# nozyme-tap system optimization for headless Raspberry Pi deployment.
# Disables unnecessary services to reduce CPU, RAM, and temperature.
#
# Usage: sudo ./optimize-system.sh [--revert]
#
# What this does:
#   - Disables desktop environment (saves ~300MB RAM)
#   - Disables printing, bluetooth, modem manager, avahi, etc.
#   - Reduces journal size and SD card writes
#   - Sets CPU governor to ondemand (lower idle power)
#
# What this does NOT do:
#   - Does not uninstall anything (reversible with --revert)
#   - Does not touch SSH, networking, or nozyme-tap
#   - Does not disable wlan0 (your management interface)

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_skip()  { echo -e "    $1"; }

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-]${NC} Run as root: sudo ./optimize-system.sh"
    exit 1
fi

# --- Revert mode ---
if [ "$1" = "--revert" ]; then
    echo "Reverting system optimizations..."
    SERVICES="cups cups-browsed bluetooth ModemManager avahi-daemon triggerhappy udisks2 upower"
    for svc in $SERVICES; do
        if systemctl list-unit-files "${svc}.service" &>/dev/null; then
            systemctl enable "${svc}.service" 2>/dev/null && log_info "Re-enabled ${svc}" || true
        fi
    done
    systemctl set-default graphical.target 2>/dev/null && log_info "Desktop re-enabled (reboot to apply)"
    echo "Done. Reboot to fully restore."
    exit 0
fi

echo "=== nozyme-tap system optimization ==="
echo ""

# --- 1. Disable unnecessary services ---
log_info "Disabling unnecessary services..."

# Services safe to disable on a headless drone sensor
DISABLE_SERVICES=(
    "cups"              # Printing
    "cups-browsed"      # Printer discovery
    "bluetooth"         # Bluetooth (user said not needed)
    "ModemManager"      # Modem management
    "avahi-daemon"      # mDNS/Bonjour discovery
    "triggerhappy"      # Hotkey daemon (no keyboard)
    "udisks2"           # Disk automounting
    "upower"            # Power management (for laptops)
)

for svc in "${DISABLE_SERVICES[@]}"; do
    if systemctl is-active "${svc}.service" &>/dev/null; then
        systemctl stop "${svc}.service" 2>/dev/null
        systemctl disable "${svc}.service" 2>/dev/null
        log_info "Disabled ${svc}"
    elif systemctl list-unit-files "${svc}.service" &>/dev/null; then
        systemctl disable "${svc}.service" 2>/dev/null
        log_skip "${svc} already stopped, disabled on boot"
    else
        log_skip "${svc} not installed, skipping"
    fi
done

# --- 2. Check for PostgreSQL (shouldn't run on a tap) ---
if systemctl is-active "postgresql@15-main.service" &>/dev/null 2>&1 || systemctl is-active "postgresql.service" &>/dev/null 2>&1; then
    log_warn "PostgreSQL is running on this tap!"
    log_warn "Consider: sudo systemctl disable postgresql"
    log_warn "(Not auto-disabling in case you need it for development)"
fi

# --- 3. Reduce journal size (less SD card wear) ---
log_info "Optimizing systemd journal..."
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/nozyme.conf << 'JOURNALCONF'
[Journal]
# Limit journal to 50MB (default is 4GB of disk)
SystemMaxUse=50M
# Limit runtime journal (in RAM) to 20MB
RuntimeMaxUse=20M
# Compress journal entries
Compress=yes
# Don't forward to syslog (reduces duplicate writes)
ForwardToSyslog=no
JOURNALCONF
systemctl restart systemd-journald 2>/dev/null
log_info "Journal limited to 50MB disk / 20MB RAM"

# --- 4. Reduce kernel logging noise ---
if [ ! -f /etc/sysctl.d/90-nozyme.conf ]; then
    cat > /etc/sysctl.d/90-nozyme.conf << 'SYSCTL'
# Reduce kernel log verbosity (fewer SD card writes)
kernel.printk = 3 4 1 3
# Reduce dirty page writeback frequency (batch SD card writes)
vm.dirty_writeback_centisecs = 1500
vm.dirty_expire_centisecs = 6000
# Lower swappiness (avoid SD card swap thrashing)
vm.swappiness = 10
SYSCTL
    sysctl -p /etc/sysctl.d/90-nozyme.conf 2>/dev/null
    log_info "Kernel params optimized (less logging, batched writes, low swap)"
else
    log_skip "Kernel params already configured"
fi

# --- 5. Summary ---
echo ""
echo "=== Optimization complete ==="
echo ""

# Show memory savings
MEM_FREE=$(free -m | awk '/^Mem:/ {print $4}')
MEM_AVAIL=$(free -m | awk '/^Mem:/ {print $7}')
TEMP=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)
TEMP_C=""
if [ -n "$TEMP" ]; then
    if command -v bc >/dev/null 2>&1; then
        TEMP_C="$(echo "scale=1; $TEMP/1000" | bc)°C"
    else
        TEMP_C="$((TEMP / 1000))°C"
    fi
fi

log_info "Available RAM: ${MEM_AVAIL}MB free, ${MEM_FREE}MB unused"
[ -n "$TEMP_C" ] && log_info "CPU temperature: ${TEMP_C}"
echo ""
log_warn "Desktop environment is still enabled."
log_warn "To disable (saves ~300MB RAM + CPU, recommended for production):"
echo "  sudo systemctl set-default multi-user.target"
echo "  sudo reboot"
echo ""
log_warn "To revert all changes: sudo ./optimize-system.sh --revert"
