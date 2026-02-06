#!/bin/bash
# nozyme-tap firewall setup using iptables.
# Allows: outbound ZMQ (port 5590), inbound SSH (port 22), DNS, DHCP, NTP.
# Blocks everything else inbound.
#
# Usage: sudo ./firewall.sh [--node-ip 192.168.1.60] [--ssh-from 0.0.0.0/0]
#
# To persist rules across reboots:
#   sudo apt install iptables-persistent
#   sudo netfilter-persistent save

set -e

NODE_IP=""
SSH_FROM="0.0.0.0/0"
ZMQ_PORT="5590"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --node-ip) NODE_IP="$2"; shift 2 ;;
        --ssh-from) SSH_FROM="$2"; shift 2 ;;
        --zmq-port) ZMQ_PORT="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-]${NC} Run as root: sudo ./firewall.sh"
    exit 1
fi

log_info "Setting up firewall rules..."

# Check iptables binary exists
if ! command -v iptables >/dev/null 2>&1; then
    echo -e "${RED}[-]${NC} iptables not found. Install with: sudo apt install iptables"
    exit 1
fi

# Backup existing rules before flushing
log_info "Backing up existing iptables rules to /tmp/iptables-backup-*.txt"
iptables-save > "/tmp/iptables-backup-$(date +%Y%m%d-%H%M%S).txt" 2>/dev/null || true
ip6tables-save > "/tmp/ip6tables-backup-$(date +%Y%m%d-%H%M%S).txt" 2>/dev/null || true

# Flush existing rules
iptables -F
iptables -X

# Default policies: allow outbound, drop inbound
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established/related connections (return traffic)
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow inbound SSH
iptables -A INPUT -p tcp --dport 22 -s "$SSH_FROM" -j ACCEPT
log_info "SSH: allowed from $SSH_FROM"

# Allow DHCP (needed for network config)
iptables -A INPUT -p udp --sport 67 --dport 68 -j ACCEPT

# Allow ICMP (ping — useful for remote diagnostics)
iptables -A INPUT -p icmp -j ACCEPT

# Restrict outbound ZMQ to specific node IP if provided
if [ -n "$NODE_IP" ]; then
    iptables -A OUTPUT -p tcp --dport "$ZMQ_PORT" -d "$NODE_IP" -j ACCEPT
    iptables -A OUTPUT -p tcp --dport "$ZMQ_PORT" -j DROP
    log_info "ZMQ: restricted to $NODE_IP:$ZMQ_PORT"
else
    log_warn "ZMQ: outbound to any host on port $ZMQ_PORT (use --node-ip to restrict)"
fi

# Log dropped packets (rate limited to avoid log spam)
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-drop: " --log-level 4

# --- IPv6 rules ---
log_info "Setting up IPv6 firewall rules..."
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -F
    ip6tables -X
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT ACCEPT
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
    log_info "IPv6: DROP policy with SSH + established + ICMPv6 allowed"
else
    log_warn "ip6tables not found, skipping IPv6 rules"
fi

log_info "Firewall rules applied:"
iptables -L -n --line-numbers

echo ""
log_info "To persist across reboots:"
echo "  sudo apt install iptables-persistent"
echo "  sudo netfilter-persistent save"
