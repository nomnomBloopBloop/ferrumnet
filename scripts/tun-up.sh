#!/usr/bin/env bash
# Configure the TUN device for the userspace TCP stack.
#
# Scope is deliberately tiny: an address on tun0 and a /32 route for the stack. It does NOT
# add a default route via tun0 and does NOT enable ip_forward, so the host's real networking
# (SSH, Docker) is never touched.
#
# Run this AFTER starting the stack binary (the stack creates the device when it opens
# /dev/net/tun). Usage: sudo ./scripts/tun-up.sh [device]
set -euo pipefail

DEV="${1:-tun0}"
HOST_IP="10.0.0.1"    # the kernel side of the point-to-point link
STACK_IP="10.0.0.2"   # the address our userspace stack answers as
PREFIX=24

if ! ip link show "$DEV" >/dev/null 2>&1; then
  echo "error: device '$DEV' does not exist — start the stack first; it creates the device." >&2
  exit 1
fi

ip addr replace "$HOST_IP/$PREFIX" dev "$DEV"
ip link set "$DEV" up
ip route replace "$STACK_IP/32" dev "$DEV"

# CRITICAL (docs/DESIGN.md device-icmp/N2): without this, the kernel leaves TCP checksums
# zero/partial on locally-originated curl traffic (it assumes hardware offload), and our
# checksum verification would drop every segment. Best-effort; the core also accepts a 0
# checksum as a fallback.
if command -v ethtool >/dev/null 2>&1; then
  ethtool -K "$DEV" tx off rx off tso off gso off gro off 2>/dev/null || true
else
  echo "note: ethtool not installed; relying on the core's checksum-0 fallback for curl." >&2
fi

echo "configured $DEV: host=$HOST_IP  stack=$STACK_IP/$PREFIX  (offload disabled)"
echo "try:  ping $STACK_IP    then    curl http://$STACK_IP:8080"
