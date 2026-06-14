#!/usr/bin/env bash
# Tear down the TUN device. Ephemeral devices vanish when the stack process exits; this also
# removes a persistent one if it was pre-created. Usage: sudo ./scripts/tun-down.sh [device]
set -euo pipefail

DEV="${1:-tun0}"

if ip link show "$DEV" >/dev/null 2>&1; then
  ip link set "$DEV" down 2>/dev/null || true
  ip tuntap del dev "$DEV" mode tun 2>/dev/null || true
  echo "tore down $DEV"
else
  echo "$DEV not present (nothing to do)"
fi
