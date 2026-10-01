#!/usr/bin/env bash
# HackTech Lightning 2026 — UNIFIED WI-FI GUARDIAN CONSOLE launcher.
# One dashboard for everything: RED TEAM (attack), BLUE TEAM (defense),
# BEACON (warning broadcast), CAPTURES. LIVE only — needs root + the AR9271.
#
#   sudo ./start-console.sh                 # http://127.0.0.1:8080
#   sudo CON_IFACE=wlan1 ./start-console.sh # pick the AR9271 interface
#
# One radio does one job: start the attack, the beacon, or defense one at a time.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONSOLE="$SCRIPT_DIR/console.py"

if [[ $EUID -ne 0 ]]; then
  echo "This needs root (monitor mode + launching attacks/beacon): sudo $0"
  exit 1
fi

echo "[*] UNIFIED CONSOLE — LIVE. Authorized / own devices only."
echo "[*] Open http://127.0.0.1:${CON_PORT:-8080}"
exec python3 "$CONSOLE"
