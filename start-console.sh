#!/usr/bin/env bash
# HackTech Lightning 2026 — UNIFIED WI-FI GUARDIAN CONSOLE launcher.
# One dashboard for everything: RED TEAM (attack), BLUE TEAM (defense),
# BEACON (warning broadcast), CAPTURES. LIVE only — needs root.
#
# MULTI-RADIO: roles are auto-assigned to monitor-capable adapters. POLICY: the
# Atheros AR9271 is used ONLY for ATTACK (airbase-ng is bulletproof on ath9k_htc);
# the other, higher-power adapter (e.g. AWUS036NHR, 1W) does DEFENSE + BEACON —
# its range helps the detector hear the twin from far. With TWO adapters, attack
# and defense run at the SAME TIME (live evil twin caught live). One adapter ->
# one job at a time.
#
#   sudo ./start-console.sh                              # http://127.0.0.1:8080, auto-assign
#   sudo CON_ATTACK_IFACE=wlan2 CON_DEFENSE_IFACE=wlan1 ./start-console.sh   # pin roles
#   sudo CON_IFACE=wlan1 ./start-console.sh              # force everything onto one radio
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
