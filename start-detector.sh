#!/usr/bin/env bash
# HackTech Lightning 2026 — Evil Twin DETECTOR launcher
# Preps the AR9271 into monitor mode, then runs the passive detector.
#
# Usage:
#   sudo ./start-detector.sh              # prep antenna + WATCH using existing baseline.json
#   sudo ./start-detector.sh learn        # prep antenna + LEARN for 60s (default), then exit
#   sudo ./start-detector.sh learn 90     # prep antenna + LEARN for 90s, then exit
#   sudo ./start-detector.sh learnwatch   # LEARN 60s, then immediately WATCH
#
# Tear down with: sudo ./stop-detector.sh

set -euo pipefail

IFACE="wlan0"
MONIFACE="wlan0mon"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTOR="$SCRIPT_DIR/evil_twin_detect.py"
BASELINE="$SCRIPT_DIR/baseline.json"
DEFAULT_LEARN=60

MODE="${1:-watch}"
LEARN_SECS="${2:-$DEFAULT_LEARN}"

if [[ $EUID -ne 0 ]]; then
  echo "Run this with sudo: sudo $0 $*"
  exit 1
fi

if [[ ! -f "$DETECTOR" ]]; then
  echo "ERROR: detector not found at $DETECTOR"
  exit 1
fi

echo "[1/4] Checking adapter..."
if ! lsusb | grep -qiE 'atheros|ar9271'; then
  echo "  ERROR: AR9271 not detected via lsusb."
  echo "  In VirtualBox: Devices -> USB -> tick the Atheros adapter, then re-run."
  exit 1
fi
echo "  OK: adapter present."

echo "[2/4] Freeing the card (airmon-ng check kill)..."
airmon-ng check kill >/dev/null 2>&1 || true

echo "[3/4] Enabling monitor mode..."
if ! iwconfig "$MONIFACE" >/dev/null 2>&1; then
  airmon-ng start "$IFACE" >/dev/null 2>&1 || true
fi
# some driver/versions flip wlan0 itself into monitor instead of creating wlan0mon
if ! iwconfig "$MONIFACE" >/dev/null 2>&1; then
  if iwconfig "$IFACE" 2>/dev/null | grep -qi "Mode:Monitor"; then
    MONIFACE="$IFACE"
  else
    echo "  ERROR: monitor interface did not come up. Check 'iwconfig' manually."
    exit 1
  fi
fi
echo "  OK: monitor mode on $MONIFACE"

# make sure the detector talks to the interface we actually have
export ET_IFACE="$MONIFACE"

echo "[4/4] Launching detector (mode: $MODE)..."
echo "----------------------------------------------------------"
case "$MODE" in
  watch)
    if [[ ! -f "$BASELINE" ]]; then
      echo "  No baseline.json found. Build one first:"
      echo "     sudo $0 learn 60"
      exit 1
    fi
    exec python3 "$DETECTOR"
    ;;
  learn)
    echo "  LEARN for ${LEARN_SECS}s — keep the attacker/hotspot OFF so the baseline stays clean."
    exec python3 "$DETECTOR" --learn "$LEARN_SECS"
    ;;
  learnwatch)
    echo "  LEARN ${LEARN_SECS}s then WATCH — keep attacker OFF during the learn window."
    exec python3 "$DETECTOR" --learn "$LEARN_SECS" --watch
    ;;
  *)
    echo "  Unknown mode '$MODE'. Use: watch | learn [secs] | learnwatch"
    exit 1
    ;;
esac
