#!/usr/bin/env bash
# HackTech Lightning 2026 — Evil Twin DETECTOR teardown
# Stops the detector, disables monitor mode, restores normal networking.
# Usage: sudo ./stop-detector.sh

set -uo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run this with sudo: sudo $0"
  exit 1
fi

echo "Stopping detector process..."
pkill -f "evil_twin_detect.py" 2>/dev/null || true

echo "Disabling monitor mode..."
# handle both cases: a created wlan0mon, or wlan0 flipped into monitor
if iwconfig wlan0mon >/dev/null 2>&1; then
  airmon-ng stop wlan0mon >/dev/null 2>&1 || true
fi
if iwconfig wlan0 2>/dev/null | grep -qi "Mode:Monitor"; then
  airmon-ng stop wlan0 >/dev/null 2>&1 || true
fi

echo "Restoring NetworkManager..."
systemctl restart NetworkManager 2>/dev/null || true

echo "Done. Antenna released, normal networking restored."
