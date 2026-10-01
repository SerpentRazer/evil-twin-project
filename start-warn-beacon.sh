#!/usr/bin/env bash
# HackTech Lightning 2026 — Wi-Fi WARNING BEACON (blue team).
# Broadcasts beacons whose SSID is a warning, so nearby phones see it in their
# Wi-Fi list. The one app-less, number-less reach. ⚠ transmits — authorized only.
#
#   sudo ./start-warn-beacon.sh                     # default warnings, ch6, wlan1
#   sudo WB_CHANNEL=11 ./start-warn-beacon.sh "DO-NOT-JOIN-FreeWiFi-FAKE"
#
# Puts ONLY the chosen adapter into monitor mode (without killing NetworkManager),
# so other adapters keep their internet. Ctrl+C restores it to managed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BEACON="$SCRIPT_DIR/defense/warn_beacon.py"
IFACE="${WB_IFACE:-wlan1}"
CH="${WB_CHANNEL:-6}"

if [[ $EUID -ne 0 ]]; then
  echo "This transmits and needs root (monitor mode): sudo $0"
  exit 1
fi

echo "[*] WARNING BEACON — LIVE. Warning SSIDs on ch$CH via $IFACE."
echo "[*] ⚠ This transmits. Authorized / own airspace only."

# Monitor on $IFACE only, leaving NetworkManager (and other adapters) alone.
nmcli device set "$IFACE" managed no 2>/dev/null || true
ip link set "$IFACE" down
iw dev "$IFACE" set type monitor
ip link set "$IFACE" up
iw dev "$IFACE" set channel "$CH"

cleanup() {
  echo
  echo "[*] restoring $IFACE to managed…"
  ip link set "$IFACE" down 2>/dev/null || true
  iw dev "$IFACE" set type managed 2>/dev/null || true
  ip link set "$IFACE" up 2>/dev/null || true
  nmcli device set "$IFACE" managed yes 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# foreground (no exec) so the cleanup trap runs on Ctrl+C
WB_IFACE="$IFACE" WB_CHANNEL="$CH" python3 "$BEACON" "$@"
