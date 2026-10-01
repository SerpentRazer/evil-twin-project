#!/usr/bin/env bash
# HackTech Lightning 2026 — Evil Twin demo teardown
# Run with sudo: sudo ./stop-evil-twin.sh

set -uo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run this with sudo: sudo $0"
  exit 1
fi

MONIFACE="wlan0mon"

echo "Stopping dnsmasq..."
pkill -f "dnsmasq -C /etc/dnsmasq-portal.conf" 2>/dev/null || true
[[ -f /tmp/evil-twin-dnsmasq.pid ]] && kill "$(cat /tmp/evil-twin-dnsmasq.pid)" 2>/dev/null
rm -f /tmp/evil-twin-dnsmasq.pid

echo "Stopping airbase-ng..."
[[ -f /tmp/evil-twin-airbase.pid ]] && kill "$(cat /tmp/evil-twin-airbase.pid)" 2>/dev/null
pkill -f "airbase-ng" 2>/dev/null || true
rm -f /tmp/evil-twin-airbase.pid

echo "Flushing iptables nat table..."
iptables -t nat -F

echo "Stopping captive portal..."
[[ -f /tmp/evil-twin-portal.pid ]] && kill "$(cat /tmp/evil-twin-portal.pid)" 2>/dev/null
pkill -f "evil_portal.py" 2>/dev/null || true
rm -f /tmp/evil-twin-portal.pid
systemctl stop apache2 2>/dev/null || true

echo "Stopping monitor mode ($MONIFACE)..."
airmon-ng stop "$MONIFACE" >/dev/null 2>&1 || true

echo "Restoring NetworkManager..."
systemctl restart NetworkManager

echo "Done. Everything torn down."
