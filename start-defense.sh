#!/usr/bin/env bash
# HackTech Lightning 2026 — Evil-twin DEFENSE CONSOLE (blue team) launcher.
# Detects evil twins, blocklists them, catches devices trying to connect, and
# alerts on the dashboard + desktop popup + phone (ntfy).
#
#   sudo ./start-defense.sh            # LIVE — real monitor-mode detection
#   sudo ./start-defense.sh contain    # LIVE + active containment (deauth rogue links)
#
# Phone push: export DEF_NTFY_TOPIC=your-unique-topic  (install the ntfy app,
#             subscribe to that topic) before launching. Free, no account.
#
# Then open http://127.0.0.1:8081  (or http://<kali-ip>:8081 from another device).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDIAN="$SCRIPT_DIR/defense/guardian.py"
CONTAIN_ARG="${1:-}"

if [[ $EUID -ne 0 ]]; then
  echo "This needs root (monitor mode): sudo $0"
  exit 1
fi
echo "[*] DEFENSE CONSOLE — LIVE. Passive detection on ${DEF_IFACE:-wlan0mon}."
if [[ "$CONTAIN_ARG" == "contain" ]]; then
  export DEF_CONTAIN=1
  echo "[*] ACTIVE CONTAINMENT ON — will deauth rogue links. Authorized / own devices only."
fi

[[ -n "${DEF_NTFY_TOPIC:-}" ]] && echo "[*] Phone push via ntfy topic: $DEF_NTFY_TOPIC"
echo "[*] Open http://127.0.0.1:${DEF_PORT:-8081}"
exec python3 "$GUARDIAN"
