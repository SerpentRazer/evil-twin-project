#!/usr/bin/env bash
# HackTech Lightning 2026 — Evil-twin OPERATOR CONSOLE launcher.
# One web panel to recon, pick a target, launch the attack, and watch output.
#
#   sudo ./start-ops.sh    # LIVE — real scans + real evil twin (needs root + AR9271)
#
# Then open http://127.0.0.1:8080  (or http://<kali-ip>:8080 from another device).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPS="$SCRIPT_DIR/portal/ops_server.py"

if [[ $EUID -ne 0 ]]; then
  echo "This needs root (monitor mode + launching the attack): sudo $0"
  exit 1
fi
echo "[*] OPERATOR CONSOLE — LIVE. Real scans + real evil twin. Authorized targets only."
echo "[*] Open http://127.0.0.1:${OPS_PORT:-8080}"
exec python3 "$OPS"
