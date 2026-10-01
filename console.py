#!/usr/bin/env python3
"""UNIFIED WI-FI GUARDIAN CONSOLE — one process, one port, one dashboard.

Centralizes the whole demo behind a single web UI on :8080, with four panels:

  * RED TEAM   — recon → impersonate → launch evil twin → live attack output
                 (reuses portal/ops_server.py).
  * BLUE TEAM  — detect evil twins, blocklist, catch connection attempts (with
                 device fingerprint), containment toggle, fan-out alerts
                 (reuses defense/guardian.py + evil_twin_detect.py).
  * BEACON     — broadcast warning SSIDs so nearby phones see "DO-NOT-JOIN…"
                 in their Wi-Fi list (reuses defense/warn_beacon.py).
  * CAPTURES   — captured captive-portal submissions.

LIVE only — needs root + the AR9271. One radio does one job: starting the attack,
the beacon, or defense each claims the adapter, so run one radio-mode at a time
(the UI shows which is active). The console itself serves fine without root; the
radio actions need it.

    sudo python3 console.py            # http://127.0.0.1:8080

Safety: fixed action allow-list; SSID sanitized + passed via env/argv, never a
shell string; channel forced to int 1-14. Authorized / own-devices use only.
"""
import os
import sys
import json
import time
import threading
import subprocess
from collections import deque

from flask import Flask, request, Response

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = HERE
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "portal"))
sys.path.insert(0, os.path.join(ROOT, "defense"))

import ops_server as ops            # red team: recon / attack / capture helpers
import guardian as guard            # blue team: detection, state, alerting, fingerprint

PORT = int(os.environ.get("CON_PORT", "8080"))
IFACE = os.environ.get("CON_IFACE", "wlan1")        # AR9271 monitor interface
guard.IFACE = IFACE                                 # keep guardian's deauth/sniff on the same radio
ops.IFACE = IFACE                                   # red-team scan/attack on the same radio (not wlan0)

app = Flask(__name__)

# ---------------- unified console log ----------------

BEACON_LOG = deque(maxlen=200)
_blue = {"sniffer": None, "hop_stop": None, "running": False}
_beacon = {"proc": None}
RADIO = {"present": True, "iface": IFACE, "mode": None, "channel": None,
         "healthy": True, "note": "", "recoveries": 0}
_radio_last_fix = 0.0


def blog(line):
    BEACON_LOG.append((time.strftime("%H:%M:%S"), f"[beacon] {line}"))
    print(f"{time.strftime('%H:%M:%S')} [beacon] {line}", flush=True)


def merged_logs():
    """RED (ops) + BLUE (guardian) + BEACON consoles, merged newest-last."""
    rows = []
    rows += [(t, f"[RED] {l}") for t, l in list(ops.CONSOLE)]
    rows += [(t, f"[BLUE] {l}") for t, l in list(guard.CONSOLE)]
    rows += list(BEACON_LOG)
    rows.sort(key=lambda r: r[0])                   # HH:MM:SS lexical sort = chronological
    return rows[-400:]


# ============================================================ RED TEAM ====

def red_status():
    try:
        return ops.status()
    except Exception:
        return {"monitor": False, "scanning": False, "airbase": False,
                "dnsmasq": False, "portal": False, "captures": 0, "target": {}}


def red_select(bssid):
    with ops._lock:
        match = next((t for t in ops.TARGETS if t["bssid"] == bssid), None)
    if not match:
        return False
    ops.TARGET.clear()
    ops.TARGET.update({"ssid": ops.sanitize_ssid(match["ssid"]),
                       "channel": ops.sanitize_channel(match["channel"]),
                       "bssid": match["bssid"], "enc": match["enc"]})
    ops.log(f"🎯 target locked: \"{ops.TARGET['ssid']}\"  ch{ops.TARGET['channel']}  "
            f"({match['bssid']}, {match['enc']})")
    return True


# ============================================================ BLUE TEAM ====

def blue_start():
    if _blue["running"]:
        return False
    try:
        from scapy.all import (AsyncSniffer, Dot11, Dot11Beacon, Dot11Auth,
                               Dot11AssoReq, Dot11ReassoReq)
        import itertools
        from evil_twin_detect import (load_baseline, fingerprint, get_rssi,
                                      get_ssid, classify_new_bssid, MIN_BEACONS_NEW)
    except Exception as e:
        guard.clog(f"!! cannot start defense: {e}", "detect")
        return False

    baseline = load_baseline()
    guard.STATE["known"] = len(baseline)
    guard.clog(f"DEFENSE ACTIVE — guarding {len(baseline)} known networks on {IFACE}")
    if not baseline:
        guard.clog("!! no baseline.json — run the detector's learn mode first", "detect")

    candidates, cand_rssi = {}, {}
    hop_stop = threading.Event()
    _blue["hop_stop"] = hop_stop

    def hopper():
        for ch in itertools.cycle([1, 6, 11]):
            if hop_stop.is_set():
                return
            use = guard.STATE["pinned_channel"] or ch
            subprocess.call(["iw", "dev", IFACE, "set", "channel", str(use)],
                            stderr=subprocess.DEVNULL)
            time.sleep(0.8)
    threading.Thread(target=hopper, daemon=True).start()

    def handle(pkt):
        if pkt.haslayer(Dot11Auth) or pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq):
            d = pkt.getlayer(Dot11)
            ap, sta = (d.addr1 or "").lower(), (d.addr2 or "").lower()
            if ap in guard.BLOCKLIST and sta:
                guard.on_connect_attempt(sta, ap)
            return
        if not pkt.haslayer(Dot11Beacon):
            return
        bssid = (pkt[Dot11].addr2 or "").lower()
        ssid = get_ssid(pkt, Dot11Beacon)
        if not bssid or not ssid or ssid not in baseline or bssid in baseline[ssid]:
            return
        if bssid in guard.EVIL:
            return
        rssi = get_rssi(pkt)
        fp = fingerprint(pkt)
        candidates[bssid] = candidates.get(bssid, 0) + 1
        if rssi is not None:
            cand_rssi[bssid] = rssi if cand_rssi.get(bssid) is None else max(cand_rssi[bssid], rssi)
        if candidates[bssid] < MIN_BEACONS_NEW:
            return
        verdict, conf, reasons = classify_new_bssid(bssid, cand_rssi.get(bssid, rssi), fp, baseline[ssid])
        if verdict == "evil":
            guard.on_evil_twin(bssid, ssid, fp.get("channel"), fp.get("crypto"), reasons)

    sniffer = AsyncSniffer(iface=IFACE, prn=handle, store=False)
    try:
        sniffer.start()
    except Exception as e:
        hop_stop.set()
        guard.clog(f"!! sniff failed on {IFACE} (monitor mode up?): {e}", "detect")
        return False
    _blue["sniffer"] = sniffer
    _blue["running"] = True
    return True


def blue_stop():
    if not _blue["running"]:
        return False
    if _blue["hop_stop"]:
        _blue["hop_stop"].set()
    if _blue["sniffer"]:
        try:
            _blue["sniffer"].stop()
        except Exception:
            pass
    guard.STATE["pinned_channel"] = None
    _blue["running"] = False
    guard.clog("defense stopped — radio released")
    return True


# ============================================================ BEACON ====

def beacon_running():
    p = _beacon["proc"]
    return bool(p and p.poll() is None)


def beacon_start(ssids, channel):
    if beacon_running():
        return False
    env = dict(os.environ)
    env["WB_IFACE"] = IFACE
    env["WB_CHANNEL"] = str(guard_sanitize_channel(channel))
    cmd = ["python3", os.path.join(ROOT, "defense", "warn_beacon.py")] + [s for s in ssids if s.strip()]
    blog(f"$ WB_CHANNEL={env['WB_CHANNEL']} warn_beacon.py {' '.join(ssids)}")
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, bufsize=1, env=env)
    _beacon["proc"] = p

    def pump():
        for line in p.stdout:
            blog(line.rstrip())
        blog(f"(beacon stopped: {p.returncode})")
    threading.Thread(target=pump, daemon=True).start()
    return True


def beacon_stop():
    p = _beacon["proc"]
    if p and p.poll() is None:
        p.terminate()
        blog("beacon terminated")
        return True
    return False


def guard_sanitize_channel(c):
    try:
        return max(1, min(14, int(c)))
    except (TypeError, ValueError):
        return 6


# ======================================================= RADIO WATCHDOG ==
# Keeps the AR9271 usable through a live demo: catches USB drop, re-enumeration
# under a new wlanN, and silent monitor-mode loss — and auto-heals what software
# can. A glitch on stage is the #1 way to lose; this makes it self-recover.

def find_ar9271():
    """Interface currently bound to the ath9k_htc driver (AR9271), or None.
    Found by DRIVER, not name, so a USB re-enumeration under a different wlanN
    is still recognised and we can rebind to it."""
    import glob as _glob
    for net in _glob.glob("/sys/class/net/*"):
        try:
            drv = os.path.basename(os.path.realpath(os.path.join(net, "device", "driver")))
        except OSError:
            continue
        if drv == "ath9k_htc":
            return os.path.basename(net)
    return None


def _iface_mode(iface):
    try:
        info = subprocess.check_output(["iw", "dev", iface, "info"], text=True,
                                       stderr=subprocess.DEVNULL)
    except Exception:
        return None, None
    mode = ch = None
    for ln in info.splitlines():
        ln = ln.strip()
        if ln.startswith("type "):
            mode = ln.split()[1]
        elif ln.startswith("channel "):
            ch = ln.split()[1]
    return mode, ch


def _monitor_job_active():
    r = red_status()
    return bool(r.get("airbase") or r.get("portal") or r.get("scanning")
                or _blue["running"] or beacon_running())


def radio_watchdog():
    global IFACE, _radio_last_fix
    while True:
        try:
            found = find_ar9271()
            if not found:
                RADIO.update(present=False, healthy=False, mode=None, channel=None,
                             note="AR9271 not detected — replug the USB adapter (check VM passthrough)")
            else:
                if found != IFACE:                        # re-enumerated → rebind every consumer
                    ops.log(f"radio re-enumerated: {IFACE} -> {found}; rebinding")
                    IFACE = found
                    guard.IFACE = found
                    ops.IFACE = found
                mode, ch = _iface_mode(found)
                RADIO.update(present=True, iface=found, mode=mode, channel=ch)
                want_mon = _monitor_job_active()
                if want_mon and mode != "monitor" and (time.time() - _radio_last_fix) > 8:
                    _radio_last_fix = time.time()
                    RADIO["recoveries"] += 1
                    ops.log(f"radio fell out of monitor mode — auto-healing {found}")
                    want_ch = (guard.STATE.get("pinned_channel")
                               or (ops.TARGET.get("channel") if ops.TARGET else None) or 6)
                    for c in (f"nmcli device set {found} managed no",
                              f"ip link set {found} down",
                              f"iw dev {found} set type monitor",
                              f"ip link set {found} up",
                              f"iw dev {found} set channel {want_ch}"):
                        subprocess.call(["bash", "-c", c + " >/dev/null 2>&1 || true"])
                    RADIO.update(healthy=True, note=f"recovered monitor mode (x{RADIO['recoveries']})")
                else:
                    RADIO["healthy"] = (mode == "monitor") if want_mon else True
                    if RADIO["healthy"] and not RADIO["note"].startswith("recovered"):
                        RADIO["note"] = ""
        except Exception as e:
            RADIO.update(healthy=False, note=f"watchdog error: {e}")
        time.sleep(3)


# ============================================================ status ====

def unified_status():
    r = red_status()
    g = guard.state()
    return {
        "red": {"target": ops.TARGET, "scanning": r.get("scanning"),
                "airbase": r.get("airbase"), "dnsmasq": r.get("dnsmasq"),
                "portal": r.get("portal"), "monitor": r.get("monitor")},
        "blue": {"running": _blue["running"], "contain": g.get("contain"),
                 "known": g.get("known"), "pinned_channel": g.get("pinned_channel"),
                 "evil": g.get("evil"), "blocklist": g.get("blocklist"),
                 "attempts": g.get("attempts"), "ntfy": g.get("ntfy")},
        "beacon": {"running": beacon_running()},
        "captures": r.get("captures", 0),
        "iface": IFACE,
        "radio": {"present": RADIO["present"], "iface": RADIO["iface"], "mode": RADIO["mode"],
                  "channel": RADIO["channel"], "healthy": RADIO["healthy"],
                  "note": RADIO["note"], "recoveries": RADIO["recoveries"]},
    }


# ============================================================ routes ====

@app.route("/")
def index():
    with open(os.path.join(HERE, "console.html")) as f:
        return Response(f.read(), mimetype="text/html")


@app.route("/api/status")
def api_status():
    with ops._lock:
        targets = list(ops.TARGETS)
    return Response(json.dumps({**unified_status(), "targets": targets}),
                    mimetype="application/json")


@app.route("/api/logs")
def api_logs():
    return Response("\n".join(f"{t}  {l}" for t, l in merged_logs()), mimetype="text/plain")


@app.route("/api/captures")
def api_captures():
    rows = []
    try:
        with open(ops.CAPTURES) as f:
            for ln in f:
                ln = ln.strip()
                if ln:
                    rows.append(json.loads(ln))
    except (OSError, ValueError):
        pass
    return Response(json.dumps(rows[-200:]), mimetype="application/json")


@app.route("/api/captures/wipe", methods=["POST"])
def api_captures_wipe():
    try:
        open(ops.CAPTURES, "w").close()
        ops.log("captures wiped")
    except OSError:
        pass
    return Response(json.dumps({"ok": True}), mimetype="application/json")


@app.route("/api/action", methods=["POST"])
def api_action():
    body = request.json or {}
    action = body.get("action")
    ok = True
    if action == "red_scan":
        threading.Thread(target=ops.real_scan, daemon=True).start()
    elif action == "red_select":
        ok = red_select(body.get("bssid"))
    elif action == "red_launch":
        if not ops.TARGET:
            ops.log("!! no target selected — pick one from the recon table first.")
            ok = False
        else:
            threading.Thread(target=ops.real_launch, daemon=True).start()
    elif action == "red_stop":
        threading.Thread(target=ops.real_stop, daemon=True).start()
    elif action == "blue_start":
        ok = blue_start()
    elif action == "blue_stop":
        ok = blue_stop()
    elif action == "blue_toggle":
        guard.STATE["contain"] = bool(body.get("contain"))
        guard.clog(f"active containment {'ENABLED — will deauth rogue links' if guard.STATE['contain'] else 'disabled — warn-only'}")
    elif action == "beacon_start":
        ok = beacon_start(body.get("ssids") or [], body.get("channel", 6))
    elif action == "beacon_stop":
        ok = beacon_stop()
    else:
        return Response(json.dumps({"ok": False, "error": "unknown action"}),
                        status=400, mimetype="application/json")
    return Response(json.dumps({"ok": ok}), mimetype="application/json")


if __name__ == "__main__":
    ops.log(f"unified console up on :{PORT}  iface={IFACE}")
    if os.geteuid() != 0:
        ops.log("!! not root — radio actions (scan/attack/defense/beacon) will fail. run with sudo.")
    threading.Thread(target=radio_watchdog, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, threaded=True)
