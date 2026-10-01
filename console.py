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

LIVE only — needs root. MULTI-RADIO: each role (attack / defense / beacon) is
mapped to a monitor-capable adapter. Roles on DIFFERENT adapters run at the SAME
time — the headline being a live evil twin (RED) caught live by the detector
(BLUE). Roles sharing one adapter stay mutually exclusive (so with a single
adapter it degrades to the old one-job-at-a-time behaviour automatically).

Role assignment is automatic and capability-based: the best-injection USB
adapter takes ATTACK (airbase-ng), the AR9271 takes DEFENSE, and BEACON shares
the defense radio (or a third adapter if present). Override per role with
CON_ATTACK_IFACE / CON_DEFENSE_IFACE / CON_BEACON_IFACE, or force everything onto
one radio with CON_IFACE (legacy single-radio mode).

    sudo python3 console.py            # http://127.0.0.1:8080

Safety: fixed action allow-list; SSID sanitized + passed via env/argv, never a
shell string; channel forced to int 1-14. Authorized / own-devices use only.
"""
import os
import sys
import glob
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

# ---- per-role interface overrides (else auto-assigned by capability) ----
ENV_ATTACK = os.environ.get("CON_ATTACK_IFACE")
ENV_DEFENSE = os.environ.get("CON_DEFENSE_IFACE")
ENV_BEACON = os.environ.get("CON_BEACON_IFACE")
LEGACY_IFACE = os.environ.get("CON_IFACE")          # force all roles onto one radio

# Injection/AP quality by driver — used only to order the NON-Atheros adapters
# when picking ATTACK (the Atheros is pinned to DEFENSE+BEACON by policy in
# assign_roles). Higher = preferred for the fake AP among the remaining radios.
INJECTION_RANK = {
    "rtl88xxau": 90, "rtl8814au": 90, "8821au": 85, "rtl8812au": 90,   # need aircrack DKMS driver
    "mt76x2u": 92, "mt7612u": 92, "mt76x0u": 60, "mt7921u": 70, "mt76": 85,
    "ath9k_htc": 80,                                # AR9271 — best AP-mode USB adapter here
    "carl9170": 55, "rt2800usb": 55,
    "rtl8192cu": 40, "rtl8xxxu": 40, "rtl8188ru": 40, "rtl8187": 35,    # AWUS036NHR family: defense
}
UNKNOWN_USB_RANK = 50                               # unknown adapter: below known-good ath9k_htc

ROLES = {"attack": None, "defense": None, "beacon": None}
RADIOS = {}                                         # iface -> health/role dict (for the UI)
_mon_cache = {}                                     # iface -> bool monitor-capable (cached)
_radio_fix = {}                                     # iface -> last auto-heal ts

app = Flask(__name__)

# ---------------- unified console log ----------------

BEACON_LOG = deque(maxlen=200)
_blue = {"sniffer": None, "hop_stop": None, "running": False}
_beacon = {"proc": None}


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


# ======================================================= RADIO MANAGER ====
# Enumerate monitor-capable adapters and map the three roles onto them. Driver-
# agnostic: a second adapter of any chipset is picked up automatically.

def list_wifaces():
    out = []
    for net in glob.glob("/sys/class/net/*"):
        name = os.path.basename(net)
        if name.startswith("wl") and os.path.exists(os.path.join(net, "wireless")):
            out.append(name)
    return sorted(out)


def _driver(iface):
    try:
        return os.path.basename(os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
    except OSError:
        return ""


def _bus(iface):
    path = os.path.realpath(f"/sys/class/net/{iface}/device")
    if "/usb" in path:
        return "usb"
    if "/pci" in path:
        return "pci"
    return "other"


def _supports_monitor(iface):
    if iface in _mon_cache:
        return _mon_cache[iface]
    ok = False
    try:
        phy = open(f"/sys/class/net/{iface}/phy80211/name").read().strip()
        info = subprocess.check_output(["iw", "phy", phy, "info"], text=True,
                                       stderr=subprocess.DEVNULL)
        ok = "* monitor" in info
    except Exception:
        ok = False
    _mon_cache[iface] = ok
    return ok


def _rank(driver):
    return INJECTION_RANK.get(driver, UNKNOWN_USB_RANK)


def radio_info(iface):
    drv = _driver(iface)
    return {"iface": iface, "driver": drv, "bus": _bus(iface),
            "monitor": _supports_monitor(iface), "rank": _rank(drv)}


def list_monitor_radios():
    """Monitor-capable radios, best-for-attack first. USB adapters preferred;
    the internal (PCI, e.g. iwlwifi) card is excluded from auto-assignment since
    it carries the system's internet."""
    radios = [radio_info(i) for i in list_wifaces()]
    radios = [r for r in radios if r["monitor"]]
    usb = [r for r in radios if r["bus"] == "usb"]
    pool = usb or radios                            # fall back to any monitor radio
    pool.sort(key=lambda r: r["rank"], reverse=True)
    return pool


def role_active(role):
    if role == "attack":
        r = red_status()
        return bool(r.get("airbase") or r.get("portal") or r.get("scanning"))
    if role == "defense":
        return _blue["running"]
    if role == "beacon":
        return beacon_running()
    return False


def assign_roles():
    """(Re)map attack/defense/beacon onto present adapters. Only idle roles are
    (re)assigned, so a hotplug or re-enumeration never yanks a running job."""
    pool = list_monitor_radios()                    # sorted best-injection first
    names = [r["iface"] for r in pool]
    ath = next((r["iface"] for r in pool if r["driver"] == "ath9k_htc"), None)

    if LEGACY_IFACE:                                # force single-radio
        atk = deff = bcn = LEGACY_IFACE
    else:
        # POLICY: the Atheros AR9271 is used ONLY for ATTACK (airbase-ng is
        # bulletproof on ath9k_htc); the other, higher-power adapter (e.g. the
        # AWUS036NHR, 1W) does DEFENSE + BEACON — its range helps the detector
        # hear the twin from far and makes the warning beacon loud. Falls back
        # sanely with no Atheros or only one adapter.
        atk = ENV_ATTACK or ath or (names[0] if names else None)
        deff = ENV_DEFENSE or next((n for n in names if n != atk), atk)
        bcn = ENV_BEACON or deff                    # beacon with detection, NOT the Atheros

    desired = {"attack": atk, "defense": deff, "beacon": bcn}
    for role, iface in desired.items():
        # always do the first assignment; afterwards don't yank a running job's radio
        if iface and (ROLES[role] is None or not role_active(role)):
            ROLES[role] = iface
    if ROLES["attack"]:
        ops.IFACE = ROLES["attack"]
    if ROLES["defense"]:
        guard.IFACE = ROLES["defense"]


def iface_busy_by_other(role):
    """If the iface this role would use is already held by another ACTIVE role,
    return that role's name (so we refuse to double-book one adapter)."""
    me = ROLES.get(role)
    for other in ("attack", "defense", "beacon"):
        if other != role and ROLES.get(other) == me and role_active(other):
            return other
    return None


def dual_radio():
    return ROLES["attack"] and ROLES["defense"] and ROLES["attack"] != ROLES["defense"]


def roles_summary():
    if dual_radio():
        return (f"attack={ROLES['attack']} defense={ROLES['defense']} "
                f"beacon={ROLES['beacon']} — DUAL-RADIO: attack+defense can run together")
    return (f"attack={ROLES['attack']} defense={ROLES['defense']} beacon={ROLES['beacon']} "
            f"— single radio: one job at a time")


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
    busy = iface_busy_by_other("defense")
    if busy:
        guard.clog(f"!! cannot start defense: {ROLES['defense']} is busy with {busy.upper()} "
                   f"— add a 2nd monitor adapter or stop {busy}", "detect")
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

    dif = ROLES["defense"]                          # defense radio (own, != attack when dual)
    baseline = load_baseline()
    guard.STATE["known"] = len(baseline)
    guard.clog(f"DEFENSE ACTIVE — guarding {len(baseline)} known networks on {dif}")
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
            subprocess.call(["iw", "dev", dif, "set", "channel", str(use)],
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

    sniffer = AsyncSniffer(iface=dif, prn=handle, store=False)
    try:
        sniffer.start()
    except Exception as e:
        hop_stop.set()
        guard.clog(f"!! sniff failed on {dif} (monitor mode up?): {e}", "detect")
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
    busy = iface_busy_by_other("beacon")
    if busy:
        blog(f"cannot start beacon: {ROLES['beacon']} is busy with {busy.upper()} "
             f"— stop {busy} or use a separate adapter")
        return False
    bif = ROLES["beacon"]
    env = dict(os.environ)
    env["WB_IFACE"] = bif
    env["WB_CHANNEL"] = str(guard_sanitize_channel(channel))
    cmd = ["python3", os.path.join(ROOT, "defense", "warn_beacon.py")] + [s for s in ssids if s.strip()]
    blog(f"$ WB_IFACE={bif} WB_CHANNEL={env['WB_CHANNEL']} warn_beacon.py {' '.join(ssids)}")
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
# Multi-radio demo-proofing: re-assign idle roles on hotplug/re-enumeration, and
# auto-heal an adapter that silently fell out of monitor mode while a job on it
# is running. A glitch on stage is the #1 way to lose; this self-recovers.

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


def _heal_monitor(iface, want_ch):
    now = time.time()
    if now - _radio_fix.get(iface, 0) < 8:
        return False
    _radio_fix[iface] = now
    ops.log(f"radio {iface} fell out of monitor — auto-healing (ch{want_ch})")
    for c in (f"nmcli device set {iface} managed no",
              f"ip link set {iface} down",
              f"iw dev {iface} set type monitor",
              f"ip link set {iface} up",
              f"iw dev {iface} set channel {want_ch}"):
        subprocess.call(["bash", "-c", c + " >/dev/null 2>&1 || true"])
    return True


def _want_channel(iface):
    if iface == ROLES.get("attack") and ops.TARGET.get("channel"):
        return ops.TARGET["channel"]
    if iface == ROLES.get("defense"):
        return guard.STATE.get("pinned_channel") or 6
    return 6


def radio_watchdog():
    while True:
        try:
            assign_roles()                          # pick up hotplug / re-enumeration (idle roles)
            present = {r["iface"]: r for r in (radio_info(i) for i in list_wifaces())}
            # which roles each assigned iface serves
            role_of = {}
            for role in ("attack", "defense", "beacon"):
                role_of.setdefault(ROLES.get(role), []).append(role)
            new = {}
            for iface, roles in role_of.items():
                if not iface:
                    continue
                info = present.get(iface)
                rec = {"iface": iface, "roles": roles,
                       "driver": info["driver"] if info else "",
                       "present": bool(info), "mode": None, "channel": None,
                       "healthy": True, "note": ""}
                if not info:
                    rec.update(healthy=False,
                               note=f"adapter for {','.join(roles)} missing — replug USB")
                else:
                    mode, ch = _iface_mode(iface)
                    rec.update(mode=mode, channel=ch)
                    want_mon = any(role_active(r) for r in roles)
                    if want_mon and mode != "monitor":
                        if _heal_monitor(iface, _want_channel(iface)):
                            rec["note"] = "recovered monitor mode"
                        rec["healthy"] = False
                    else:
                        rec["healthy"] = (mode == "monitor") if want_mon else True
                new[iface] = rec
            RADIOS.clear()
            RADIOS.update(new)
        except Exception as e:
            RADIOS["_err"] = {"iface": "_err", "roles": [], "present": False,
                              "healthy": False, "note": f"watchdog error: {e}"}
        time.sleep(3)


# ============================================================ status ====

def unified_status():
    r = red_status()
    g = guard.state()
    radios = [RADIOS[k] for k in sorted(RADIOS) if k != "_err"]
    overall_ok = all(x.get("healthy") for x in radios) if radios else True
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
        "roles": dict(ROLES),
        "dual_radio": bool(dual_radio()),
        "iface": ROLES.get("attack"),               # legacy field = attack radio
        "radios": radios,
        "radio_ok": overall_ok,
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
        elif iface_busy_by_other("attack"):
            ops.log(f"!! {ROLES['attack']} busy with {iface_busy_by_other('attack').upper()} "
                    f"— attack needs its own radio")
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
    assign_roles()
    ops.log(f"unified console up on :{PORT}  {roles_summary()}")
    if os.geteuid() != 0:
        ops.log("!! not root — radio actions (scan/attack/defense/beacon) will fail. run with sudo.")
    threading.Thread(target=radio_watchdog, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, threaded=True)
