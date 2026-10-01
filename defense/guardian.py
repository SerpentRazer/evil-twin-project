#!/usr/bin/env python3
"""Evil-twin DEFENSE CONSOLE / GUARDIAN  (blue team).

The countermeasure to the attack side. It:
  1. DETECTS evil twins on the air (reuses the detector's infra-aware scoring)
     and auto-adds each confirmed rogue BSSID to a live BLOCKLIST.
  2. Sees CONNECTION ATTEMPTS toward a blocklisted rogue — auth / association /
     data frames whose BSSID is the rogue tell you *which device* is walking into
     the trap, before it's fully joined.
  3. ALERTS everywhere at that moment: defender dashboard + desktop popup
     (notify-send) + phone push (ntfy) — "⚠ DO NOT CONNECT".
  4. Optional ACTIVE CONTAINMENT: targeted deauth to break/deny the victim's
     link to the rogue (like commercial WIPS "rogue containment").
     ⚠ authorized / own-devices only — this transmits.

LIVE only: needs root + AR9271 in monitor mode.

    sudo python3 guardian.py                               # live dashboard on :8081
    sudo DEF_CONTAIN=1 python3 guardian.py                 # + containment
    sudo DEF_NTFY_TOPIC=my-evil-twin-alerts python3 guardian.py   # + phone push

Client guardian (runs on the protected laptop): see guardian_client.py.
"""
import os, sys, json, time, threading, subprocess, urllib.request
from collections import deque
from flask import Flask, request, Response

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)                         # to reuse the detector's logic

CONTAIN = os.environ.get("DEF_CONTAIN", "0") == "1"
PORT = int(os.environ.get("DEF_PORT", "8081"))
IFACE = os.environ.get("DEF_IFACE", "wlan0mon")
NTFY_TOPIC = os.environ.get("DEF_NTFY_TOPIC", "")     # e.g. "raz-evil-twin-alerts"
NTFY_URL = os.environ.get("DEF_NTFY_URL", "https://ntfy.sh")

app = Flask(__name__)

_lock = threading.Lock()
CONSOLE = deque(maxlen=500)
EVIL = {}                 # bssid -> {ssid, channel, crypto, reasons, ts}
BLOCKLIST = set()         # bssid strings
ATTEMPTS = deque(maxlen=100)
STATE = {"active": True, "contain": CONTAIN, "known": 0, "pinned_channel": None}


# ---------------- alerting fan-out ----------------

def clog(line, tag="def"):
    ts = time.strftime("%H:%M:%S")
    with _lock:
        CONSOLE.append((ts, line if tag == "def" else f"[{tag}] {line}"))
    print(f"{ts} {line}", flush=True)


def notify_desktop(title, msg):
    """Best-effort desktop popup on the defender box (Linux notify-send)."""
    try:
        subprocess.Popen(["notify-send", "-u", "critical", "-i", "security-high",
                          title, msg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def notify_phone(title, msg, tags="warning,rotating_light", priority="urgent"):
    """Best-effort phone push via ntfy.sh (install the ntfy app, subscribe to the topic)."""
    if not NTFY_TOPIC:
        return
    def _send():
        try:
            req = urllib.request.Request(
                f"{NTFY_URL.rstrip('/')}/{NTFY_TOPIC}", data=msg.encode(),
                headers={"Title": title, "Priority": priority, "Tags": tags})
            urllib.request.urlopen(req, timeout=4)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()


def raise_alert(title, msg, tag="ALERT"):
    """Fire on every channel at once."""
    clog(f"*** {title} — {msg}", tag)
    notify_desktop(title, msg)
    notify_phone(title, msg)


# ---------------- detection events ----------------

def on_evil_twin(bssid, ssid, channel, crypto, reasons):
    with _lock:
        if bssid in EVIL:
            return
        EVIL[bssid] = {"ssid": ssid, "channel": channel, "crypto": crypto,
                       "reasons": reasons, "ts": time.strftime("%H:%M:%S")}
        BLOCKLIST.add(bssid)
        STATE["pinned_channel"] = channel        # lock onto the rogue's channel
    clog(f"EVIL TWIN DETECTED: \"{ssid}\" {bssid} ch{channel} "
         f"{','.join(crypto or ['OPEN'])} → BLOCKLISTED", "detect")
    for r in (reasons or []):
        clog(f"   ↳ {r}", "detect")
    raise_alert("🛡 Evil twin detected",
                f"Rogue \"{ssid}\" ({bssid}) is impersonating a known network. Blocklisted.",
                tag="detect")


def on_connect_attempt(sta, bssid):
    ssid = EVIL.get(bssid, {}).get("ssid", "?")
    with _lock:
        ATTEMPTS.appendleft({"ts": time.strftime("%H:%M:%S"), "sta": sta,
                             "bssid": bssid, "ssid": ssid,
                             "action": "contained" if STATE["contain"] else "warned"})
    raise_alert("⚠ DO NOT CONNECT",
                f"Device {sta} is trying to join the FAKE \"{ssid}\" ({bssid}). "
                f"This is an evil twin — do not connect.", tag="ATTEMPT")
    if STATE["contain"]:
        contain(sta, bssid)


def contain(sta, bssid):
    """Targeted deauth to deny the victim's link to the rogue."""
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
        pkts = [RadioTap()/Dot11(addr1=sta, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7),
                RadioTap()/Dot11(addr1=bssid, addr2=sta, addr3=bssid)/Dot11Deauth(reason=7)]
        sendp(pkts, iface=IFACE, count=8, inter=0.05, verbose=False)
        clog(f"CONTAINMENT: deauth ×16 to {sta} ⇄ {bssid} — link denied", "contain")
    except Exception as e:
        clog(f"CONTAINMENT failed: {e}", "contain")


# ============================================================ LIVE ENGINE ==

def live_engine():
    from scapy.all import (sniff, Dot11, Dot11Beacon, Dot11Auth, Dot11AssoReq,
                           Dot11ReassoReq, RadioTap)
    import itertools
    from evil_twin_detect import (load_baseline, fingerprint, get_rssi, get_ssid,
                                  classify_new_bssid, MIN_BEACONS_NEW)

    baseline = load_baseline()
    STATE["known"] = len(baseline)
    clog(f"DEFENSE ACTIVE — guarding {len(baseline)} known networks on {IFACE}")
    if not baseline:
        clog("!! no baseline.json — run the detector's learn mode first for best results", "detect")

    candidates, cand_rssi = {}, {}

    def hopper():
        for ch in itertools.cycle([1, 6, 11]):
            pin = STATE["pinned_channel"]
            use = pin if pin else ch
            subprocess.call(["iw", "dev", IFACE, "set", "channel", str(use)],
                            stderr=subprocess.DEVNULL)
            time.sleep(0.8)
    threading.Thread(target=hopper, daemon=True).start()

    def handle(pkt):
        # --- connection attempts toward a blocklisted rogue ---
        if pkt.haslayer(Dot11Auth) or pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq):
            d = pkt.getlayer(Dot11)
            ap, sta = (d.addr1 or "").lower(), (d.addr2 or "").lower()
            if ap in BLOCKLIST and sta:
                on_connect_attempt(sta, ap)
            return
        # --- evil-twin discovery ---
        if not pkt.haslayer(Dot11Beacon):
            return
        bssid = (pkt[Dot11].addr2 or "").lower()
        ssid = get_ssid(pkt, Dot11Beacon)
        if not bssid or not ssid or ssid not in baseline or bssid in baseline[ssid]:
            return
        if bssid in EVIL:
            return
        rssi = get_rssi(pkt)
        fp = fingerprint(pkt)
        key = bssid
        candidates[key] = candidates.get(key, 0) + 1
        if rssi is not None:
            cand_rssi[key] = rssi if cand_rssi.get(key) is None else max(cand_rssi[key], rssi)
        if candidates[key] < MIN_BEACONS_NEW:
            return
        verdict, conf, reasons = classify_new_bssid(bssid, cand_rssi.get(key, rssi), fp, baseline[ssid])
        if verdict == "evil":
            on_evil_twin(bssid, ssid, fp.get("channel"), fp.get("crypto"), reasons)

    sniff(iface=IFACE, prn=handle, store=False)


# ============================================================ DEMO ENGINE ==

def demo_engine():
    STATE["known"] = 62
    clog("DEFENSE ACTIVE — guarding 62 known networks (SIM)")
    time.sleep(2)
    clog("[SIM] beacon storm — scoring new BSSIDs against baseline…", "detect")
    time.sleep(2)
    on_evil_twin("4e:49:6c:40:10:aa", "PRV_GUEST", 6, ["OPEN"],
                 ["OUI 4e:49:6c is not part of this network's known hardware",
                  "signal -24 dBm is 43 dB LOUDER than the real AP's peak (-67)"])
    victims = [("a4:83:e7:11:02:d0", 3), ("6a:7e:db:34:04:9e", 5), ("6c:1f:8a:79:0a:b0", 4)]
    for sta, delay in victims:
        time.sleep(delay)
        clog(f"[SIM] {sta} → Auth/AssocReq to 4e:49:6c:40:10:aa (rogue)", "detect")
        on_connect_attempt(sta, "4e:49:6c:40:10:aa")
    time.sleep(2)
    clog("[SIM] demo complete — rogue blocklisted, victims warned"
         + (" & contained" if STATE["contain"] else ""))


# ============================================================ routes ==

def state():
    with _lock:
        return {"active": STATE["active"], "contain": STATE["contain"],
                "known": STATE["known"], "pinned_channel": STATE["pinned_channel"],
                "ntfy": bool(NTFY_TOPIC), "ntfy_topic": NTFY_TOPIC,
                "evil": [{"bssid": b, **v} for b, v in EVIL.items()],
                "blocklist": sorted(BLOCKLIST),
                "attempts": list(ATTEMPTS)}


@app.route("/")
def index():
    with open(os.path.join(HERE, "defense.html")) as f:
        return Response(f.read(), mimetype="text/html")


@app.route("/api/state")
def api_state():
    return Response(json.dumps({**state(), "mode": "LIVE"}),
                    mimetype="application/json")


@app.route("/api/logs")
def api_logs():
    with _lock:
        return Response("\n".join(f"{t}  {l}" for t, l in CONSOLE), mimetype="text/plain")


@app.route("/api/blocklist")
def api_blocklist():
    """Consumed by guardian_client.py on protected devices."""
    with _lock:
        return Response(json.dumps([{"bssid": b, "ssid": EVIL.get(b, {}).get("ssid")}
                                    for b in BLOCKLIST]), mimetype="application/json")


@app.route("/api/toggle", methods=["POST"])
def api_toggle():
    STATE["contain"] = bool((request.json or {}).get("contain"))
    clog(f"active containment {'ENABLED — will deauth rogue links' if STATE['contain'] else 'disabled — warn-only'}")
    return Response(json.dumps({"contain": STATE["contain"]}), mimetype="application/json")


if __name__ == "__main__":
    clog(f"guardian up on :{PORT}  mode=LIVE  "
         f"contain={'ON' if CONTAIN else 'off'}  phone={'ntfy:'+NTFY_TOPIC if NTFY_TOPIC else 'off'}")
    threading.Thread(target=live_engine, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, threaded=True)
