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
KNOWN_FILE = os.environ.get("DEF_KNOWN", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                      "known_devices.json"))
KNOWN = {}    # mac(lower) -> {name, vendor?, ntfy?, contain?}  per-device policy

app = Flask(__name__)

_lock = threading.Lock()
CONSOLE = deque(maxlen=500)
EVIL = {}                 # bssid -> {ssid, channel, crypto, reasons, ts}
BLOCKLIST = set()         # bssid strings
ATTEMPTS = deque(maxlen=100)
STATE = {"active": True, "contain": CONTAIN, "known": 0, "known_devices": 0,
         "pinned_channel": None}


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


def notify_phone(title, msg, tags="warning,rotating_light", priority="urgent", topic=None):
    """Best-effort phone push via ntfy.sh (install the ntfy app, subscribe to the topic).

    `topic` overrides the global DEF_NTFY_TOPIC so a known device can route its
    alert to its own owner's topic (see known_devices.json)."""
    dest = topic or NTFY_TOPIC
    if not dest:
        return
    def _send():
        try:
            req = urllib.request.Request(
                f"{NTFY_URL.rstrip('/')}/{dest}", data=msg.encode(),
                headers={"Title": title, "Priority": priority, "Tags": tags})
            urllib.request.urlopen(req, timeout=4)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()


def raise_alert(title, msg, tag="ALERT", topic=None):
    """Fire on every channel at once; `topic` routes the phone push per-device."""
    clog(f"*** {title} — {msg}", tag)
    notify_desktop(title, msg)
    notify_phone(title, msg, topic=topic)


# ---------------- device fingerprint ----------------

_manufdb = None


def load_known():
    """Load per-device policy from known_devices.json: MAC -> {name, ntfy?, contain?}.

    Lets the guardian NAME a device instead of only its vendor (and name a phone
    whose MAC is randomized, which hides the vendor), and route/contain it per
    device. Unknown devices fall back to deauth containment — the only app-less
    reach to a stranger's phone. Hot-reloadable via /api/known."""
    global KNOWN
    try:
        with open(KNOWN_FILE) as f:
            raw = json.load(f)
        KNOWN = {str(k).lower(): (v if isinstance(v, dict) else {"name": str(v)})
                 for k, v in raw.items()}
        STATE["known_devices"] = len(KNOWN)
        clog(f"loaded {len(KNOWN)} known device(s) from {os.path.basename(KNOWN_FILE)}")
    except FileNotFoundError:
        KNOWN = {}
        STATE["known_devices"] = 0
    except Exception as e:
        KNOWN = {}
        STATE["known_devices"] = 0
        clog(f"known_devices.json parse error: {e} — all devices treated as unknown", "detect")
    return KNOWN


def _oui_vendor(mac):
    """Best-effort hardware vendor from the OUI, via scapy's IEEE manuf DB.
    Returns the short vendor name, or None if unknown."""
    global _manufdb
    try:
        if _manufdb is None:
            from scapy.all import conf
            _manufdb = conf.manufdb
        short, long = _manufdb.lookup(mac)
        return short or long or None
    except Exception:
        return None


def fingerprint_device(mac):
    """Identify a station reaching for a rogue.

    Phones (iOS 14+/Android 10+) randomize their MAC per-SSID by setting the
    locally-administered (U/L) bit — so for exactly the devices that matter the
    real vendor is HIDDEN. We flag that honestly instead of guessing a vendor
    off a randomized address. A globally-unique MAC gets an OUI vendor lookup.

    Returns {vendor, randomized, known, name, policy, label}. A MAC listed in
    known_devices.json wins over any heuristic — that's how we put a real NAME
    on a device whose randomized MAC otherwise hides its vendor.
    """
    mac = (mac or "").lower()
    pol = KNOWN.get(mac)
    if pol:
        return {"vendor": pol.get("vendor"), "randomized": False, "known": True,
                "name": pol.get("name"), "policy": pol,
                "label": pol.get("name") or "known device"}
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return {"vendor": None, "randomized": False, "known": False,
                "name": None, "policy": None, "label": "unknown device"}
    if first_octet & 0x02:                       # U/L bit set → randomized / private
        return {"vendor": None, "randomized": True, "known": False,
                "name": None, "policy": None,
                "label": "randomized MAC (privacy) — vendor hidden"}
    vendor = _oui_vendor(mac)
    return {"vendor": vendor, "randomized": False, "known": False,
            "name": None, "policy": None, "label": vendor or "unknown vendor"}


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
    fp = fingerprint_device(sta)
    policy = fp.get("policy") or {}
    # Routing (known_devices.json): a KNOWN device is warned by name and only
    # contained if its own policy opts in (default off — don't deauth your own
    # gear); an UNKNOWN device falls back to deauth containment, the only
    # app-less way to reach a stranger's phone. Containment still requires the
    # global toggle to be on.
    if fp.get("known"):
        do_contain = STATE["contain"] and bool(policy.get("contain", False))
    else:
        do_contain = STATE["contain"]
    who = fp.get("name") or fp["label"]
    with _lock:
        ATTEMPTS.appendleft({"ts": time.strftime("%H:%M:%S"), "sta": sta,
                             "bssid": bssid, "ssid": ssid,
                             "vendor": fp["vendor"], "device": fp["label"],
                             "name": fp.get("name"), "known": fp.get("known"),
                             "randomized": fp["randomized"],
                             "action": "contained" if do_contain else "warned"})
    raise_alert("⚠ DO NOT CONNECT",
                f"Device {sta} ({who}) is trying to join the FAKE \"{ssid}\" ({bssid}). "
                f"This is an evil twin — do not connect.",
                tag="ATTEMPT", topic=policy.get("ntfy"))
    if do_contain:
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
                                  classify_new_bssid, MIN_BEACONS_NEW, CHANNELS)

    baseline = load_baseline()
    STATE["known"] = len(baseline)
    load_known()
    clog(f"DEFENSE ACTIVE — guarding {len(baseline)} known networks on {IFACE}")
    if not baseline:
        clog("!! no baseline.json — run the detector's learn mode first for best results", "detect")

    candidates, cand_rssi = {}, {}

    def hopper():
        for ch in itertools.cycle(CHANNELS):
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


# ============================================================ routes ==

def state():
    with _lock:
        return {"active": STATE["active"], "contain": STATE["contain"],
                "known": STATE["known"], "known_devices": STATE["known_devices"],
                "pinned_channel": STATE["pinned_channel"],
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


@app.route("/api/known", methods=["GET", "POST"])
def api_known():
    """GET lists the per-device policy; POST hot-reloads known_devices.json."""
    if request.method == "POST":
        load_known()
    with _lock:
        return Response(json.dumps({"count": len(KNOWN),
                                    "devices": [{"mac": m, **v} for m, v in KNOWN.items()]}),
                        mimetype="application/json")


@app.route("/api/toggle", methods=["POST"])
def api_toggle():
    STATE["contain"] = bool((request.json or {}).get("contain"))
    clog(f"active containment {'ENABLED — will deauth rogue links' if STATE['contain'] else 'disabled — warn-only'}")
    return Response(json.dumps({"contain": STATE["contain"]}), mimetype="application/json")


if __name__ == "__main__":
    load_known()
    clog(f"guardian up on :{PORT}  mode=LIVE  "
         f"contain={'ON' if CONTAIN else 'off'}  phone={'ntfy:'+NTFY_TOPIC if NTFY_TOPIC else 'off'}  "
         f"known-devices={STATE['known_devices']}")
    threading.Thread(target=live_engine, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, threaded=True)
