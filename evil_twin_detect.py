#!/usr/bin/env python3
"""Evil Twin Detector — passive WIDS-style detector for one adapter.

Passive-only (no association, no traffic tampering — see project guardrails).
See EVIL-TWIN-CONCEPTS.md for the full reasoning; summary of the logic:

An evil twin = the same SSID broadcast from a NEW device (BSSID) that is not
part of the real network's known hardware. The hard part is NOT crying wolf on
legitimate multi-AP networks, which routinely put one SSID on many BSSIDs across
channels 1/6/11 and derive per-SSID virtual BSSIDs (often with the
locally-administered bit set) from a shared base MAC. So we do INFRA-AWARE
scoring, not "any new/different BSSID is evil".

For a beacon whose SSID is known but BSSID is new, we build a profile from the
baseline (trusted OUIs, base-MAC prefixes, whether the net is secured
everywhere, the real APs' loudest RSSI) and score:

1. SECURITY DOWNGRADE (strongest)  — net secured everywhere but new BSSID is
   OPEN. The attacker lacks the PSK; a real AP of a secured SSID is never Open.
2. FOREIGN OUI / BASE-MAC           — new BSSID's OUI+prefix not among the
   network's known hardware. Same-OUI / same-radio-prefix => same operator =>
   benign (this is what stops multi-AP false positives).
3. RELATIVE RSSI (corroborating)    — new BSSID far LOUDER than the real AP's
   learned peak => attacker closer / higher power.
4. DEAUTH FLOOD                     — classic companion attack.
5. KARMA / PROBE PROMISCUITY        — one BSSID answering many SSIDs.

Verdicts: BENIGN (same infra, not flagged) / REVIEW=yellow (unrecognized, no
corroboration) / EVIL=red (downgrade, or foreign-OUI + louder).

Deliberately NOT used as evidence: channel difference and supported-rates/HT
difference between BSSIDs of one SSID — legit multi-AP ESS spans channels and
mixes AP models by design, so these produced false HIGH-confidence alerts.
A locally-administered MAC is likewise NOT suspicious alone (legit virtual
BSSIDs set it) — only combined with a foreign OUI.

Not implemented: clock-skew/TSF fingerprinting (needs hardware radiotap
timestamps for accuracy; unreliable with a USB adapter in a VM + channel
hopping — produces false skews in the hundreds/thousands of ppm when real
drift is only tens of ppm, so it's intentionally left out). Also out of
scope for one passive adapter: sequence-number cross-check, triangulation,
RTT/gateway validation, 802.1X/RADIUS cert validation. 2.4GHz ch 1/6/11 only.

Usage:
    sudo python3 evil_twin_detect.py --learn 60      # build/refresh baseline
    sudo python3 evil_twin_detect.py                 # watch using saved baseline
    sudo python3 evil_twin_detect.py --learn 60 --watch
"""
from scapy.all import (sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Deauth,
                        Dot11Elt, RadioTap)
from collections import defaultdict, deque
import threading, subprocess, itertools, time, sys, json, argparse, os, socket

IFACE = os.environ.get("ET_IFACE", "wlan0mon")   # start-detector.sh sets ET_IFACE
BASELINE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.json")
HOP = True

# ---------------- UDP push to M4 dashboard ----------------
# Leave ET_M4_IP unset for now; bind it at the very end once the dashboard is
# ready:  export ET_M4_IP=192.168.x.x    (no code change needed). Until then
# send_udp() is a no-op, so the detector runs and prints exactly as before.
M4_IP = os.environ.get("ET_M4_IP", "")
M4_PORT = int(os.environ.get("ET_M4_PORT", "9999"))
_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_udp(msg_type, **fields):
    """Fire one JSON packet at the M4 dashboard (fire-and-forget)."""
    if not M4_IP:
        return
    payload = {"type": msg_type, "ts": time.time(), **fields}
    try:
        _udp_sock.sendto(json.dumps(payload).encode(), (M4_IP, M4_PORT))
    except OSError:
        pass

def heartbeat_loop():
    """Tell the dashboard the Kali detector is still alive."""
    while True:
        send_udp("heartbeat", iface=IFACE)
        time.sleep(5)

# ---------------- live inventory display ----------------
INVENTORY_INTERVAL = 3        # seconds between terminal redraw + inventory UDP push
RED, YELLOW, RESET, BOLD, DIM = "\033[91m", "\033[93m", "\033[0m", "\033[1m", "\033[2m"

MIN_BEACONS_NEW = 3           # new-BSSID candidates need this many sightings before alerting
STALE_AFTER = 60              # seconds of silence before dropping a live candidate
RSSI_CORRIDOR_MARGIN = 15     # dB beyond recorded min/max before flagging a known BSSID
RSSI_TWIN_LOUDER_MARGIN = 12  # dB a suspected twin must exceed the real AP's peak to corroborate
DEAUTH_WINDOW = 5             # seconds
DEAUTH_THRESHOLD = 10         # deauth frames within window from one source = flood
PROBE_SSID_THRESHOLD = 4      # distinct SSIDs one BSSID answers for = promiscuous/karma
PROBE_WINDOW = 30            # seconds to accumulate distinct probe-response SSIDs


def _parse_channels(val, default):
    chans = [int(c) for c in (val or "").split(",") if c.strip().isdigit()]
    return chans or default

# 2.4 GHz channels to hop while watching/learning. Default = the WHOLE band
# (1-13), so a twin is caught whatever channel the attacker's AP sits on — not
# just the 1/6/11 non-overlapping set (airbase-ng can be on any channel). Both
# the AR9271 (attack) and AWUS036NHR (defense) are 2.4 GHz-only, so this covers
# the attacker's entire reachable range. Override with ET_CHANNELS="1,6,11" to
# sweep faster, or add 5 GHz channels here if you ever use a 5 GHz monitor radio.
CHANNELS = _parse_channels(os.environ.get("ET_CHANNELS"), list(range(1, 14)))

# ---------------- helpers ----------------

def mac_prefix(bssid, n):
    """First n octets, lowercased — n=3 is the OUI (vendor), n=5 is the
    per-radio base-MAC prefix (virtual BSSIDs of one physical AP share it)."""
    return ":".join(bssid.lower().split(":")[:n])

def is_locally_administered(bssid):
    return bool(int(bssid.split(":")[0], 16) & 0x02)

def has_ht(pkt):
    """Walk 802.11 information elements; ID 45 = HT Capabilities (802.11n)."""
    el = pkt.getlayer(Dot11Elt)
    while el is not None and el.name == "802.11 Information Element":
        if el.ID == 45:
            return True
        el = el.payload.getlayer(Dot11Elt)
    return False

def fingerprint(pkt):
    try:
        stats = pkt[Dot11Beacon].network_stats()
    except Exception:
        stats = {}
    rates = stats.get("rates")
    return {
        "channel": stats.get("channel"),
        "crypto": sorted(stats.get("crypto", [])),
        "rates": sorted(rates) if rates else [],
        "ht": has_ht(pkt),
    }

def get_rssi(pkt):
    try:
        return pkt[RadioTap].dBm_AntSignal
    except Exception:
        return None

def get_ssid(pkt, layer):
    try:
        return pkt[layer].network_stats().get("ssid", "")
    except Exception:
        return ""

# ---------------- baseline I/O ----------------

def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return {}
    with open(BASELINE_FILE) as f:
        data = json.load(f)
    out = {}
    for ssid, bssids in data.items():
        upgraded = {}
        if isinstance(bssids, list):                     # oldest format: [bssid,...]
            for b in bssids:
                upgraded[b] = _blank_entry()
        else:
            for b, v in bssids.items():
                if not isinstance(v, dict):
                    v = _blank_entry()
                for k, dv in _blank_entry().items():
                    v.setdefault(k, dv)
                upgraded[b] = v
        out[ssid] = upgraded
    return out

def _blank_entry():
    return {"channel": None, "crypto": [], "rates": [], "ht": False,
            "rssi_min": None, "rssi_max": None}

def save_baseline(baseline):
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

def channel_hopper(iface):
    for ch in itertools.cycle(CHANNELS):
        subprocess.call(["iw", "dev", iface, "set", "channel", str(ch)],
                         stderr=subprocess.DEVNULL)
        time.sleep(0.8)

# ---------------- LEARN ----------------

def run_learn(duration):
    baseline = load_baseline()
    print(f"[*] LEARN mode for {duration}s — fingerprints + RSSI corridor on {IFACE}")
    if HOP:
        threading.Thread(target=channel_hopper, args=(IFACE,), daemon=True).start()

    def handle(pkt):
        if not pkt.haslayer(Dot11Beacon):
            return
        bssid = pkt[Dot11].addr2
        ssid = get_ssid(pkt, Dot11Beacon)
        if not bssid or not ssid:
            return
        fp = fingerprint(pkt)
        rssi = get_rssi(pkt)
        entry = baseline.setdefault(ssid, {}).setdefault(bssid, _blank_entry())
        entry.update({k: fp[k] for k in ("channel", "crypto", "rates", "ht")})
        if rssi is not None:
            entry["rssi_min"] = rssi if entry["rssi_min"] is None else min(entry["rssi_min"], rssi)
            entry["rssi_max"] = rssi if entry["rssi_max"] is None else max(entry["rssi_max"], rssi)

    sniff(iface=IFACE, prn=handle, store=False, timeout=duration)

    save_baseline(baseline)
    total_bssids = sum(len(v) for v in baseline.values())
    print(f"[*] Baseline saved: {len(baseline)} SSIDs, {total_bssids} BSSIDs -> {BASELINE_FILE}")
    return baseline

# ---------------- WATCH ----------------

def network_profile(known):
    """Summarize a known SSID's real infrastructure from the baseline:
    trusted vendor OUIs, per-radio base-MAC prefixes, whether it is secured on
    every known BSSID, and the loudest RSSI ever learned for it."""
    ouis, base5, peak = set(), set(), None
    secured_all, have_bssid = True, False
    for b, e in known.items():
        have_bssid = True
        ouis.add(mac_prefix(b, 3))
        base5.add(mac_prefix(b, 5))
        if not e.get("crypto"):
            secured_all = False
        if e.get("rssi_max") is not None:
            peak = e["rssi_max"] if peak is None else max(peak, e["rssi_max"])
    return {"ouis": ouis, "base5": base5, "peak": peak,
            "secured": secured_all and have_bssid}

def classify_new_bssid(bssid, rssi, fp, known):
    """Infra-aware verdict for a NEW BSSID broadcasting a KNOWN SSID.

    Returns (verdict, confidence, reasons) where verdict is one of:
      "benign" — same operator's hardware, just a BSSID the learn missed
      "review" — unrecognized, worth a human glance, not a confirmed twin
      "evil"   — real evil-twin signature (downgrade, or foreign-OUI + louder)

    Why each check: see EVIL-TWIN-CONCEPTS.md. Channel / rates / HT differences
    are intentionally NOT used — legit multi-AP ESS varies them by design.
    """
    prof = network_profile(known)
    new_crypto = fp.get("crypto") or []
    same_radio = mac_prefix(bssid, 5) in prof["base5"]   # same physical radio
    same_oui   = mac_prefix(bssid, 3) in prof["ouis"]    # same vendor infra
    laa        = is_locally_administered(bssid)
    downgrade  = prof["secured"] and not new_crypto      # secured net, OPEN twin
    louder = (rssi is not None and prof["peak"] is not None
              and rssi > prof["peak"] + RSSI_TWIN_LOUDER_MARGIN)

    reasons = []
    if downgrade:
        reasons.append("network is secured on every known AP but this BSSID is "
                       "OPEN — classic evil-twin downgrade (attacker has no PSK)")

    # Benign shortcuts — only when it's NOT an open-downgrade of a secured net.
    if not downgrade:
        if same_radio:
            return ("benign", "LOW",
                    [f"shares radio base-MAC {mac_prefix(bssid,5)}:.. with a known "
                     f"AP — same physical access point (virtual BSSID)"])
        if same_oui and not louder:
            return ("benign", "LOW",
                    [f"OUI {mac_prefix(bssid,3)} matches this network's known "
                     f"hardware — same operator, BSSID just unseen during learn"])

    if not same_oui:
        reasons.append(f"OUI {mac_prefix(bssid,3)} is not part of this network's "
                       f"known hardware (foreign vendor cloning the name)")
        if laa:
            reasons.append("locally-administered (software-set) MAC on a foreign OUI")
    if louder:
        reasons.append(f"signal {rssi} dBm is {rssi - prof['peak']} dB LOUDER than "
                       f"the real AP's peak ({prof['peak']}) — attacker likely "
                       f"closer / higher power")

    # Scoring.
    if downgrade or (not same_oui and louder):
        return ("evil", "HIGH", reasons)
    if not same_oui:
        return ("review", "MEDIUM", reasons)
    if louder:  # same OUI but suspiciously louder than the known APs
        return ("review", "MEDIUM",
                reasons + ["same OUI as known APs but much louder than any of them"])
    return ("benign", "LOW", reasons)

def run_watch(baseline):
    print(f"[*] WATCH mode on {IFACE} using baseline ({len(baseline)} known SSIDs) — Ctrl-C to stop")
    print(f"[*] UDP push: {'-> ' + M4_IP + ':' + str(M4_PORT) if M4_IP else 'disabled (set ET_M4_IP to enable)'}")
    if HOP:
        threading.Thread(target=channel_hopper, args=(IFACE,), daemon=True).start()
    threading.Thread(target=heartbeat_loop, daemon=True).start()

    candidate_counts = defaultdict(int)
    alerted = set()
    last_seen, last_fp, cand_rssi = {}, {}, {}
    rssi_spoof_alerted = set()
    deauth_events = defaultdict(deque)
    deauth_alerted = {}
    probe_ssids = defaultdict(dict)
    probe_alerted = {}

    # live inventory of every AP currently on air (bssid -> info), plus the set
    # of BSSIDs confirmed as evil twins and a rolling log of recent alerts.
    # One lock guards all three because the sniff callback and the redraw thread
    # both touch them.
    live_aps = {}
    evil_bssids = set()       # red — confirmed evil-twin signature
    review_bssids = set()     # yellow — unrecognized, needs a human glance
    recent_alerts = deque(maxlen=8)
    live_lock = threading.Lock()

    def log_alert(msg):
        recent_alerts.appendleft((time.strftime("%H:%M:%S"), msg))

    def alert_new_bssid(ssid, bssid, rssi, fp, known):
        verdict, confidence, reasons = classify_new_bssid(bssid, rssi, fp, known)
        crypto = fp.get("crypto") or ["OPEN"]
        if verdict == "benign":
            # Same operator's hardware, just unseen during learn. Fold it into
            # the baseline so we don't re-evaluate it every few seconds, and
            # don't raise an alert.
            known[bssid] = {**_blank_entry(), **{k: fp.get(k) for k in
                            ("channel", "crypto", "rates", "ht")}}
            if rssi is not None:
                known[bssid]["rssi_min"] = known[bssid]["rssi_max"] = rssi
            return
        if verdict == "evil":
            with live_lock:
                evil_bssids.add(bssid)
                log_alert(f"EVIL TWIN  \"{ssid}\"  {bssid}  conf={confidence}  "
                          f"ch{fp.get('channel')}  {','.join(crypto)}")
                for r in reasons:
                    log_alert(f"   ↳ {r}")
            send_udp("evil_twin", ssid=ssid, bssid=bssid, rssi=rssi,
                     channel=fp.get("channel"), crypto=crypto,
                     confidence=confidence, reasons=reasons)
        else:  # review
            with live_lock:
                review_bssids.add(bssid)
                log_alert(f"REVIEW  \"{ssid}\"  {bssid}  conf={confidence}  "
                          f"ch{fp.get('channel')}  {','.join(crypto)}")
                for r in reasons:
                    log_alert(f"   ↳ {r}")
            send_udp("suspicious_ap", ssid=ssid, bssid=bssid, rssi=rssi,
                     channel=fp.get("channel"), crypto=crypto,
                     confidence=confidence, reasons=reasons)

    def alert_rssi_spoof(ssid, bssid, rssi, corridor):
        with live_lock:
            log_alert(f"RSSI ANOMALY  \"{ssid}\"  {bssid}  rssi={rssi} vs corridor {corridor}")
        send_udp("rssi_anomaly", ssid=ssid, bssid=bssid, rssi=rssi,
                 corridor=list(corridor))

    def alert_deauth(bssid, count):
        with live_lock:
            log_alert(f"DEAUTH FLOOD  {bssid}  {count} frames / {DEAUTH_WINDOW}s")
        send_udp("deauth_flood", bssid=bssid, count=count, window=DEAUTH_WINDOW)

    def alert_karma(bssid, ssids):
        with live_lock:
            log_alert(f"KARMA  {bssid}  answered {len(ssids)} SSIDs: {', '.join(sorted(ssids))}")
        send_udp("karma", bssid=bssid, ssids=sorted(ssids), count=len(ssids))

    def render():
        """Clear the screen and redraw the full live AP table + recent alerts."""
        now = time.time()
        with live_lock:
            for b in [b for b, v in live_aps.items() if now - v["last"] > STALE_AFTER]:
                del live_aps[b]
            evil = set(evil_bssids)
            review = set(review_bssids)
            # sort: evil first, then review, then the rest — alphabetical within each
            rows = sorted(live_aps.values(),
                          key=lambda v: (v["bssid"] not in evil,
                                         v["bssid"] not in review,
                                         (v["ssid"] or "").lower()))
            alerts = list(recent_alerts)
        udp_state = f"-> {M4_IP}:{M4_PORT}" if M4_IP else "off (set ET_M4_IP)"
        out = ["\033[2J\033[H"]
        out.append(f"{BOLD}EVIL-TWIN DETECTOR{RESET}  live {time.strftime('%H:%M:%S')}   "
                   f"{len(rows)} APs on air   UDP {udp_state}   "
                   f"{RED}red = evil twin{RESET}  {YELLOW}yellow = review{RESET}")
        out.append("-" * 78)
        out.append(f"{BOLD}{'SSID':22.22} {'BSSID':17} {'CH':>3} {'CRYPTO':16.16} {'RSSI':>5}{RESET}")
        for v in rows:
            line = (f"{(v['ssid'] or '<hidden>'):22.22} {v['bssid']:17} "
                    f"{str(v['channel'] if v['channel'] is not None else '?'):>3} "
                    f"{','.join(v['crypto']):16.16} "
                    f"{str(v['rssi'] if v['rssi'] is not None else '?'):>5}")
            if v["bssid"] in evil:
                out.append(f"{RED}{line}  <<< EVIL TWIN{RESET}")
            elif v["bssid"] in review:
                out.append(f"{YELLOW}{line}  <<< review{RESET}")
            else:
                out.append(line)
        out.append("-" * 78)
        out.append(f"{BOLD}recent alerts:{RESET}")
        if not alerts:
            out.append(f"  {DIM}(none yet — watching){RESET}")
        for ts, msg in alerts:
            color = RED if msg.startswith("EVIL") else ""
            out.append(f"  {DIM}{ts}{RESET}  {color}{msg}{RESET}")
        print("\n".join(out), flush=True)

        aps_payload = [{"bssid": v["bssid"], "ssid": v["ssid"], "channel": v["channel"],
                        "crypto": v["crypto"], "rssi": v["rssi"],
                        "evil": v["bssid"] in evil,
                        "review": v["bssid"] in review} for v in rows]
        send_udp("inventory", count=len(aps_payload), aps=aps_payload)

    def inventory_loop():
        while True:
            time.sleep(INVENTORY_INTERVAL)
            render()

    def handle(pkt):
        now = time.time()

        if pkt.haslayer(Dot11Deauth):
            src = pkt[Dot11].addr2 or pkt[Dot11].addr3
            if src:
                dq = deauth_events[src]
                dq.append(now)
                while dq and now - dq[0] > DEAUTH_WINDOW:
                    dq.popleft()
                if len(dq) >= DEAUTH_THRESHOLD and now - deauth_alerted.get(src, 0) > DEAUTH_WINDOW:
                    deauth_alerted[src] = now
                    alert_deauth(src, len(dq))
            return

        if pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[Dot11].addr2
            ssid = get_ssid(pkt, Dot11ProbeResp)
            if bssid and ssid:
                d = probe_ssids[bssid]
                d[ssid] = now
                for s in list(d):
                    if now - d[s] > PROBE_WINDOW:
                        del d[s]
                if len(d) >= PROBE_SSID_THRESHOLD and now - probe_alerted.get(bssid, 0) > PROBE_WINDOW:
                    probe_alerted[bssid] = now
                    alert_karma(bssid, set(d.keys()))
            return

        if not pkt.haslayer(Dot11Beacon):
            return
        bssid = pkt[Dot11].addr2
        ssid = get_ssid(pkt, Dot11Beacon)
        if not bssid or not ssid:
            return
        rssi = get_rssi(pkt)
        fp = fingerprint(pkt)

        # record EVERY beacon into the live inventory (this is the full list the
        # dashboard shows) — before any known/candidate filtering below.
        with live_lock:
            live_aps[bssid] = {"bssid": bssid, "ssid": ssid, "channel": fp.get("channel"),
                               "crypto": fp.get("crypto") or ["OPEN"], "rssi": rssi, "last": now}

        known = baseline.get(ssid, {})

        if bssid in known:
            entry = known[bssid]
            # RSSI corridor check — LOUDER-ONLY. A known BSSID suddenly much
            # louder than ever learned can mean a spoofer replaying its MAC from
            # closer. A *weaker* signal is just distance/fading, so it is ignored
            # (flagging the weak side was pure false-positive noise).
            hi = entry.get("rssi_max")
            if rssi is not None and hi is not None and rssi > hi + RSSI_CORRIDOR_MARGIN:
                key = (ssid, bssid)
                if key not in rssi_spoof_alerted:
                    rssi_spoof_alerted.add(key)
                    alert_rssi_spoof(ssid, bssid, rssi, (entry.get("rssi_min"), hi))
            return

        if ssid not in baseline:
            return

        key = (ssid, bssid)
        candidate_counts[key] += 1
        last_seen[key] = now
        last_fp[key] = fp
        # Track the LOUDEST RSSI across this candidate's beacons — individual
        # beacons often arrive with no signal field (None), and the "louder than
        # the real AP" tell is what separates a real (closer) twin from a
        # legit-but-foreign neighbour AP, so classify on the peak, not one frame.
        if rssi is not None:
            cand_rssi[key] = rssi if cand_rssi.get(key) is None else max(cand_rssi[key], rssi)
        for k in list(candidate_counts):
            if now - last_seen.get(k, 0) > STALE_AFTER:
                del candidate_counts[k]
                last_seen.pop(k, None)
                last_fp.pop(k, None)
                cand_rssi.pop(k, None)
                alerted.discard(k)
        if candidate_counts[key] < MIN_BEACONS_NEW or key in alerted:
            return
        alerted.add(key)
        alert_new_bssid(ssid, bssid, cand_rssi.get(key, rssi), fp, known)

    threading.Thread(target=inventory_loop, daemon=True).start()
    sniff(iface=IFACE, prn=handle, store=False)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--learn", type=int, metavar="SECONDS")
    ap.add_argument("--watch", action="store_true")
    args = ap.parse_args()
    try:
        if args.learn:
            baseline = run_learn(args.learn)
            if not args.watch:
                sys.exit(0)
        else:
            baseline = load_baseline()
            if not baseline:
                print("[!] No baseline found. Run with --learn SECONDS first, e.g.:")
                print(f"      sudo python3 {sys.argv[0]} --learn 60")
                sys.exit(1)
        run_watch(baseline)
    except KeyboardInterrupt:
        print("\n[*] stopped")
        sys.exit(0)
