#!/usr/bin/env python3
"""Evil Twin Detector — passive WIDS-style detector for one adapter.

Passive-only (no association, no traffic tampering — see project guardrails).
Detection layers and why each exists:

1. BASELINE DEVIATION (core)
   Learn what's normal (SSID -> BSSID set) first; alert only on a NEW BSSID
   for an SSID we already know. Beats naive "SSID on 2+ BSSIDs", which
   false-positives on legit multi-AP deployments.

2. IE / CAPABILITY FINGERPRINT
   Per BSSID: channel, encryption/cipher, supported rates, HT (802.11n)
   capability. A cloned SSID rarely reproduces the real radio's exact
   fingerprint — above all encryption (a twin usually runs Open because it
   lacks the passphrase).

3. RSSI CORRIDOR
   Record each known BSSID's signal-strength range; a beacon claiming a
   known BSSID at a wildly different RSSI hints at a spoof from another spot.
   Noisy on its own -> treated as a hint, not proof.

4. DEAUTH FLOOD
   Evil twins are often paired with deauth floods to push victims off the
   real AP. Passive to detect.

5. PROBE-RESPONSE PROMISCUITY ("Karma")
   A real AP answers probes only for its own SSID(s); a rogue/Pineapple
   answers for many. One BSSID replying with many distinct SSIDs is a tell.

Not implemented: clock-skew/TSF fingerprinting (needs hardware radiotap
timestamps for accuracy; unreliable with a USB adapter in a VM + channel
hopping — produces false skews in the hundreds/thousands of ppm when real
drift is only tens of ppm, so it's intentionally left out). Also out of
scope for one passive adapter: sequence-number cross-check, triangulation,
RTT/gateway validation. 2.4GHz channels 1/6/11 only.

Usage:
    sudo python3 evil_twin_detect.py --learn 60      # build/refresh baseline
    sudo python3 evil_twin_detect.py                 # watch using saved baseline
    sudo python3 evil_twin_detect.py --learn 60 --watch
"""
from scapy.all import (sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Deauth,
                        Dot11Elt, RadioTap)
from collections import defaultdict, deque
import threading, subprocess, itertools, time, sys, json, argparse, os

IFACE = os.environ.get("ET_IFACE", "wlan0mon")   # start-detector.sh sets ET_IFACE
BASELINE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.json")
HOP = True

MIN_BEACONS_NEW = 3           # new-BSSID candidates need this many sightings before alerting
STALE_AFTER = 60              # seconds of silence before dropping a live candidate
RSSI_CORRIDOR_MARGIN = 15     # dB beyond recorded min/max before flagging a known BSSID
DEAUTH_WINDOW = 5             # seconds
DEAUTH_THRESHOLD = 10         # deauth frames within window from one source = flood
PROBE_SSID_THRESHOLD = 4      # distinct SSIDs one BSSID answers for = promiscuous/karma
PROBE_WINDOW = 30            # seconds to accumulate distinct probe-response SSIDs

# ---------------- helpers ----------------

def oui(bssid):
    return bssid.lower().split(":")[0:3]

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
    for ch in itertools.cycle([1, 6, 11]):
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

def fingerprint_mismatch(new_fp, known_fps):
    reasons = []
    for b, fp in known_fps.items():
        if fp.get("crypto") and not new_fp.get("crypto"):
            reasons.append(f"real AP {b} is secured ({','.join(fp['crypto'])}) but new BSSID is OPEN — classic downgrade")
        elif fp.get("crypto") != new_fp.get("crypto") and fp.get("crypto"):
            reasons.append(f"encryption differs from {b}: {fp.get('crypto')} vs {new_fp.get('crypto')}")
        if fp.get("channel") is not None and new_fp.get("channel") is not None and fp["channel"] != new_fp["channel"]:
            reasons.append(f"channel differs from {b}: {fp['channel']} vs {new_fp['channel']}")
        if fp.get("rates") and new_fp.get("rates") and fp["rates"] != new_fp["rates"]:
            reasons.append(f"supported-rates fingerprint differs from {b} (different radio/firmware)")
        if fp.get("ht") != new_fp.get("ht"):
            reasons.append(f"HT-capability mismatch vs {b} (ht={fp.get('ht')} vs {new_fp.get('ht')})")
    return reasons

def run_watch(baseline):
    print(f"[*] WATCH mode on {IFACE} using baseline ({len(baseline)} known SSIDs) — Ctrl-C to stop")
    if HOP:
        threading.Thread(target=channel_hopper, args=(IFACE,), daemon=True).start()

    candidate_counts = defaultdict(int)
    alerted = set()
    last_seen, last_fp = {}, {}
    rssi_spoof_alerted = set()
    deauth_events = defaultdict(deque)
    deauth_alerted = {}
    probe_ssids = defaultdict(dict)
    probe_alerted = {}

    def alert_new_bssid(ssid, bssid, rssi, fp, known):
        la = is_locally_administered(bssid)
        oui_known = any(oui(b) == oui(bssid) for b in known)
        mismatches = fingerprint_mismatch(fp, known)
        confidence = "LOW"
        if mismatches:
            confidence = "HIGH"
        elif la or not oui_known:
            confidence = "MEDIUM-HIGH" if (la and not oui_known) else "MEDIUM"
        print("\n" + "=" * 60)
        print(f'[!!!] EVIL TWIN SUSPECTED  —  SSID: "{ssid}"   confidence: {confidence}')
        print(f"      NEW BSSID: {bssid}   RSSI {rssi}   channel {fp.get('channel')}   crypto {fp.get('crypto') or ['OPEN']}")
        print(f"      locally-administered MAC: {la}   known vendor OUI: {oui_known}")
        for r in mismatches:
            print(f"      ⚠ {r}")
        print(f"      known baseline BSSID(s): {', '.join(known.keys()) if known else '(none)'}")
        print("=" * 60 + "\n")

    def alert_rssi_spoof(ssid, bssid, rssi, corridor):
        print("\n" + "-" * 60)
        print(f'[?] RSSI ANOMALY — SSID: "{ssid}"  BSSID: {bssid}')
        print(f"    seen at RSSI {rssi}, historical corridor {corridor} — possible BSSID spoof")
        print("-" * 60 + "\n")

    def alert_deauth(bssid, count):
        print("\n" + "!" * 60)
        print(f"[!!!] DEAUTH FLOOD from/to {bssid} — {count} deauth frames in {DEAUTH_WINDOW}s")
        print("      possible attempt to force clients off a real AP onto a rogue twin")
        print("!" * 60 + "\n")

    def alert_karma(bssid, ssids):
        print("\n" + "~" * 60)
        print(f"[!!!] PROBE-RESPONSE PROMISCUITY — BSSID {bssid} answered {len(ssids)} distinct SSIDs")
        print(f"      SSIDs: {', '.join(sorted(ssids))}")
        print("      classic Karma / Wi-Fi-Pineapple-style rogue AP behavior")
        print("~" * 60 + "\n")

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
        known = baseline.get(ssid, {})

        if bssid in known:
            entry = known[bssid]
            # RSSI corridor check
            lo, hi = entry.get("rssi_min"), entry.get("rssi_max")
            if rssi is not None and lo is not None and hi is not None:
                if rssi < lo - RSSI_CORRIDOR_MARGIN or rssi > hi + RSSI_CORRIDOR_MARGIN:
                    key = (ssid, bssid)
                    if key not in rssi_spoof_alerted:
                        rssi_spoof_alerted.add(key)
                        alert_rssi_spoof(ssid, bssid, rssi, (lo, hi))
            return

        if ssid not in baseline:
            return

        key = (ssid, bssid)
        candidate_counts[key] += 1
        last_seen[key] = now
        last_fp[key] = fp
        for k in list(candidate_counts):
            if now - last_seen.get(k, 0) > STALE_AFTER:
                del candidate_counts[k]
                last_seen.pop(k, None)
                last_fp.pop(k, None)
                alerted.discard(k)
        if candidate_counts[key] < MIN_BEACONS_NEW or key in alerted:
            return
        alerted.add(key)
        alert_new_bssid(ssid, bssid, rssi, fp, known)

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
