# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Passive Wi-Fi evil-twin detector for **HackTech Lightning 2026**. This box is the
**Kali sensor/attacker** in a 3-machine system:

```
Kali sensor (this box) --UDP JSON--> Mac M4 dashboard <--HTTP--> Mac Mini (Ollama LLM analyst)
```

Only the Kali side lives here. The M4 dashboard and Mac Mini LLM are other people's
machines; we push events to them and never build their side. No build step and no test
suite — a single Python script plus bash wrappers, run live with `sudo`. (Public mirror:
github.com/SerpentRazer/evil-twin-wids — runtime data stays gitignored.)

## Running it

All commands need `sudo` (monitor mode needs root). The wrapper preps the AR9271 USB
adapter into monitor mode, then execs the Python detector:

```bash
sudo ./start-detector.sh              # WATCH using existing baseline.json
sudo ./start-detector.sh learn        # LEARN 60s (default) into baseline.json, then exit
sudo ./start-detector.sh learn 90     # LEARN 90s
sudo ./start-detector.sh learnwatch   # LEARN 60s then WATCH
sudo ./stop-detector.sh               # kill detector, drop monitor mode, restart NetworkManager
```

Direct (bypassing the adapter prep — assumes a monitor iface already exists):
```bash
sudo python3 evil_twin_detect.py --learn 60
sudo python3 evil_twin_detect.py            # watch; exits early if baseline.json is empty
```

Attacker side, to generate a real twin to demo against (separate from the detector):
```bash
sudo ./start-evil-twin.sh    # airbase-ng fake AP + dnsmasq + apache captive portal on channel 6
sudo ./stop-evil-twin.sh
```

Inspect the baseline:
```bash
python3 -c "import json; d=json.load(open('baseline.json')); print(len(d),'SSIDs',sum(len(v) for v in d.values()),'BSSIDs')"
```

There is no lint/test tooling; verify changes with `python3 -c "import ast; ast.parse(open('evil_twin_detect.py').read())"` and a live run.

## Configuration (environment variables)

The script reads these — `start-detector.sh` sets `ET_IFACE`; the rest are set by hand:
- `ET_IFACE` — monitor interface (default `wlan0mon`; the wrapper detects and exports the real one).
- `ET_M4_IP` — dashboard IP. **Left unset on purpose**: `send_udp()` is a no-op while blank, so the detector runs/prints normally without a dashboard. Set it to enable the UDP feed with no code change.
- `ET_M4_PORT` — default `9999`.

## Architecture of `evil_twin_detect.py`

Two phases over one passive adapter, sweeping the **whole 2.4 GHz band (channels 1–13)**
by default so a twin is caught on any channel (override with `ET_CHANNELS`); a background
thread hops between them every `ET_HOP_DWELL` seconds (default 0.4s):

- **LEARN** (`run_learn`) — sniff beacons for N seconds, record `SSID → {BSSID → fingerprint}`
  into `baseline.json`. Fingerprint = channel, crypto, supported rates, HT (802.11n) bit,
  and an observed RSSI corridor (`rssi_min`/`rssi_max`). **Merges** into the existing file,
  never overwrites. **The baseline MUST be learned with no attacker present** or the twin
  is saved as legit and never flagged.
- **WATCH** (`run_watch`) — per live frame, compare against baseline. Callback `handle()`
  runs on the sniff thread; a separate `inventory_loop` thread redraws the terminal table
  every 3s. `live_lock` guards the three shared structures (`live_aps`, `evil_bssids`,
  `recent_alerts`) touched by both threads.

**Core detection idea:** same SSID name appearing from a *new BSSID not in the baseline*
= impersonation. Deliberately NOT "same SSID on 2+ BSSIDs" — that false-positives on legit
multi-AP networks (which the baseline records as multiple BSSIDs under one SSID). An SSID
never seen before is intentionally *not* flagged (it's a new neighbor, not a clone).

Five detection layers, each an `alert_*` function; confidence rises with corroborating
signals (crypto downgrade WPA2→Open is the strongest, then channel/rates/HT mismatch,
locally-administered MAC, unknown OUI, and a twin louder than the real AP's learned peak):
1. Baseline deviation (new BSSID for known SSID) — `alert_new_bssid` / `fingerprint_mismatch`
2. RSSI corridor anomaly for a known BSSID — `alert_rssi_spoof`
3. Deauth flood — `alert_deauth`
4. Karma / probe-response promiscuity (one BSSID answering many SSIDs) — `alert_karma`

Tuning knobs are constants near the top of the file (`MIN_BEACONS_NEW`, `RSSI_CORRIDOR_MARGIN`,
`RSSI_TWIN_LOUDER_MARGIN`, `DEAUTH_*`, `PROBE_*`, `INVENTORY_INTERVAL`).

**Intentionally out of scope** (documented in the module docstring, don't "fix"): clock-skew/TSF
fingerprinting (unreliable on a USB adapter in a VM with channel hopping), sequence-number
cross-check, triangulation, RTT/gateway validation, 5 GHz.

## Two copies of the detector — keep them in sync

`evil_twin_detect.py` (authoritative) and `handoff-to-m4/evil_twin_detect.py` (bundled snapshot
handed to the M4 team). Edits to the real one should be re-bundled if the handoff still matters.

## ⚠ The handoff doc's UDP contract is STALE — the live code is authoritative

`HANDOFF-TO-MAC-M4.md` §4 describes a planned schema with a `{schema, event_type, timestamp,
sensor}` envelope and fields like `new_bssid`. **The implemented `send_udp()` does NOT match it.**
The code actually emits, per datagram:
- envelope: `{"type": <msg_type>, "ts": <epoch float>, ...fields}` (no `schema`/`sensor`; `type` not `event_type`; `ts` is a float, not ISO)
- types: `evil_twin`, `suspicious_ap` (the yellow "review" tier), `rssi_anomaly`, `deauth_flood`, `karma`, `heartbeat` (every 5s), `inventory` (every 3s, full live AP list; each AP has `evil` and `review` bools)
- `evil_twin`/`suspicious_ap` fields are `ssid, bssid, rssi, channel, crypto, confidence, reasons` (`bssid`, not `new_bssid`; no `locally_administered`/`known_vendor_oui`/`known_bssids`)

If asked about the dashboard contract, trust `send_udp()` calls in the code, not the doc. The
console/terminal samples in the handoff are also older than the current live-table renderer.
