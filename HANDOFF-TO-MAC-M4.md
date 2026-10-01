# Handoff → Claude on the Mac M4 (Dashboard)

Hi. I'm the Claude instance running inside the **Kali VM** (the sensor/attacker box).
This document tells you what we built here and how to wire your **M4 dashboard** to it.
Read it fully before building.

> **This bundle includes the real source — read it for the exact behavior:**
> - `evil_twin_detect.py` — the actual detector (authoritative; this README describes
>   it, but the code is the source of truth — read it end to end).
> - `baseline.sample.json` — a small clean example of the baseline schema.
> - `README.md` — this handoff.

---

## ⚠ READ FIRST — what EXISTS now vs what is PLANNED

Don't build against things that aren't there yet. Precise status:

| Thing | Status |
|---|---|
| `evil_twin_detect.py` detector, learn + watch modes | ✅ **EXISTS, working, tested** |
| `baseline.json` learned from the air | ✅ **EXISTS** (real one lives on the Kali box) |
| Human-readable **console** alert output | ✅ **EXISTS** (see real samples in §2a) |
| **JSON-over-UDP event emitter** (§4 contract) | ❌ **NOT BUILT YET** — this is the next Kali task |
| **Heartbeat** events | ❌ NOT BUILT YET |
| Cross-machine networking (bridged VM) | ⚙️ **you + Raz must set up** (see §3) |

So: the JSON schema in §4 is the **agreed contract to build to**, not a live feed.
You CAN build your whole dashboard now against the fake `nc` feed in §6 — when I add
the Kali emitter it will speak that exact schema, so nothing you build is wasted.

---

## 1. The system (3 machines)

| Machine | Role | Owner |
|---|---|---|
| **Kali VM** (this box, Dell G6 + AR9271 antenna) | Passive Wi-Fi **sensor** — detects evil twins | me |
| **Mac M4** (your box) | **Dashboard** — shows alerts, live status, "Ask the AI" box | **you** |
| **Mac Mini** | **Local LLM** (Ollama) — AI security analyst that explains/rates alerts | later |

Data flow:
```
Kali sensor  --(JSON events over UDP)-->  M4 dashboard  <--(HTTP API)-->  Mac Mini LLM
```

---

## 2. What we built on Kali (done + working)

- **`evil_twin_detect.py`** — passive evil-twin detector. It learns a baseline of
  the normal Wi-Fi environment (`baseline.json`, learned from the air — nothing
  hardcoded) and flags deviations, the way a real WIDS does.
- Detection signals: new BSSID for a known SSID, encryption downgrade
  (WPA2→Open), channel/rates/HT-capability mismatch, RSSI anomaly, deauth flood,
  karma/probe-response promiscuity. Each alert carries a **confidence** (LOW→HIGH).
- Attacker side (for generating a real twin to demo against): `start-evil-twin.sh`
  broadcasts a duplicate-SSID open AP + captive portal.
- Automation: `start-detector.sh` / `stop-detector.sh`, docs in `INSTRUCTIONS.md`.

**Honest scope (state this to judges, don't oversell):** 2.4 GHz channels 1/6/11,
one passive adapter. Comparable to a solid open-source scanner, not a commercial WIPS.

**Current output format:** right now the detector prints **human-readable text** to
the terminal. It does **NOT yet emit JSON over the network** — that emitter is the
next task, and section 4 below is the contract we should both build to.

---

## 2a. What the detector's REAL output looks like right now (ground truth)

These are actual console blocks from live runs on the Kali box. Your JSON mapping
should match these fields exactly.

**An evil-twin detection (a new BSSID impersonating a known SSID):**
```
============================================================
[!!!] EVIL TWIN SUSPECTED  —  SSID: "PRV_GUEST"   confidence: HIGH
      NEW BSSID: 4e:49:6c:40:10:aa   RSSI -30   channel 1   crypto ['WPA2/PSK']
      locally-administered MAC: True   known vendor OUI: False
      ⚠ channel differs from aa:9c:6c:a8:bb:03: 6 vs 1
      known baseline BSSID(s): aa:9c:6c:a8:bb:03
============================================================
```
Maps to a `evil_twin` JSON event: `ssid`, `new_bssid`, `rssi`, `channel`, `crypto`,
`locally_administered`, `known_vendor_oui`, `reasons` (the ⚠ lines), `known_bssids`,
`confidence`.

**The strongest signal — an OPEN twin of a secured network (crypto downgrade):**
```
============================================================
[!!!] EVIL TWIN SUSPECTED  —  SSID: "MyHomeWiFi"   confidence: HIGH
      NEW BSSID: c0:1c:30:0d:a3:e1   RSSI -41   channel 6   crypto ['OPEN']
      locally-administered MAC: False   known vendor OUI: False
      ⚠ real AP aa:9c:.. is secured (WPA2/PSK) but new BSSID is OPEN — classic downgrade
      known baseline BSSID(s): aa:9c:6c:a8:bb:03
============================================================
```

**Other alert types** (RSSI anomaly / deauth flood / karma) print as `[?]` or
`[!!!]` blocks with `-`, `!`, or `~` borders respectively — see the `alert_*`
functions in `evil_twin_detect.py` for the exact text.

**Startup line:** `[*] WATCH mode on wlan0mon using baseline (62 known SSIDs) — Ctrl-C to stop`

> Note: the console currently prints these; the JSON emitter (not built yet) will
> send the SAME information as the structured events in §4.

---

## 2b. How the detection logic actually works (so you understand the system)

It is **baseline + anomaly detection**, exactly like real WIDS (Kismet, sentrygun,
Cisco/Aruba WIPS). Two phases:

**LEARN phase** — the sensor listens for N seconds and records every legitimate
network it hears into `baseline.json`. This is "what normal looks like here."
Nothing is hardcoded — verified: zero hardcoded MACs, SSIDs, or vendor names in the
code, only generic numeric thresholds. **Critical rule:** the baseline must be
captured with **no attacker present**, or the twin gets learned as "good" and is
never flagged.

**WATCH phase** — for each beacon heard live, it compares against the baseline:
- BSSID already in baseline for this SSID → **normal, ignored**.
- New BSSID for a **known** SSID → **evil twin suspected**. Confidence rises with
  each corroborating signal: encryption downgrade (WPA2→Open), channel mismatch,
  supported-rates/HT-capability mismatch, locally-administered MAC, unknown vendor OUI.
- SSID never seen before at all → **not flagged** (it's just a new neighbor, not an
  impersonation of anything we know).
- Known BSSID at a wildly different signal strength → RSSI anomaly (possible spoof).
- Bursts of deauth frames → deauth-flood alert.
- One BSSID answering many different SSID probes → karma alert.

The core evil-twin idea in one line: **the same network NAME (SSID) suddenly
appearing from a NEW, unrelated DEVICE (BSSID) = impersonation.**

### `baseline.json` structure

Top level is `SSID → { BSSID → fingerprint }`. Example:

```json
{
  "MyHomeWiFi": {
    "aa:9c:6c:a8:bb:03": {
      "channel": 6,
      "crypto": ["WPA2/PSK"],
      "rates": [1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0],
      "ht": true,
      "rssi_min": -62,
      "rssi_max": -48
    }
  },
  "Guest": {
    "42:ed:00:8b:16:f0": { "channel": 6, "crypto": ["WPA2/PSK"], "rates": [...], "ht": true, "rssi_min": -57, "rssi_max": -51 },
    "42:ed:00:8b:13:ca": { "channel": 6, "crypto": ["WPA2/PSK"], "rates": [...], "ht": true, "rssi_min": -89, "rssi_max": -76 }
  }
}
```

Note `Guest` legitimately has **multiple BSSIDs** (a real multi-AP network) — that's
why "same SSID on 2+ BSSIDs" alone is NOT used as the trigger; it would false-positive
on every coffee-shop/campus network. The trigger is a BSSID that is **new relative to
the learned baseline**. You can read this file directly on the dashboard to render the
"known APs" inventory; the M4 can fetch a copy from the Kali box (scp / shared file /
an endpoint I can add).

> Older versions of this file used a simpler shape (`SSID → [bssid, ...]`). The
> current detector auto-upgrades old files on load, but the schema above is current.

---

## 3. Networking: how the M4 reaches the Kali VM

The Kali box is a **VirtualBox VM**, so its networking must be reachable from your M4.

**Recommended: Bridged adapter.**
- In VirtualBox: VM → Settings → Network → Adapter 1 → *Attached to: **Bridged Adapter*** →
  pick the Dell's active NIC. This puts the Kali VM on the **same LAN** as your M4.
- Find the Kali VM's IP: `ip addr show eth0` (look for `inet 192.168.x.x`).
- Both machines must be on the **same Wi-Fi/LAN**.

**Transport: UDP push (Kali → M4).** Simplest and robust for a live demo:
- Kali sends one JSON datagram per alert to `M4_IP:9999`.
- Your dashboard listens on **UDP port 9999** and renders whatever arrives.
- UDP because it's fire-and-forget, no connection state, no blocking the sensor if
  the dashboard restarts. Loss of an occasional packet is fine for a demo.

(If you'd rather the M4 *pull*, we can switch to the sensor exposing an HTTP
`/events` endpoint instead — but UDP push is less code on both sides. Your call;
tell me and I'll build the Kali side to match.)

---

## 4. The JSON event contract (build to this)

Every event is a **single JSON object**, one per UDP datagram (newline-terminated).
Common envelope fields on every event:

```json
{
  "schema": "evil-twin-detector/v1",
  "event_type": "evil_twin | rssi_anomaly | deauth_flood | karma | heartbeat",
  "timestamp": "2026-09-29T09:15:42Z",
  "sensor": "kali-ar9271",
  "confidence": "LOW | MEDIUM | MEDIUM-HIGH | HIGH"
}
```

Per-type payloads:

**`evil_twin`** (a new BSSID impersonating a known SSID):
```json
{
  "event_type": "evil_twin",
  "ssid": "MyHomeWiFi",
  "new_bssid": "4e:49:6c:40:10:aa",
  "rssi": -30,
  "channel": 1,
  "crypto": ["OPEN"],
  "locally_administered": true,
  "known_vendor_oui": false,
  "reasons": ["real AP aa:9c:.. is secured (WPA2/PSK) but new BSSID is OPEN — classic downgrade"],
  "known_bssids": ["aa:9c:6c:a8:bb:03"],
  "confidence": "HIGH"
}
```

**`rssi_anomaly`** (known BSSID at an impossible signal level — possible spoof):
```json
{ "event_type": "rssi_anomaly", "ssid": "...", "bssid": "...", "rssi": -20, "corridor": [-70, -55] }
```

**`deauth_flood`**:
```json
{ "event_type": "deauth_flood", "source": "aa:bb:cc:dd:ee:ff", "count": 42, "window_s": 5 }
```

**`karma`** (one BSSID answering many SSID names):
```json
{ "event_type": "karma", "bssid": "...", "ssids": ["FreeWiFi","Starbucks","Airport"] }
```

**`heartbeat`** (sent every ~10s so the dashboard can show sensor = alive):
```json
{ "event_type": "heartbeat", "known_ssids": 62, "uptime_s": 305 }
```

---

## 5. What you (M4) should build

1. **UDP listener** on port 9999 that parses these JSON events.
2. **Dashboard UI**:
   - Live sensor status (green if heartbeats arriving, red if silent > 30s).
   - Alert feed / timeline, color-coded by `event_type` + `confidence`.
   - A map/list of known vs suspicious APs (SSID → BSSIDs).
   - An **"Ask the AI"** box (wires to the Mac Mini LLM later — see below).
3. **LLM bridge (phase 2):** for each alert, POST the JSON event to the Mac Mini's
   Ollama API and show the model's plain-English explanation + severity next to the
   raw alert. Suggested prompt: *"You are a wireless security analyst. Here is a
   detection event: {json}. Explain what's happening, rate severity 1–5, recommend
   an action."* Model: Llama 3.1 8B or Qwen 2.5 7B via Ollama (runs local on the Mini).

---

## 6. To test the wiring before the Kali emitter exists

You can develop the dashboard immediately against a fake feed. On any machine:

```bash
# send one test event to your dashboard (replace M4_IP)
echo '{"schema":"evil-twin-detector/v1","event_type":"evil_twin","timestamp":"2026-09-29T09:15:42Z","sensor":"kali-ar9271","ssid":"MyHomeWiFi","new_bssid":"4e:49:6c:40:10:aa","rssi":-30,"channel":1,"crypto":["OPEN"],"locally_administered":true,"known_vendor_oui":false,"reasons":["WPA2->OPEN downgrade"],"known_bssids":["aa:9c:6c:a8:bb:03"],"confidence":"HIGH"}' \
| nc -u -w1 M4_IP 9999
```

Build the UI against that, and when I add the emitter on Kali it'll speak the same
schema — no rework.

---

## 7. Next step on my (Kali) side

I'll add a JSON-over-UDP emitter to `evil_twin_detect.py` (configurable
`--emit M4_IP:9999`) that fires these exact events alongside the console output,
plus the heartbeat. Tell me your chosen M4 IP + port (or confirm UDP 9999) and
whether you want push (UDP) or pull (HTTP), and I'll match it.

— Claude @ Kali
```
Files on Kali: evil_twin_detect.py · baseline.json · start-detector.sh ·
stop-detector.sh · start-evil-twin.sh · stop-evil-twin.sh · INSTRUCTIONS.md
```
