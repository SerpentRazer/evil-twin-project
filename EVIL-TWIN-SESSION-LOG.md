# Evil Twin — Full Session Log & Project Documentation

**Project:** HackTech Lightning 2026 — evil-twin detection + attack demo
**Machine role:** Kali VM (Dell G6 + AR9271 antenna) — sensor **and** attacker
**Date of this work:** 2026-09-30
**Scope reminder:** authorized hackathon/CTF demo, against own devices/networks only.

This document collects everything covered in the session: the concept baseline, the
false-positive bug and its fix, the captive portal + capture dashboard, and the web
operator console that runs the whole demo.

---

## 1. What an evil twin is (concept baseline)

An **evil twin** is a rogue access point that **impersonates a legitimate network** so
victims connect to the attacker instead of the real AP. Wi-Fi identifiers (SSID name,
BSSID/MAC, channel, advertised crypto) are all trivially forgeable, so the attacker
clones them. Once a client associates, the attacker is a man-in-the-middle: sniff
traffic, run a captive portal to phish credentials/PSK, strip TLS, etc.
(MITRE ATT&CK **T1557.004**, "Adversary-in-the-Middle: Evil Twin".)

**One-line definition that drives detection:**
> The same network NAME (SSID) suddenly broadcast from a NEW, unrelated DEVICE (BSSID)
> that is not part of the real network's known hardware.

**Typical attack shape (and our demo):**
- Attacker runs `airbase-ng` / a Wi-Fi Pineapple / a phone hotspot with the target SSID.
- Usually **OPEN** (no passphrase) because they don't have the real PSK — the single
  strongest tell, the "**encryption downgrade**".
- Often sits **physically closer / higher TX power** so their signal beats the real AP.
- Frequently paired with a **deauth flood** to kick clients off the real AP.
- A Pineapple may answer probe requests for **many** SSIDs at once ("karma").

---

## 2. Why naive detection gives false positives

The tempting rule "same SSID on 2+ BSSIDs = evil twin" is **wrong**. Legitimate networks
routinely use many BSSIDs for one SSID:

1. **Multi-AP ESS (Extended Service Set).** Enterprise / campus / coffee-shop networks
   have several physical APs sharing one SSID for roaming, **deliberately spread across
   channels 1/6/11**. So "different channel" between two BSSIDs of one SSID is **normal**.
2. **Virtual APs / multiple BSSIDs per radio.** One physical AP broadcasting several
   SSIDs derives a **BSSID per SSID from a base MAC**, incrementing low octets, and
   commonly **sets the locally-administered (U/L) bit**. So:
   - BSSIDs sharing the **first 3 octets (OUI)** or **first 5 octets (base MAC)** are the
     **same vendor / same physical AP** → legit.
   - A **locally-administered MAC is NOT suspicious by itself** — legit virtual BSSIDs
     set it too. Only meaningful combined with a foreign OUI.
3. **Migration mixes.** During a WPA2→WPA3 rollout, one SSID legitimately has some APs on
   `WPA2/PSK` and others on `WPA3-transition`. So "crypto differs between two BSSIDs" is
   NOT proof — only a **downgrade to OPEN of an otherwise-secured network** is.

Standard WIDS mitigation: a **baseline/whitelist of known BSSIDs per SSID** plus scoring
that weights the signals an attacker can't fake benignly.

### Signals, ranked by reliability

| Signal | Reliable? | Why |
|---|---|---|
| **Security downgrade** (secured everywhere in baseline, new BSSID OPEN) | ★★★ | Attacker lacks the PSK |
| **Foreign OUI / base-MAC** (not among network's known hardware) | ★★ | New vendor cloning the name |
| **Louder than the real AP** (RSSI far above learned peak) | ★★ corroborating | Attacker closer / higher power |
| **Deauth flood** | ★★ | Classic companion attack |
| **Karma / probe promiscuity** (one BSSID answering many SSIDs) | ★★ | Real APs answer only their own |
| **Locally-administered MAC** | ★ weak alone | Legit virtual BSSIDs set it too |
| **Channel differs** from another BSSID of the SSID | ✗ | Legit ESS spans 1/6/11 — **removed** |
| **Supported-rates / HT differs** | ✗ | Varies across legit models — **removed** |

---

## 3. The false-positive incident and fix

### What happened
Running the detector in a dense environment (Parc Stiintific science park), legit
enterprise APs were flagged **red / HIGH-confidence evil twin**:
- `Parc Stiintific_Guest` (extra BSSIDs on the same `40:ed:00` hardware)
- `SCR` / `Street Coffee` (second physical AP of the same venue)
- plus RSSI-anomaly false alarms on `SteamHQ` / `INNO-GUEST` (just weaker/farther signals)

The real attacker (`PRV_GUEST 4e:49:6c:40:10:aa @ -24 dBm`) was correctly caught, but it
was drowning in false positives.

### Root cause
The old `fingerprint_mismatch()` flagged **any** per-BSSID difference in
**channel / supported-rates / HT / crypto-vs-each-known-AP** as HIGH-confidence evil, and
painted **every** new-BSSID-for-known-SSID red regardless of confidence. But those
differences are normal in legit multi-AP networks (see §2). The RSSI corridor check also
flagged **weaker** signals, which are just distance, not attacks.

### The fix — infra-aware scoring (`classify_new_bssid()`)
For a new BSSID on a known SSID, build a profile from the baseline (trusted OUIs,
base-MAC prefixes, whether the net is secured everywhere, the real APs' loudest RSSI),
then produce one of three verdicts:

- **benign** (not alerted, folded into baseline) — shares base-MAC prefix or OUI with a
  known AP, no downgrade, not louder → same operator's hardware.
- **evil / red (HIGH)** — **security downgrade** (secured net, OPEN twin — overrides even
  a spoofed matching OUI), OR **foreign OUI + louder** than the real AP's peak.
- **review / yellow (MEDIUM)** — foreign OUI with no corroboration → worth a glance, not a
  red alarm.

Also:
- **Dropped as evidence:** channel diff, rates/HT diff, LAA-bit-alone.
- **RSSI corridor** on a known BSSID now fires **louder-only** (weaker = distance, ignored).
- Classification uses the **loudest RSSI across a candidate's beacons**, not one frame
  (individual beacons often arrive with no signal field → the "louder" tell was being
  missed, which once demoted the real attacker to "review").

### Verified result (against the exact screen data)

| AP | Old | New |
|---|---|---|
| `PRV_GUEST 4e:49:6c… @ -24` (attacker) | red | **red / evil HIGH** ✅ |
| `Parc Stiintific_Guest 40:ed:00:8b:18:60/64` | red | **benign** ✅ |
| `SCR 28:70:4e…` / `Street Coffee 2e:70:4e…` | red | **yellow / review** ✅ |
| OPEN spoofed-OUI twin (sanity) | — | **red / evil** ✅ |

### Honest limitation
A twin that spoofs the real OUI, matches crypto, and isn't louder is passively
near-indistinguishable — needs 802.1X/RADIUS cert validation or TSF/sequence-number
analysis (out of scope for one passive 2.4 GHz adapter).

---

## 4. Captive portal + capture dashboard (attacker side)

`start-evil-twin.sh` already brought up the fake AP (airbase-ng) + DHCP/DNS (dnsmasq) +
the iptables redirect, but shipped no portal page and captured nothing. Added a
self-contained portal in `portal/`.

**`evil_portal.py`** (Flask, port 80) — replaces the old Apache step:
- Serves a fake "Guest Wi-Fi" sign-in page to **every** URL a client opens.
- Answers the **iOS / Android / Windows captive-portal detection probes**, so the phone
  auto-pops the "Sign in to network" sheet the moment it connects.
- Logs each submission (+ device IP / MAC / hostname / user-agent) to `captures.jsonl`.
- Live dashboard at **`/admin`**.

**Portal pages:**
- `portal.html` — the victim login page. **Deliberately innocuous** ("Guest Wi-Fi", blue
  theme) so it blends in and actually fools the target. Edit this to change the look.
- `connecting.html` — the "Connecting you to the internet…" page shown after submit.

**`admin.html`** — the attacker dashboard. Terminal / phosphor-green "hacker" theme with:
- Stat tiles: captures, unique devices hooked, live DHCP clients, **reused passwords**.
- **Credential-reuse detection** — same password across devices → `⚠ REUSED` badge.
- **OS detection** from user-agent (iOS / Android / Windows) + OS breakdown bars.
- Search filter (press `/`), **CSV export**, wipe button, live status beacon, auto-refresh.

**Full flow demonstrated:** phone connects → innocuous portal pops → victim submits →
"connecting" spinner → credentials appear instantly on the console with OS tags and
reuse flags.

**Caveat:** HTTPS sites won't load on the victim (no TLS interception) — expected for an
evil twin; the captive popup still fires from the plaintext probe, so capture works. On
the real AP, victims get `10.0.0.x` DHCP leases so MAC + hostname are filled in (loopback
tests show blanks).

---

## 5. Web operator console (drives the whole demo)

`ops_server.py` + `ops.html` + `start-ops.sh` — one panel to run the entire chain with no
terminal, so it presents cleanly on stage.

**Capabilities:**
- **Recon** — "enable monitor & scan" lists nearby APs airodump-style
  (BSSID / CH / PWR / ENC / SSID), each with a **🎯 impersonate** button.
- **Impersonate** — click a row → target locks (SSID + channel).
- **Attack** — "launch evil twin" runs `start-evil-twin.sh` against that target; the
  7-step output **streams into the in-panel live console**.
- **Watch** — status chips (MONITOR / AIRBASE / DNSMASQ / PORTAL / CAPTURES) go green;
  victim associations + `CAPTURE` lines stream in; link to the capture dashboard.
- **Stop all** — tears everything down.

**Two modes** (env `OPS_DEMO`):
- **DEMO** (default) — fully simulated: fake scan, streamed fake attack output, fake
  victims, writes demo rows to `captures.jsonl`. Safe to rehearse anywhere; no hardware,
  no root, nothing transmitted. Ideal stage walkthrough / backup.
- **LIVE** (`OPS_DEMO=0`) — real airodump-ng scan + real `start/stop-evil-twin.sh`
  (needs root + AR9271).

**Safety:** only a fixed action allow-list can run (scan / launch / stop); the SSID is
sanitized and passed to the script via **env/argv, never a shell string**; channel forced
to an int 1–14 — so nothing on the recon list can inject commands.

**Wiring change:** `start-evil-twin.sh` was parameterized with `ET_SSID` / `ET_CHANNEL`
so the panel targets the chosen network.

---

## 5b. Defense console — the countermeasure (blue team)

The blue-team half: prove the attack, then catch it and warn the user. Built to mirror
the ops console (DEMO / LIVE modes, terminal theme — cyan/shield to separate it from the
red-team green). Files in `defense/`.

**Key insight — a "connection attempt" is visible on the air.** No agent is needed on the
victim to *see* them reaching for the fake: in monitor mode the sensor reads the management
frames of a join — probe request (looking), **auth / association request with the rogue as
BSSID (actively trying to connect)**, and data frames (already joined). Watching for
auth/assoc frames whose BSSID is a confirmed rogue tells you *which device* is walking into
the trap, in real time.

**`defense/guardian.py`** (engine + dashboard on :8081):
1. **Detects** evil twins (reuses `classify_new_bssid` from the detector) and
   **auto-blocklists** each confirmed rogue BSSID.
2. **Channel-locks** onto the rogue's channel once detected (stops hopping so it doesn't
   miss the critical frames).
3. **Catches connection attempts** — auth/assoc/data toward a blocklisted BSSID → names the
   victim device (MAC).
4. **Alerts on every channel at once:** defender dashboard banner + **desktop popup**
   (`notify-send`) + **phone push** (ntfy) — "⚠ DO NOT CONNECT".
5. **Active containment** (opt-in, `DEF_CONTAIN=1`): targeted deauth to break/deny the
   victim's link to the rogue — like commercial WIPS "rogue containment".
   ⚠ transmits — authorized / own-devices only.

**`defense/defense.html`** — defender dashboard: DEFENSE ACTIVE status, blocklisted rogues
(with the reasons they were flagged), a live **connection-attempts** feed, a big pulsing
**DO NOT CONNECT** banner on each new attempt, a containment toggle, and the live guardian
console. Phone/desktop/dashboard alerts all fire together.

**`defense/guardian_client.py`** — the client-side guardian that runs on the **protected
device**. It pulls the live blocklist from the console and scans this device's own Wi-Fi;
if a blocklisted rogue is in range it pops a native **"DO NOT CONNECT"** notification right
on the user's screen. Cross-platform: Linux (`nmcli` + `notify-send`), Windows (`netsh` +
PowerShell toast), macOS (`airport` + `osascript`).

**Phone push setup (free, no account):** install the **ntfy** app, subscribe to a unique
topic, then `export DEF_NTFY_TOPIC=<your-topic>` before launching. The console POSTs alerts
to `ntfy.sh/<topic>` → your phone buzzes the instant a device reaches for the fake.

**Notification targets delivered:** defender dashboard ✅ · desktop popup (Linux/Win/mac via
the client) ✅ · phone push (ntfy) ✅.

---

## 6. How to run everything

```bash
# --- DETECTOR (defensive sensor) ---
rm baseline.json                         # only for a fresh location (learn MERGES, never deletes)
sudo ./start-detector.sh learn 60        # build a clean baseline — attacker OFF
sudo ./start-detector.sh                 # watch; only real twins go red, review = yellow
sudo ./stop-detector.sh

# --- OPERATOR CONSOLE (attacker demo, recommended entry point) ---
./start-ops.sh                           # DEMO mode  -> http://127.0.0.1:8080
sudo ./start-ops.sh live                 # LIVE mode (root + AR9271)

# --- ATTACK scripts directly (the console calls these for you) ---
sudo ./start-evil-twin.sh                # fake AP + portal + capture dashboard on :80/admin
sudo ET_SSID="PRV_GUEST" ET_CHANNEL=6 ./start-evil-twin.sh   # impersonate a specific target
sudo ./stop-evil-twin.sh

# capture dashboard (while the portal is up): http://127.0.0.1/admin

# --- DEFENSE CONSOLE (blue team / countermeasure) ---
./start-defense.sh                       # DEMO  -> http://127.0.0.1:8081
sudo ./start-defense.sh live             # LIVE passive detection + alerts
sudo ./start-defense.sh live contain     # LIVE + active containment (deauth rogue links)
export DEF_NTFY_TOPIC=my-evil-twin-alerts # phone push (install ntfy app, subscribe) then launch

# client guardian — on the device you want to protect:
python3 defense/guardian_client.py --server http://<kali-ip>:8081
```

**Suggested hackathon script:** run the console in **DEMO** on the projector for the clean
narrated walkthrough (recon → impersonate → attack → captured creds), then switch to
**LIVE** against your own test phone for the "and here it is for real" moment. Finish on
the **detector** showing the twin flagged red while legit APs stay quiet.

---

## 7. File map

| File | Purpose |
|---|---|
| `evil_twin_detect.py` | Passive detector (learn + watch) with infra-aware scoring |
| `baseline.json` | Learned "known good" networks (auto-created/updated) |
| `start-detector.sh` / `stop-detector.sh` | Detector monitor-mode wrappers |
| `EVIL-TWIN-CONCEPTS.md` | Concept baseline + detection reasoning + sources |
| `portal/evil_portal.py` | Captive portal + capture dashboard server (:80) |
| `portal/portal.html` | Victim-facing "Guest Wi-Fi" login (innocuous) |
| `portal/connecting.html` | Post-submit "connecting…" page |
| `portal/admin.html` | Attacker capture dashboard (terminal theme) |
| `portal/captures.jsonl` | Captured submissions (created at runtime; clear after demo) |
| `portal/ops_server.py` | Web operator console server (:8080) |
| `portal/ops.html` | Operator console UI |
| `start-ops.sh` | Operator console launcher (demo / live) |
| `defense/guardian.py` | Defense engine + defender dashboard (:8081) |
| `defense/defense.html` | Defender (blue-team) dashboard UI |
| `defense/guardian_client.py` | Client-side guardian for protected devices (cross-platform) |
| `start-defense.sh` | Defense console launcher (demo / live / contain) |
| `start-evil-twin.sh` / `stop-evil-twin.sh` | Fake AP bring-up / teardown (now `ET_SSID`/`ET_CHANNEL` aware) |

---

## 8. Sources
- [MITRE ATT&CK T1557.004 — Evil Twin](https://attack.mitre.org/techniques/T1557/004/)
- [MITRE DET0379 — Detect Evil Twin Wi-Fi APs](https://attack.mitre.org/detectionstrategies/DET0379)
- [ETSniffer (TAMU) — evil-twin detection research](https://people.engr.tamu.edu/guofei/paper/ETSniffer_TIFS12.pdf)
- [User-side evil-twin detection (UCF)](https://www.cs.ucf.edu/~czou/research/evilTwin-CCNC-2015.pdf)
- [Stealth & evasion in rogue AP attacks (arXiv 2512.10470)](https://arxiv.org/html/2512.10470)
- [Derivation of BSSIDs for APs (US11388137B1)](https://patents.google.com/patent/US11388137) — virtual-BSSID base-MAC + LAA bit
- [AccessAgility — private/LAA MAC addresses](https://go.accessagility.com/hc/private-mac-laa-mac-address)
