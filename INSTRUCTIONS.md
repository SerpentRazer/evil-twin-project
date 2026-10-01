# Evil Twin Detector — How To

HackTech Lightning 2026. This is the **detector** side (passive listening on the
Kali box with the AR9271 antenna). No attacking, no connecting — it only listens
to Wi-Fi beacons and flags evil twins.

---

## What it does

It learns a **baseline** of the normal Wi-Fi around you, then watches the air and
alerts when something deviates — the way real Wireless Intrusion Detection
Systems (WIDS) work. Nothing about any network is hardcoded; the baseline is
learned from the air and saved to `baseline.json`.

**Detection signals** (infra-aware scoring — see `EVIL-TWIN-CONCEPTS.md`):
- New BSSID broadcasting an SSID already in the baseline, scored by whether it's
  really the operator's hardware or a foreign device cloning the name.
- Encryption downgrade (network is secured everywhere but a twin appears Open) — strongest.
- Foreign vendor OUI / base-MAC not seen for that SSID.
- Signal far LOUDER than the real AP's learned peak (attacker closer / higher power).
- Deauth flood (attacker trying to kick clients off the real AP).
- Karma / probe-response promiscuity (one BSSID answering many SSID names).

**Three verdicts:** `benign` (same operator's hardware — not alerted, folded into the
baseline), `review` (yellow — unrecognized BSSID with no corroborating tell, worth a
glance), `evil` (red — a real twin signature: downgrade, or foreign OUI + louder).

> Deliberately **not** used as evidence: a channel or supported-rates/HT difference
> between BSSIDs of one SSID, or a locally-administered MAC on its own — legit multi-AP
> networks do all of these by design, and using them caused the false positives.

**Honest scope:** 2.4 GHz channels 1/6/11 only, one passive adapter. Comparable
to a solid open-source scanner — not a commercial WIPS.

---

## Files

| File | Purpose |
|---|---|
| `evil_twin_detect.py` | The detector (learn + watch modes) |
| `baseline.json` | Learned "known good" networks (auto-created/updated) |
| `start-detector.sh` | Preps the antenna into monitor mode, then runs the detector |
| `stop-detector.sh` | Stops the detector, restores normal networking |

---

## Prerequisites

- AR9271 USB adapter **passed through to the Kali VM**
  (VirtualBox: *Devices → USB → tick the Atheros adapter*).
  If `lsusb | grep -i atheros` shows nothing, fix this first.
- Python 3 + scapy (already installed).

---

## Quick start (demo-day flow)

All commands run with `sudo` (monitor mode needs root).

**1. Build a clean baseline** — attacker/hotspot **OFF**, walk the area:
```bash
sudo ./start-detector.sh learn 60
```
Watch the summary line, e.g. `Baseline saved: 62 SSIDs, 82 BSSIDs`.
Run it again in other spots to add more (it **merges**, never overwrites).

> ⚠ The baseline MUST be captured with no attacker present. If the twin is on
> while you learn, it gets recorded as "known good" and will never be flagged.

**2. Start watching:**
```bash
sudo ./start-detector.sh
```
It should stay quiet on all legitimate networks.

**3. Trigger the twin** (the other machine / laptop hotspot broadcasting a
duplicate SSID). Within a few seconds you should see:
```
[!!!] EVIL TWIN SUSPECTED — SSID: "..."   confidence: HIGH
      NEW BSSID: ...   crypto ['OPEN']
      ⚠ real AP ... is secured (WPA2/PSK) but new BSSID is OPEN — classic downgrade
```

**4. Clean up:**
```bash
sudo ./stop-detector.sh
```

---

## start-detector.sh modes

```bash
sudo ./start-detector.sh              # watch using existing baseline.json
sudo ./start-detector.sh learn        # learn 60s (default), then exit
sudo ./start-detector.sh learn 90     # learn 90s
sudo ./start-detector.sh learnwatch   # learn 60s then auto-watch
```

---

## Managing the baseline

- **Add more networks:** just run `learn` again — it merges into `baseline.json`.
- **Start fresh (new location):** delete it, then learn:
  ```bash
  rm baseline.json
  sudo ./start-detector.sh learn 60
  ```
- **Check what's in it:**
  ```bash
  python3 -c "import json; d=json.load(open('baseline.json')); print(len(d),'SSIDs',sum(len(v) for v in d.values()),'BSSIDs')"
  ```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `AR9271 not detected` | Re-attach USB in VirtualBox (Devices → USB → Atheros) |
| Monitor mode won't start | Re-run the script; if stuck, `sudo airmon-ng check kill` then retry |
| Adapter vanished mid-run (`No such device`) | Known VirtualBox USB drop-off — re-attach in VirtualBox, re-run `start-detector.sh` |
| No alert when twin is on | Confirm the twin's SSID exists in `baseline.json` from a clean learn pass; a brand-new SSID never seen before is intentionally not flagged |
| Too many false alerts | Your baseline was likely captured with the attacker on, or is stale — rebuild it clean |

---

## The bigger picture (roadmap)

This box is the **sensor**. Next: emit each alert as a JSON event → Mac M4
dashboard displays it → Mac Mini local LLM (Ollama) acts as an AI security
analyst that explains and rates each alert. The detector stays deterministic;
the AI provides judgement and interaction on top.
