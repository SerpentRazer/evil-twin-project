# Evil-Twin Wi-Fi WIDS — attack · detect · defend

A live red-team / blue-team Wi-Fi security demo for **HackTech Lightning 2026**.
It doesn't just *detect* an evil-twin access point — it stands up the attack, catches
it live on a second radio, explains the verdict with a local LLM, and knocks the
victim off the rogue. Everything drives from one web console.

> ⚠️ **Authorized / own-devices use only.** The attack side broadcasts a rogue AP and
> captures whatever is typed into its captive portal. Point it only at networks and
> devices you own or are explicitly authorized to test.

---

## What it does

**RED TEAM (attack)** — recon the air, pick a target SSID, clone it with `airbase-ng`
(open AP + DHCP + captive portal), and capture captive-portal submissions.

**BLUE TEAM (defense)** — a passive, infra-aware detector flags an evil twin the moment
a **new BSSID appears for a known (baselined) SSID**, scored on the signals an attacker
can't fake benignly: security downgrade (WPA2→Open), foreign hardware (OUI), and a twin
that's louder than the real AP. On detection it blocklists the rogue, fingerprints every
device reaching for it, fans out a **DO-NOT-CONNECT** warning (dashboard + desktop +
phone push), and — opt-in — **contains** the victim with a targeted deauth.

**AI ANALYST** — each detection gets a second opinion from a local LLM (Ollama, reached
over Tailscale): a structured verdict (severity / evidence / recommended action) plus a
chat to ask about the live situation ("why was PRV_GUEST flagged?").

---

## Dual-radio: attack **and** defense at the same time

The headline moment: a live evil twin (RED) caught live by the detector (BLUE), on two
radios simultaneously. Roles are auto-assigned to monitor-capable adapters:

| Role | Adapter | Why |
|---|---|---|
| **ATTACK** | Atheros **AR9271** (`ath9k_htc`) | airbase-ng is bulletproof on it |
| **DEFENSE** | high-power adapter (e.g. **Alfa AWUS036NHR**, 1 W) | range helps it hear the twin from far + strong deauth |

With one adapter it degrades to one-job-at-a-time automatically. Override with
`CON_ATTACK_IFACE` / `CON_DEFENSE_IFACE`.

---

## Quick start

```bash
sudo ./start-console.sh            # unified console at http://127.0.0.1:8080
```

Demo flow (one screen): **BLUE** start defense → **RED** scan → 🎯 impersonate a target
you control → launch evil twin → a test phone joins → captive portal captures creds,
**BLUE** flags the twin red, warns, and (if containment is on) deauths it.

The detector needs a clean baseline of the venue (learn with the attacker off):

```bash
sudo ./start-detector.sh learn 60   # then watch
```

---

## Components

| Path | Role |
|---|---|
| `console.py` / `console.html` | unified web console (:8080) — RED / BLUE / CAPTURES + AI panel, multi-radio role manager, radio watchdog |
| `evil_twin_detect.py` | passive detector — infra-aware scoring (benign / review / evil) |
| `defense/guardian.py` | blue engine — detect, blocklist, device fingerprint, alert fan-out, containment, `known_devices.json` routing |
| `defense/ai_analyst.py` | LLM analyst (Ollama; dual-model with fallback) + verdict/chat |
| `defense/guardian_client.py` | client-side guardian for a protected device |
| `portal/ops_server.py` | red-team recon / attack control (feeds the console) |
| `portal/evil_portal.py` | captive portal + capture dashboard |
| `start-evil-twin.sh` / `stop-evil-twin.sh` | fake-AP bring-up / teardown |

Runtime data (`baseline.json`, `portal/captures.jsonl`) is git-ignored.
