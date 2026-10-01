# Evil Twin — concept baseline & detection logic

This is the reference understanding the detector is built on. Read it before touching
the detection code so changes stay grounded, not guesswork.

## What an evil twin actually is

An **evil twin** is a rogue access point that **impersonates a legitimate network** so
victims connect to the attacker instead of the real AP. Wi-Fi identifiers (SSID name,
BSSID/MAC, channel, advertised crypto) are all trivially forgeable, so the attacker
clones them. Once a client associates, the attacker is a man-in-the-middle: they can
sniff traffic, run a captive portal to phish credentials/PSK, strip TLS, etc.
(MITRE ATT&CK T1557.004, "Adversary-in-the-Middle: Evil Twin".)

The one-line definition that drives detection:

> **The same network NAME (SSID) suddenly broadcast from a NEW, unrelated DEVICE
> (BSSID) that is not part of the real network's known hardware.**

Typical attack shape in the wild (and in our demo):
- Attacker runs `airbase-ng` / a Wi-Fi Pineapple / a phone hotspot with the target SSID.
- They usually run it **OPEN** (no passphrase) because they don't have the real PSK —
  this is the single strongest tell, the "**encryption downgrade**".
- They often sit **physically closer / higher TX power** so their signal beats the real
  AP and clients roam to them.
- They frequently pair it with a **deauth flood** to kick clients off the real AP.
- A Pineapple may answer probe requests for **many** SSIDs at once ("karma").

## Why naive detection produces false positives

The tempting rule "same SSID on 2+ BSSIDs = evil twin" is **wrong** and is what bit us.
Legitimate networks routinely use many BSSIDs for one SSID:

1. **Multi-AP ESS (Extended Service Set).** Any enterprise / campus / coffee-shop
   network has several physical APs sharing one SSID for seamless roaming. Each AP has
   its own BSSID. They are **deliberately spread across channels 1/6/11** to avoid
   co-channel interference. So "different channel" between two BSSIDs of one SSID is
   **normal, not evidence.**

2. **Virtual APs / multiple BSSIDs per radio.** One physical AP broadcasting several
   SSIDs derives a **BSSID per SSID from a base MAC**, incrementing the low octets, and
   commonly **sets the locally-administered (U/L) bit** on the derived MACs. So:
   - Multiple BSSIDs that share the **first 3 octets (OUI)** or the **first 5 octets
     (base-MAC prefix)** are the **same vendor / same physical AP** → legit.
   - A **locally-administered MAC is NOT suspicious by itself** — enterprise gear sets
     it on virtual BSSIDs all the time. It only matters combined with other tells.

3. **Migration mixes.** During a WPA2→WPA3 rollout, one SSID legitimately has some APs
   on `WPA2/PSK` and others on `WPA3-transition`. So "crypto differs between two BSSIDs"
   is **not** proof — only a **downgrade to OPEN of an otherwise-secured network** is.

The standard WIDS mitigation for all of this is a **baseline/whitelist of known BSSIDs
per SSID** (which is exactly what `baseline.json` is), plus scoring that weights the
signals an attacker *can't* easily fake benignly.

## Signals, ranked by reliability

| Signal | Reliable? | Why |
|---|---|---|
| **Security downgrade** (network secured everywhere in baseline, new BSSID is OPEN) | ★★★ strong | Attacker lacks the PSK; a real AP of a secured SSID is never Open |
| **Foreign OUI / base-MAC** (new BSSID's OUI+prefix not among the network's known hardware) | ★★ good | The real operator's APs share vendor OUI / base MAC; a new vendor cloning the name is suspect |
| **Louder than the real AP** (RSSI far above the real APs' learned peak) | ★★ good (corroborating) | Attacker sits closer / higher power to win clients |
| **Deauth flood** | ★★ good | Classic companion attack to force roaming |
| **Karma / probe promiscuity** (one BSSID answering many SSIDs) | ★★ good | Real APs answer only for their own SSIDs |
| **Locally-administered MAC** | ★ weak alone | Legit virtual BSSIDs set it too — only meaningful with a foreign OUI |
| **Channel differs** from another BSSID of the SSID | ✗ not a signal | Legit multi-AP ESS spans 1/6/11 by design — **removed as evidence** |
| **Supported-rates / HT differs** | ✗ weak/noisy | Varies across legit AP models/firmware — **removed as standalone evidence** |

## How our detector scores a new BSSID (watch phase)

For a beacon whose **SSID is in the baseline** but whose **BSSID is new**, we compute a
profile of the real network from the baseline: the set of trusted OUIs, the set of
base-MAC (first-5-octet) prefixes, whether the network is **secured everywhere**, and
the real APs' **loudest learned RSSI**. Then:

- **`downgrade`** = network secured everywhere in baseline **and** new BSSID is OPEN.
- **`same_radio`** = new BSSID's first-5-octet prefix matches a known one → same physical AP.
- **`same_oui`** = new BSSID's OUI matches a known one → same vendor infra.
- **`louder`** = new RSSI > real peak + `RSSI_TWIN_LOUDER_MARGIN`.

Verdict:

- **BENIGN (not flagged)** — `same_radio`, or `same_oui` with no downgrade and not louder.
  → same operator's hardware, just a BSSID the learn window missed. *(This is what killed
  the `Parc Stiintific_Guest` and same-OUI false positives.)*
- **EVIL / red (HIGH)** — `downgrade` (even if OUI is spoofed to match), **or**
  foreign-OUI **and** louder. → the real attack signature.
- **REVIEW / yellow (MEDIUM)** — foreign-OUI new BSSID with no corroboration, or same-OUI
  but suspiciously louder. → genuinely unrecognized, worth a human glance, but **not**
  screamed as a confirmed twin. *(This is where a legit-but-new neighbor AP like the
  second `SCR`/`Street Coffee` radio lands — visible, not a red alarm.)*

RSSI-corridor check on a **known** BSSID now fires **only when it appears far LOUDER**
than its learned range (possible closer spoofer). A *weaker* signal is just distance and
is ignored — that removed the `SteamHQ` / `INNO-GUEST` false alarms.

## Honest limitations (state these to judges)

- Passive, single adapter, **2.4 GHz channels 1/6/11 only**.
- A **sophisticated twin that spoofs the real OUI, matches crypto, and isn't louder** is
  passively near-indistinguishable from a legit new AP. Real WIDS catches that with
  **802.1X/RADIUS certificate validation**, **sequence-number / TSF-timing analysis**, or
  a controller that knows its own AP inventory — all out of scope here.
- The baseline **must be learned with no attacker present**, or the twin is recorded as
  legit and never flagged.

## Sources
- [MITRE ATT&CK T1557.004 — Evil Twin](https://attack.mitre.org/techniques/T1557/004/)
- [MITRE DET0379 — Detect Evil Twin Wi-Fi APs](https://attack.mitre.org/detectionstrategies/DET0379)
- [ETSniffer (TAMU) — evil-twin detection research](https://people.engr.tamu.edu/guofei/paper/ETSniffer_TIFS12.pdf)
- [User-side evil-twin detection (UCF)](https://www.cs.ucf.edu/~czou/research/evilTwin-CCNC-2015.pdf)
- [Stealth & evasion in rogue AP attacks (arXiv 2512.10470)](https://arxiv.org/html/2512.10470)
- [Derivation of BSSIDs for APs (US11388137B1)](https://patents.google.com/patent/US11388137) — virtual-BSSID base-MAC + LAA bit
- [AccessAgility — private/LAA MAC addresses](https://go.accessagility.com/hc/private-mac-laa-mac-address)
