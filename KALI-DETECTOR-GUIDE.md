# Briefing for Claude inside Kali — Evil Twin DETECTOR

> You are Claude Code inside a **Kali Linux VM (VirtualBox)** on a Dell G6, with an **Atheros AR9271** USB adapter passed through to this VM.
> Read this fully before running anything. Raz is at the keyboard. Work **one step at a time** and confirm each step before moving on. Do not rush, do not improvise beyond this file.

---

## 1. The plan in plain words (what we're doing and why)

We are proving an **evil twin detector.** An "evil twin" = **two wifi networks with the SAME name (SSID) but different devices (BSSID).** One is real, one is a fake pretending to be it.

For this test there are **three wifi radios**:

| Role | Where it comes from | Notes |
|---|---|---|
| 🟢 **Real wifi** | Raz's **home router** (already broadcasting) | e.g. name "MyHomeWifi". We do NOT touch it. |
| 🔴 **Fake wifi (twin)** | The **Dell's Windows Mobile Hotspot**, set to the **same name** as the home wifi | This runs on the Windows HOST, NOT in this Kali VM. Raz sets it up. |
| 👂 **Detector** | **THIS Kali VM + the AR9271 antenna** in monitor mode | **Your job.** Listen to the air, catch the duplicate name. |

**Your one job: put the AR9271 into LISTENING (monitor) mode and run a detector that flags when one SSID is broadcast by two different BSSIDs.**

Key facts:
- This is 100% **passive listening** — you do NOT connect to anything, need no password, no internet, no portal.
- The AR9271 does **ONE job here: listen.** Earlier today it may have been *broadcasting* (airbase-ng) — that must be **stopped** first, because one adapter cannot broadcast and listen at the same time.
- The **fake wifi is NOT created by you** — it's the Dell's Windows hotspot. You only listen.

---

## 2. Step 0 — Stop any broadcasting, free the antenna

If airbase-ng (or any AP) is still running on the AR9271 from earlier, **stop it** (Ctrl-C in that terminal). The antenna must be free to listen.

Confirm the adapter is present and note its interface name:
```bash
iw dev                       # note the wlan interface (e.g. wlan0)
lsusb | grep -i atheros      # confirm the AR9271 is attached to the VM
```

---

## 3. Step 1 — Put the antenna into LISTENING (monitor) mode

```bash
sudo airmon-ng check kill        # stop NetworkManager etc. so they don't grab the card (expected: VM wifi "drops" — that's fine)
sudo airmon-ng start wlan0       # use the real interface name; creates wlan0mon
iwconfig                         # confirm an interface like wlan0mon is in "Mode:Monitor"
```
Note the exact monitor interface name (assume `wlan0mon` below).

---

## 4. Step 2 — Confirm the antenna hears the air

```bash
sudo airodump-ng wlan0mon        # watch ~15s: nearby wifis should populate. Ctrl-C to stop.
```
If networks scroll by, the antenna is listening correctly. **Ask Raz:** at this point his **Dell Windows hotspot should be ON and named the SAME as his home wifi.** You should then see that name appear on **two different BSSID rows** (home router + Dell hotspot). If you see the same name twice → detection will work.

> IMPORTANT: airodump-ng and the detector script both use the antenna. Only run one at a time. Ctrl-C airodump-ng before the next step.

---

## 5. Step 3 — Run the detector script

Make sure Scapy is installed:
```bash
python3 -c "import scapy; print(scapy.__version__)" || sudo apt install -y python3-scapy
```

Save this as `~/evil_twin_detect.py`:

```python
#!/usr/bin/env python3
"""Evil Twin Detector — flags one SSID broadcast by 2+ different BSSIDs."""
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap
from collections import defaultdict
import threading, subprocess, itertools, time, sys

IFACE = "wlan0mon"     # change if your monitor interface differs
HOP   = True           # cycle channels 1/6/11 so we hear APs on any of them
seen    = defaultdict(dict)   # ssid -> { bssid: {rssi, count} }
alerted = set()

def channel_hopper(iface):
    for ch in itertools.cycle([1, 6, 11]):
        subprocess.call(["iw", "dev", iface, "set", "channel", str(ch)],
                        stderr=subprocess.DEVNULL)
        time.sleep(0.8)

def handle(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return
    bssid = pkt[Dot11].addr2
    try:
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")
    except Exception:
        ssid = ""
    if not ssid:
        return
    rssi = None
    try:
        rssi = pkt[RadioTap].dBm_AntSignal
    except Exception:
        pass
    rec = seen[ssid].setdefault(bssid, {"count": 0, "rssi": rssi})
    rec["count"] += 1
    rec["rssi"]   = rssi

    # EVIL TWIN condition: same name, 2+ different BSSIDs
    if len(seen[ssid]) > 1 and ssid not in alerted:
        alerted.add(ssid)
        print("\n" + "=" * 60)
        print(f'[!!!] EVIL TWIN SUSPECTED  —  SSID: "{ssid}"')
        for b, info in seen[ssid].items():
            print(f"      BSSID {b}   RSSI {info['rssi']}   beacons {info['count']}")
        print("=" * 60 + "\n")

if __name__ == "__main__":
    print(f"[*] Detector listening on {IFACE} (channel hop: {HOP}) — Ctrl-C to stop")
    if HOP:
        threading.Thread(target=channel_hopper, args=(IFACE,), daemon=True).start()
    try:
        sniff(iface=IFACE, prn=handle, store=False)
    except KeyboardInterrupt:
        print("\n[*] stopped"); sys.exit(0)
```

Run it:
```bash
sudo python3 ~/evil_twin_detect.py
```

**What should happen:**
- With the Dell hotspot OFF: quiet (each name has one device).
- Ask Raz to turn the **Dell Windows hotspot ON, named the same as his home wifi** → within a few seconds the terminal prints:
  `[!!!] EVIL TWIN SUSPECTED — SSID: "..."` listing **two BSSIDs**.

**That alert firing = the detector works. This is the milestone.**

---

## 6. Step 4 — Prove it reacts to the real thing

Turn the Dell hotspot OFF, restart the script → no alert. Turn it ON → alert. This proves it flags the real duplicate, not random noise.

---

## 7. Report back to Raz
1. Monitor mode came up? (interface name)
2. `airodump-ng` showed the home-wifi name on **two** BSSIDs?
3. The Python detector printed the **EVIL TWIN** alert when the Dell hotspot went live?
4. Paste the alert output (the two BSSIDs + RSSI).

---

## 8. What's next (do NOT build yet — just be aware)
This flags on **duplicate SSID + different BSSID** — the strongest, simplest signal, and enough to prove the concept. Later we add richer features (signal/timing) and send events to the dashboard on the Mac. Not now.

## 9. Guardrails
- Passive listening only. Do not connect, deauth, or capture anyone's traffic.
- Only Raz's own home wifi / his own Dell hotspot are in play. Controlled, authorized test.
- The fake wifi is the Dell's Windows hotspot — you do NOT create it here.
- Stuck after 2–3 tries on a step? Stop and report to Raz.
