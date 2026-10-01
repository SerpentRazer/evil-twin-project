#!/usr/bin/env python3
"""Warning-beacon broadcaster — the one app-less, number-less Wi-Fi-native reach.

Broadcasts 802.11 beacons whose SSID *is* the message, e.g.
"DO-NOT-JOIN-FreeWiFi-FAKE". Anyone who opens their phone's Wi-Fi list sees it —
no app, no phone number, no association needed. It is the only way Wi-Fi itself
lets you put words in front of every nearby stranger.

Honest limits:
  * SSID max 32 BYTES (UTF-8), and only seen if the user opens the Wi-Fi list.
  * It TRANSMITS — authorized / own-airspace use only.
  * Beacon-only: there is no real AP behind it, so a device that tries to join
    just fails — which only reinforces "don't join".
  * One radio does one job: the AR9271 can sniff (detector/guardian) OR beacon,
    not both. Beacon from a second adapter if you need detection running too.

BSSIDs use a locally-administered, obviously-fake prefix (de:ad:...) so this is
never mistaken for, or used to spoof, real hardware.

    sudo WB_IFACE=wlan1 WB_CHANNEL=6 python3 warn_beacon.py
    sudo python3 warn_beacon.py "DO-NOT-JOIN-FreeWiFi-FAKE" "Evil-Twin-Nearby"

The launcher start-warn-beacon.sh preps the adapter into monitor mode first.
"""
import os
import sys
import time
import random

IFACE = os.environ.get("WB_IFACE", "wlan1")
CHANNEL = int(os.environ.get("WB_CHANNEL", "6"))
INTERVAL = float(os.environ.get("WB_INTERVAL", "0.1"))   # seconds between frames

# Default warning SSIDs (keep each <= 32 bytes). Override via argv.
DEFAULT_SSIDS = [
    "DO-NOT-JOIN-FreeWiFi-is-FAKE",
    "WARNING-Evil-Twin-Nearby",
]


def laa_bssid():
    """A locally-administered, clearly-fake BSSID — never a real vendor MAC."""
    return "de:ad:" + ":".join("%02x" % random.randint(0, 255) for _ in range(4))


def build_beacon(ssid, bssid):
    from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt
    ssid_bytes = ssid.encode("utf-8")[:32]                # 802.11 SSID cap
    dot11 = Dot11(type=0, subtype=8,                      # mgmt / beacon
                  addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon(cap="ESS")
    e_ssid = Dot11Elt(ID=0, info=ssid_bytes)
    e_rates = Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
    e_ds = Dot11Elt(ID=3, info=bytes([CHANNEL]))          # DS Parameter Set (channel)
    return RadioTap() / dot11 / beacon / e_ssid / e_rates / e_ds


def main():
    from scapy.all import sendp
    ssids = [s for s in sys.argv[1:] if s.strip()] or DEFAULT_SSIDS
    # one stable fake BSSID per SSID, so each shows as a single steady AP
    frames = [build_beacon(s, laa_bssid()) for s in ssids]
    for s in ssids:
        n = len(s.encode("utf-8"))
        flag = "  (!! >32 bytes, will be truncated)" if n > 32 else ""
        print(f"  beaconing: \"{s}\" ({n} bytes){flag}")
    print(f"[*] {len(frames)} warning SSID(s) on ch{CHANNEL} via {IFACE} "
          f"every {INTERVAL*len(frames):.2f}s — Ctrl+C to stop")
    try:
        sendp(frames, iface=IFACE, inter=INTERVAL, loop=1, verbose=0)
    except KeyboardInterrupt:
        print("\n[*] stopped.")
    except OSError as e:
        print(f"!! send failed on {IFACE}: {e}\n"
              f"   is {IFACE} in monitor mode? run via start-warn-beacon.sh", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
