#!/usr/bin/env python3
"""Client-side GUARDIAN — runs on the device you want to protect.

It pulls the live rogue BLOCKLIST from the defense console (guardian.py) and
scans the Wi-Fi around *this* device. If a blocklisted evil-twin BSSID (or a
known rogue SSID) is in range, it pops a native "⚠ DO NOT CONNECT" notification
right here, on the user's own screen — the warning where it matters most.

Cross-platform: Linux (nmcli + notify-send), Windows (netsh + PowerShell toast),
macOS (airport + osascript).

    python3 guardian_client.py --server http://<kali-ip>:8081
    python3 guardian_client.py --server http://192.168.1.50:8081 --interval 5
"""
import argparse, json, platform, re, subprocess, sys, time, urllib.request

OS = platform.system()          # 'Linux' | 'Windows' | 'Darwin'


def fetch_blocklist(server):
    try:
        with urllib.request.urlopen(server.rstrip("/") + "/api/blocklist", timeout=4) as r:
            return json.load(r)
    except Exception as e:
        print(f"[!] cannot reach defense server: {e}")
        return []


def scan_nearby():
    """Return a set of (bssid_lower, ssid) currently in range on this device."""
    seen = set()
    try:
        if OS == "Linux":
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "BSSID,SSID", "dev", "wifi", "list", "--rescan", "yes"],
                text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                # nmcli escapes the colons in BSSID as \:
                m = re.match(r"((?:[0-9A-Fa-f]{2}\\?:){5}[0-9A-Fa-f]{2}):(.*)", line)
                if m:
                    seen.add((m.group(1).replace("\\", "").lower(), m.group(2)))
        elif OS == "Windows":
            out = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"],
                                          text=True, errors="ignore")
            ssid = None
            for line in out.splitlines():
                s = re.match(r"\s*SSID\s+\d+\s*:\s*(.*)", line)
                b = re.search(r"BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]{17})", line)
                if s: ssid = s.group(1).strip()
                if b: seen.add((b.group(1).lower(), ssid))
        elif OS == "Darwin":
            air = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            out = subprocess.check_output([air, "-s"], text=True)
            for line in out.splitlines()[1:]:
                m = re.search(r"([0-9a-f]{2}(:[0-9a-f]{2}){5})", line)
                if m:
                    seen.add((m.group(1).lower(), line[:32].strip()))
    except Exception as e:
        print(f"[!] scan failed ({OS}): {e}")
    return seen


def notify(title, msg):
    print(f"\n{'='*60}\n  {title}\n  {msg}\n{'='*60}")
    try:
        if OS == "Linux":
            subprocess.Popen(["notify-send", "-u", "critical", title, msg])
        elif OS == "Darwin":
            subprocess.Popen(["osascript", "-e",
                              f'display notification "{msg}" with title "{title}" sound name "Sosumi"'])
        elif OS == "Windows":
            ps = (f'[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,'
                  f'ContentType=WindowsRuntime]|Out-Null; '
                  f'$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent('
                  f'[Windows.UI.Notifications.ToastTemplateType]::ToastText02); '
                  f'$x=$t.GetElementsByTagName("text"); $x[0].AppendChild($t.CreateTextNode("{title}"))|Out-Null; '
                  f'$x[1].AppendChild($t.CreateTextNode("{msg}"))|Out-Null; '
                  f'[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Guardian").Show('
                  f'[Windows.UI.Notifications.ToastNotification]::new($t))')
            subprocess.Popen(["powershell", "-NoProfile", "-Command", ps])
    except Exception as e:
        print(f"[!] notify failed: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True, help="defense console URL, e.g. http://192.168.1.50:8081")
    ap.add_argument("--interval", type=int, default=6, help="seconds between scans")
    args = ap.parse_args()

    print(f"[*] Client guardian on {OS} — watching against {args.server} every {args.interval}s")
    warned = set()
    while True:
        block = fetch_blocklist(args.server)
        bad_bssid = {b["bssid"].lower() for b in block if b.get("bssid")}
        bad_ssid = {b["ssid"] for b in block if b.get("ssid")}
        near = scan_nearby()
        hits = [(bssid, ssid) for bssid, ssid in near
                if bssid in bad_bssid or (ssid and ssid in bad_ssid)]
        for bssid, ssid in hits:
            if bssid not in warned:
                warned.add(bssid)
                notify("⚠ DO NOT CONNECT — Evil Twin nearby",
                       f'"{ssid}" ({bssid}) is a known fake Wi-Fi. Do not connect to it.')
        if not hits:
            warned.clear()
            print(f"  [{time.strftime('%H:%M:%S')}] clear — {len(near)} APs in range, no rogues")
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] stopped")
        sys.exit(0)
