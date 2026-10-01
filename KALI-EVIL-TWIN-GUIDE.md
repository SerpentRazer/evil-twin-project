# Briefing for Claude running inside Kali — Evil Twin Simulation

> You are Claude Code running **inside a Kali Linux VM (Oracle VirtualBox)** on a Dell G6 laptop.
> This file is your full context and task. Read it completely before running anything.
> The human (Raz) is present and will plug/attach hardware when you ask. Work **one step at a time** and confirm each step before moving on. Do not rush.

---

## 1. The big picture (why you're doing this)

Raz is building an **Evil Twin / Rogue Wi-Fi AP Detector** for a hackathon (HackTech Lightning 2026, Oct 2). The full system has three roles on different machines:

- **Attacker** = this Kali box + an **Atheros AR9271** USB Wi-Fi adapter → broadcasts a *fake* access point (the "evil twin").
- **Detector** = a separate machine sniffing beacons and flagging the fake (NOT your job).
- **Brain/dashboard** = a Mac (NOT your job).

**Your job right now: get this Kali box to broadcast a fake ("evil twin") access point, and verify it works.** This is a controlled, authorized lab exercise on Raz's own hardware and his own SSID. Nothing here touches any third-party network.

**Scope discipline:** only simulate the evil twin and verify it. Do NOT try to build the detector, capture handshakes, deauth real clients, or connect to any network you don't own. If something is ambiguous, stop and ask Raz.

---

## 2. Key hardware fact (read this twice)

The **AR9271 can only do ONE job at a time** — it can *broadcast* OR *sniff*, never both. On this box you will use it to **broadcast** the fake AP. So you will NOT be able to also detect from this same box with this same adapter. That's expected and fine — detection happens on a different machine.

---

## 3. Prerequisites — VirtualBox USB passthrough (the #1 blocker)

Because Kali is a VM, the AR9271 (a USB device physically plugged into the Dell) must be **passed through** from the Windows/host into this VM. If `lsusb` inside Kali does not show the Atheros adapter, nothing else will work.

Checklist to give Raz if the adapter isn't visible:
1. **Oracle VM VirtualBox Extension Pack** must be installed on the host (enables USB 2.0/3.0 passthrough). Without it, USB passthrough fails silently.
2. VM settings → **USB** → enable the **USB 2.0 (EHCI)** or **USB 3.0 (xHCI)** controller.
3. With the VM running: host menu **Devices → USB → select "Atheros Communications AR9271"** (or similar). A checkmark = attached to the VM.
4. Optional: add a **USB device filter** so it auto-attaches next boot.

Ask Raz to plug the AR9271 into the Dell and attach it to the VM, then continue.

---

## 4. Step-by-step (run these WITH Raz, confirming each)

### Step 0 — Confirm the adapter is visible inside Kali
```bash
lsusb | grep -i -E 'atheros|ar9271'      # expect a line naming Atheros / AR9271
iw dev                                    # expect a wlan interface (e.g. wlan0)
dmesg | grep -i ath9k_htc                 # expect firmware loaded, no errors
```
- If `lsusb` shows it but `iw dev` shows no wlan → firmware issue. Check `ls /lib/firmware/ath9k_htc/` for `htc_9271.fw`; if missing: `sudo apt install -y firmware-atheros` then re-attach the adapter.
- **Note the interface name** it gives you (assume `wlan0` below; substitute the real one).

### Step 1 — Confirm the required tools exist
```bash
which airmon-ng airodump-ng airbase-ng iw macchanger
aircrack-ng --help | head -1
```
Missing anything? `sudo apt update && sudo apt install -y aircrack-ng iw wireless-tools macchanger`

### Step 2 — Stop processes that fight monitor mode
```bash
sudo airmon-ng check kill      # stops NetworkManager / wpa_supplicant that would grab the card
```
(This will drop the VM's Wi-Fi-based networking if any — expected. The VM's normal network is via VirtualBox's virtual NIC, not this adapter, so you stay connected.)

### Step 3 — Enable monitor mode
```bash
sudo airmon-ng start wlan0     # use the real interface name from Step 0
iwconfig                       # confirm a new interface like wlan0mon is in "Mode:Monitor"
```
Expected: an interface named `wlan0mon` (or the card itself flips to Monitor mode). Note the exact name.

### Step 4 — Sanity check: can it hear the air?
```bash
sudo airodump-ng wlan0mon      # should populate with nearby networks. Ctrl-C after ~10s.
```
If you see live networks scrolling, the adapter + monitor mode work. **This confirms the hardware is good before we broadcast.**

> IMPORTANT: airodump-ng (Step 4) and airbase-ng (Step 5) both need the adapter. You can't run both at once. Stop airodump-ng (Ctrl-C) before Step 5.

### Step 5 — Broadcast the evil twin
Ask Raz for the **exact SSID** to clone and the **channel** of his real AP (his own TP-Link hotspot). Default example uses `HackTech-Guest` on channel 6.
```bash
sudo airbase-ng -e "HackTech-Guest" -c 6 wlan0mon
```
- `-e` = the ESSID (network *name*) to impersonate — this is what makes it a "twin".
- `-c` = channel — should match the real AP's channel for a convincing twin.
- Leave this running; it now beacons a fake AP whose BSSID = this adapter's MAC.
- airbase-ng also creates an `at0` interface for client traffic — **ignore it**, the demo only needs the beacons.

### Step 6 — Verify the twin is actually broadcasting
Best done from **another device** (Raz's phone or laptop): open Wi-Fi settings and look for `HackTech-Guest` appearing. If Raz's real TP-Link is also on with the same SSID, phones will show **two entries with the same name** (or one name backed by two BSSIDs) — that's the evil twin condition the detector is built to catch.

To read the BSSID (fake MAC) this box is using:
```bash
ip link show wlan0mon        # the MAC here is the evil twin's BSSID
```

### Step 7 (optional) — Control the fake BSSID
To set a specific/obviously-different MAC before broadcasting:
```bash
sudo ip link set wlan0mon down
sudo macchanger -r wlan0mon       # random MAC (or -m XX:XX:.. for a specific one)
sudo ip link set wlan0mon up
```
Then re-run Step 5.

---

## 5. How to stop / clean up
```bash
# Ctrl-C the airbase-ng terminal to stop broadcasting, then:
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager   # restore normal networking
```

---

## 6. Report back to Raz

After the run, tell him clearly:
1. Did `lsusb` / `iw dev` see the AR9271? (adapter passthrough OK?)
2. Did monitor mode enable? (exact interface name)
3. Did `airodump-ng` show live networks? (capture works?)
4. Did `airbase-ng` broadcast, and was `HackTech-Guest` visible from another device? (twin confirmed?)
5. What BSSID (MAC) did the fake AP use?

If any step failed, report the exact error text and where it stopped — don't improvise workarounds beyond the troubleshooting notes above.

---

## 7. Guardrails
- Only broadcast an SSID Raz owns/controls, in a controlled space. This is authorized lab work on his own gear.
- No deauth, no capturing other people's traffic, no cloning networks that aren't his.
- One adapter = one job. Don't try to detect and broadcast simultaneously.
- Stuck after 2–3 attempts on any step? Stop and report to Raz rather than looping.

---

## 8. Session state — RESUME HERE after VM restart

_Last updated: 2026-09-29. Read this whole section before running anything._

### Where we got to before the restart
- ✅ Sections 0–3 completed successfully (adapter passed through, tools installed, monitor mode works, airodump-ng saw the air).
- ✅ Broadcasting an **OPEN** evil twin named `HackTech-Free-WiFi` on channel 6 (verified from Raz's other laptop — SSID was visible).
- 🔨 Extending the demo with a **captive portal** (beyond the original guide's scope — Raz agreed to this scope expansion under the rules below).
- ⏸ Paused mid-Section 9 Step C: `at0` had IP `10.0.0.1/24`, dnsmasq about to be installed/started for the first time.

### Design decisions made this session (do not re-litigate)
- **Open twin**, not WPA2 (`-Z 4` deliberately NOT used). Raz picked this for the more common real-world attack scenario (public-Wi-Fi impersonation).
- SSID = `HackTech-Free-WiFi`, channel = 6.
- Captive portal will be a **benign educational splash page**. No fake login, no credential harvesting.
- Portal only runs in Raz's controlled lab space. Not deployed anywhere with uncontrolled bystanders.

### Persistent files (survive reboot — don't recreate if they already exist)
- `/etc/dnsmasq-portal.conf`
- `/var/www/html/index.html`
- `/etc/apache2/sites-available/portal.conf`

Check them first with `ls -la` / `cat`. Only rewrite if missing or changed.

### Volatile state (WIPED on reboot — must re-run)
- NetworkManager comes back → re-do `airmon-ng check kill`.
- Monitor mode gone → re-do `airmon-ng start wlan0`.
- `airbase-ng` process → restart (this recreates `at0`).
- `at0` IP → gone with the interface, re-add.
- `dnsmasq` running instance → restart manually (we deliberately disabled the systemd unit).
- `iptables` rules → wiped, must re-apply.
- Apache config survives; the service should auto-start, but verify.

---

## 9. Captive-portal build (extension of Section 4)

Architecture:
```
phone → AR9271 (monitor) → at0 (10.0.0.1/24)
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
           dnsmasq         apache2         iptables
        (DHCP + DNS)   (splash page)   (redirect 80/443)
```

Rules of engagement:
- **Benign splash only.** No fake login forms.
- **Controlled space only.** Do not enable this where uncontrolled bystanders may associate.

### Full resume sequence (run in order after VM boots)

**Prereq:** confirm the AR9271 is still USB-passed-through to the VM (`lsusb | grep -i atheros`). If not, see Section 3.

**Terminal 1 — broadcast**
```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
sudo airbase-ng -e "HackTech-Free-WiFi" -c 6 wlan0mon
# leave running
```

**Terminal 2 — at0 + dnsmasq**
```bash
sudo ip addr add 10.0.0.1/24 dev at0
sudo ip link set at0 up

# Write config only if /etc/dnsmasq-portal.conf does not already exist:
sudo tee /etc/dnsmasq-portal.conf > /dev/null <<'EOF'
interface=at0
bind-interfaces
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
address=/#/10.0.0.1
EOF

sudo systemctl stop dnsmasq 2>/dev/null
sudo systemctl disable dnsmasq 2>/dev/null
sudo dnsmasq -C /etc/dnsmasq-portal.conf --no-daemon --log-queries
# leave running
```

**Terminal 3 — apache + portal page**
```bash
sudo apt install -y apache2   # only first time

# Write portal page only if missing:
sudo tee /var/www/html/index.html > /dev/null <<'EOF'
<!DOCTYPE html>
<html>
<head><title>HackTech Lightning 2026 — Evil Twin Demo</title></head>
<body style="font-family:sans-serif;text-align:center;padding:3em;background:#111;color:#eee">
  <h1 style="color:#ff5555">⚠ You've been evil-twinned</h1>
  <p>This is a controlled security research demo (HackTech Lightning 2026).</p>
  <p>No credentials, traffic, or personal data are being captured.</p>
  <p>Disconnect and rejoin your real network.</p>
</body>
</html>
EOF

# Write apache site config only if missing:
sudo tee /etc/apache2/sites-available/portal.conf > /dev/null <<'EOF'
<VirtualHost *:80>
  DocumentRoot /var/www/html
  <Directory /var/www/html>
    RewriteEngine On
    RewriteRule .* /index.html [L]
  </Directory>
</VirtualHost>
EOF

sudo a2enmod rewrite
sudo a2dissite 000-default.conf 2>/dev/null
sudo a2ensite portal.conf
sudo systemctl restart apache2
curl -s http://10.0.0.1/anything | head -5   # sanity check
```

**Terminal 3 — iptables (redirect + accept)**
```bash
sudo iptables -t nat -F
sudo iptables -t nat -A PREROUTING -i at0 -p tcp --dport 80  -j DNAT --to-destination 10.0.0.1:80
sudo iptables -t nat -A PREROUTING -i at0 -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80
sudo iptables -A INPUT -i at0 -j ACCEPT
```

**Verify from phone**
1. Join `HackTech-Free-WiFi`.
2. Within ~10s the OS should pop **"Sign in to network"**.
3. Tap it → red splash page loads.
4. Watch dnsmasq log (Terminal 2) — you'll see the phone's DHCP + DNS queries live.

### Cleanup after demo
```bash
# Ctrl-C airbase-ng (T1) and dnsmasq (T2)
sudo airmon-ng stop wlan0mon
sudo iptables -t nat -F
sudo systemctl stop apache2
sudo systemctl restart NetworkManager
```

