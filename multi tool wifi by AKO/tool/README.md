# 🛡️ WiFi Multitool — by AKO

> A professional all-in-one WiFi & network security toolkit for Windows, built in Python.

---

## ⚡ Quick Start

### 1. Install Python
Download Python 3.10+ from → https://python.org/downloads  
✅ Check **"Add Python to PATH"** during installation.

### 2. Install dependencies
Open a terminal in this folder and run:
```bash
pip install -r requirements.txt
```

### 3. Install Npcap
Required for packet capture and ARP scanning:  
→ https://npcap.com/#download

### 4. Run the tool
```bash
python WiFiTool_AKO_v5.0.py
```
> 💡 **Run as Administrator** for full functionality (right-click → Run as administrator)

---

## 🌍 Languages
At startup, choose your language:
```
[1] Français   [2] English   [3] Español
```

---

## 📋 Features

### 🌐 Network
- Scan available WiFi networks (SSID, BSSID, signal, channel, encryption)
- View connected network info (IP, gateway, DNS, speed)
- View saved network history
- Check network security (WEP / WPA / WPA2 / WPA3)

### 📡 Devices
- ARP scan — detect all devices on your network (IP, MAC, hostname)
- ARP block — cut a device's internet access with real-time disconnection detection
- Connection / disconnection history log

### 💬 Messages
- Local TCP chat — real-time multi-client messaging on LAN (server + client mode)

### 🔒 Security
- IDS — detect SYN floods, port scans, Xmas/NULL scans, ARP spoofing
- Rogue AP detector — spot fake access points mimicking your network
- WiFi compromise checker — analyze your public IP and SSID exposure

### 🔍 IP & Diagnostics
- IP Lookup (country, city, ISP, ASN, GPS coords)
- Ping & latency test (multi-host)
- Internet speed test
- Traceroute
- Open port scanner (common or custom range)
- Real-time WiFi signal monitor
- Packet capture with save option
- Surveillance mode — continuous scan with new network alerts

### ⚙️ Control & Advanced
- Turn WiFi on / off / restart adapter
- Change saved SSID name or password
- View / change MAC address
- Change DNS (Google, Cloudflare, OpenDNS, Quad9 or manual)
- Flush DNS cache
- View active connections (netstat)
- Block / unblock websites via hosts file
- Set static IP or switch back to DHCP

### 🔧 Tools
- Network processes viewer (PID + process name)
- Active network shares + sessions
- Ban / unban device via Windows Firewall
- Subnet mapper (multithreaded ping sweep)
- OS fingerprinting (TTL + port signature detection)
- Password strength tester (entropy, brute-force time estimate)
- Strong password generator

### 📤 Export
- Export WiFi scan to CSV or TXT
- Generate full network report (interfaces, ARP, routes, netstat, firewall)

---

## 📁 Folder Structure

```
WIFI MULTITOOL-by AKO/
│
├── WiFiTool_AKO_v5.0.py      ← Main script
├── requirements.txt           ← Python dependencies
├── README.md                  ← This file
├── LICENSE                    ← MIT License
├── .gitignore
│
├── wifi_logs/                 ← Auto-created when you run the tool
│   ├── scan_*.csv / *.txt
│   ├── capture_*.txt
│   └── rapport_reseau_*.txt
│
└── previous_versions/         ← Older versions archive
    ├── wifi_multitool_v3.2.py
    └── ...
```

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `colorama` | Colored terminal output |
| `scapy` | ARP scan, packet capture, ARP block |
| `requests` | IP lookup, speed test |
| **Npcap** | Low-level network access for Scapy (Windows) |

---

## 🔑 Features requiring Administrator rights

| Feature | Option # |
|---------|---------|
| ARP scan & ARP block | 05, 06 |
| Packet capture | 15 |
| WiFi on / off | 20, 21 |
| MAC address change | 26 |
| DNS modification | 27 |
| Hosts file edit | 30 |
| Firewall ban/unban | 35 |

---

## 📜 Version History

| Version | What's new |
|---------|-----------|
| **v5.0** | Subnet mapper, OS fingerprinting, password tester & generator |
| v4.1 | Network processes, shares viewer, firewall ban/unban |
| v4.0 | DNS control, hosts editor, static IP, MAC changer, netstat, full report |
| v3.8 | Language selector, local TCP chat, IDS, Rogue AP detector |
| v3.5 | Faster ARP block (~400 pkt/s), disconnection detection |
| v3.4 | Signal monitor, traceroute, port scanner, IP lookup |
| v3.0 | New UI, ARP block, speed test, surveillance mode |

---

## ⚠️ Disclaimer

This tool is intended **exclusively for use on networks and devices you own or have explicit written authorization to test.**  
Unauthorized use on third-party networks is **illegal**.  
The author assumes **no responsibility** for any misuse of this software.

---

## 📄 License

MIT License — see `LICENSE` file.

---

*Made with ❤️ by **AKO***  
*"Built for professionals. Designed for clarity. Engineered for control."*
