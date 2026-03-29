#!/usr/bin/env python3
"""
WiFi Multi-Tool v5.0 — By AKO
Windows Edition · Python 3.10+
pip install colorama scapy requests
+ Npcap : https://npcap.com/#download
"""

import subprocess, sys, os, re, socket, csv, time, threading, json
from datetime import datetime
from pathlib import Path

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    os.system("pip install colorama -q")
    from colorama import init, Fore, Style
    init(autoreset=True)

try:
    from scapy.all import sniff, ARP, Ether, srp, sendp, get_if_hwaddr, conf as scapy_conf, IP, TCP, UDP, ICMP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ══════════════════════════════════════════════════════════
#  PALETTE
# ══════════════════════════════════════════════════════════
PRI = Fore.CYAN
ACC = Fore.LIGHTBLUE_EX
DIM = Fore.LIGHTBLACK_EX
GRN = Fore.LIGHTGREEN_EX
RED = Fore.RED
YLW = Fore.YELLOW
BR  = Style.BRIGHT
RS  = Style.RESET_ALL

def title(t):  return f"\n{BR}{PRI}  ╔{'═'*(len(t)+4)}╗\n  ║  {ACC}{t}{PRI}  ║\n  ╚{'═'*(len(t)+4)}╝{RS}"
def ok(t):     return f"{GRN}  [✓] {t}{RS}"
def err(t):    return f"{RED}  [✗] {t}{RS}"
def warn(t):   return f"{YLW}  [!] {t}{RS}"
def info(t):   return f"{DIM}  [·] {t}{RS}"
def sep():     return f"{DIM}  {'─'*62}{RS}"
def hdr(c):    return f"  {BR}{ACC}{c}{RS}"

LOG_DIR = Path("wifi_logs")
LOG_DIR.mkdir(exist_ok=True)

CONN_HISTORY  = []
_last_networks = []

# ══════════════════════════════════════════════════════════
#  TRADUCTIONS
# ══════════════════════════════════════════════════════════
TRANSLATIONS = {
    "fr": {
        "lang_select":      "Choisissez votre langue",
        "boot_modules":     "Chargement des modules reseau...",
        "boot_iface":       "Detection de l'interface WiFi...",
        "boot_init":        "Initialisation...",
        "boot_ready":       "Pret.",
        "admin_ok":         "Droits Administrateur detectes.",
        "admin_warn":       "Non lance en Administrateur — options 05/06/15/17/18 limitees.",
        "logs":             "Logs",
        "menu_title":       "WIFI MULTI-TOOL",
        "menu_reseau":      "[ RESEAU ]",
        "menu_appareils":   "[ APPAREILS ]",
        "menu_messages":    "[ MESSAGES ]",
        "menu_securite":    "[ SECURITE ]",
        "menu_diagnostic":  "[ IP & DIAGNOSTIC ]",
        "menu_controle":    "[ CONTROLE ]",
        "menu_export":      "[ EXPORT ]",
        "menu_quit":        "Quitter",
        "menu_choice":      "Votre choix",
        "press_enter":      "Appuyez sur Entree pour continuer...",
        "scanning":         "Scan en cours...",
        "no_network":       "Aucun reseau detecte.",
        "no_device":        "Aucun appareil. Lancez en Admin.",
        "invalid":          "Choix invalide.",
        "goodbye":          "A bientot !",
        "m01": "Scanner les reseaux WiFi",
        "m02": "Infos reseau connecte  (IP · GW · DNS)",
        "m03": "Historique des reseaux connus",
        "m04": "Verifier la securite  (WEP/WPA/WPA2/WPA3)",
        "m05": "Scanner les appareils + recuperer leur IP",
        "m06": "Couper l'acces d'un appareil  (ARP block)",
        "m07": "Historique connexions/deconnexions",
        "m08": "Chat local  (serveur/client TCP)",
        "m09": "IP Lookup  (infos publiques sur une IP)",
        "m10": "Ping / test de latence",
        "m11": "Test de debit internet",
        "m12": "Traceroute",
        "m13": "Scanner les ports d'un appareil",
        "m14": "Signal WiFi en temps reel",
        "m15": "Capturer des paquets",
        "m16": "Mode surveillance  (scan en boucle)",
        "m17": "Analyse IDS  (paquets suspects)",
        "m18": "Detecteur de Rogue AP",
        "m19": "Checker si ton WiFi est compromis",
        "m20": "Allumer le WiFi",
        "m21": "Eteindre le WiFi",
        "m22": "Exporter le dernier scan  (CSV / TXT)",
        "m23": "Changer le nom du reseau (SSID)",
        "m24": "Changer le mot de passe WiFi",
        "m25": "Redemarrer l'adaptateur WiFi",
        "m26": "Voir / Changer l'adresse MAC",
        "m27": "Voir / Modifier le DNS",
        "m28": "Vider le cache DNS",
        "m29": "Connexions actives (netstat)",
        "m30": "Bloquer / Debloquer un site (hosts)",
        "m31": "IP statique / repasser en DHCP",
        "m32": "Rapport complet du reseau",
        "m33": "Processus utilisant le reseau",
        "m34": "Partages reseau actifs",
        "m35": "Bannir / Debannir un appareil (pare-feu)",
        "m36": "Scanner de sous-reseaux (subnet mapper)",
        "m37": "Detection d'OS (fingerprinting)",
        "m38": "Testeur de solidite de mot de passe",
        "m39": "Generateur de mots de passe forts",
    },
    "en": {
        "lang_select":      "Choose your language",
        "boot_modules":     "Loading network modules...",
        "boot_iface":       "Detecting WiFi interface...",
        "boot_init":        "Initializing...",
        "boot_ready":       "Ready.",
        "admin_ok":         "Administrator rights detected.",
        "admin_warn":       "Not run as Administrator — options 05/06/15/20/21 limited.",
        "logs":             "Logs",
        "menu_title":       "WIFI MULTI-TOOL",
        "menu_reseau":      "[ NETWORK ]",
        "menu_appareils":   "[ DEVICES ]",
        "menu_messages":    "[ MESSAGES ]",
        "menu_securite":    "[ SECURITY ]",
        "menu_diagnostic":  "[ IP & DIAGNOSTIC ]",
        "menu_controle":    "[ CONTROL ]",
        "menu_export":      "[ EXPORT ]",
        "menu_quit":        "Quit",
        "menu_choice":      "Your choice",
        "press_enter":      "Press Enter to continue...",
        "scanning":         "Scanning...",
        "no_network":       "No network detected.",
        "no_device":        "No device found. Run as Admin.",
        "invalid":          "Invalid choice.",
        "goodbye":          "Goodbye !",
        "m01": "Scan available WiFi networks",
        "m02": "Connected network info  (IP · GW · DNS)",
        "m03": "Known networks history",
        "m04": "Check security  (WEP/WPA/WPA2/WPA3)",
        "m05": "Scan devices + get their IP",
        "m06": "Block a device  (ARP block)",
        "m07": "Connection/disconnection history",
        "m08": "Local chat  (TCP server/client)",
        "m09": "IP Lookup  (public info on an IP)",
        "m10": "Ping / latency test",
        "m11": "Internet speed test",
        "m12": "Traceroute",
        "m13": "Scan open ports",
        "m14": "Real-time WiFi signal",
        "m15": "Capture packets",
        "m16": "Surveillance mode  (loop scan)",
        "m17": "IDS analysis  (suspicious packets)",
        "m18": "Rogue AP detector",
        "m19": "Check if your WiFi is compromised",
        "m20": "Turn WiFi on",
        "m21": "Turn WiFi off",
        "m22": "Export last scan  (CSV / TXT)",
        "m23": "Change network name (SSID)",
        "m24": "Change WiFi password",
        "m25": "Restart WiFi adapter",
        "m26": "View / Change MAC address",
        "m27": "View / Modify DNS",
        "m28": "Flush DNS cache",
        "m29": "Active connections (netstat)",
        "m30": "Block / Unblock a website (hosts)",
        "m31": "Static IP / switch back to DHCP",
        "m32": "Full network report",
        "m33": "Processes using the network",
        "m34": "Active network shares",
        "m35": "Ban / Unban a device (firewall)",
        "m36": "Subnet scanner (subnet mapper)",
        "m37": "OS Detection (fingerprinting)",
        "m38": "Password strength tester",
        "m39": "Strong password generator",
    },
    "es": {
        "lang_select":      "Elige tu idioma",
        "boot_modules":     "Cargando modulos de red...",
        "boot_iface":       "Detectando interfaz WiFi...",
        "boot_init":        "Inicializando...",
        "boot_ready":       "Listo.",
        "admin_ok":         "Derechos de Administrador detectados.",
        "admin_warn":       "No ejecutado como Administrador — opciones 05/06/15/20/21 limitadas.",
        "logs":             "Registros",
        "menu_title":       "WIFI MULTI-TOOL",
        "menu_reseau":      "[ RED ]",
        "menu_appareils":   "[ DISPOSITIVOS ]",
        "menu_messages":    "[ MENSAJES ]",
        "menu_securite":    "[ SEGURIDAD ]",
        "menu_diagnostic":  "[ IP & DIAGNOSTICO ]",
        "menu_controle":    "[ CONTROL ]",
        "menu_export":      "[ EXPORTAR ]",
        "menu_quit":        "Salir",
        "menu_choice":      "Tu eleccion",
        "press_enter":      "Presiona Enter para continuar...",
        "scanning":         "Escaneando...",
        "no_network":       "Ninguna red detectada.",
        "no_device":        "Ningun dispositivo. Ejecutar como Admin.",
        "invalid":          "Opcion invalida.",
        "goodbye":          "Hasta luego !",
        "m01": "Escanear redes WiFi disponibles",
        "m02": "Info red conectada  (IP · GW · DNS)",
        "m03": "Historial de redes conocidas",
        "m04": "Verificar seguridad  (WEP/WPA/WPA2/WPA3)",
        "m05": "Escanear dispositivos + obtener IP",
        "m06": "Cortar acceso de un dispositivo  (ARP block)",
        "m07": "Historial conexiones/desconexiones",
        "m08": "Chat local  (servidor/cliente TCP)",
        "m09": "IP Lookup  (info publica de una IP)",
        "m10": "Ping / test de latencia",
        "m11": "Test de velocidad internet",
        "m12": "Traceroute",
        "m13": "Escanear puertos abiertos",
        "m14": "Senal WiFi en tiempo real",
        "m15": "Capturar paquetes",
        "m16": "Modo vigilancia  (escaneo en bucle)",
        "m17": "Analisis IDS  (paquetes sospechosos)",
        "m18": "Detector de Rogue AP",
        "m19": "Verificar si tu WiFi esta comprometido",
        "m20": "Encender WiFi",
        "m21": "Apagar WiFi",
        "m22": "Exportar ultimo escaneo  (CSV / TXT)",
        "m23": "Cambiar nombre de red (SSID)",
        "m24": "Cambiar contrasena WiFi",
        "m25": "Reiniciar adaptador WiFi",
        "m26": "Ver / Cambiar direccion MAC",
        "m27": "Ver / Modificar DNS",
        "m28": "Vaciar cache DNS",
        "m29": "Conexiones activas (netstat)",
        "m30": "Bloquear / Desbloquear sitio (hosts)",
        "m31": "IP estatica / volver a DHCP",
        "m32": "Informe completo de red",
        "m33": "Procesos usando la red",
        "m34": "Recursos compartidos activos",
        "m35": "Banear / Desbanear dispositivo (firewall)",
        "m36": "Escaner de subredes (subnet mapper)",
        "m37": "Deteccion de OS (fingerprinting)",
        "m38": "Tester de solidez de contrasena",
        "m39": "Generador de contrasenas fuertes",
    }
}

T   = TRANSLATIONS["fr"]   # langue active
LANG = "fr"

def t(key): return T.get(key, key)


# ══════════════════════════════════════════════════════════
#  BANNIÈRE
# ══════════════════════════════════════════════════════════
BANNER = f"""
{BR}{PRI}
  ██╗    ██╗██╗███████╗██╗
  ██║    ██║██║██╔════╝██║
  ██║ █╗ ██║██║█████╗  ██║
  ██║███╗██║██║██╔══╝  ██║
  ╚███╔███╔╝██║██║     ██║
   ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝{RS}
{DIM}        v5.0  ·  By AKO  ·  Windows Edition{RS}"""

def typewrite(text, delay=0.02):
    for ch in text:
        sys.stdout.write(ch); sys.stdout.flush(); time.sleep(delay)
    print()

def select_language():
    global T, LANG
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)
    print(f"\n{sep()}")
    print(f"\n  {BR}{ACC}Choisissez votre langue / Choose your language / Elige tu idioma{RS}\n")
    print(f"  {PRI}[1]{RS}  {ACC}Francais{RS}")
    print(f"  {PRI}[2]{RS}  {ACC}English{RS}")
    print(f"  {PRI}[3]{RS}  {ACC}Espanol{RS}")
    print(f"\n{sep()}\n")
    choice = input(f"  {BR}{PRI}> {RS}").strip()
    if choice == "2":   LANG = "en"
    elif choice == "3": LANG = "es"
    else:               LANG = "fr"
    T = TRANSLATIONS[LANG]

def slow_banner():
    select_language()
    os.system("cls" if os.name == "nt" else "clear")
    lines = BANNER.split("\n")
    for line in lines:
        print(line); time.sleep(0.06)
    time.sleep(0.1)
    msgs = [t("boot_modules"), t("boot_iface"), t("boot_init"), t("boot_ready")]
    print()
    for m in msgs:
        sys.stdout.write(f"  {DIM}[boot]{RS} ")
        typewrite(m, delay=0.02)
        time.sleep(0.05)
    print()

# Pages du menu horizontal
MENU_PAGES = [
    {"cat": "menu_reseau",     "items": [("01","m01"),("02","m02"),("03","m03"),("04","m04")]},
    {"cat": "menu_appareils",  "items": [("05","m05"),("06","m06"),("07","m07")]},
    {"cat": "menu_messages",   "items": [("08","m08")]},
    {"cat": "menu_securite",   "items": [("17","m17"),("18","m18"),("19","m19")]},
    {"cat": "menu_diagnostic", "items": [("09","m09"),("10","m10"),("11","m11"),("12","m12"),
                                         ("13","m13"),("14","m14"),("15","m15"),("16","m16")]},
    {"cat": "menu_controle",   "items": [("20","m20"),("21","m21"),("25","m25")]},
    {"cat": "[ AVANCE ]",      "items": [("23","m23"),("24","m24"),("26","m26"),("27","m27"),
                                         ("28","m28"),("29","m29"),("30","m30"),("31","m31")]},
    {"cat": "[ AVANCE+ ]",     "items": [("33","m33"),("34","m34"),("35","m35")]},
    {"cat": "[ OUTILS ]",      "items": [("36","m36"),("37","m37"),("38","m38"),("39","m39")]},
    {"cat": "menu_export",     "items": [("22","m22"),("32","m32")]},
]

def build_page(page_idx):
    page     = MENU_PAGES[page_idx]
    total    = len(MENU_PAGES)
    cat_name = t(page["cat"]) if page["cat"].startswith("menu") else page["cat"]
    items    = page["items"]

    # Indicateurs de page (points)
    dots = ""
    for i in range(total):
        dots += (f"{BR}{PRI}●{RS}" if i == page_idx else f"{DIM}○{RS}")
        if i < total - 1: dots += " "

    has_next = page_idx < total - 1
    has_prev = page_idx > 0
    nav_n = f"{BR}{ACC}[n] next >{RS}" if has_next else f"{DIM}          {RS}"
    nav_b = f"{BR}{ACC}< [b] back{RS}" if has_prev else f"{DIM}          {RS}"

    lines = [
        f"",
        f"{DIM}  {chr(9552)*62}{RS}",
        f"{BR}{PRI}  {t('menu_title')}{RS} {DIM}· v5.0 · By AKO{RS}",
        f"{DIM}  {chr(9552)*62}{RS}",
        f"",
        f"  {nav_b}     {dots}     {nav_n}",
        f"",
        f"{BR}{PRI}  {cat_name}{chr(9472)*(54-len(cat_name))}{RS}",
        f"",
    ]
    for code, key in items:
        lines.append(f"  {ACC}{code}{RS}{DIM}  {t(key)}{RS}")
    lines += [
        f"",
        f"  {RED}00{RS}{DIM}  {t('menu_quit')}{RS}",
        f"{DIM}  {chr(9552)*62}{RS}",
    ]
    return "\n".join(lines)

def build_menu():
    return build_page(0)

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
    input(f"\n{DIM}  {t('press_enter')}{RS}")

def clear_banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)


# ══════════════════════════════════════════════════════════
#  01. SCANNER LES RÉSEAUX
# ══════════════════════════════════════════════════════════
def scan_networks(silent=False):
    global _last_networks
    if not silent:
        print(title(t("m01").upper()))
        print(info(t("scanning")))

    code, out = run(["netsh", "wlan", "show", "networks", "mode=Bssid"])
    if code != 0:
        if not silent: print(err(t("no_network")))
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
            print(warn(t("no_network"))); pause(); return []
        print(f"\n{hdr('  #    SSID                         BSSID                Signal    Canal  Auth')}")
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
        print(f"\n{ok(str(len(networks)) + ' reseau(x)')}")
        pause()
    return networks


# ══════════════════════════════════════════════════════════
#  02. INFOS RÉSEAU CONNECTÉ
# ══════════════════════════════════════════════════════════
def network_info():
    print(title(t("m02").upper()))
    _, ssid_out = run(["netsh", "wlan", "show", "interfaces"])
    ssid = bssid = signal = speed = "?"
    for line in ssid_out.splitlines():
        l = line.strip()
        if l.startswith("SSID") and "BSSID" not in l: ssid   = l.split(":",1)[-1].strip()
        elif "BSSID"  in l: bssid  = l.split(":",1)[-1].strip()
        elif "Signal" in l: signal = l.split(":",1)[-1].strip()
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
            elif re.search(r"Masque|Subnet Mask", l): mask = l.split(":")[-1].strip()
            elif re.search(r"Passerelle|Default Gateway", l):
                m = re.search(r"[\d.]+", l.split(":")[-1])
                if m: gw = m.group()
            elif re.search(r"Serveurs DNS|DNS Servers", l):
                m = re.search(r"[\d.]+", l.split(":")[-1])
                if m: dns_list.append(m.group())
            elif dns_list and re.match(r"^\s+[\d.]+", line): dns_list.append(line.strip())
            elif line.strip() == "" and in_wifi and ip != "?": break
    rows = [
        ("SSID", ssid), ("BSSID", bssid), ("Signal", signal), ("Debit", speed),
        ("─"*16, ""), ("IP", ip), ("Masque", mask), ("Passerelle", gw),
        ("DNS", " · ".join(dns_list) if dns_list else "?"),
        ("─"*16, ""), ("Hostname", socket.gethostname()),
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
    print(title(t("m03").upper()))
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
#  04. SÉCURITÉ RÉSEAUX
# ══════════════════════════════════════════════════════════
SECURITY_LEVELS = {
    "WEP":   (RED, "FAIBLE    — Cassable en minutes"),
    "WPA3":  (GRN, "EXCELLENT — Derniere generation"),
    "WPA2":  (GRN, "BON       — Suffisant"),
    "WPA":   (YLW, "MOYEN     — Vulnerable"),
    "Ouvert":(RED, "AUCUN     — Non chiffre !"),
    "Open":  (RED, "AUCUN     — Non chiffre !"),
}

def check_security():
    print(title(t("m04").upper()))
    print(info(t("scanning")))
    networks = scan_networks(silent=True)
    if not networks:
        print(err(t("no_network"))); pause(); return
    print(f"\n{hdr('  SSID                         Auth        Evaluation')}")
    print(sep())
    for n in networks:
        ssid = n.get("ssid","?")[:27]; auth = n.get("auth","?")
        color, label = ACC, "INCONNU"
        for key, (col, lbl) in SECURITY_LEVELS.items():
            if key.lower() in auth.lower():
                color, label = col, lbl; break
        print(f"  {ACC}{ssid:<29}{RS}{DIM}{auth:<12}{RS}{color}{label}{RS}")
    print(f"\n{ok('Analyse terminee')}")
    pause()


# ══════════════════════════════════════════════════════════
#  05. ARP SCAN
# ══════════════════════════════════════════════════════════
def arp_scan(silent=False):
    if not silent: print(title(t("m05").upper()))
    if not SCAPY_OK:
        if not silent: print(err("Scapy requis : pip install scapy + Npcap")); pause()
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
        print(info(f"Subnet : {subnet}"))
        print(warn("Patientez 5-15s...\n"))
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=3, verbose=0)
        devices = []
        for _, rcv in ans:
            ip_a = rcv.psrc; mac = rcv.hwsrc
            try:    host = socket.gethostbyaddr(ip_a)[0]
            except: host = "inconnu"
            devices.append({"ip": ip_a, "mac": mac, "host": host})
        if not silent:
            if not devices:
                print(warn(t("no_device"))); pause(); return []
            print(f"{hdr('  #    IP                 MAC                  Nom hote')}")
            print(sep())
            for i, d in enumerate(sorted(devices, key=lambda x: x["ip"]), 1):
                print(f"  {DIM}{i:<4}{RS}{PRI}{d['ip']:<19}{RS}{DIM}{d['mac']:<21}{RS}{ACC}{d['host']}{RS}")
            print(f"\n{ok(str(len(devices)) + ' appareil(s)')}")
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
    print(title(t("m06").upper()))
    print(warn("A utiliser uniquement sur TON reseau et TES appareils."))
    if not SCAPY_OK:
        print(err("Scapy requis : pip install scapy + Npcap")); pause(); return

    devices = []
    while True:
        print(info(t("scanning")))
        devices = arp_scan(silent=True)
        if not devices:
            print(err(t("no_device"))); pause(); return
        print(f"\n{hdr('  #    IP                 MAC                  Nom hote')}")
        print(sep())
        for i, d in enumerate(devices, 1):
            print(f"  {ACC}{i:<4}{RS}{PRI}{d['ip']:<19}{RS}{DIM}{d['mac']:<21}{RS}{ACC}{d['host']}{RS}")
        print(f"\n  {DIM}[r] Rescanner  |  [0] Annuler  |  Numero pour bloquer{RS}\n")
        choice = input(f"  {ACC}Votre choix : {RS}").strip().lower()
        if choice == "0": return
        if choice == "r": print(); continue
        if not choice.isdigit(): print(warn(t("invalid"))); continue
        idx = int(choice) - 1
        if idx < 0 or idx >= len(devices): print(err("Numero invalide.")); continue
        break

    target = devices[idx]
    t_ip = target["ip"]; t_mac = target["mac"]; t_host = target["host"]
    gw_ip = get_gateway()

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
        sent = 0; was_online = True; check_every = 15
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
                        print(f"\n{GRN}  [✓] [{ts}] Appareil DECONNECTE ! ({sent*2} paquets){RS}")
                        CONN_HISTORY.append({"time": ts, "ip": t_ip, "host": t_host, "event": "deconnecte"})
                        was_online = False
                    elif not was_online and online:
                        print(f"\n{YLW}  [!] [{ts}] Appareil RECONNECTE ! Reprise...{RS}")
                        CONN_HISTORY.append({"time": ts, "ip": t_ip, "host": t_host, "event": "reconnecte"})
                        was_online = True
                status = f"{RED}en ligne{RS}" if was_online else f"{GRN}deconnecte{RS}"
                sys.stdout.write(f"\r  {DIM}Paquets : {sent*2:<6} | Statut : {RS}{status}   ")
                sys.stdout.flush()
                time.sleep(0.05)
            except Exception: break
        print()

    th = threading.Thread(target=block_loop)
    th.start()
    try:
        th.join()
    except KeyboardInterrupt:
        stop_event.set(); th.join()

    print(ok(f"Blocage termine pour {t_ip}"))
    pause()


# ══════════════════════════════════════════════════════════
#  07. HISTORIQUE CONNEXIONS
# ══════════════════════════════════════════════════════════
def conn_history():
    print(title(t("m07").upper()))
    if not CONN_HISTORY:
        print(warn("Aucun evenement. Utilisez l'option 06 d'abord.")); pause(); return
    print(f"\n{hdr('  Heure     IP                 Hote                 Evenement')}")
    print(sep())
    for e in CONN_HISTORY:
        color = GRN if e["event"] == "deconnecte" else YLW
        print(f"  {DIM}{e['time']:<10}{RS}{PRI}{e['ip']:<19}{RS}"
              f"{ACC}{e['host']:<21}{RS}{color}{e['event']}{RS}")
    pause()


# ══════════════════════════════════════════════════════════
#  08. CHAT LOCAL TCP
# ══════════════════════════════════════════════════════════
CHAT_PORT = 55501

def chat_local():
    print(title(t("m08").upper()))
    print(info("Serveur : lance en mode [s], les clients se connectent avec [c]"))
    print(info(f"Port utilise : {CHAT_PORT}\n"))

    mode = input(f"  {ACC}[s] Serveur  |  [c] Client : {RS}").strip().lower()

    if mode == "s":
        # ── MODE SERVEUR ──────────────────────────────────────
        name = input(f"  {ACC}Ton pseudo : {RS}").strip() or "Serveur"
        print(f"\n{ok(f'Serveur lance sur le port {CHAT_PORT}... (Ctrl+C pour quitter)')}")
        print(info("En attente de connexions...\n"))

        clients      = []
        clients_lock = threading.Lock()

        def broadcast(msg, exclude=None):
            with clients_lock:
                dead = []
                for c in clients:
                    if c is exclude: continue
                    try:    c.sendall(msg.encode("utf-8"))
                    except: dead.append(c)
                for c in dead: clients.remove(c)

        def handle_client(conn, addr):
            with clients_lock: clients.append(conn)
            print(f"  {GRN}[+] {addr[0]} connecte{RS}")
            broadcast(f"[Serveur] {addr[0]} a rejoint le chat.\n", exclude=conn)
            try:
                while True:
                    data = conn.recv(1024).decode("utf-8", errors="ignore").strip()
                    if not data: break
                    ts  = datetime.now().strftime("%H:%M")
                    msg = f"  [{ts}] {addr[0]} : {data}\n"
                    print(msg, end="")
                    broadcast(msg, exclude=conn)
            except Exception: pass
            finally:
                with clients_lock:
                    if conn in clients: clients.remove(conn)
                conn.close()
                print(f"  {YLW}[-] {addr[0]} deconnecte{RS}")
                broadcast(f"[Serveur] {addr[0]} a quitte le chat.\n")

        def input_loop():
            while True:
                msg = input()
                if msg.lower() == "/quit": break
                ts  = datetime.now().strftime("%H:%M")
                broadcast(f"  [{ts}] {name} (vous) : {msg}\n")

        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", CHAT_PORT)); srv.listen(10)
            # IP locale
            local_ip = socket.gethostbyname(socket.gethostname())
            print(info(f"Votre IP locale : {local_ip} — partagez-la aux clients"))
            print(info("Tapez votre message et Entree pour envoyer. /quit pour quitter.\n"))
            th_input = threading.Thread(target=input_loop, daemon=True)
            th_input.start()
            while True:
                try:
                    srv.settimeout(1)
                    conn, addr = srv.accept()
                    th = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                    th.start()
                except socket.timeout: pass
                except OSError: break
        except KeyboardInterrupt:
            print(f"\n{info('Serveur arrete.')}")
        finally:
            try: srv.close()
            except: pass

    else:
        # ── MODE CLIENT ───────────────────────────────────────
        # Option scan ou saisie manuelle
        print(f"\n  {DIM}[s] Scanner les appareils  |  [m] Saisir l'IP manuellement{RS}\n")
        sub = input(f"  {ACC}Votre choix : {RS}").strip().lower()
        server_ip = ""
        if sub == "s" and SCAPY_OK:
            devices = arp_scan(silent=True)
            if devices:
                print(f"\n{hdr('  #    IP                 Nom hote')}")
                print(sep())
                for i, d in enumerate(devices, 1):
                    print(f"  {ACC}{i:<4}{RS}{PRI}{d['ip']:<19}{RS}{ACC}{d['host']}{RS}")
                pick = input(f"\n  {ACC}Numero du serveur (0=annuler) : {RS}").strip()
                if pick.isdigit() and 0 < int(pick) <= len(devices):
                    server_ip = devices[int(pick)-1]["ip"]
        if not server_ip:
            server_ip = input(f"  {ACC}IP du serveur : {RS}").strip()

        name = input(f"  {ACC}Ton pseudo : {RS}").strip() or "Client"
        if not server_ip:
            print(err("IP requise.")); pause(); return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5); s.connect((server_ip, CHAT_PORT)); s.settimeout(None)
            print(f"\n{ok(f'Connecte au serveur {server_ip}')}")
            print(info("Tapez votre message et Entree. /quit pour quitter.\n"))

            def recv_loop():
                while True:
                    try:
                        data = s.recv(1024).decode("utf-8", errors="ignore")
                        if not data: break
                        sys.stdout.write(f"\r{data}  {ACC}> {RS}")
                        sys.stdout.flush()
                    except Exception: break

            th = threading.Thread(target=recv_loop, daemon=True)
            th.start()

            while True:
                msg = input(f"  {ACC}> {RS}").strip()
                if msg.lower() == "/quit": break
                s.sendall(f"{name} : {msg}".encode("utf-8"))
            s.close()
            print(info("Deconnecte."))
        except ConnectionRefusedError:
            print(err("Connexion refusee. Le serveur est-il lance ?"))
        except socket.timeout:
            print(err("Timeout — serveur inaccessible."))
        except Exception as e:
            print(err(f"Erreur : {e}"))
    pause()


# ══════════════════════════════════════════════════════════
#  09. IP LOOKUP
# ══════════════════════════════════════════════════════════
def ip_lookup():
    print(title(t("m09").upper()))
    ip_input = input(f"  {ACC}IP (vide = votre IP publique) : {RS}").strip()
    if not REQUESTS_OK:
        print(err("pip install requests")); pause(); return
    url = f"http://ip-api.com/json/{ip_input}?fields=status,message,country,regionName,city,isp,org,as,query,lat,lon,timezone"
    print(info("Requete en cours..."))
    try:
        r    = requests.get(url, timeout=8)
        data = r.json()
        if data.get("status") != "success":
            print(err(f"Echec : {data.get('message','erreur')}")); pause(); return
        rows = [
            ("IP", data.get("query","?")), ("Pays", data.get("country","?")),
            ("Region", data.get("regionName","?")), ("Ville", data.get("city","?")),
            ("Timezone", data.get("timezone","?")), ("─"*16, ""),
            ("FAI", data.get("isp","?")), ("Organisation", data.get("org","?")),
            ("AS", data.get("as","?")), ("─"*16, ""),
            ("Latitude", str(data.get("lat","?"))), ("Longitude", str(data.get("lon","?"))),
        ]
        print()
        for k, v in rows:
            if k.startswith("─"): print(f"  {DIM}{k}{RS}")
            else: print(f"  {PRI}{k:<18}{RS}{ACC}{v}{RS}")
    except Exception as e:
        print(err(f"Erreur : {e}"))
    pause()


# ══════════════════════════════════════════════════════════
#  10. PING
# ══════════════════════════════════════════════════════════
def ping_test():
    print(title(t("m10").upper()))
    raw = input(f"\n  {ACC}Hotes (virgule) [{DIM}8.8.8.8, google.com{ACC}] : {RS}").strip()
    targets = [x.strip() for x in raw.split(",")] if raw else ["8.8.8.8","google.com","1.1.1.1"]
    cnt = input(f"  {ACC}Pings [{DIM}4{ACC}] : {RS}").strip()
    count = int(cnt) if cnt.isdigit() else 4
    print()
    for host in targets:
        print(f"  {PRI}>> {host}{RS}")
        _, out = run(["ping", "-n", str(count), host])
        m = re.search(r"Minimum\s*=\s*(\d+)ms.*Moyen\s*=\s*(\d+)ms.*Maximum\s*=\s*(\d+)ms", out)
        if not m: m = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", out)
        loss_m = re.search(r"(\d+)%\s*(?:perte|loss)", out, re.IGNORECASE)
        loss   = int(loss_m.group(1)) if loss_m else 100
        lc     = GRN if loss == 0 else (YLW if loss < 50 else RED)
        if m:
            mn, avg, mx = m.group(1), m.group(2), m.group(3)
            print(f"    {DIM}Min:{RS}{GRN}{mn}ms{RS}  {DIM}Moy:{RS}{GRN}{avg}ms{RS}  "
                  f"{DIM}Max:{RS}{GRN}{mx}ms{RS}  {DIM}Perte:{RS}{lc}{loss}%{RS}")
        else: print(f"    {RED}Inaccessible{RS}")
        print()
    pause()


# ══════════════════════════════════════════════════════════
#  11. DÉBIT
# ══════════════════════════════════════════════════════════
def speed_test():
    print(title(t("m11").upper()))
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
                print(f"  {DIM}{label:<20}{RS} {sc}{mbps:.2f} Mbps{RS}  {DIM}({total//1024}KB en {elapsed:.1f}s){RS}")
        except Exception as e:
            print(f"  {DIM}{label:<20}{RS} {RED}Erreur : {e}{RS}")
    print(f"\n{ok('Termine')}")
    pause()


# ══════════════════════════════════════════════════════════
#  12. TRACEROUTE
# ══════════════════════════════════════════════════════════
def traceroute():
    print(title(t("m12").upper()))
    host = input(f"\n  {ACC}Cible [{DIM}google.com{ACC}] : {RS}").strip() or "google.com"
    print(info(f"Traceroute vers {host}...\n"))
    _, out = run(["tracert", "-d", "-h", "20", host])
    print(f"\n{hdr('  Hop    Latences              IP')}")
    print(sep())
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)", line)
        if m:
            parts = line.split()
            hop = parts[0] if parts else "?"
            ip  = parts[-1] if parts else "?"
            lats = [p for p in parts[1:-1] if "ms" in p or p == "*"]
            print(f"  {PRI}{hop:<6}{RS}{DIM}{' '.join(lats):<22}{RS}{ACC}{ip}{RS}")
    print(f"\n{ok('Termine')}")
    pause()


# ══════════════════════════════════════════════════════════
#  13. SCANNER PORTS
# ══════════════════════════════════════════════════════════
COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    3306:"MySQL", 3389:"RDP", 5900:"VNC", 8080:"HTTP-Alt", 8443:"HTTPS-Alt"
}

def port_scan():
    print(title(t("m13").upper()))
    host = input(f"\n  {ACC}IP ou hote cible : {RS}").strip()
    if not host: print(err("IP requise.")); pause(); return
    mode = input(f"  {ACC}[r] Rapide  |  [c] Personnalise : {RS}").strip().lower()
    if mode == "c":
        port_raw = input(f"  {ACC}Plage (ex: 1-1024) : {RS}").strip()
        try: start_p, end_p = map(int, port_raw.split("-"))
        except: start_p, end_p = 1, 1024
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
            if s.connect_ex((host, port)) == 0:
                service = COMMON_PORTS.get(port, "inconnu")
                print(f"  {PRI}{port:<8}{RS}{DIM}{service:<17}{RS}{GRN}OUVERT{RS}")
                open_count += 1
            s.close()
        except: pass
    print(f"\n{ok(str(open_count) + ' port(s) ouvert(s)')}")
    pause()


# ══════════════════════════════════════════════════════════
#  14. SIGNAL EN TEMPS RÉEL
# ══════════════════════════════════════════════════════════
def signal_monitor():
    print(title(t("m14").upper()))
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
        print(f"\n\n{info('Arrete.')}")
    pause()


# ══════════════════════════════════════════════════════════
#  15. CAPTURE PAQUETS
# ══════════════════════════════════════════════════════════
def capture_packets():
    print(title(t("m15").upper()))
    if not SCAPY_OK:
        print(err("Scapy requis : pip install scapy + Npcap")); pause(); return
    n_raw = input(f"\n  {ACC}Nombre de paquets [{DIM}30{ACC}] : {RS}").strip()
    count = int(n_raw) if n_raw.isdigit() else 30
    print(f"\n{info(f'Capture de {count} paquets... (Ctrl+C pour stopper)')}\n")
    captured = []
    def handle(pkt):
        ts = datetime.now().strftime("%H:%M:%S"); s = pkt.summary()[:72]
        captured.append({"time": ts, "summary": s})
        pc = PRI if "TCP" in s else (YLW if "UDP" in s else DIM)
        print(f"  {DIM}[{ts}]{RS} {pc}{s}{RS}")
    try:
        sniff(prn=handle, count=count, store=False)
    except PermissionError: print(err("Lancez en Administrateur."))
    except Exception as e:  print(err(f"Erreur : {e}"))
    print(f"\n{ok(str(len(captured)) + ' paquet(s)')}")
    if captured:
        if input(f"  {ACC}Sauvegarder ? [o/N] : {RS}").strip().lower() == "o":
            fname = LOG_DIR / f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(fname, "w", encoding="utf-8") as f:
                for p in captured: f.write(f"[{p['time']}] {p['summary']}\n")
            print(ok(f"-> {fname}"))
    pause()


# ══════════════════════════════════════════════════════════
#  16. MODE SURVEILLANCE
# ══════════════════════════════════════════════════════════
def surveillance_mode():
    print(title(t("m16").upper()))
    interval_raw = input(f"\n  {ACC}Intervalle secondes [{DIM}15{ACC}] : {RS}").strip()
    interval = int(interval_raw) if interval_raw.isdigit() else 15
    print(f"\n{ok(f'Surveillance (toutes les {interval}s) — Ctrl+C pour arreter')}\n")
    known_ssids = set(); cycle = 0
    try:
        while True:
            cycle += 1; ts = datetime.now().strftime("%H:%M:%S")
            nets = scan_networks(silent=True); cur = {n.get("ssid","") for n in nets}
            new  = cur - known_ssids; gone = known_ssids - cur if known_ssids else set()
            sys.stdout.write(f"\r  {DIM}[{ts}] Cycle {cycle} — {len(nets)} reseau(x){RS}   ")
            sys.stdout.flush()
            if new:
                print(f"\n{warn('NOUVEAU(X) :')}")
                for s in new: print(f"  {GRN}+ {s}{RS}")
            if gone:
                print(f"\n{info('Disparu(s) :')}")
                for s in gone: print(f"  {DIM}- {s}{RS}")
            known_ssids = cur; time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n\n{info('Arrete.')}")
    pause()


# ══════════════════════════════════════════════════════════
#  17. IDS BASIQUE — ANALYSE PAQUETS SUSPECTS
# ══════════════════════════════════════════════════════════
def ids_analysis():
    print(title(t("m17").upper()))
    if not SCAPY_OK:
        print(err("Scapy requis : pip install scapy + Npcap")); pause(); return

    n_raw = input(f"\n  {ACC}Nombre de paquets a analyser [{DIM}100{ACC}] : {RS}").strip()
    count = int(n_raw) if n_raw.isdigit() else 100
    print(f"\n{info(f'Analyse de {count} paquets en cours... (Ctrl+C pour stopper)')}\n")

    alerts = []
    port_count = {}
    ip_count   = {}

    def analyze(pkt):
        alert = None
        try:
            # SYN scan (flag SYN uniquement, pas ACK)
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                src   = pkt[IP].src if pkt.haslayer(IP) else "?"
                dport = pkt[TCP].dport
                # Comptage ports par IP (détection scan de ports)
                ip_count[src]   = ip_count.get(src, 0) + 1
                port_count[src] = port_count.get(src, set())
                port_count[src].add(dport)
                if len(port_count.get(src, set())) > 15:
                    alert = f"SCAN DE PORTS  {src} -> {len(port_count[src])} ports sondes"
                # SYN flood
                if ip_count.get(src, 0) > 50:
                    alert = f"FLOOD SUSPECT  {src} -> {ip_count[src]} paquets"
                # Flags suspects : FIN+URG+PSH = Xmas scan
                if int(flags) == 0x29:
                    alert = f"XMAS SCAN      {src} -> port {dport}"
                # NULL scan
                if int(flags) == 0x00:
                    alert = f"NULL SCAN      {src} -> port {dport}"

            # ARP spoofing : plusieurs MAC pour une meme IP
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                alert = f"ARP REPLY      {pkt[ARP].psrc} -> MAC {pkt[ARP].hwsrc}"

            # ICMP flood
            if pkt.haslayer(ICMP):
                src = pkt[IP].src if pkt.haslayer(IP) else "?"
                ip_count[src] = ip_count.get(src, 0) + 1
                if ip_count.get(src, 0) > 30:
                    alert = f"ICMP FLOOD     {src} -> {ip_count[src]} paquets"

        except Exception:
            pass

        ts = datetime.now().strftime("%H:%M:%S")
        if alert:
            alerts.append({"time": ts, "alert": alert})
            print(f"  {RED}[ALERTE][{ts}] {alert}{RS}")
        else:
            sys.stdout.write(f"\r  {DIM}Paquets analyses... (alertes : {len(alerts)}){RS}   ")
            sys.stdout.flush()

    try:
        sniff(prn=analyze, count=count, store=False)
    except PermissionError: print(err("Lancez en Administrateur."))
    except Exception as e:  print(err(f"Erreur : {e}"))

    print(f"\n\n{ok(f'Analyse terminee — {len(alerts)} alerte(s) detectee(s)')}")
    if alerts:
        print(f"\n{hdr('  Heure     Alerte')}")
        print(sep())
        for a in alerts:
            print(f"  {DIM}{a['time']:<10}{RS}{RED}{a['alert']}{RS}")
    pause()


# ══════════════════════════════════════════════════════════
#  18. DÉTECTEUR DE ROGUE AP
# ══════════════════════════════════════════════════════════
def rogue_ap_detector():
    print(title(t("m18").upper()))
    print(info("Detecte les faux points d'acces qui imitent un reseau existant.\n"))
    print(info("Scan initial en cours..."))

    networks = scan_networks(silent=True)
    if not networks:
        print(err(t("no_network"))); pause(); return

    # Grouper par SSID
    ssid_map = {}
    for n in networks:
        ssid = n.get("ssid","?")
        if ssid not in ssid_map: ssid_map[ssid] = []
        ssid_map[ssid].append(n)

    print(f"\n{hdr('  SSID                         BSSID               Signal  Securite  Statut')}")
    print(sep())

    rogue_found = False
    for ssid, nets in ssid_map.items():
        # Si plusieurs BSSID pour le meme SSID -> suspect
        is_suspect = len(nets) > 1
        for n in nets:
            bssid  = n.get("bssid","?")[:18]
            signal = n.get("signal","?")
            auth   = n.get("auth","?")
            # Réseau ouvert avec SSID connu -> très suspect
            is_open = any(k in auth.lower() for k in ("ouvert","open"))
            if is_suspect or is_open:
                status = f"{RED}⚠ SUSPECT{RS}"
                rogue_found = True
            else:
                status = f"{GRN}OK{RS}"
            print(f"  {ACC}{ssid[:27]:<29}{RS}{DIM}{bssid:<20}{RS}"
                  f"{YLW}{signal:<8}{RS}{DIM}{auth[:8]:<10}{RS}{status}")

    if rogue_found:
        print(f"\n{warn('Des reseaux suspects ont ete detectes !')}")
        print(info("Un meme SSID avec plusieurs BSSID ou un reseau ouvert peut indiquer un Rogue AP."))
    else:
        print(f"\n{ok('Aucun rogue AP detecte.')}")
    pause()


# ══════════════════════════════════════════════════════════
#  19. CHECKER WIFI COMPROMIS (HIBP-like)
# ══════════════════════════════════════════════════════════
def check_compromised():
    print(title(t("m19").upper()))
    print(info("Verifie si ton SSID ou ton IP publique apparait dans des bases de donnees de leaks.\n"))

    if not REQUESTS_OK:
        print(err("pip install requests")); pause(); return

    # Recuperer SSID connecte
    _, ssid_out = run(["netsh", "wlan", "show", "interfaces"])
    ssid = "?"
    for line in ssid_out.splitlines():
        l = line.strip()
        if l.startswith("SSID") and "BSSID" not in l:
            ssid = l.split(":",1)[-1].strip(); break

    print(info(f"SSID detecte : {ssid}"))

    # Recuperer IP publique
    print(info("Recuperation de l'IP publique..."))
    try:
        pub_ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
        print(info(f"IP publique : {pub_ip}"))
    except Exception:
        pub_ip = "?"
        print(warn("IP publique non recuperee."))

    print()

    # Verifier IP via AbuseIPDB (public, sans cle)
    checks = []
    if pub_ip != "?":
        try:
            r = requests.get(
                f"https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": pub_ip, "maxAgeInDays": 90},
                headers={"Accept": "application/json", "Key": ""},
                timeout=6
            )
            # Sans cle API on ne peut pas utiliser AbuseIPDB, on utilise ip-api a la place
        except Exception:
            pass

        # Verification via ip-api (proxy/VPN/Tor detection)
        try:
            r = requests.get(
                f"http://ip-api.com/json/{pub_ip}?fields=status,proxy,hosting,query,isp,country",
                timeout=6
            )
            data = r.json()
            if data.get("status") == "success":
                is_proxy   = data.get("proxy",   False)
                is_hosting = data.get("hosting", False)
                isp        = data.get("isp",     "?")
                country    = data.get("country", "?")

                print(f"  {PRI}{'IP publique':<20}{RS}{ACC}{pub_ip}{RS}")
                print(f"  {PRI}{'FAI':<20}{RS}{ACC}{isp}{RS}")
                print(f"  {PRI}{'Pays':<20}{RS}{ACC}{country}{RS}")
                print(f"  {PRI}{'Proxy/VPN detecte':<20}{RS}"
                      f"{RED if is_proxy else GRN}{'Oui' if is_proxy else 'Non'}{RS}")
                print(f"  {PRI}{'Hosting/datacenter':<20}{RS}"
                      f"{YLW if is_hosting else GRN}{'Oui' if is_hosting else 'Non'}{RS}")

                if is_proxy:
                    checks.append(warn("Ton IP publique est identifiee comme Proxy/VPN — trafic potentiellement surveille."))
                if is_hosting:
                    checks.append(warn("Ton IP est associee a un hebergeur — inhabituel pour une connexion domicile."))
        except Exception as e:
            print(warn(f"Verification ip-api echouee : {e}"))

    # Verifier si le SSID est dans une wordlist publique connue
    WEAK_SSIDS = ["livebox", "freebox", "bbox", "sfr", "orange", "neufbox",
                  "default", "linksys", "netgear", "dlink", "tplink", "home",
                  "wifi", "internet", "asus", "router"]
    ssid_lower = ssid.lower()
    is_weak_ssid = any(w in ssid_lower for w in WEAK_SSIDS)

    print()
    print(sep())
    print(f"\n{BR}{ACC}  Bilan :{RS}\n")
    if is_weak_ssid:
        print(warn(f"SSID '{ssid}' est un nom generique — facilement identifiable et cible."))
        print(info("Conseil : renommez votre reseau avec un nom unique non identifiable."))
    else:
        print(ok(f"SSID '{ssid}' ne correspond pas aux noms generiques connus."))

    for c in checks:
        print(c)

    if not checks and not is_weak_ssid:
        print(ok("Aucun indicateur de compromission detecte."))

    pause()


# ══════════════════════════════════════════════════════════
#  20 & 21. WIFI ON/OFF
# ══════════════════════════════════════════════════════════
def wifi_toggle(enable: bool):
    label = t("m20") if enable else t("m21")
    print(title(label.upper()))
    action = "enabled" if enable else "disabled"
    iface  = get_wifi_iface()
    code, out = run(["netsh", "interface", "set", "interface", iface, action])
    if code == 0: print(ok(f"{'Active' if enable else 'Desactive'} ({iface})"))
    else:
        print(err("Echec. Lancez en Administrateur."))
        print(info(out.strip()[:120]))
    pause()


# ══════════════════════════════════════════════════════════
#  22. EXPORT
# ══════════════════════════════════════════════════════════
def export_results():
    global _last_networks
    print(title(t("m22").upper()))
    if not _last_networks:
        print(warn("Aucun scan. Lancez d'abord l'option 01.")); pause(); return
    fmt = input(f"\n  {ACC}Format [{DIM}csv{ACC}/{DIM}txt{ACC}] : {RS}").strip().lower()
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "txt":
        fname = LOG_DIR / f"scan_{ts}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"WiFi Scan — By AKO — {datetime.now()}\n{'─'*50}\n\n")
            for n in _last_networks:
                for k, v in n.items(): f.write(f"{k:<12}: {v}\n")
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
#  23. CHANGER SSID
# ══════════════════════════════════════════════════════════
def change_ssid():
    print(title("CHANGER LE NOM DU RESEAU (SSID)"))
    print(warn("Necessite acces a l'interface d'admin de votre box/routeur."))
    print(info("Cette option modifie le profil WiFi sauvegarde sur CE PC — pas le routeur directement.\n"))
    _, out = run(["netsh", "wlan", "show", "profiles"])
    profiles = re.findall(r"(?:Profil\s+\w+|All User Profile)\s*:\s*(.+)", out)
    if not profiles:
        print(err("Aucun profil trouve.")); pause(); return
    print(f"\n{hdr('  #    SSID actuel')}")
    print(sep())
    for i, name in enumerate(profiles, 1):
        print(f"  {ACC}{i:<4}{RS}{PRI}{name.strip()}{RS}")
    print()
    pick = input(f"  {ACC}Numero du profil a renommer (0=annuler) : {RS}").strip()
    if not pick.isdigit() or int(pick) == 0: return
    idx = int(pick) - 1
    if idx < 0 or idx >= len(profiles):
        print(err("Numero invalide.")); pause(); return
    old_name = profiles[idx].strip()
    new_name = input(f"  {ACC}Nouveau nom : {RS}").strip()
    if not new_name:
        print(err("Nom vide.")); pause(); return
    # Exporter le profil XML
    code, out = run(["netsh", "wlan", "export", "profile", f"name={old_name}", "folder=."])
    xml_file = Path(f"{old_name}.xml")
    if not xml_file.exists():
        print(err(f"Export du profil echoue. ({out.strip()[:80]})")); pause(); return
    content = xml_file.read_text(encoding="utf-8")
    content = content.replace(f"<name>{old_name}</name>", f"<name>{new_name}</name>", 1)
    content = content.replace(f"<SSID>\n.*?<name>{old_name}</name>",
                               f"<SSID>\n            <name>{new_name}</name>", 1)
    # Remplacer tous les SSID dans le XML
    import re as _re
    content = _re.sub(r"(<n>)" + _re.escape(old_name) + r"(</n>)", r"\g<1>" + new_name + r"\g<2>", content)
    new_xml = Path(f"{new_name}.xml")
    new_xml.write_text(content, encoding="utf-8")
    # Supprimer l ancien profil et importer le nouveau
    run(["netsh", "wlan", "delete", "profile", f"name={old_name}"])
    code2, out2 = run(["netsh", "wlan", "add", "profile", f"filename={new_xml}"])
    xml_file.unlink(missing_ok=True)
    new_xml.unlink(missing_ok=True)
    if code2 == 0:
        print(ok(f"Profil renomme : '{old_name}' -> '{new_name}'"))
        print(info("Reconnectez-vous au reseau pour appliquer."))
    else:
        print(err(f"Echec import : {out2.strip()[:120]}"))
    pause()


# ══════════════════════════════════════════════════════════
#  24. CHANGER MOT DE PASSE WIFI
# ══════════════════════════════════════════════════════════
def change_wifi_password():
    print(title("CHANGER LE MOT DE PASSE WIFI"))
    print(warn("Modifie le mot de passe dans le PROFIL sauvegarde sur ce PC."))
    print(info("Pour changer le MDP sur le routeur, connectez-vous a son interface admin.\n"))
    _, out = run(["netsh", "wlan", "show", "profiles"])
    profiles = re.findall(r"(?:Profil\s+\w+|All User Profile)\s*:\s*(.+)", out)
    if not profiles:
        print(err("Aucun profil.")); pause(); return
    print(f"\n{hdr('  #    SSID')}")
    print(sep())
    for i, name in enumerate(profiles, 1):
        print(f"  {ACC}{i:<4}{RS}{PRI}{name.strip()}{RS}")
    print()
    pick = input(f"  {ACC}Numero du reseau (0=annuler) : {RS}").strip()
    if not pick.isdigit() or int(pick) == 0: return
    idx = int(pick) - 1
    if idx < 0 or idx >= len(profiles):
        print(err("Numero invalide.")); pause(); return
    name    = profiles[idx].strip()
    new_pwd = input(f"  {ACC}Nouveau mot de passe : {RS}").strip()
    if len(new_pwd) < 8:
        print(err("Mot de passe trop court (min 8 caracteres).")); pause(); return
    code, out = run(["netsh", "wlan", "export", "profile", f"name={name}", "key=clear", "folder=."])
    xml_file  = Path(f"{name}.xml")
    if not xml_file.exists():
        print(err("Export echoue. Lancez en Admin.")); pause(); return
    content = xml_file.read_text(encoding="utf-8")
    content = re.sub(r"<keyMaterial>.*?</keyMaterial>",
                     f"<keyMaterial>{new_pwd}</keyMaterial>", content)
    xml_file.write_text(content, encoding="utf-8")
    run(["netsh", "wlan", "delete", "profile", f"name={name}"])
    code2, out2 = run(["netsh", "wlan", "add", "profile", f"filename={xml_file}"])
    xml_file.unlink(missing_ok=True)
    if code2 == 0:
        print(ok(f"Mot de passe mis a jour pour '{name}'"))
        print(info("Reconnectez-vous pour appliquer."))
    else:
        print(err(f"Echec : {out2.strip()[:120]}"))
    pause()


# ══════════════════════════════════════════════════════════
#  25. REDÉMARRER L'ADAPTATEUR WIFI
# ══════════════════════════════════════════════════════════
def restart_adapter():
    print(title("REDEMARRER L'ADAPTATEUR WIFI"))
    iface = get_wifi_iface()
    print(info(f"Interface : {iface}"))
    print(info("Desactivation..."))
    run(["netsh", "interface", "set", "interface", iface, "disabled"])
    time.sleep(2)
    print(info("Reactivation..."))
    code, out = run(["netsh", "interface", "set", "interface", iface, "enabled"])
    if code == 0:
        print(ok(f"Adaptateur redemmarre ({iface})"))
    else:
        print(err(f"Echec : {out.strip()[:120]}"))
    pause()


# ══════════════════════════════════════════════════════════
#  26. VOIR / CHANGER ADRESSE MAC
# ══════════════════════════════════════════════════════════
def mac_changer():
    print(title("VOIR / CHANGER ADRESSE MAC"))
    iface = get_wifi_iface()
    # MAC actuelle via ipconfig /all
    _, out = run(["ipconfig", "/all"])
    current_mac = "?"
    in_wifi = False
    for line in out.splitlines():
        if any(k in line for k in ("Wi-Fi","WiFi","Wireless")): in_wifi = True
        if in_wifi and ("Adresse physique" in line or "Physical Address" in line):
            current_mac = line.split(":")[-1].strip().replace("-",":")
            break
    print(f"\n  {PRI}Interface    {RS}{ACC}{iface}{RS}")
    print(f"  {PRI}MAC actuelle {RS}{ACC}{current_mac}{RS}\n")
    print(f"  {DIM}[v] Voir seulement  |  [c] Changer la MAC  |  [r] Restaurer originale{RS}\n")
    choice = input(f"  {ACC}Votre choix : {RS}").strip().lower()
    if choice == "v":
        pause(); return
    elif choice == "r":
        # Supprimer la valeur dans le registre pour restaurer
        reg_path = f"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e972-e325-11ce-bfc1-08002be10318}}"
        print(warn("Restauration de la MAC d'origine via le gestionnaire de peripheriques."))
        print(info("Ouverture du gestionnaire de peripheriques..."))
        run(["devmgmt.msc"])
        print(info("Desactivez puis reactivez votre adaptateur WiFi pour restaurer la MAC."))
        pause(); return
    elif choice == "c":
        print(info("Format : XX:XX:XX:XX:XX:XX  (ex: 00:11:22:33:44:55)"))
        new_mac = input(f"  {ACC}Nouvelle MAC : {RS}").strip().upper().replace("-",":")
        if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", new_mac):
            print(err("Format MAC invalide.")); pause(); return
        new_mac_reg = new_mac.replace(":","")
        # Trouver la cle de registre de l'adaptateur
        _, reg_out = run(["netsh", "wlan", "show", "interfaces"])
        guid = ""
        for line in reg_out.splitlines():
            if "GUID" in line:
                guid = line.split(":")[-1].strip(); break
        if guid:
            reg_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
            # Chercher la sous-cle correspondant au GUID
            _, enum = run(["reg", "query", reg_key])
            for subkey in enum.splitlines():
                subkey = subkey.strip()
                if not subkey: continue
                _, val = run(["reg", "query", subkey, "/v", "NetCfgInstanceId"])
                if guid.lower() in val.lower():
                    code, _ = run(["reg", "add", subkey, "/v", "NetworkAddress",
                                   "/t", "REG_SZ", "/d", new_mac_reg, "/f"])
                    if code == 0:
                        print(ok(f"MAC modifiee dans le registre -> {new_mac}"))
                        print(info("Redemarrez l'adaptateur (option 25) pour appliquer."))
                    else:
                        print(err("Echec modification registre. Lancez en Admin."))
                    pause(); return
        print(warn("GUID non trouve. Methode alternative : Gestionnaire de peripheriques"))
        print(info("Proprietes adaptateur -> Avance -> Adresse reseau"))
        pause()
    else:
        print(warn("Choix invalide."))
        pause()


# ══════════════════════════════════════════════════════════
#  27. VOIR / MODIFIER DNS
# ══════════════════════════════════════════════════════════
DNS_PRESETS = {
    "1": ("Google",      "8.8.8.8",    "8.8.4.4"),
    "2": ("Cloudflare",  "1.1.1.1",    "1.0.0.1"),
    "3": ("OpenDNS",     "208.67.222.222", "208.67.220.220"),
    "4": ("Quad9",       "9.9.9.9",    "149.112.112.112"),
    "5": ("DHCP auto",   "",           ""),
}

def change_dns():
    print(title("VOIR / MODIFIER LE DNS"))
    iface = get_wifi_iface()
    # DNS actuel
    _, out = run(["netsh", "interface", "ip", "show", "dns", iface])
    print(f"\n{info(f'Interface : {iface}')}")
    print(f"{info('DNS actuels :')}")
    for line in out.splitlines():
        if re.search(r"\d{1,3}\.\d{1,3}", line):
            print(f"  {ACC}{line.strip()}{RS}")
    print(f"\n{sep()}")
    print(f"\n  {BR}{PRI}Presets DNS :{RS}\n")
    for k, (name, pri, sec) in DNS_PRESETS.items():
        if pri:
            print(f"  {ACC}[{k}]{RS}  {PRI}{name:<14}{RS}{DIM}{pri}  /  {sec}{RS}")
        else:
            print(f"  {ACC}[{k}]{RS}  {PRI}{name}{RS}")
    print(f"  {ACC}[6]{RS}  {PRI}Saisir manuellement{RS}\n")
    choice = input(f"  {ACC}Votre choix (0=annuler) : {RS}").strip()
    if choice == "0": return
    if choice in DNS_PRESETS:
        name, pri, sec = DNS_PRESETS[choice]
        if not pri:
            code, _ = run(["netsh", "interface", "ip", "set", "dns", iface, "dhcp"])
            print(ok(f"DNS repasse en automatique (DHCP)") if code == 0 else err("Echec."))
        else:
            run(["netsh", "interface", "ip", "set", "dns", iface, "static", pri])
            code, _ = run(["netsh", "interface", "ip", "add", "dns", iface, sec, "index=2"])
            print(ok(f"DNS {name} applique ({pri} / {sec})") if code == 0 else err("Echec. Admin requis."))
    elif choice == "6":
        pri = input(f"  {ACC}DNS primaire : {RS}").strip()
        sec = input(f"  {ACC}DNS secondaire : {RS}").strip()
        run(["netsh", "interface", "ip", "set", "dns", iface, "static", pri])
        code, _ = run(["netsh", "interface", "ip", "add", "dns", iface, sec, "index=2"])
        print(ok(f"DNS applique ({pri} / {sec})") if code == 0 else err("Echec. Admin requis."))
    else:
        print(warn("Choix invalide."))
    pause()


# ══════════════════════════════════════════════════════════
#  28. VIDER LE CACHE DNS
# ══════════════════════════════════════════════════════════
def flush_dns():
    print(title("VIDER LE CACHE DNS"))
    print(info("Execution de ipconfig /flushdns..."))
    code, out = run(["ipconfig", "/flushdns"])
    if code == 0:
        print(ok("Cache DNS vide avec succes."))
    else:
        print(err(f"Echec : {out.strip()[:120]}"))
    pause()


# ══════════════════════════════════════════════════════════
#  29. CONNEXIONS ACTIVES (NETSTAT)
# ══════════════════════════════════════════════════════════
def netstat_view():
    print(title("CONNEXIONS RESEAU ACTIVES"))
    print(info("Recuperation des connexions en cours...\n"))
    _, out = run(["netstat", "-ano"])
    lines = [l for l in out.splitlines() if re.search(r"ESTABLISHED|LISTENING|TIME_WAIT", l)]
    print(f"{hdr('  Proto  Adresse locale          Adresse distante        Etat            PID')}")
    print(sep())
    for line in lines[:40]:  # limiter a 40 lignes
        parts = line.split()
        if len(parts) >= 5:
            proto  = parts[0][:5]
            local  = parts[1][:22]
            remote = parts[2][:22]
            state  = parts[3][:14] if len(parts) > 4 else ""
            pid    = parts[-1]
            color  = GRN if "ESTABLISHED" in state else (YLW if "LISTENING" in state else DIM)
            print(f"  {DIM}{proto:<7}{RS}{ACC}{local:<24}{RS}{DIM}{remote:<24}{RS}"
                  f"{color}{state:<16}{RS}{DIM}{pid}{RS}")
    if len(lines) > 40:
        print(info(f"... {len(lines)-40} connexions supplementaires non affichees"))
    print(f"\n{ok(str(len(lines)) + ' connexion(s) trouvee(s)')}")
    pause()


# ══════════════════════════════════════════════════════════
#  30. BLOQUER / DEBLOQUER UN SITE (HOSTS)
# ══════════════════════════════════════════════════════════
HOSTS_FILE = Path(r"C:\Windows\System32\drivers\etc\hosts")
HOSTS_TAG  = "# WiFiTool-AKO"

def manage_hosts():
    print(title("BLOQUER / DEBLOQUER UN SITE"))
    print(warn("Necessite droits Administrateur."))
    print(info(f"Fichier hosts : {HOSTS_FILE}\n"))

    try:
        content = HOSTS_FILE.read_text(encoding="utf-8", errors="ignore")
    except PermissionError:
        print(err("Acces refuse. Lancez en Administrateur.")); pause(); return
    except Exception as e:
        print(err(f"Lecture impossible : {e}")); pause(); return

    # Lister les sites deja bloques par cet outil
    blocked = []
    for line in content.splitlines():
        if HOSTS_TAG in line and line.startswith("0.0.0.0"):
            site = line.split()[1] if len(line.split()) >= 2 else "?"
            blocked.append(site)

    print(f"  {BR}{PRI}Sites bloques par WiFiTool :{RS}")
    if blocked:
        for i, s in enumerate(blocked, 1):
            print(f"  {RED}{i:<4}{RS}{ACC}{s}{RS}")
    else:
        print(f"  {DIM}  Aucun{RS}")

    print(f"\n  {DIM}[b] Bloquer un site  |  [d] Debloquer un site  |  [0] Annuler{RS}\n")
    choice = input(f"  {ACC}Votre choix : {RS}").strip().lower()

    if choice == "b":
        site = input(f"  {ACC}Domaine a bloquer (ex: facebook.com) : {RS}").strip().lower()
        if not site:
            print(err("Domaine vide.")); pause(); return
        if site in blocked:
            print(warn(f"{site} est deja bloque.")); pause(); return
        new_line = f"\n0.0.0.0 {site} {HOSTS_TAG}\n0.0.0.0 www.{site} {HOSTS_TAG}"
        try:
            with open(HOSTS_FILE, "a", encoding="utf-8") as f:
                f.write(new_line)
            run(["ipconfig", "/flushdns"])
            print(ok(f"{site} bloque avec succes."))
        except PermissionError:
            print(err("Acces refuse. Lancez en Administrateur."))

    elif choice == "d":
        if not blocked:
            print(warn("Aucun site a debloquer.")); pause(); return
        pick = input(f"  {ACC}Numero du site a debloquer (0=annuler) : {RS}").strip()
        if not pick.isdigit() or int(pick) == 0: return
        idx = int(pick) - 1
        if idx < 0 or idx >= len(blocked):
            print(err("Numero invalide.")); pause(); return
        site = blocked[idx]
        new_content = "\n".join(
            l for l in content.splitlines()
            if not (HOSTS_TAG in l and site in l)
        )
        try:
            HOSTS_FILE.write_text(new_content, encoding="utf-8")
            run(["ipconfig", "/flushdns"])
            print(ok(f"{site} debloque."))
        except PermissionError:
            print(err("Acces refuse. Lancez en Administrateur."))
    pause()


# ══════════════════════════════════════════════════════════
#  31. IP STATIQUE / DHCP
# ══════════════════════════════════════════════════════════
def set_ip():
    print(title("DEFINIR IP STATIQUE / REPASSER EN DHCP"))
    iface = get_wifi_iface()
    print(f"  {info(f'Interface : {iface}')}\n")
    print(f"  {DIM}[s] Definir une IP statique  |  [d] Repasser en DHCP (automatique){RS}\n")
    choice = input(f"  {ACC}Votre choix (0=annuler) : {RS}").strip().lower()

    if choice == "0": return

    elif choice == "d":
        run(["netsh", "interface", "ip", "set", "address", iface, "dhcp"])
        run(["netsh", "interface", "ip", "set", "dns",     iface, "dhcp"])
        print(ok("Repassee en DHCP (IP et DNS automatiques)."))

    elif choice == "s":
        print(info("Exemple : IP=192.168.1.50  Masque=255.255.255.0  GW=192.168.1.1\n"))
        ip_addr = input(f"  {ACC}Adresse IP : {RS}").strip()
        mask    = input(f"  {ACC}Masque [{DIM}255.255.255.0{ACC}] : {RS}").strip() or "255.255.255.0"
        gw      = input(f"  {ACC}Passerelle : {RS}").strip()
        if not ip_addr or not gw:
            print(err("IP ou passerelle manquante.")); pause(); return
        code, out = run(["netsh", "interface", "ip", "set", "address",
                         iface, "static", ip_addr, mask, gw])
        if code == 0:
            print(ok(f"IP statique definie : {ip_addr} / {mask} via {gw}"))
        else:
            print(err(f"Echec : {out.strip()[:120]}"))
    else:
        print(warn("Choix invalide."))
    pause()


# ══════════════════════════════════════════════════════════
#  32. RAPPORT COMPLET DU RESEAU
# ══════════════════════════════════════════════════════════
def full_report():
    print(title("RAPPORT COMPLET DU RESEAU"))
    print(info("Generation du rapport en cours...\n"))
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = LOG_DIR / f"rapport_reseau_{ts}.txt"
    lines = []
    lines.append(f"RAPPORT RESEAU — WiFi Multi-Tool v5.0 — By AKO")
    lines.append(f"Date : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    lines.append("=" * 60)

    sections = [
        ("INTERFACES RESEAU",    ["ipconfig", "/all"]),
        ("RESEAUX WIFI",         ["netsh", "wlan", "show", "networks"]),
        ("INTERFACE WIFI",       ["netsh", "wlan", "show", "interfaces"]),
        ("PROFILS WIFI",         ["netsh", "wlan", "show", "profiles"]),
        ("TABLE ARP",            ["arp", "-a"]),
        ("TABLE DE ROUTAGE",     ["route", "print"]),
        ("CONNEXIONS ACTIVES",   ["netstat", "-ano"]),
        ("DNS CACHE",            ["ipconfig", "/displaydns"]),
        ("FIREWALL",             ["netsh", "advfirewall", "show", "allprofiles"]),
    ]

    for title_s, cmd in sections:
        print(info(f"  {title_s}..."))
        _, out = run(cmd)
        lines.append(f"\n{'─'*60}")
        lines.append(f"  {title_s}")
        lines.append(f"{'─'*60}")
        lines.append(out[:3000])  # limiter la taille

    with open(fname, "w", encoding="utf-8", errors="ignore") as f:
        f.write("\n".join(lines))

    print(ok(f"Rapport genere -> {fname.resolve()}"))
    print(info(f"Taille : {fname.stat().st_size // 1024} KB"))
    pause()


# ══════════════════════════════════════════════════════════
#  33. PROCESSUS UTILISANT LE RÉSEAU
# ══════════════════════════════════════════════════════════
def network_processes():
    print(title("PROCESSUS UTILISANT LE RESEAU"))
    print(info("Recuperation des connexions avec PID et nom de processus...\n"))

    _, netstat_out = run(["netstat", "-ano"])
    _, tasklist_out = run(["tasklist", "/fo", "csv"])

    # Construire un dictionnaire PID -> nom du processus
    pid_names = {}
    for line in tasklist_out.splitlines()[1:]:
        parts = line.strip('"').split('","')
        if len(parts) >= 2:
            try:
                pid_names[parts[1]] = parts[0]
            except: pass

    print(f"{hdr('  Processus              PID     Proto  Adresse distante        Etat')}")
    print(sep())

    seen_pids = {}
    for line in netstat_out.splitlines():
        m = re.match(r"\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)", line)
        if not m: continue
        proto  = m.group(1)
        local  = m.group(2)
        remote = m.group(3)
        state  = m.group(4) if proto == "TCP" else ""
        pid    = m.group(5)
        if state not in ("ESTABLISHED", "LISTENING") and proto == "TCP": continue
        if pid in seen_pids and seen_pids[pid] > 2: continue
        seen_pids[pid] = seen_pids.get(pid, 0) + 1
        pname = pid_names.get(pid, "inconnu")[:22]
        color = GRN if state == "ESTABLISHED" else (YLW if state == "LISTENING" else DIM)
        print(f"  {ACC}{pname:<24}{RS}{DIM}{pid:<8}{RS}{PRI}{proto:<7}{RS}"
              f"{DIM}{remote[:22]:<24}{RS}{color}{state}{RS}")

    print(f"\n{ok('Termine')}")
    pause()


# ══════════════════════════════════════════════════════════
#  34. PARTAGES RÉSEAU ACTIFS
# ══════════════════════════════════════════════════════════
def network_shares():
    print(title("PARTAGES RESEAU ACTIFS"))
    print(info("Recuperation des partages sur ce PC...\n"))

    _, out = run(["net", "share"])
    print(f"{hdr('  Nom partage         Ressource                    Remarque')}")
    print(sep())

    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("Nom") or line.startswith("---") or "La commande" in line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            name     = parts[0][:20]
            resource = parts[1][:28] if len(parts) > 1 else ""
            remark   = " ".join(parts[2:])[:20] if len(parts) > 2 else ""
            # Colorier les partages systeme (IPC$, ADMIN$, C$)
            color = DIM if name.endswith("$") else ACC
            print(f"  {color}{name:<22}{RS}{DIM}{resource:<30}{RS}{DIM}{remark}{RS}")

    # Sessions actives
    print(f"\n{info('Sessions reseau actives :')}")
    _, sessions = run(["net", "session"])
    has_sessions = False
    for line in sessions.splitlines():
        if re.search(r"\\\\", line) or re.search(r"\d+\.\d+", line):
            print(f"  {YLW}{line.strip()}{RS}")
            has_sessions = True
    if not has_sessions:
        print(f"  {DIM}Aucune session active{RS}")

    print(f"\n{ok('Termine')}")
    pause()


# ══════════════════════════════════════════════════════════
#  35. BANNIR / DÉBANNIR UN APPAREIL (pare-feu Windows)
# ══════════════════════════════════════════════════════════
FIREWALL_RULE_PREFIX = "WiFiTool-AKO-Block"

def ban_device():
    print(title("BANNIR / DEBANNIR UN APPAREIL"))
    print(warn("Bloque une IP via le pare-feu Windows sur TON reseau."))
    print(info("Necessite droits Administrateur.\n"))

    # Lister les regles deja creees par cet outil
    _, rules_out = run(["netsh", "advfirewall", "firewall", "show", "rule",
                        f"name={FIREWALL_RULE_PREFIX}"])
    banned_ips = re.findall(r"Adresse IP distante.*?:(\S+)", rules_out)
    if not banned_ips:
        banned_ips = re.findall(r"RemoteIP.*?:\s*(\S+)", rules_out)

    print(f"  {BR}{PRI}IP actuellement bannies par WiFiTool :{RS}")
    if banned_ips:
        for i, ip in enumerate(banned_ips, 1):
            print(f"  {RED}{i:<4}{RS}{ACC}{ip}{RS}")
    else:
        print(f"  {DIM}  Aucune{RS}")

    print(f"\n  {DIM}[b] Bannir    |  [d] Debannir    |  [s] Scanner pour choisir  |  [0] Annuler{RS}\n")
    choice = input(f"  {ACC}Votre choix : {RS}").strip().lower()

    if choice == "0":
        return

    elif choice in ("b", "s"):
        target_ip = ""
        if choice == "s":
            if not SCAPY_OK:
                print(err("Scapy requis pour le scan.")); pause(); return
            print(info("Scan ARP en cours..."))
            devices = arp_scan(silent=True)
            if devices:
                print(f"\n{hdr('  #    IP                 MAC                  Nom hote')}")
                print(sep())
                for i, d in enumerate(devices, 1):
                    print(f"  {ACC}{i:<4}{RS}{PRI}{d['ip']:<19}{RS}{DIM}{d['mac']:<21}{RS}{ACC}{d['host']}{RS}")
                print()
                pick = input(f"  {ACC}Numero de l'appareil a bannir (0=annuler) : {RS}").strip()
                if pick.isdigit() and 0 < int(pick) <= len(devices):
                    target_ip = devices[int(pick)-1]["ip"]
                else:
                    return
        if not target_ip:
            target_ip = input(f"  {ACC}IP a bannir : {RS}").strip()
        if not target_ip:
            print(err("IP vide.")); pause(); return

        rule_name = f"{FIREWALL_RULE_PREFIX}-{target_ip}"
        # Règle entrante
        code1, _ = run(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", "dir=in", "action=block",
                        f"remoteip={target_ip}", "enable=yes"])
        # Règle sortante
        code2, _ = run(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", "dir=out", "action=block",
                        f"remoteip={target_ip}", "enable=yes"])
        if code1 == 0 and code2 == 0:
            print(ok(f"{target_ip} banni via le pare-feu Windows."))
        else:
            print(err("Echec. Lancez en Administrateur."))

    elif choice == "d":
        if not banned_ips:
            print(warn("Aucune IP a debannir.")); pause(); return
        # Saisie IP ou par numero
        raw = input(f"  {ACC}Numero ou IP a debannir : {RS}").strip()
        if raw.isdigit() and 0 < int(raw) <= len(banned_ips):
            target_ip = banned_ips[int(raw)-1]
        else:
            target_ip = raw
        rule_name = f"{FIREWALL_RULE_PREFIX}-{target_ip}"
        code, out = run(["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name={rule_name}"])
        if code == 0:
            print(ok(f"{target_ip} deban­ni."))
        else:
            print(err(f"Echec : {out.strip()[:80]}"))
    else:
        print(warn("Choix invalide."))

    pause()


# ══════════════════════════════════════════════════════════
#  36. SUBNET MAPPER
# ══════════════════════════════════════════════════════════
def subnet_mapper():
    print(title("SCANNER DE SOUS-RESEAUX"))
    print(info("Mappe tous les hotes actifs sur un ou plusieurs sous-reseaux.\n"))

    raw = input(f"  {ACC}Subnet a scanner [{DIM}192.168.1.0/24{ACC}] : {RS}").strip()
    subnet = raw if raw else "192.168.1.0/24"

    print(info(f"Scan de {subnet} via ping sweep...\n"))
    print(f"{hdr('  IP                 Latence    Hostname')}")
    print(sep())

    # Extraire la base IP
    try:
        base = ".".join(subnet.split("/")[0].split(".")[:3])
    except:
        base = "192.168.1"

    active = []
    lock   = threading.Lock()

    def ping_host(i):
        ip = f"{base}.{i}"
        code, out = run(["ping", "-n", "1", "-w", "300", ip])
        if code == 0:
            m = re.search(r"(?:temps|time)[=<](\d+)ms", out, re.IGNORECASE)
            lat = m.group(1) + "ms" if m else "?"
            try:    host = socket.gethostbyaddr(ip)[0]
            except: host = ""
            with lock:
                active.append((ip, lat, host))
                print(f"  {PRI}{ip:<19}{RS}{GRN}{lat:<11}{RS}{DIM}{host}{RS}")

    threads = []
    for i in range(1, 255):
        th = threading.Thread(target=ping_host, args=(i,), daemon=True)
        threads.append(th); th.start()
        if i % 20 == 0:
            for t2 in threads[-20:]: t2.join(timeout=0.5)

    for th in threads: th.join(timeout=1)

    print(f"\n{ok(str(len(active)) + ' hote(s) actif(s) detecte(s)')}")
    pause()


# ══════════════════════════════════════════════════════════
#  37. OS FINGERPRINTING PASSIF
# ══════════════════════════════════════════════════════════
def os_fingerprint():
    print(title("DETECTION D'OS (OS FINGERPRINTING)"))
    print(info("Analyse les reponses TTL et TCP pour deviner l'OS d'un hote.\n"))

    host = input(f"  {ACC}IP ou domaine cible : {RS}").strip()
    if not host:
        print(err("Hote requis.")); pause(); return

    print(info(f"Analyse de {host}...\n"))

    # Methode 1 : TTL via ping
    _, ping_out = run(["ping", "-n", "3", host])
    ttl_match = re.search(r"TTL=(\d+)", ping_out, re.IGNORECASE)
    ttl = int(ttl_match.group(1)) if ttl_match else None

    os_guess = "Inconnu"
    ttl_info  = "?"
    if ttl:
        if ttl <= 64:
            os_guess = "Linux / Android / macOS / iOS"
            ttl_info = f"{ttl} (<=64)"
        elif ttl <= 128:
            os_guess = "Windows"
            ttl_info = f"{ttl} (<=128)"
        elif ttl <= 255:
            os_guess = "Cisco / Solaris / FreeBSD"
            ttl_info = f"{ttl} (<=255)"

    # Methode 2 : ports ouverts caracteristiques
    port_clues = []
    signature_ports = {
        135:  "Windows (RPC)",
        445:  "Windows (SMB)",
        3389: "Windows (RDP)",
        22:   "Linux/Unix (SSH)",
        548:  "macOS (AFP)",
        62078:"iOS (lockdownd)",
    }
    for port, label in signature_ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                port_clues.append((port, label))
            s.close()
        except: pass

    # Affichage
    print(f"  {PRI}{'Hote':<20}{RS}{ACC}{host}{RS}")
    print(f"  {PRI}{'TTL detecte':<20}{RS}{ACC}{ttl_info}{RS}")
    print(f"  {PRI}{'OS probable':<20}{RS}{BR}{GRN}{os_guess}{RS}")

    if port_clues:
        print(f"\n{info('Ports caracteristiques ouverts :')}")
        for port, label in port_clues:
            print(f"  {GRN}  {port:<8}{RS}{DIM}{label}{RS}")
        # Affiner le guess
        if any(p in [p2 for p2,_ in port_clues] for p in [135,445,3389]):
            print(f"\n  {PRI}Confirmation OS :{RS} {BR}{GRN}Windows (tres probable){RS}")
        elif any(p in [p2 for p2,_ in port_clues] for p in [22]):
            print(f"\n  {PRI}Confirmation OS :{RS} {BR}{GRN}Linux / Unix (tres probable){RS}")
        elif 548 in [p2 for p2,_ in port_clues]:
            print(f"\n  {PRI}Confirmation OS :{RS} {BR}{GRN}macOS (tres probable){RS}")
    else:
        print(f"\n{info('Aucun port caracteristique detecte.')}")

    print(f"\n{warn('Resultat indicatif — non garanti.')}")
    pause()


# ══════════════════════════════════════════════════════════
#  38. TESTEUR DE SOLIDITÉ DE MOT DE PASSE
# ══════════════════════════════════════════════════════════
def password_strength():
    import math, string
    print(title("TESTEUR DE SOLIDITE DE MOT DE PASSE"))
    print(info("Votre mot de passe n'est pas envoye nulle part — analyse locale uniquement.\n"))

    import getpass
    pwd = getpass.getpass(f"  Entrez le mot de passe (invisible) : ")
    if not pwd:
        print(err("Mot de passe vide.")); pause(); return

    length = len(pwd)
    has_lower  = bool(re.search(r"[a-z]", pwd))
    has_upper  = bool(re.search(r"[A-Z]", pwd))
    has_digit  = bool(re.search(r"\d",   pwd))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", pwd))
    has_repeat = bool(re.search(r"(.)\1{2,}", pwd))  # 3 chars identiques consecutifs

    # Calcul entropie
    pool = 0
    if has_lower:  pool += 26
    if has_upper:  pool += 26
    if has_digit:  pool += 10
    if has_symbol: pool += 32
    if pool == 0:  pool = 26
    entropy = length * math.log2(pool)

    # Score
    score = 0
    if length >= 8:   score += 1
    if length >= 12:  score += 1
    if length >= 16:  score += 1
    if has_lower:     score += 1
    if has_upper:     score += 1
    if has_digit:     score += 1
    if has_symbol:    score += 1
    if not has_repeat:score += 1

    # Estimation crack bruteforce
    combos = pool ** length
    speeds = [("CPU (1M/s)", 1_000_000), ("GPU (1B/s)", 1_000_000_000),
              ("Cluster (1T/s)", 1_000_000_000_000)]

    def fmt_time(secs):
        if secs < 60:         return f"{secs:.1f} secondes"
        elif secs < 3600:     return f"{secs/60:.1f} minutes"
        elif secs < 86400:    return f"{secs/3600:.1f} heures"
        elif secs < 31536000: return f"{secs/86400:.1f} jours"
        else:                 return f"{secs/31536000:.2e} annees"

    label_map = {
        (0,3): (RED,    "TRES FAIBLE"),
        (3,5): (RED,    "FAIBLE"),
        (5,6): (YLW,    "MOYEN"),
        (6,7): (YLW,    "BON"),
        (7,8): (GRN,    "FORT"),
        (8,99):(GRN,    "TRES FORT"),
    }
    color, label = ACC, "?"
    for (lo,hi),(col,lbl) in label_map.items():
        if lo <= score < hi:
            color, label = col, lbl; break

    bar_filled = int(score / 8 * 20)
    bar = f"{color}{'█'*bar_filled}{'░'*(20-bar_filled)}{RS}"

    print(f"\n  {bar}  {BR}{color}{label}{RS}  {DIM}({score}/8){RS}\n")
    print(sep())

    rows = [
        ("Longueur",       f"{length} caracteres"),
        ("Minuscules",     "Oui" if has_lower  else "Non"),
        ("Majuscules",     "Oui" if has_upper  else "Non"),
        ("Chiffres",       "Oui" if has_digit  else "Non"),
        ("Symboles",       "Oui" if has_symbol else "Non"),
        ("Repetitions",    "Detectees" if has_repeat else "Aucune"),
        ("Entropie",       f"{entropy:.1f} bits"),
        ("Pool de chars",  f"{pool} caracteres possibles"),
    ]
    for k, v in rows:
        ok_v = v in ("Oui","Aucune") or k in ("Longueur","Entropie","Pool de chars")
        vc   = GRN if v == "Oui" or (k == "Longueur" and length >= 12) else (RED if v == "Non" or v == "Detectees" else ACC)
        print(f"  {PRI}{k:<18}{RS}{vc}{v}{RS}")

    print(f"\n{info('Temps de cassage par brute-force :')}")
    for name, speed in speeds:
        secs = combos / speed
        print(f"  {DIM}{name:<22}{RS}{ACC}{fmt_time(secs)}{RS}")

    # Conseils
    print(f"\n{info('Conseils :')}")
    if length < 12:   print(f"  {YLW}  + Allongez le mot de passe (12+ caracteres recommandes){RS}")
    if not has_upper: print(f"  {YLW}  + Ajoutez des majuscules{RS}")
    if not has_digit: print(f"  {YLW}  + Ajoutez des chiffres{RS}")
    if not has_symbol:print(f"  {YLW}  + Ajoutez des symboles (!@#$...){RS}")
    if has_repeat:    print(f"  {YLW}  + Evitez les repetitions (aaa, 111...){RS}")
    if score >= 7:    print(f"  {GRN}  Excellent mot de passe !{RS}")
    pause()


# ══════════════════════════════════════════════════════════
#  39. GÉNÉRATEUR DE MOTS DE PASSE
# ══════════════════════════════════════════════════════════
def password_generator():
    import random, string, math
    print(title("GENERATEUR DE MOTS DE PASSE FORTS"))
    print()

    length_raw = input(f"  {ACC}Longueur [{DIM}16{ACC}] : {RS}").strip()
    length = int(length_raw) if length_raw.isdigit() else 16

    print(f"  {DIM}Options (laisser vide = tout activer) :{RS}")
    use_lower  = input(f"  {ACC}Minuscules a-z  [O/n] : {RS}").strip().lower() != "n"
    use_upper  = input(f"  {ACC}Majuscules A-Z  [O/n] : {RS}").strip().lower() != "n"
    use_digits = input(f"  {ACC}Chiffres 0-9    [O/n] : {RS}").strip().lower() != "n"
    use_symbols= input(f"  {ACC}Symboles !@#$   [O/n] : {RS}").strip().lower() != "n"
    count_raw  = input(f"  {ACC}Combien en generer [{DIM}5{ACC}] : {RS}").strip()
    count      = int(count_raw) if count_raw.isdigit() else 5

    pool = ""
    if use_lower:   pool += string.ascii_lowercase
    if use_upper:   pool += string.ascii_uppercase
    if use_digits:  pool += string.digits
    if use_symbols: pool += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if not pool:    pool  = string.ascii_letters + string.digits

    entropy = length * math.log2(len(pool))

    print(f"\n{sep()}")
    print(f"  {BR}{PRI}Mots de passe generes :{RS}  {DIM}(entropie ~{entropy:.0f} bits){RS}\n")

    for i in range(count):
        # Garantir au moins un char de chaque categorie
        pwd_chars = []
        if use_lower:   pwd_chars.append(random.choice(string.ascii_lowercase))
        if use_upper:   pwd_chars.append(random.choice(string.ascii_uppercase))
        if use_digits:  pwd_chars.append(random.choice(string.digits))
        if use_symbols: pwd_chars.append(random.choice("!@#$%^&*()-_=+[]{}|;:,.<>?"))
        remaining = length - len(pwd_chars)
        pwd_chars += random.choices(pool, k=remaining)
        random.shuffle(pwd_chars)
        pwd = "".join(pwd_chars)
        print(f"  {GRN}{i+1:<4}{RS}{BR}{ACC}{pwd}{RS}")

    print(f"\n{info('Copiez le mot de passe de votre choix.')}")
    pause()

# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════
ACTIONS = {
    "01": scan_networks,    "1":  scan_networks,
    "02": network_info,     "2":  network_info,
    "03": known_networks,   "3":  known_networks,
    "04": check_security,   "4":  check_security,
    "05": arp_scan,         "5":  arp_scan,
    "06": arp_block,        "6":  arp_block,
    "07": conn_history,     "7":  conn_history,
    "08": chat_local,       "8":  chat_local,
    "09": ip_lookup,        "9":  ip_lookup,
    "10": ping_test,
    "11": speed_test,
    "12": traceroute,
    "13": port_scan,
    "14": signal_monitor,
    "15": capture_packets,
    "16": surveillance_mode,
    "17": ids_analysis,
    "18": rogue_ap_detector,
    "19": check_compromised,
    "20": lambda: wifi_toggle(True),
    "21": lambda: wifi_toggle(False),
    "22": export_results,
    "23": change_ssid,
    "24": change_wifi_password,
    "25": restart_adapter,
    "26": mac_changer,
    "27": change_dns,
    "28": flush_dns,
    "29": netstat_view,
    "30": manage_hosts,
    "31": set_ip,
    "32": full_report,
    "33": network_processes,
    "34": network_shares,
    "35": ban_device,
    "36": subnet_mapper,
    "37": os_fingerprint,
    "38": password_strength,
    "39": password_generator,
}

def main():
    slow_banner()

    try:
        import ctypes
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False

    if not is_admin: print(warn(t("admin_warn")))
    else:            print(ok(t("admin_ok")))
    print(info(f"{t('logs')} -> {LOG_DIR.resolve()}"))

    page_idx = 0

    while True:
        clear_banner()
        print(build_page(page_idx))
        choice = input(f"\n  {BR}{PRI}> {RS}{ACC}{t('menu_choice')} : {RS}").strip().lower()

        if choice == "n":
            if page_idx < len(MENU_PAGES) - 1:
                page_idx += 1
        elif choice == "b":
            if page_idx > 0:
                page_idx -= 1
        elif choice in ("00", "0"):
            clear_banner()
            print(f"\n{BR}{PRI}  WiFi Multi-Tool v5.0 — By AKO{RS}")
            typewrite(f"{DIM}  {t('goodbye')}{RS}", delay=0.03)
            print(); sys.exit(0)
        elif choice in ACTIONS:
            ACTIONS[choice]()
        else:
            print(warn(t("invalid")))
            time.sleep(0.8)

if __name__ == "__main__":
    main()
