#!/usr/bin/env python3
"""
web_fingerprint.py — rozpoznaje technologię paneli webowych i wypisuje
                     KANDYDUJĄCE domyślne poświadczenia do RĘCZNEJ weryfikacji.

Co robi:
  - bierze cele web (z pliku IP, z pliku URL, albo prosto z nmap .gnmap/.xml —
    wtedy sam wyłapuje KAŻDY port z usługą http, też nietypowe jak 10443),
  - dla każdego robi LEKKI fingerprint (tytuł strony, nagłówki Server/WWW-Authenticate,
    realm basic-auth, znane ścieżki),
  - zgaduje technologię (router, drukarka, iDRAC/iLO, NAS, ownCloud, itd.),
  - wypisuje host -> technologia -> ZNANE domyślne loginy (do ręcznego sprawdzenia).

Czego NIE robi (świadomie):
  - NIE wysyła żadnych haseł, nie loguje się, nie brute'uje. Zero ryzyka lockoutu.
    Default-creds są tylko DRUKOWANE jako materiał do kontrolowanej, ręcznej weryfikacji.

Użycie:
  python3 web_fingerprint.py --gnmap ../nmap/nmap_all.gnmap -o web_out
  python3 web_fingerprint.py --ips ../targets/web.txt -o web_out
  python3 web_fingerprint.py --urls web_urls.txt -o web_out
  python3 web_fingerprint.py --gnmap ../nmap/nmap_all.gnmap --open   # otwórz wszystko w Firefoksie
  python3 web_fingerprint.py --urls web_urls.txt --open-only          # TYLKO otwórz, bez fingerprintu

Opcje:
  --open        po fingerprincie otwiera wszystkie URL-e w kartach Firefoksa
  --open-only   pomija fingerprint, od razu otwiera karty (szybkie "pokaż mi wszystko")
  --timeout N   timeout pojedynczego żądania (domyślnie 6s)
  --insecure    nie weryfikuj certyfikatów TLS (domyślnie włączone dla self-signed)
"""

import argparse
import concurrent.futures as cf
import os
import re
import ssl
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
from urllib.error import URLError, HTTPError

# ── Baza sygnatur: (wzorzec w tytule/nagłówku/realm) -> (nazwa, [default creds]) ──
# Rozszerzaj swobodnie. Creds to PUBLICZNIE znane fabryczne wartości — do ręcznej weryfikacji.
SIGNATURES = [
    # routery / sieć
    (r"mikrotik|routeros",          "MikroTik RouterOS",        ["admin:(puste)"]),
    (r"ubiquiti|unifi|edgeos",      "Ubiquiti",                 ["ubnt:ubnt"]),
    (r"cisco",                      "Cisco",                    ["cisco:cisco", "admin:admin"]),
    (r"tp-link|tplink",             "TP-Link",                  ["admin:admin"]),
    (r"mikrotik|winbox",            "MikroTik",                 ["admin:(puste)"]),
    (r"fortinet|fortigate",         "Fortinet FortiGate",       ["admin:(puste)"]),
    (r"pfsense",                    "pfSense",                  ["admin:pfsense"]),
    (r"draytek|vigor",              "DrayTek Vigor",            ["admin:admin"]),
    # serwery zarządzania / BMC
    (r"idrac|integrated dell",      "Dell iDRAC",               ["root:calvin"]),
    (r"\bilo\b|integrated lights",  "HPE iLO",                  ["Administrator:(na naklejce)"]),
    (r"supermicro|ipmi",            "Supermicro IPMI",          ["ADMIN:ADMIN"]),
    (r"lenovo xclarity|imm",        "Lenovo XClarity/IMM",      ["USERID:PASSW0RD"]),
    # wirtualizacja / infra
    (r"vmware|vsphere|esxi",        "VMware ESXi/vSphere",      ["root:(ustawiane przy instalacji)"]),
    (r"proxmox",                    "Proxmox VE",               ["root:(ustawiane przy instalacji)"]),
    (r"hyper-v|windows admin cent", "Windows Admin Center",     ["(konto domenowe/lokalne)"]),
    # NAS / storage
    (r"synology|diskstation|dsm",   "Synology DSM",             ["admin:(puste, starsze DSM)"]),
    (r"qnap|qts",                   "QNAP QTS",                 ["admin:admin"]),
    (r"truenas|freenas",            "TrueNAS",                  ["root:(ustawiane)"]),
    # aplikacje
    (r"owncloud",                   "ownCloud",                 ["(konto użytkownika; brak fabrycznych)"]),
    (r"nextcloud",                  "Nextcloud",                ["(konto użytkownika; brak fabrycznych)"]),
    (r"iredadmin|iredmail",         "iRedMail/iRedAdmin",       ["postmaster@domena:(ustawiane przy instalacji)"]),
    (r"grafana",                    "Grafana",                  ["admin:admin"]),
    (r"jenkins",                    "Jenkins",                  ["(initialAdminPassword / brak auth)"]),
    (r"phpmyadmin",                 "phpMyAdmin",               ["root:(puste lub hasło MySQL)"]),
    (r"tomcat|apache tomcat",       "Apache Tomcat",            ["tomcat:tomcat", "admin:admin"]),
    (r"zabbix",                     "Zabbix",                   ["Admin:zabbix"]),
    (r"prtg",                       "PRTG",                     ["prtgadmin:prtgadmin"]),
    (r"webmin",                     "Webmin",                   ["(konto root systemu)"]),
    (r"gitlab",                     "GitLab",                   ["root:(ustawiane przy instalacji)"]),
    (r"printer|jetdirect|laserjet|officejet", "Drukarka HP",    ["admin:(puste lub nr seryjny)"]),
    (r"kyocera|command center",     "Drukarka Kyocera",         ["Admin:Admin", "admin:admin00"]),
    (r"brother",                    "Drukarka Brother",         ["admin:initpass", "admin:access"]),
    (r"xerox|centreware",           "Drukarka Xerox",           ["admin:1111"]),
    (r"lexmark",                    "Drukarka Lexmark",         ["admin:(brak/ustawiane)"]),
    (r"canon|remote ui",            "Drukarka Canon",           ["7654321 (PIN)", "ADMIN:(puste)"]),
]

PRINTER_HINT = re.compile(r"print|jetdirect|laser|officejet|kyocera|brother|xerox|lexmark|canon", re.I)

# Porty, które używają HTTP jako TRANSPORTU, ale NIE są panelami przeglądarkowymi
# (usługi systemowe / maszynowe). Nmap oznacza je usługą z "http" w nazwie, więc
# trzeba je jawnie wykluczyć — inaczej zaśmiecają listę celów web.
EXCLUDE_PORTS = {
    "5985",   # WinRM HTTP (WS-Management) — zarządzanie, nie przeglądarka
    "5986",   # WinRM HTTPS
    "5357",   # WSDAPI / Function Discovery (Windows) — usługa systemowa
    "2869",   # SSDP / UPnP Event (Windows) — nie panel
    "1900",   # SSDP (UPnP discovery)
    "3702",   # WS-Discovery
    "49152", "49153", "49154",  # dynamiczne porty RPC/UPnP Windows (często "http")
    "5431",   # UPnP (niektóre urządzenia)
    "7435",   # Dell OpenManage agent (maszynowe, nie panel)
}


def ctx_insecure():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def fetch(url, timeout, insecure):
    """Zwraca (status, headers_dict, title, realm) albo (None, {}, '', '') przy błędzie."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (pentest-recon)"})
    ctx = ctx_insecure() if insecure else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read(20000)
            headers = {k.lower(): v for k, v in r.headers.items()}
            status = r.status
    except HTTPError as e:
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        status = e.code
        raw = b""
    except Exception:
        # każdy inny błąd (BadStatusLine, RemoteDisconnected, timeout, zły TLS,
        # host mówiący nie-HTTP itd.) = ten host po prostu nie jest web. Pomiń go,
        # NIGDY nie wywracaj całego przebiegu przez jeden zepsuty cel.
        return None, {}, "", ""
    try:
        text = raw.decode("utf-8", "replace")
    except Exception:
        text = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = (m.group(1).strip()[:120] if m else "")
    realm = ""
    wa = headers.get("www-authenticate", "")
    rm = re.search(r'realm="([^"]+)"', wa)
    if rm:
        realm = rm.group(1)
    return status, headers, title, realm


def identify(title, server, realm):
    blob = " ".join([title or "", server or "", realm or ""]).lower()
    for pat, name, creds in SIGNATURES:
        if re.search(pat, blob):
            return name, creds
    return None, None


def targets_from_gnmap(path):
    """Każdy port z usługą http/https w .gnmap -> URL (łapie też 10443 itp.)."""
    out = []
    host_re = re.compile(r"Host:\s+(\d+\.\d+\.\d+\.\d+).*?Ports:\s+(.*)")
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = host_re.search(line)
            if not m:
                continue
            ip, blob = m.group(1), m.group(2)
            for entry in blob.split(","):
                f = entry.strip().split("/")
                if len(f) < 7:
                    continue
                port, state, proto, _, name = f[0], f[1], f[2], f[3], f[4]
                if state != "open":
                    continue
                if port in EXCLUDE_PORTS:          # WinRM itd. — nie panele web
                    continue
                svc = name.lower()
                if "http" not in svc and port not in ("80", "443", "8080", "8443", "10443", "10080"):
                    continue
                scheme = "https" if ("https" in svc or "ssl" in svc or port in ("443", "8443", "10443")) else "http"
                out.append(f"{scheme}://{ip}:{port}/")
    return sorted(set(out))


def targets_from_xml(path):
    out = []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return out
    for host in root.findall("host"):
        ip = None
        for a in host.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
        if not ip:
            continue
        ports = host.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            if (p.find("state") is None) or p.find("state").get("state") != "open":
                continue
            port = p.get("portid")
            if port in EXCLUDE_PORTS:              # WinRM itd. — nie panele web
                continue
            svc = p.find("service")
            name = (svc.get("name") if svc is not None else "") or ""
            tunnel = (svc.get("tunnel") if svc is not None else "") or ""
            if "http" not in name.lower() and port not in ("80", "443", "8080", "8443", "10443", "10080"):
                continue
            scheme = "https" if ("ssl" in tunnel or "https" in name.lower() or port in ("443", "8443", "10443")) else "http"
            out.append(f"{scheme}://{ip}:{port}/")
    return sorted(set(out))


def targets_from_ips(path):
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ip = line.strip()
            if not ip:
                continue
            # jeśli linia jest już URL-em (np. ktoś podał web_live.txt pod --ips),
            # nie dokładaj http+https — weź ją taką, jaka jest. Bez tego robi się x2.
            if ip.startswith(("http://", "https://")):
                out.append(ip)
                continue
            out.append(f"http://{ip}/")
            out.append(f"https://{ip}/")
    return out


def targets_from_urls(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [l.strip() for l in fh if l.strip()]


def open_in_firefox(urls):
    print(f"\n[+] Otwieram {len(urls)} kart w Firefoksie...")
    for u in urls:
        try:
            subprocess.Popen(["firefox", "--new-tab", u],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            print("[!] Nie znaleziono 'firefox' w PATH.", file=sys.stderr)
            return
    print("[+] Zlecone. Firefox otworzy karty w tle.")


def main():
    ap = argparse.ArgumentParser(description="Fingerprint paneli web + kandydujące default creds (bez logowania).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--gnmap", help="plik nmap .gnmap")
    g.add_argument("--xml", help="plik nmap .xml")
    g.add_argument("--ips", help="plik z samymi IP (próbuje http+https)")
    g.add_argument("--urls", help="plik z gotowymi URL-ami")
    ap.add_argument("-o", "--outdir", default="web_out")
    ap.add_argument("--open", action="store_true", help="po fingerprincie otwórz wszystko w Firefoksie")
    ap.add_argument("--open-only", action="store_true", help="tylko otwórz karty, pomiń fingerprint")
    ap.add_argument("--timeout", type=int, default=6)
    ap.add_argument("--insecure", action="store_true", default=True, help="ignoruj błędy certyfikatów (domyślnie wł.)")
    ap.add_argument("--workers", type=int, default=10)
    args = ap.parse_args()

    if args.gnmap:
        urls = targets_from_gnmap(args.gnmap)
    elif args.xml:
        urls = targets_from_xml(args.xml)
    elif args.ips:
        urls = targets_from_ips(args.ips)
    else:
        urls = targets_from_urls(args.urls)

    if not urls:
        print("[!] Brak celów web.", file=sys.stderr)
        sys.exit(1)

    print(f"[i] Celów web: {len(urls)}")

    def work(url):
        try:
            status, headers, title, realm = fetch(url, args.timeout, args.insecure)
            if status is None:
                return (url, None, {}, "", "", None, None)
            server = headers.get("server", "")
            name, creds = identify(title, server, realm)
            # fallback: drukarka po nagłówkach/tytule
            if not name and (PRINTER_HINT.search((title or "") + " " + (server or ""))):
                name, creds = "Drukarka (nieokreślony producent)", ["sprawdź naklejkę/dokumentację"]
            return (url, status, headers, title, realm, name, creds)
        except Exception:
            # ostatnia linia obrony — jeden host nigdy nie wywraca całego skanu
            return (url, None, {}, "", "", None, None)

    # tryb "tylko otwórz" — NAJPIERW sprawdź co żyje, otwórz WYŁĄCZNIE odpowiadające
    if args.open_only:
        live_only = []
        with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
            for r in ex.map(work, urls):
                if r[1] is not None:          # status != None => host odpowiedział
                    live_only.append(r[0])
        print(f"[i] Odpowiedziało: {len(live_only)}/{len(urls)} — otwieram tylko żywe")
        open_in_firefox(sorted(live_only))
        return

    os.makedirs(args.outdir, exist_ok=True)
    results = []

    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for r in ex.map(work, urls):
            results.append(r)

    live = [r for r in results if r[1] is not None]
    live_urls = [r[0] for r in live]

    # raport tekstowy
    report = os.path.join(args.outdir, "web_fingerprint.txt")
    with open(report, "w") as fh:
        fh.write(f"# Fingerprint web — {len(live)}/{len(urls)} odpowiedziało\n")
        fh.write("# UWAGA: default creds = KANDYDACI do RĘCZNEJ weryfikacji. Nic nie było logowane.\n\n")
        for url, status, headers, title, realm, name, creds in sorted(live, key=lambda r: r[0]):
            fh.write(f"{url}\n")
            fh.write(f"    HTTP {status}   Server: {headers.get('server','-')}\n")
            if title:
                fh.write(f"    Tytuł: {title}\n")
            if realm:
                fh.write(f"    Realm (basic-auth): {realm}\n")
            if name:
                fh.write(f"    >> TECHNOLOGIA: {name}\n")
                fh.write(f"    >> domyślne loginy (do ręcznego sprawdzenia): {', '.join(creds)}\n")
            else:
                fh.write(f"    >> technologia: nierozpoznana (obejrzyj ręcznie)\n")
            fh.write("\n")

    # lista żywych URL do EyeWitness / --open
    with open(os.path.join(args.outdir, "web_live.txt"), "w") as fh:
        for u in sorted(live_urls):
            fh.write(u + "\n")

    # podsumowanie na ekran
    rozpoznane = [r for r in live if r[5]]
    print(f"\n  Odpowiedziało : {len(live)}/{len(urls)}")
    print(f"  Rozpoznane    : {len(rozpoznane)}")
    print(f"  Raport        : {report}")
    print(f"  Żywe URL      : {args.outdir}/web_live.txt\n")
    for url, status, headers, title, realm, name, creds in sorted(rozpoznane, key=lambda r: r[0]):
        print(f"  {name:32} {url}")

    if args.open:
        open_in_firefox(live_urls)


if __name__ == "__main__":
    main()
