#!/usr/bin/env python3
"""
parse_nmap_targets.py — rozbija wyniki nmapa na pliki IP per usługa.

Wejście : jeden lub więcej plików .xml z nmapa (-oX / -oA).  Fallback: .gnmap.
Wyjście : katalog z plikami smb.txt, rdp.txt, ssh.txt, web.txt, ...
          (same adresy IP, po jednym w wierszu, unikalne, posortowane).

Użycie:
    python3 parse_nmap_targets.py skan_top10k_2026-10-08.xml
    python3 parse_nmap_targets.py *.xml -o targets
    python3 parse_nmap_targets.py skan.gnmap            # jak nie masz XML
    python3 parse_nmap_targets.py skan.xml --open-filtered   # licz też open|filtered

Potem w nmapie / narzędziach:  nmap ... -iL targets/smb.txt
"""

import argparse
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# Definicje usług.  Każda kategoria dopasowuje się po NAZWIE usługi (z -sV)
# LUB po numerze portu.  Dopisz/zmień swobodnie — to steruje całym podziałem.
#   ports     : porty charakterystyczne dla usługi
#   names     : fragmenty nazwy usługi nmapa (dopasowanie "zawiera", bez wielkości liter)
# ─────────────────────────────────────────────────────────────────────────────
CATEGORIES = {
    "smb":        {"ports": {139, 445},              "names": {"microsoft-ds", "netbios-ssn", "smb"}},
    "rdp":        {"ports": {3389},                  "names": {"ms-wbt-server", "rdp"}},
    "ssh":        {"ports": {22},                    "names": {"ssh"}},
    "web":        {"ports": {80, 443, 8080, 8000, 8443, 8888, 8081, 8008,
                             5000, 7001, 9090, 9000, 8443}, "names": {"http", "https", "http-proxy", "http-alt", "ssl/http"}},
    "ftp":        {"ports": {21},                    "names": {"ftp"}},
    "telnet":     {"ports": {23},                    "names": {"telnet"}},
    "msrpc":      {"ports": {135},                   "names": {"msrpc"}},
    "ldap":       {"ports": {389, 636, 3268, 3269},  "names": {"ldap", "ldapssl"}},
    "kerberos":   {"ports": {88},                    "names": {"kerberos", "kerberos-sec"}},
    "dns":        {"ports": {53},                    "names": {"domain"}},
    "mssql":      {"ports": {1433, 1434},            "names": {"ms-sql", "ms-sql-s"}},
    "mysql":      {"ports": {3306},                  "names": {"mysql"}},
    "postgres":   {"ports": {5432},                  "names": {"postgresql", "postgres"}},
    "oracle":     {"ports": {1521},                  "names": {"oracle", "oracle-tns"}},
    "smtp":       {"ports": {25, 465, 587},          "names": {"smtp"}},
    "pop3":       {"ports": {110, 995},              "names": {"pop3"}},
    "imap":       {"ports": {143, 993},              "names": {"imap"}},
    "snmp":       {"ports": {161},                   "names": {"snmp"}},
    "vnc":        {"ports": {5900, 5901, 5902, 5903, 5904, 5905, 5906}, "names": {"vnc"}},
    "winrm":      {"ports": {5985, 5986},            "names": {"wsman", "winrm"}},
    "redis":      {"ports": {6379},                  "names": {"redis"}},
    "mongodb":    {"ports": {27017, 27018},          "names": {"mongod", "mongodb"}},
    "elastic":    {"ports": {9200, 9300},            "names": {"elasticsearch"}},
    "printer":    {"ports": {9100, 515, 631},        "names": {"jetdirect", "printer", "ipp", "lpd", "pdl-datastream"}},
    "nfs":        {"ports": {2049},                  "names": {"nfs"}},
    "rsync":      {"ports": {873},                   "names": {"rsync"}},
    "docker":     {"ports": {2375, 2376},            "names": {"docker"}},
}

OPEN_STATES = {"open"}  # domyślnie; z --open-filtered dojdzie "open|filtered"


# WinRM (5985/5986) jedzie po HTTP, więc nmap oznacza je usługą "http"/"ssl/http".
# To NIE są panele przeglądarkowe — nie mają trafiać do web.txt (zostają w winrm.txt).
WEB_EXCLUDE_PORTS = {5985, 5986}


def classify(port, name):
    """Zwraca zbiór kategorii pasujących do danego (port, nazwa_uslugi)."""
    name = (name or "").lower()
    hits = set()
    for cat, rule in CATEGORIES.items():
        matched = port in rule["ports"] or any(n in name for n in rule["names"])
        if not matched:
            continue
        # WinRM nie jest webem: nie dopuść 5985/5986 do kategorii web,
        # nawet jeśli nmap zobaczył tam "http". Reszta kategorii (winrm) bez zmian.
        if cat == "web" and port in WEB_EXCLUDE_PORTS:
            continue
        hits.add(cat)
    return hits


def parse_xml(path, allowed_states):
    """Yield (ip, port:int, proto, service_name) dla otwartych portów."""
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f"[!] {path}: błąd parsowania XML ({e}) — pomijam", file=sys.stderr)
        return
    root = tree.getroot()
    for host in root.findall("host"):
        st = host.find("status")
        if st is not None and st.get("state") != "up":
            continue
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break
        if not ip:
            continue
        ports = host.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            pstate = p.find("state")
            if pstate is None or pstate.get("state") not in allowed_states:
                continue
            try:
                portid = int(p.get("portid"))
            except (TypeError, ValueError):
                continue
            proto = p.get("protocol", "tcp")
            svc = p.find("service")
            name = svc.get("name") if svc is not None else ""
            yield ip, portid, proto, name


GNMAP_RE = re.compile(r"Host:\s+(\d+\.\d+\.\d+\.\d+).*?Ports:\s+(.*)")


def parse_gnmap(path, allowed_states):
    """Fallback dla .gnmap. Format portu: 22/open/tcp//ssh///"""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = GNMAP_RE.search(line)
            if not m:
                continue
            ip, portblob = m.group(1), m.group(2)
            for entry in portblob.split(","):
                f = entry.strip().split("/")
                if len(f) < 5:
                    continue
                portid, state, proto, _, name = f[0], f[1], f[2], f[3], f[4]
                state_norm = state.replace("|", "|")
                if state_norm not in allowed_states:
                    continue
                try:
                    yield ip, int(portid), proto, name
                except ValueError:
                    continue


def main():
    ap = argparse.ArgumentParser(description="Rozbija wyniki nmapa na pliki IP per usługa.")
    ap.add_argument("inputs", nargs="+", help="pliki .xml (lub .gnmap) z nmapa; można glob np. '*.xml'")
    ap.add_argument("-o", "--outdir", default="targets", help="katalog wyjściowy (domyślnie: targets)")
    ap.add_argument("--open-filtered", action="store_true", help="licz też porty open|filtered")
    args = ap.parse_args()

    allowed = set(OPEN_STATES)
    if args.open_filtered:
        allowed.add("open|filtered")

    # rozwiń globy (gdy shell ich nie rozwinął)
    files = []
    for pat in args.inputs:
        hits = glob.glob(pat)
        files.extend(hits if hits else [pat])
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        print("[!] Brak plików wejściowych.", file=sys.stderr)
        sys.exit(1)

    buckets = defaultdict(set)      # kategoria -> {ip}
    all_hosts = set()
    unmatched = defaultdict(set)    # (port,proto,name) nietrafione nigdzie -> {ip}

    for f in files:
        reader = parse_gnmap if f.endswith(".gnmap") else parse_xml
        for ip, port, proto, name in reader(f, allowed):
            all_hosts.add(ip)
            cats = classify(port, name)
            if cats:
                for c in cats:
                    buckets[c].add(ip)
            else:
                unmatched[(port, proto, name)].add(ip)

    os.makedirs(args.outdir, exist_ok=True)

    def ipsort(ip):
        return tuple(int(x) for x in ip.split("."))

    # pliki per usługa
    for cat in sorted(buckets):
        path = os.path.join(args.outdir, f"{cat}.txt")
        with open(path, "w") as fh:
            for ip in sorted(buckets[cat], key=ipsort):
                fh.write(ip + "\n")

    # bonus: wszystkie hosty z czymkolwiek otwartym
    with open(os.path.join(args.outdir, "_all_hosts.txt"), "w") as fh:
        for ip in sorted(all_hosts, key=ipsort):
            fh.write(ip + "\n")

    # raport nietrafionych portów — żeby nic nie uciekło po cichu
    if unmatched:
        with open(os.path.join(args.outdir, "_unmatched.txt"), "w") as fh:
            for (port, proto, name), ips in sorted(unmatched.items()):
                fh.write(f"{port}/{proto}  {name or '?'}  -> {len(ips)} host(ów)\n")

    # podsumowanie na ekran
    print(f"\n  Wejście:  {len(files)} plik(ów),  hostów z otwartymi portami: {len(all_hosts)}")
    print(f"  Wyjście:  {args.outdir}/\n")
    print(f"  {'USŁUGA':<12} {'HOSTÓW':>7}   PLIK")
    print(f"  {'-'*12} {'-'*7}   {'-'*20}")
    for cat in sorted(buckets, key=lambda c: (-len(buckets[c]), c)):
        print(f"  {cat:<12} {len(buckets[cat]):>7}   {args.outdir}/{cat}.txt")
    if unmatched:
        n = sum(len(v) for v in unmatched.values())
        print(f"\n  [i] {len(unmatched)} nietrafionych usług/portów (szczegóły: {args.outdir}/_unmatched.txt)")
    print()


if __name__ == "__main__":
    main()
