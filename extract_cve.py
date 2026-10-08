#!/usr/bin/env python3
"""
extract_cve.py — wyciąga CVE z wyników nmapa (skrypty vuln / vulners).

Wejście : pliki .xml z nmapa (-oX / -oA) ze skanu vuln i/lub vulners.
Wyjście : - cve_wszystkie.csv   (host, port, usługa, CVE, CVSS, źródło, stan)
          - cve_per_host.txt    (czytelne zestawienie host -> CVE)
          - cve_lista.txt       (unikalne CVE, posortowane po CVSS malejąco)
          - exploitable.txt      (CVE, które skrypt oznaczył jako potwierdzone/EXPLOITABLE)

Użycie:
    python3 extract_cve.py vulns/vuln.xml vulns/vulners_cve_2026-10-08.xml -o cve_out
    python3 extract_cve.py *.xml -o cve_out
    python3 extract_cve.py vulns/vulners.xml --min-cvss 7.0 -o cve_out

WAŻNE — rozróżnienie stanu (kolumna 'stan'):
    POTWIERDZONE  = skrypt NSE realnie przetestował podatność i host jest podatny
                    (np. ms17-010 State: VULNERABLE, smb-vuln-* VULNERABLE).
                    To jedyne, co wolno nazwać potwierdzonym w raporcie.
    WG_WERSJI     = dopasowanie tylko po wersji usługi (vulners, i część vuln).
                    To są KANDYDACI do weryfikacji, NIE potwierdzone podatności.
                    Backporty łatek dają tu fałszywe alarmy.
"""

import argparse
import csv
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# linie vulners mają zwykle format:  CVE-2021-1234   7.5   https://vulners.com/...
CVSS_NEAR_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d{1,2}\.\d)")
# ogólne "CVSS: 9.8" gdziekolwiek w tekście
CVSS_LABEL_RE = re.compile(r"CVSS[:\s]+(\d{1,2}\.\d)", re.IGNORECASE)

# markery, że skrypt REALNIE potwierdził podatność (nie tylko wersja)
CONFIRMED_MARKERS = (
    "State: VULNERABLE",
    "VULNERABLE:",
    "EXPLOITABLE",
)


def parse_file(path):
    """Yield dict per znalezione CVE: host, port, proto, service, cve, cvss, source, confirmed."""
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f"[!] {path}: błąd XML ({e}) — pomijam", file=sys.stderr)
        return
    root = tree.getroot()
    src = "vulners" if "vulners" in os.path.basename(path).lower() else "vuln"

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

        # skrypty host-level (np. smb-vuln na porcie 445 raportują się pod portem,
        # ale część vuln-ów bywa też w <hostscript>)
        blocks = []
        ports = host.find("ports")
        if ports is not None:
            for p in ports.findall("port"):
                portid = p.get("portid")
                proto = p.get("protocol", "tcp")
                svc = p.find("service")
                sname = svc.get("name") if svc is not None else ""
                prod = (svc.get("product") if svc is not None else "") or ""
                ver = (svc.get("version") if svc is not None else "") or ""
                svc_full = " ".join(x for x in (sname, prod, ver) if x)
                for scr in p.findall("script"):
                    blocks.append((portid, proto, svc_full, scr))
        hs = host.find("hostscript")
        if hs is not None:
            for scr in hs.findall("script"):
                blocks.append(("-", "-", "", scr))

        for portid, proto, svc_full, scr in blocks:
            output = scr.get("output") or ""
            confirmed = any(m in output for m in CONFIRMED_MARKERS)

            # zbierz CVE z tego bloku skryptu
            found = {}
            for m in CVSS_NEAR_RE.finditer(output):
                found[m.group(1).upper()] = m.group(2)
            for cve in CVE_RE.findall(output):
                found.setdefault(cve.upper(), None)

            if not found:
                continue

            # jeśli CVE bez własnego CVSS, spróbuj wyłapać CVSS z etykiety w bloku
            label = CVSS_LABEL_RE.search(output)
            fallback_cvss = label.group(1) if label else ""

            for cve, cvss in found.items():
                yield {
                    "host": ip,
                    "port": portid,
                    "proto": proto,
                    "service": svc_full,
                    "cve": cve,
                    "cvss": cvss or fallback_cvss or "",
                    "source": src,
                    "confirmed": confirmed,
                }


def cvss_key(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return -1.0


def ipsort(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def main():
    ap = argparse.ArgumentParser(description="Wyciąga CVE z wyników nmapa (vuln/vulners).")
    ap.add_argument("inputs", nargs="+", help="pliki .xml z nmapa (vuln i/lub vulners)")
    ap.add_argument("-o", "--outdir", default="cve_out", help="katalog wyjściowy")
    ap.add_argument("--min-cvss", type=float, default=0.0, help="pomiń CVE poniżej tego CVSS (domyślnie 0 = wszystkie)")
    args = ap.parse_args()

    files = []
    for pat in args.inputs:
        hits = glob.glob(pat)
        files.extend(hits if hits else [pat])
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        print("[!] Brak plików wejściowych.", file=sys.stderr)
        sys.exit(1)

    rows = []
    for f in files:
        rows.extend(parse_file(f))

    # filtr min-cvss (CVE bez CVSS zostają — lepiej nie gubić)
    def keep(r):
        if not r["cvss"]:
            return True
        return cvss_key(r["cvss"]) >= args.min_cvss
    rows = [r for r in rows if keep(r)]

    if not rows:
        print("[i] Nie znaleziono żadnych CVE w podanych plikach.")
        print("    (To normalne, jeśli vuln znalazł tylko podatności bez numeru CVE,")
        print("     albo vulners nie miał internetu i nic nie dopasował.)")
        # i tak utwórz katalog + pusty raport, żeby pipeline nie padał
        os.makedirs(args.outdir, exist_ok=True)
        open(os.path.join(args.outdir, "cve_lista.txt"), "w").close()
        return

    os.makedirs(args.outdir, exist_ok=True)

    # 1) pełny CSV
    with open(os.path.join(args.outdir, "cve_wszystkie.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "port", "proto", "usluga", "cve", "cvss", "zrodlo", "stan"])
        for r in sorted(rows, key=lambda r: (ipsort(r["host"]), -cvss_key(r["cvss"]))):
            w.writerow([r["host"], r["port"], r["proto"], r["service"], r["cve"],
                        r["cvss"], r["source"], "POTWIERDZONE" if r["confirmed"] else "WG_WERSJI"])

    # 2) per host, czytelnie
    by_host = defaultdict(list)
    for r in rows:
        by_host[r["host"]].append(r)
    with open(os.path.join(args.outdir, "cve_per_host.txt"), "w") as fh:
        for host in sorted(by_host, key=ipsort):
            hr = by_host[host]
            conf = sum(1 for r in hr if r["confirmed"])
            fh.write(f"\n=== {host}  ({len(hr)} CVE, w tym {conf} POTWIERDZONE) ===\n")
            for r in sorted(hr, key=lambda r: -cvss_key(r["cvss"])):
                tag = "[POTW]" if r["confirmed"] else "[wersja]"
                cvss = r["cvss"] or "?"
                fh.write(f"  {tag:9} CVSS {cvss:>4}  {r['cve']:18} {r['port']}/{r['proto']}  {r['service']}\n")

    # 3) unikalne CVE po CVSS malejąco
    uniq = {}
    for r in rows:
        c = r["cve"]
        if c not in uniq or cvss_key(r["cvss"]) > cvss_key(uniq[c]["cvss"]):
            uniq[c] = r
    with open(os.path.join(args.outdir, "cve_lista.txt"), "w") as fh:
        for c in sorted(uniq, key=lambda c: -cvss_key(uniq[c]["cvss"])):
            fh.write(f"{uniq[c]['cvss'] or '?':>4}  {c}\n")

    # 4) tylko realnie potwierdzone przez skrypt
    confirmed_rows = [r for r in rows if r["confirmed"]]
    with open(os.path.join(args.outdir, "potwierdzone.txt"), "w") as fh:
        if confirmed_rows:
            for r in sorted(confirmed_rows, key=lambda r: (ipsort(r["host"]), -cvss_key(r["cvss"]))):
                fh.write(f"{r['host']:16} {r['cve']:18} CVSS {r['cvss'] or '?':>4}  {r['port']}/{r['proto']}  {r['service']}\n")
        else:
            fh.write("# Żaden skrypt NSE nie oznaczył podatności jako VULNERABLE/EXPLOITABLE.\n")
            fh.write("# Wszystkie znalezione CVE to dopasowania PO WERSJI — wymagają ręcznej weryfikacji.\n")

    # podsumowanie
    n_conf = len(confirmed_rows)
    hosts = len(by_host)
    print(f"\n  Plików wejściowych : {len(files)}")
    print(f"  Wierszy CVE        : {len(rows)}  (na {hosts} hostach)")
    print(f"  Unikalnych CVE     : {len(uniq)}")
    print(f"  POTWIERDZONE (NSE) : {n_conf}   <- tylko te wolno tak nazwać w raporcie")
    print(f"  WG WERSJI          : {len(rows) - n_conf}   <- kandydaci do weryfikacji")
    print(f"\n  Wyniki w: {args.outdir}/")
    print("    cve_wszystkie.csv   — pełne zestawienie (host/port/usługa/CVE/CVSS/stan)")
    print("    cve_per_host.txt    — czytelnie per host")
    print("    cve_lista.txt       — unikalne CVE po CVSS")
    print("    potwierdzone.txt    — tylko realnie potwierdzone przez NSE\n")


if __name__ == "__main__":
    main()
