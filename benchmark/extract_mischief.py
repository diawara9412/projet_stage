#!/usr/bin/env python3
"""
benchmark/extract_mischief.py — extrait la VÉRITÉ-TERRAIN malveillante du
Android Mischief Dataset (Stratosphere) : pour chaque RAT, le C2 (Controller IP
du README) + son éventuel domaine (DNS/SNI), + les ports de contrôle.

Sortie : benchmark/results/mischief_c2.json  (liste de {rat, c2_ip, c2_domain, ports})
Lecture seule sur les logs Zeek déjà extraits dans le scratchpad. Pas de réseau.
"""
from __future__ import annotations
import json
import pathlib
import re
import sys

SC = pathlib.Path("/tmp/claude-1000/-home-kali-Desktop-projet/"
                  "b68a94b1-f930-4154-843d-009d371cf75a/scratchpad/malware")
OUT = pathlib.Path(__file__).resolve().parent / "results" / "mischief_c2.json"


def find(folder: pathlib.Path, pattern: str):
    return list(folder.rglob(pattern))


def parse_readme(p: pathlib.Path):
    txt = p.read_text(errors="ignore")
    ctrl = re.search(r"Controller IP:\s*([\d.]+)", txt)
    vict = re.search(r"Victim IP:\s*([\d.]+)", txt)
    return (ctrl.group(1) if ctrl else None), (vict.group(1) if vict else None)


def conn_ports(p: pathlib.Path, c2_ip: str):
    """Ports vers le C2 + toutes destinations vues (pour info)."""
    ports = set()
    for line in p.read_text(errors="ignore").splitlines():
        if line.startswith("#"):
            continue
        r = line.split("\t")
        if len(r) > 6 and r[4] == c2_ip:
            ports.add((r[5], r[6]))
    return sorted(ports)


def c2_domain(folder: pathlib.Path, c2_ip: str):
    """Cherche un domaine associé au C2 dans dns.log (réponse = c2_ip) ou ssl.log."""
    # dns.log : ... query ... answers (contient l'IP)
    for dns in find(folder, "dns.log"):
        for line in dns.read_text(errors="ignore").splitlines():
            if line.startswith("#") or c2_ip not in line:
                continue
            for tok in line.split("\t"):
                if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", tok) and not re.fullmatch(r"[\d.]+", tok):
                    return tok
    return None


def main():
    if not SC.exists():
        print("scratchpad malware absent"); return 1
    rats = sorted([d for d in SC.iterdir() if d.is_dir()])
    res = []
    for rat in rats:
        readmes = find(rat, "README.md")
        if not readmes:
            continue
        c2, victim = parse_readme(readmes[0])
        if not c2:
            print(f"  {rat.name}: pas de Controller IP dans le README"); continue
        conns = find(rat, "conn.log")
        ports = conn_ports(conns[0], c2) if conns else []
        dom = c2_domain(rat, c2)
        res.append({"rat": rat.name, "c2_ip": c2, "victim_ip": victim,
                    "c2_domain": dom, "ports": ports})
        print(f"  {rat.name:<12} C2={c2:<16} domaine={dom or '-':<22} ports={ports}")
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(res, indent=2))
    print(f"\n  → {len(res)} C2 réels écrits dans {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
