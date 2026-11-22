#!/usr/bin/env python3
"""
benchmark/granularity_precision_recall.py — (A) consolidé : précision / rappel
des 4 clés de décision du whitelisting (IP exacte / /16 / ASN / domaine rDNS).

Pour chaque app-PROFIL P et chaque clé K, sur LES MÊMES IP :
  • RAPPEL  = sur une dérive légitime (hold-out : moitié des IP de P jamais vue),
    % de vraies destinations de P que K étend correctement.  (↑ mieux)
  • FUITE/FP = sur le trafic ÉTRANGER (toutes les autres apps), % laissé passer à
    tort (faux positifs).  (↓ mieux — c'est la "précision" au sens demandé)

Déterministe, OFFLINE, sans LLM, sans quota. Échantillon = tes traces existantes.
Idéal recherché : RAPPEL élevé + FUITE basse. Aucune clé n'y arrive sous infra cloud.

Usage : python3 benchmark/granularity_precision_recall.py
"""
from __future__ import annotations
import pathlib
import re
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from enrichment.csv_reader import read_app

_GENERIC = {"amazonaws.com", "compute-1.amazonaws.com", "amazon.com",
            "akamaitechnologies.com", "googleusercontent.com", "1e100.net",
            "poneytelecom.eu", "ovh.net", "softlayer.com", "linode.com",
            "members.linode.com"}
_TWO_TLD = {"co.uk", "com.br", "co.jp", "org.uk", "ac.uk", "com.au"}


def is_ip(s: str) -> bool:
    return bool(re.fullmatch(r"[\d.]+", s or ""))


def reg_domain(host):
    if not host:
        return None
    h = str(host).strip().lower().rstrip(".")
    if not h or is_ip(h):
        return None
    l = h.split(".")
    if len(l) < 2:
        return None
    if len(l) >= 3 and ".".join(l[-2:]) in _TWO_TLD:
        return ".".join(l[-3:])
    return ".".join(l[-2:])


def prefix16(ip):
    return ".".join(ip.split(".")[:2])


_ASN: dict[str, int | None] = {}
try:
    from enrichment.asn_resolver import AsnResolver
    _R = AsnResolver(); _ASN_OK = True
except Exception as e:
    _ASN_OK = False; print(f"⚠️ ASN indispo ({e})")


def asn(ip):
    if not _ASN_OK:
        return None
    if ip not in _ASN:
        try:
            _ASN[ip] = getattr(_R.resolve(ip), "asn", None)
        except Exception:
            _ASN[ip] = None
    return _ASN[ip]


def load(app):
    f = read_app(app)
    return {ip: ep.dstname for ip, ep in f.endpoints.items()} if f and f.endpoints else {}


class Ref:
    """Profil de référence construit sur un sous-ensemble d'IP."""
    def __init__(self, ip2name):
        self.ips = set(ip2name)
        self.pref = {prefix16(ip) for ip in self.ips}
        self.doms = {d for d in (reg_domain(n) for n in ip2name.values()) if d}
        self.asns = {a for a in (asn(ip) for ip in self.ips) if a is not None}


KEYS = ["IP", "/16", "ASN", "domaine"]


def extends(ref: Ref, ip: str, name) -> dict:
    d = reg_domain(name)
    return {
        "IP": ip in ref.ips,
        "/16": prefix16(ip) in ref.pref,
        "ASN": (asn(ip) is not None and asn(ip) in ref.asns),
        "domaine": (d is not None and d in ref.doms),
    }


def rate(ref, ip2name) -> dict:
    """% EXTEND par clé sur l'ensemble d'IP fourni."""
    ips = list(ip2name)
    n = len(ips) or 1
    acc = {k: 0 for k in KEYS}
    for ip in ips:
        e = extends(ref, ip, ip2name[ip])
        for k in KEYS:
            acc[k] += e[k]
    return {k: 100 * acc[k] / n for k in KEYS}


def main() -> int:
    apps_all = ["dropbox", "faceswitch", "lequipe", "meteo", "ninegag",
                "pokemongo", "skype", "viber", "disneyland", "ratp"]
    data = {a: load(a) for a in apps_all}
    data = {a: d for a, d in data.items() if d}
    profiles = [a for a in apps_all if len(data.get(a, {})) >= 16]  # hold-out crédible

    print("=" * 78)
    print("  (A) PRÉCISION / RAPPEL des 4 clés — par profil de référence")
    print(f"  profils testés : {profiles}")
    print("=" * 78)

    agg = {k: {"rec": [], "leak": []} for k in KEYS}
    for P in profiles:
        ip2name = data[P]
        ips = sorted(ip2name)
        halfA = {ip: ip2name[ip] for ip in ips[::2]}
        halfB = {ip: ip2name[ip] for ip in ips[1::2]}   # dérive légitime (jamais vue)
        ref = Ref(halfA)
        rec = rate(ref, halfB)                            # RAPPEL
        # FUITE/FP : trafic étranger (toutes les autres apps), poolé
        foreign = {}
        for O, d in data.items():
            if O == P:
                continue
            for ip, nm in d.items():
                if ip not in ip2name:    # exclut le vrai chevauchement (CDN communs réels)
                    foreign[ip] = nm
        leak = rate(ref, foreign)                         # FAUX POSITIFS
        print(f"\n  ── profil = {P}  (réf={len(halfA)} IP, dérive={len(halfB)} IP, "
              f"étranger={len(foreign)} IP) ──")
        print(f"     {'clé':<9}{'RAPPEL ↑':>10}{'FUITE/FP ↓':>12}")
        for k in KEYS:
            print(f"     {k:<9}{rec[k]:>9.0f}%{leak[k]:>11.0f}%")
            agg[k]["rec"].append(rec[k]); agg[k]["leak"].append(leak[k])

    print("\n" + "=" * 78)
    print("  SYNTHÈSE — moyenne sur tous les profils (tendance générale)")
    print("=" * 78)
    print(f"  {'clé':<9}{'RAPPEL moy ↑':>14}{'FUITE/FP moy ↓':>16}")
    for k in KEYS:
        r = sum(agg[k]["rec"]) / len(agg[k]["rec"])
        f = sum(agg[k]["leak"]) / len(agg[k]["leak"])
        print(f"  {k:<9}{r:>13.0f}%{f:>15.0f}%")

    print("\n" + "=" * 78)
    print("  ⚠️  HONNÊTETÉ SCIENTIFIQUE")
    print("=" * 78)
    print(f"  • {len(profiles)} profils, hold-out parfois petit (dropbox→8 IP) → ce sont")
    print("    des TENDANCES sur CES données, pas des lois universelles.")
    print("  • RAPPEL = dérive légitime correctement étendue (↑) ; FUITE = trafic")
    print("    étranger étendu à tort (↓). Idéal = rappel haut + fuite basse.")
    print("  • IP-exacte : rappel ~0 par construction (ne généralise pas).")
    print("  • domaine : limité par la qualité du rDNS (générique cloud → échoue).")
    print("    Le vrai signal (DNS forward/SNI) est absent des traces → étape (B).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
