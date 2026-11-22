#!/usr/bin/env python3
"""benchmark/prefix_sweep.py — Balayage de la finesse du préfixe pour la boucle.
Compare recall (dérive légitime) vs fuite (étranger) pour /28 /24 /20 /16 /8,
moyenné sur les profils. Offline déterministe, pas de LLM. Référence : IP exacte.
"""
from __future__ import annotations
import ipaddress
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from whitelist.profile_builder import build_profile

APPS = ["dropbox", "faceswitch", "lequipe", "meteo", "ninegag", "pokemongo", "skype", "viber"]


def pref(ip: str, bits: int) -> int:
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return int(ipaddress.ip_address(ip)) & mask


def rates(bits: int, ips: dict) -> tuple[float, float]:
    recs, leaks = [], []
    for P in APPS:
        all_ = sorted(ips[P])
        # recall : hold-out
        refA = set(all_[::2]); B = all_[1::2]
        keysA = {pref(x, bits) for x in refA}
        rec = sum(1 for ip in B if pref(ip, bits) in keysA) / (len(B) or 1)
        recs.append(100 * rec)
        # leak : étranger
        refF = set(all_); keysF = {pref(x, bits) for x in refF}
        foreign = [ip for O in APPS if O != P for ip in ips[O] if ip not in refF]
        lk = sum(1 for ip in foreign if pref(ip, bits) in keysF) / (len(foreign) or 1)
        leaks.append(100 * lk)
    return sum(recs) / len(recs), sum(leaks) / len(leaks)


def main() -> int:
    ips = {a: build_profile(a).ips for a in APPS}
    print("=" * 60)
    print("  BALAYAGE FINESSE PRÉFIXE — moyenne sur 8 profils")
    print("  (recall = dérive légitime étendue ↑ ; fuite = étranger à tort ↓)")
    print("=" * 60)
    print(f"  {'critère':<12}{'RECALL ↑':>10}{'FUITE ↓':>10}{'écart R-F':>11}")
    # IP exacte = /32
    for bits, label in [(32, "IP exacte"), (28, "/28"), (24, "/24"),
                        (20, "/20"), (16, "/16 (actuel)"), (8, "/8")]:
        r, f = rates(bits, ips)
        print(f"  {label:<12}{r:>9.0f}%{f:>9.0f}%{r-f:>10.0f}")
    print("=" * 60)
    print("  écart R-F élevé = bon compromis (étend la dérive sans trop fuiter).")
    print("  Échantillon = 8 apps → tendances sur tes données, pas universel.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
