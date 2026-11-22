#!/usr/bin/env python3
"""
benchmark/loop_cases_asn.py — Même récit cas-par-cas, mais clé = ASN (au lieu de /16).
Affiche la version ASN ET une comparaison /16 vs ASN de la fuite. Offline déterministe.
"""
from __future__ import annotations
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from whitelist.profile_builder import build_profile
from enrichment.asn_resolver import AsnResolver

_R = AsnResolver()
_ASN: dict[str, int | None] = {}
_ORG: dict[str, str | None] = {}


def asn(ip: str):
    if ip not in _ASN:
        try:
            r = _R.resolve(ip)
            _ASN[ip] = getattr(r, "asn", None)
            _ORG[ip] = getattr(r, "org", None) or getattr(r, "name", None)
        except Exception:
            _ASN[ip] = None; _ORG[ip] = None
    return _ASN[ip]


def p16(ip: str) -> str:
    return ".".join(ip.split(".")[:2])


def compute(ref: str, app: str, key: str, holdout: bool):
    R_all = sorted(build_profile(ref).ips)
    if holdout:
        ref_ips = set(R_all[::2]); app_ips = R_all[1::2]; ref_full = set(R_all)
    else:
        ref_ips = set(R_all); app_ips = sorted(build_profile(app).ips); ref_full = set(R_all)
    kf = (lambda ip: p16(ip)) if key == "p16" else (lambda ip: asn(ip))
    ref_keys = {kf(x) for x in ref_ips}; ref_keys.discard(None)
    directs = [ip for ip in app_ips if ip in ref_ips]
    escal = [ip for ip in app_ips if ip not in ref_ips]
    ext = [ip for ip in escal if kf(ip) is not None and kf(ip) in ref_keys]
    blk = [ip for ip in escal if not (kf(ip) is not None and kf(ip) in ref_keys)]
    fuite = [ip for ip in ext if ip not in ref_full]

    def match(ip):
        k = kf(ip)
        for r in sorted(ref_ips):
            if kf(r) == k:
                return r
        return None
    return dict(ref=ref, app=app, ho=holdout, ref_size=len(ref_ips), n=len(app_ips),
                directs=directs, escal=escal, ext=ext, blk=blk, fuite=fuite, match=match)


def render_asn(c):
    R, A = c["ref"], c["app"]
    N, X, Y = c["n"], len(c["directs"]), len(c["escal"])
    E, B, F = len(c["ext"]), len(c["blk"]), len(c["fuite"])
    lbl = f"{A} (hold-out)" if c["ho"] else A
    print("\n" + "═" * 70)
    print(f"  CAS (clé = ASN) : profil {R} déployé → rejeu de {lbl}")
    print("═" * 70)
    print(f"  1) DÉPART (profil = {c['ref_size']} IP) : N={N}  acceptées X={X}  bloquées Y={Y}")
    print(f"  2) REMONTÉE (clé ASN) : EXTEND E={E}  BLOCK B={B}  (E+B={E+B}, Y={Y} {'✓' if E+B==Y else '✗'})")
    for ip in c["ext"][:2]:
        r = c["match"](ip)
        print(f"       EXTEND ex. {ip} (AS{asn(ip)} {_ORG.get(ip)}) ← {R} a {r} (même AS{asn(ip)})")
    for ip in c["blk"][:1]:
        print(f"       BLOCK  ex. {ip} (AS{asn(ip)} {_ORG.get(ip)}) ← aucune IP {R} sur cet ASN")
    print(f"  3) APRÈS : +{E} ALLOW, +{B} DROP → {X+E} passent, {B} bloquées · FUITE F={F}")
    pct = 100 * F / Y if Y else 0
    print(f"  4) POURQUOI : fuite {F}/{Y} = {pct:.0f}% "
          + ("(ÉLEVÉE — même ASN cloud partagé)" if pct >= 30 else "(faible)"))


def main():
    cases = [("lequipe", "lequipe", True), ("lequipe", "faceswitch", False),
             ("faceswitch", "lequipe", False), ("lequipe", "skype", False),
             ("skype", "lequipe", False), ("lequipe", "viber", False),
             ("viber", "lequipe", False)]
    comp = []
    for ref, app, ho in cases:
        ca = compute(ref, app, "asn", ho)
        render_asn(ca)
        cp = compute(ref, app, "p16", ho)
        comp.append((f"{ref}→{app}" + ("*" if ho else ""), len(ca["escal"]),
                     len(cp["ext"]), len(cp["fuite"]), len(ca["ext"]), len(ca["fuite"])))

    print("\n" + "═" * 70)
    print("  COMPARAISON /16 vs ASN  (* hold-out)")
    print("═" * 70)
    print(f"  {'cas':<20}{'escal':>6}{'EXT/16':>8}{'fuite/16':>10}{'EXT_ASN':>9}{'fuite_ASN':>11}")
    tf16 = ta = sf16 = sa = 0
    for cas, esc, e16, f16, ea, fa in comp:
        print(f"  {cas:<20}{esc:>6}{e16:>8}{f16:>10}{ea:>9}{fa:>11}")
    off = [r for r in comp if not r[0].endswith("*")]
    print("  ── totaux hors-diagonale ──")
    print(f"  fuite /16 = {sum(r[3] for r in off)}   |   fuite ASN = {sum(r[5] for r in off)}")
    print("\n  Échantillon = tes traces → tendances, pas universel.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
