#!/usr/bin/env python3
"""
benchmark/loop_cases.py — Récit CAS PAR CAS de la boucle /16 (offline déterministe).

Pour chaque couple (profil REF déployé → rejeu APP), raconte l'histoire complète :
  1) DÉPART (switch statique)  : N, acceptées (directs), bloquées (table-miss)
  2) REMONTÉE (boucle /16)     : EXTEND vs BLOCK, avec exemples d'IP + /16 + plage REF
  3) APRÈS REDÉPLOIEMENT        : (X+E) passent, B bloquées ; fuite F
  4) POURQUOI                   : explication en clair

Vraies IP des traces (whitelist.profile_builder.build_profile). Pas de LLM, pas de réseau.
"""
from __future__ import annotations
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from whitelist.profile_builder import build_profile


def p16(ip: str) -> str:
    return ".".join(ip.split(".")[:2])


def case(ref: str, app: str, holdout: bool = False) -> dict:
    R_all = sorted(build_profile(ref).ips)
    if holdout:
        ref_ips = set(R_all[::2])         # profil = moitié des IP
        app_ips = R_all[1::2]             # rejeu = autre moitié (dérive)
        ref_full = set(R_all)             # « vraies IP de REF » = tout REF
        app_label = f"{app} (hold-out : autre moitié)"
    else:
        ref_ips = set(R_all)
        app_ips = sorted(build_profile(app).ips)
        ref_full = set(R_all)
        app_label = app
    ref_pref = {p16(x) for x in ref_ips}
    directs = [ip for ip in app_ips if ip in ref_ips]
    escal = [ip for ip in app_ips if ip not in ref_ips]
    ext = [ip for ip in escal if p16(ip) in ref_pref]
    blk = [ip for ip in escal if p16(ip) not in ref_pref]
    fuite = [ip for ip in ext if ip not in ref_full]

    def match_ref(ip):
        pp = p16(ip)
        for r in sorted(ref_ips):
            if p16(r) == pp:
                return r
        return None

    return dict(ref=ref, app=app, app_label=app_label, holdout=holdout,
                n=len(app_ips), directs=directs, escal=escal, ext=ext, blk=blk,
                fuite=fuite, ref_size=len(ref_ips), match_ref=match_ref)


def render(c: dict) -> None:
    R, A = c["ref"], c["app"]
    N, X, Y = c["n"], len(c["directs"]), len(c["escal"])
    E, B, F = len(c["ext"]), len(c["blk"]), len(c["fuite"])
    print("\n" + "═" * 70)
    print(f"  CAS : profil {R} déployé → rejeu de {c['app_label']}")
    print("═" * 70)
    print(f"  1) DÉPART (switch statique, avant la boucle) — profil = {c['ref_size']} IP de {R}")
    print(f"     • IP de {A} rejouées (N)                : {N}")
    print(f"     • Acceptées (déjà dans whitelist {R}) (X): {X}"
          + (f"   ex. {c['directs'][:2]}" if X else "   (aucune commune)"))
    print(f"     • Bloquées (table-miss, hors profil) (Y): {Y}   → pas dans la table → DROP fail-closed")

    print(f"  2) REMONTÉE (mode boucle : les {Y} bloquées → contrôleur → Redis → décision /16)")
    print(f"     • EXTEND (/16 ∈ plages de {R}) (E)      : {E}")
    for ip in c["ext"][:2]:
        r = c["match_ref"](ip)
        print(f"         ex. {ip}  (/16={p16(ip)})  ← {R} utilise {r} (même /16 {p16(ip)})")
    print(f"     • BLOCK  (/16 inconnu de {R}) (B)       : {B}")
    for ip in c["blk"][:2]:
        print(f"         ex. {ip}  (/16={p16(ip)})  ← aucune IP {R} dans {p16(ip)}.x")
    print(f"     • vérif E+B = Y : {E}+{B} = {E+B}  (Y={Y}) {'✓' if E+B==Y else '✗'}")

    print(f"  3) APRÈS REDÉPLOIEMENT (s1 mis à jour)")
    print(f"     • Nouvelles règles : +{E} ALLOW (prio 100), +{B} DROP (prio 950)")
    print(f"     • Total {A} : {X+E} IP passent ({X} directes + {E} étendues), {B} bloquées")
    if c["holdout"]:
        print(f"     • Parmi les {E} étendues : {E} sont de VRAIES IP de {R} (légitime), FUITE F = {F}")
    else:
        print(f"     • Parmi les {E} étendues : {E-F} vraies IP de {R} / FUITE F = {F} "
              f"(IP de {A} autorisées À TORT, même /16)")
        for ip in c["fuite"][:2]:
            r = c["match_ref"](ip)
            print(f"         fuite ex. {ip} ({A}) étendue car /16={p16(ip)} = celui de {r} ({R})")

    pct = (100 * F / Y) if Y else 0
    print(f"  4) POURQUOI")
    if c["holdout"]:
        print(f"     Rejeu de {R} contre lui-même : les IP étendues SONT des {R} légitimes")
        print(f"     tombant dans des /16 déjà connus → dérive correctement étendue, FUITE 0.")
    elif pct >= 30:
        print(f"     FUITE ÉLEVÉE ({F}/{Y} = {pct:.0f}%) : {R} et {A} partagent les mêmes")
        print(f"     plages cloud (AWS/Google/Akamai) → beaucoup d'IP {A} tombent dans un /16")
        print(f"     que {R} utilise aussi → étendues à tort. Limite du /16 sous infra partagée.")
    else:
        print(f"     FUITE FAIBLE ({F}/{Y} = {pct:.0f}%) : {A} est surtout sur des plages /16")
        print(f"     que {R} n'utilise pas → la grande majorité est correctement bloquée.")


def main() -> int:
    cases = [
        ("lequipe", "lequipe", True),
        ("lequipe", "faceswitch", False),
        ("faceswitch", "lequipe", False),
        ("lequipe", "skype", False),
        ("skype", "lequipe", False),
        ("lequipe", "viber", False),
        ("viber", "lequipe", False),
    ]
    recap = []
    for ref, app, ho in cases:
        c = case(ref, app, ho)
        render(c)
        recap.append((f"{ref}→{app}" + ("*" if ho else ""), c["n"], len(c["directs"]),
                      len(c["escal"]), len(c["ext"]), len(c["blk"]), len(c["fuite"])))
    print("\n" + "═" * 70)
    print("  RÉCAP  (* = hold-out, app contre elle-même)")
    print("═" * 70)
    print(f"  {'cas':<20}{'N':>5}{'acc.dép':>9}{'blq.dép':>9}{'EXTEND':>8}{'BLOCK':>7}{'FUITE':>7}")
    for r in recap:
        print(f"  {r[0]:<20}{r[1]:>5}{r[2]:>9}{r[3]:>9}{r[4]:>8}{r[5]:>7}{r[6]:>7}")
    print("\n  Échantillon = traces de tes apps → TENDANCES sur tes données, pas universel.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
