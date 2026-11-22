#!/usr/bin/env python3
"""
benchmark/loop_matrix.py — Matrice complète de la boucle d'auto-extension /16.

Décision /16 DÉTERMINISTE → on calcule EXACTEMENT et OFFLINE, pour chaque couple
(référence R, rejeu O), ce que la boucle déciderait sur le switch :
  • escaladés  = IP de O inconnues du profil R (tombent sur table-miss),
  • EXTEND     = escaladés dont le /16 ∈ préfixes de R  (→ ALLOW prio 100 posée),
  • BLOCK      = escaladés dont le /16 ∉ R              (→ DROP prio 950 posée),
  • FUITE/FP   = parmi les EXTEND, ceux qui ne sont PAS de vraies IP de R
                (autorisés à tort car même /16) — LE chiffre qui montre la limite /16.

Diagonale (R rejoue R) = hold-out (réf = moitié des IP, rejeu = autre moitié) :
  EXTEND y = extension LÉGITIME (rappel), fuite = 0 par construction.

Le switch étant déterministe (match exact), ce calcul = ce que poserait s1 (validé en
live par benchmark/loop_experiment.py). Pas de LLM, pas de réseau, pas de quota.

Usage : python3 benchmark/loop_matrix.py
"""
from __future__ import annotations
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from whitelist.profile_builder import build_profile

APPS = ["dropbox", "faceswitch", "lequipe", "meteo", "ninegag",
        "pokemongo", "skype", "viber"]


def p16(ip: str) -> str:
    return ".".join(ip.split(".")[:2])


def load_ips() -> dict[str, list[str]]:
    out = {}
    for a in APPS:
        try:
            out[a] = sorted(build_profile(a).ips)
        except Exception as e:
            print(f"  {a}: {e}")
    return out


def decide(ref_ips: set[str], ref_pref: set[str], replay_ips: list[str]) -> dict:
    """Boucle /16 sur les IP de `replay_ips` face au profil (ref_ips, ref_pref)."""
    escal = [ip for ip in replay_ips if ip not in ref_ips]   # inconnus → table-miss
    ext = [ip for ip in escal if p16(ip) in ref_pref]        # /16 connu → EXTEND
    blk = [ip for ip in escal if p16(ip) not in ref_pref]    # /16 inconnu → BLOCK
    return {"escal": escal, "ext": ext, "blk": blk,
            "direct": [ip for ip in replay_ips if ip in ref_ips]}


def main() -> int:
    ips = load_ips()
    apps = [a for a in APPS if a in ips]

    rows = []  # (ref, replay, n_replay, direct, escal, ext, blk, leak, ext_pct, leak_pct)
    for R in apps:
        Rips = ips[R]
        for O in apps:
            if R == O:
                # hold-out : réf = pairs, rejeu = impairs (dérive légitime)
                ref = set(Rips[::2]); refp = {p16(x) for x in ref}
                rep = Rips[1::2]
                d = decide(ref, refp, rep)
                leak = 0  # EXTEND ici = vraies IP de R → légitime, pas de fuite
            else:
                ref = set(Rips); refp = {p16(x) for x in ref}
                d = decide(ref, refp, ips[O])
                # fuite = EXTEND qui ne sont pas de vraies IP de R (ici tous, car O≠R)
                leak = sum(1 for ip in d["ext"] if ip not in Rips)
            n = len(d["escal"]) or 1
            rows.append((R, O, len(ips[O]), len(d["direct"]), len(d["escal"]),
                         len(d["ext"]), len(d["blk"]), leak,
                         100 * len(d["ext"]) / n, 100 * leak / n))

    # ── Matrice EXTEND% (diag = rappel ; hors-diag = fuite) ──────────────────
    print("=" * 78)
    print("  MATRICE EXTEND %  (ligne = profil référence, colonne = app rejouée)")
    print("  diagonale = RAPPEL (dérive légitime) ; hors-diagonale = FUITE (faux positif)")
    print("=" * 78)
    hdr = "  ref\\rejeu " + "".join(f"{a[:6]:>8}" for a in apps)
    print(hdr)
    cell = {(r[0], r[1]): r[8] for r in rows}
    for R in apps:
        line = f"  {R[:9]:<10}"
        for O in apps:
            v = cell[(R, O)]
            mark = "*" if R == O else " "
            line += f"{v:>6.0f}%{mark}"
        print(line)
    print("  (*) diagonale = rappel hold-out. Hors-diag = % d'IP étrangères étendues À TORT.")

    # ── Détail par couple : EXTEND/BLOCK/fuite ──────────────────────────────
    print("\n" + "=" * 78)
    print("  DÉTAIL PAR COUPLE  (escaladés → EXTEND/BLOCK ; fuite = faux positifs)")
    print("  + flows posés sur s1 : ALLOW ajoutées = EXTEND, DROP ajoutées = BLOCK")
    print("=" * 78)
    print(f"  {'réf':<10}{'rejeu':<10}{'#IP':>5}{'directs':>8}{'escal':>7}"
          f"{'EXT':>5}{'BLK':>5}{'FUITE':>7}{'fuite%':>8}")
    for r in rows:
        R, O, nO, direct, escal, ext, blk, leak, extp, leakp = r
        tag = " (hold-out)" if R == O else ""
        print(f"  {R:<10}{O:<10}{nO:>5}{direct:>8}{escal:>7}{ext:>5}{blk:>5}"
              f"{leak:>7}{leakp:>7.0f}%{tag}")

    # ── Synthèse fuite ──────────────────────────────────────────────────────
    off = [r for r in rows if r[0] != r[1]]
    diag = [r for r in rows if r[0] == r[1]]
    mean_leak = sum(r[9] for r in off) / len(off)
    mean_recall = sum(r[8] for r in diag) / len(diag)
    print("\n" + "=" * 78)
    print("  SYNTHÈSE")
    print("=" * 78)
    print(f"  Rappel moyen (diagonale, dérive légitime étendue) : {mean_recall:.0f}%")
    print(f"  FUITE moyenne (hors-diagonale, étranger étendu à tort) : {mean_leak:.0f}%")
    print(f"  couples hors-diagonale : {len(off)}  |  profils : {len(apps)}")

    print("\n" + "=" * 78)
    print("  ⚠️  HONNÊTETÉ : échantillon = %d apps → TENDANCES sur CES données," % len(apps))
    print("     pas des lois universelles. Décision /16 = déterministe (résultats stables).")
    print("     EXTEND/BLOCK/fuite = exacts (offline) ; délai+convergence = mesurés en live")
    print("     (benchmark/loop_experiment.py) car ce sont des métriques de timing système.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
