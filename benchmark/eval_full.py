#!/usr/bin/env python3
"""
benchmark/eval_full.py — Évaluation FINALE avec métriques (benign + malware RÉEL + synthétique).

Classes :
  • BÉNIN              = dérive légitime des apps (hold-out)           → ALLOW attendu
  • MALWARE RÉEL       = C2 du Android Mischief Dataset (mischief_c2.json) → BLOCK attendu
                         (RAT Android réels : AndroRAT, AhMyth, SpyMAX… C2 dédié)
  • MALWARE SYNTHÉTIQUE = C2/exfil co-hébergés sur le cloud des apps     → BLOCK attendu
                         (le cas DUR : domain-fronting / abus de cloud partagé)

Pour chaque clé (IP / /24 / /16 / ASN / domaine) : matrice de confusion + accuracy/
precision/recall/F1/FPR/FNR, AVEC recall détaillé par classe (réel vs synthétique).
Positif = malveillant. Déterministe, offline, sans LLM. (synthétique seedé, reproductible)
"""
from __future__ import annotations
import json
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmark.eval_malware import (APPS, KEYS, asn, regdom, pref, key_of,
                                    profile_set, load_named, gen_malware, SEED)

C2_JSON = _ROOT / "benchmark" / "results" / "mischief_c2.json"


def load_real_c2():
    if not C2_JSON.exists():
        return []
    return [(c["c2_ip"], c.get("c2_domain")) for c in json.loads(C2_JSON.read_text())]


def metrics(TP, FP, TN, FN):
    tot = TP + FP + TN + FN or 1
    acc = (TP + TN) / tot
    prec = TP / (TP + FP) if TP + FP else 0
    rec = TP / (TP + FN) if TP + FN else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    fpr = FP / (FP + TN) if FP + TN else 0
    fnr = FN / (FN + TP) if FN + TP else 0
    return acc, prec, rec, f1, fpr, fnr


def main():
    data = {a: load_named(a) for a in APPS}
    data = {a: d for a, d in data.items() if d}
    apps = [a for a in APPS if a in data and len(data[a]) >= 16]
    real = load_real_c2()
    print("=" * 90)
    print("  ÉVALUATION FINALE — benign + malware RÉEL (Mischief) + synthétique co-hébergé")
    print(f"  apps={len(apps)}  C2 réels={len(real)}  (positif = malveillant)")
    print("=" * 90)

    agg = {k: dict(TP=0, FP=0, TN=0, FN=0, tp_real=0, n_real=0, tp_syn=0, n_syn=0) for k in KEYS}
    for app in apps:
        ips = sorted(data[app]); names = data[app]
        train, drift = ips[::2], ips[1::2]
        synth = gen_malware(train, len(drift), SEED)        # malware synthétique co-hébergé
        for k in KEYS:
            ps = profile_set(k, train, names)
            for ip in drift:                                 # bénin
                agg[k]["TN" if key_of(k, ip, names.get(ip)) in ps else "FP"] += 1
            for ip, dom in real:                             # malware RÉEL
                allow = key_of(k, ip, dom) in ps
                agg[k]["FN" if allow else "TP"] += 1
                agg[k]["n_real"] += 1; agg[k]["tp_real"] += (0 if allow else 1)
            for ip, dom in synth:                            # malware SYNTHÉTIQUE
                allow = key_of(k, ip, dom) in ps
                agg[k]["FN" if allow else "TP"] += 1
                agg[k]["n_syn"] += 1; agg[k]["tp_syn"] += (0 if allow else 1)

    print(f"  {'clé':<9}{'Acc':>6}{'Prec':>6}{'Rec':>6}{'F1':>6}{'FPR':>6}{'FNR':>6}"
          f"{'  détection réel':>16}{'  détection synth':>18}")
    for k in KEYS:
        c = agg[k]
        acc, prec, rec, f1, fpr, fnr = metrics(c["TP"], c["FP"], c["TN"], c["FN"])
        dr = 100 * c["tp_real"] / c["n_real"] if c["n_real"] else 0
        dsn = 100 * c["tp_syn"] / c["n_syn"] if c["n_syn"] else 0
        print(f"  {k:<9}{acc:>6.2f}{prec:>6.2f}{rec:>6.2f}{f1:>6.2f}{fpr:>6.2f}{fnr:>6.2f}"
              f"{dr:>14.0f}%{dsn:>16.0f}%")
    print("=" * 90)
    print("  détection réel  = % de C2 RÉELS (Mischief) bloqués  | détection synth = % co-hébergés bloqués")
    print("  Attendu : tous bloquent le C2 RÉEL dédié (autre plage) ; seul domaine/SNI bloque le co-hébergé.")
    print("\n  ⚠️ HONNÊTETÉ : C2 réels = lab Stratosphere (plage dédiée → cas facile, réaliste) ;")
    print("     co-hébergé = synthétique (cas dur). Échantillon modeste → tendances. SNI réel = étape suivante.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
