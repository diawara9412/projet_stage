#!/usr/bin/env python3
"""
benchmark/eval_metrics_full.py — P3 : métriques rigoureuses.
  • moyenne ± écart-type par clé (IP/24/16/ASN/domaine) sur les 8 app-profils
  • courbe ROC : balayage de la finesse du préfixe (/32→/8) → (FPR, TPR)
benign = dérive hold-out ; malware = C2 réels (Mischief) + synthétique co-hébergé.
Positif = malveillant. Offline déterministe, sans LLM, sans quota.
"""
from __future__ import annotations
import ipaddress
import json
import pathlib
import statistics
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from benchmark.eval_malware import APPS, asn, regdom, load_named, gen_malware, SEED

REAL = [(c["c2_ip"], c.get("c2_domain"))
        for c in json.loads((_ROOT / "benchmark/results/mischief_c2.json").read_text())]


def pmask(ip, bits):
    return int(ipaddress.ip_address(ip)) & ((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF)


def per_app_scores(keyfn, profset_fn, data, apps):
    out = []
    for app in apps:
        ips = sorted(data[app]); names = data[app]
        train, drift = ips[::2], ips[1::2]
        mal = REAL + gen_malware(train, len(drift), SEED)
        ps = profset_fn(train, names)
        TN = sum(1 for ip in drift if keyfn(ip, names.get(ip)) in ps)
        FP = len(drift) - TN
        TP = sum(1 for ip, dom in mal if keyfn(ip, dom) not in ps)
        FN = len(mal) - TP
        rec = TP / (TP + FN) if TP + FN else 0
        fpr = FP / (FP + TN) if FP + TN else 0
        acc = (TP + TN) / (TP + TN + FP + FN)
        out.append((rec, fpr, acc))
    return out


def ms(vals):
    return statistics.mean(vals), (statistics.stdev(vals) if len(vals) > 1 else 0.0)


def main():
    data = {a: load_named(a) for a in APPS}
    data = {a: d for a, d in data.items() if d}
    apps = [a for a in APPS if a in data and len(data[a]) >= 16]

    # clés
    keys = {
        "IP":      (lambda ip, nm: ip,            lambda tr, nm: set(tr)),
        "/24":     (lambda ip, nm: pmask(ip, 24), lambda tr, nm: {pmask(x, 24) for x in tr}),
        "/16":     (lambda ip, nm: pmask(ip, 16), lambda tr, nm: {pmask(x, 16) for x in tr}),
        "ASN":     (lambda ip, nm: asn(ip),       lambda tr, nm: {asn(x) for x in tr} - {None}),
        "domaine": (lambda ip, nm: regdom(nm),    lambda tr, nm: {regdom(nm[x]) for x in tr} - {None}),
    }

    print("=" * 74)
    print(f"  P3 — MÉTRIQUES moyenne ± écart-type sur {len(apps)} profils")
    print("  (recall = détection malware ↑ · FPR = bénin bloqué à tort ↓)")
    print("=" * 74)
    print(f"  {'clé':<9}{'Recall':>16}{'FPR':>16}{'Accuracy':>16}")
    for k, (kf, pf) in keys.items():
        sc = per_app_scores(kf, pf, data, apps)
        rm, rs = ms([s[0] for s in sc]); fm, fs = ms([s[1] for s in sc]); am, as_ = ms([s[2] for s in sc])
        print(f"  {k:<9}{rm:>7.2f} ± {rs:<5.2f}{fm:>7.2f} ± {fs:<5.2f}{am:>7.2f} ± {as_:<5.2f}")

    print("\n" + "=" * 74)
    print("  COURBE ROC — balayage de la finesse du préfixe (point = moyenne sur profils)")
    print("=" * 74)
    print(f"  {'préfixe':<10}{'FPR (x)':>10}{'TPR/recall (y)':>16}")
    for bits in [8, 12, 16, 20, 24, 28, 32]:
        kf = (lambda b: (lambda ip, nm: pmask(ip, b)))(bits)
        pf = (lambda b: (lambda tr, nm: {pmask(x, b) for x in tr}))(bits)
        sc = per_app_scores(kf, pf, data, apps)
        tpr = statistics.mean([s[0] for s in sc]); fpr = statistics.mean([s[1] for s in sc])
        bar = "#" * int(tpr * 30)
        print(f"  /{bits:<8}{fpr:>10.2f}{tpr:>12.2f}   {bar}")
    print("  (de /8 coarse → /32 fine : TPR et FPR montent ensemble = compromis classique)")

    print("\n  ⚠️ Échantillon = {} apps + {} C2 réels → tendances, pas lois universelles."
          .format(len(apps), len(REAL)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
