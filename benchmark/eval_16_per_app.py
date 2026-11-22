#!/usr/bin/env python3
"""
benchmark/eval_16_per_app.py — Tableau /16 PAR APP (le tableau du mémoire).
OFFLINE, déterministe (seed=42). benign = dérive hold-out (moitié des IP de l'app),
malware = 7 C2 réels (Mischief) + synthétique co-hébergé. Positif = malveillant.

C'est la SOURCE des chiffres du mémoire (ex. dropbox : bénin 8, malware 15).
À ne pas confondre avec benchmark/live_eval.py (démo sur le vrai switch).

Usage : python3 benchmark/eval_16_per_app.py
"""
from __future__ import annotations
import json
import pathlib
import statistics
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from benchmark.eval_malware import APPS, load_named, gen_malware, SEED

REAL = [(c["c2_ip"], c.get("c2_domain"))
        for c in json.loads((_ROOT / "benchmark/results/mischief_c2.json").read_text())]


def p16(ip):
    return ".".join(ip.split(".")[:2])


def main():
    data = {a: load_named(a) for a in APPS}
    data = {a: d for a, d in data.items() if d}
    apps = [a for a in APPS if a in data and len(data[a]) >= 16]

    print("ÉVALUATION /16 — PAR APP  (le tableau du mémoire)")
    print("benign = dérive hold-out · malware = 7 C2 réels + synthétique · positif = malveillant\n")
    print(f"{'app':<11}{'bénin':>6}{'malw':>6}{'TP':>4}{'FP':>4}{'TN':>4}{'FN':>4}"
          f"{'acc':>6}{'prec':>6}{'rec':>6}{'F1':>6}{'FPR':>6}{'FNR':>6}")
    A = []
    for app in apps:
        ips = sorted(data[app]); train, drift = ips[::2], ips[1::2]
        mal = REAL + gen_malware(train, len(drift), SEED)
        pset = {p16(x) for x in train}
        TN = sum(1 for ip in drift if p16(ip) in pset); FP = len(drift) - TN
        TP = sum(1 for ip, _ in mal if p16(ip) not in pset); FN = len(mal) - TP
        tot = TP + FP + TN + FN
        acc = (TP + TN) / tot
        pr = TP / (TP + FP) if TP + FP else 0
        rec = TP / (TP + FN) if TP + FN else 0
        f1 = 2 * pr * rec / (pr + rec) if pr + rec else 0
        fpr = FP / (FP + TN) if FP + TN else 0
        fnr = FN / (FN + TP) if FN + TP else 0
        A.append((acc, pr, rec, f1, fpr, fnr))
        print(f"{app:<11}{len(drift):>6}{len(mal):>6}{TP:>4}{FP:>4}{TN:>4}{FN:>4}"
              f"{acc:>6.2f}{pr:>6.2f}{rec:>6.2f}{f1:>6.2f}{fpr:>6.2f}{fnr:>6.2f}")
    m = lambda i: statistics.mean(x[i] for x in A)
    s = lambda i: statistics.stdev(x[i] for x in A)
    print(f"\n{'MOY±σ':<11}{'':>16}{m(0):.2f}±{s(0):.2f}  prec {m(1):.2f}  rec {m(2):.2f}  "
          f"F1 {m(3):.2f}  FPR {m(4):.2f}  FNR {m(5):.2f}")
    print("\nLecture : FN = malware co-hébergé (même /16 que l'app → fuite du /16).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
