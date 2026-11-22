#!/usr/bin/env python3
"""
benchmark/measure_deviation_matrix.py — MATRICE DE CONFUSION PAR DÉVIATION.

Remplace l'ancienne matrice (trafic malveillant synthétique, blocage attendu par
construction) par une matrice fondée sur du TRAFIC RÉEL : chaque application est
confrontée à la chaîne de chaque autre (toutes contre toutes).

Principe (au niveau des flux (ip, port, proto), source unique = traces d'enrich) :
  • chaîne de A déployée = liste blanche des triplets réellement contactés par A ;
  • on rejoue les flux de B ; un flux passe s'il est dans la liste blanche de A.
  Vérité de terrain :
    - B == A  → flux LÉGITIME (doit passer)  : passe=TN, bloqué=FP (fausse alarme)
    - B != A  → flux ÉTRANGER (doit être bloqué) : bloqué=TP, passe=FN (fuite)
  Une FN n'est pas un « raté » du pare-feu : c'est un serveur PARTAGÉ par A et B
  (même (ip,port)) → c'est la mesure de l'INTERSECTION entre applications, et la
  limite structurelle de la granularité (adresse, port).

Sortie : benchmark/figures/deviation_matrix.{json,png} + deviation_overlap.png
Usage :  python3 benchmark/measure_deviation_matrix.py   (hors-ligne, pas de réseau)
"""
from __future__ import annotations
import json, pathlib, sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from benchmark.traffic_test import behavior_profile   # même source que la chaîne

APPS = ["disneyland", "dropbox", "faceswitch", "lequipe", "pokemongo", "ratp", "viber"]
OUT = pathlib.Path(__file__).resolve().parent / "figures" / "deviation_matrix.json"


def main():
    wl = {}
    for a in APPS:
        try:
            wl[a] = set(behavior_profile(a).triplets)
        except Exception as e:
            print(f"  (ignore {a}: {e})")
    apps = [a for a in APPS if a in wl and wl[a]]
    n = len(apps)
    print(f"{n} applications : {', '.join(apps)}\n")

    # matrice de recouvrement : part des flux de B qui passent la chaîne de A
    overlap = [[0.0] * n for _ in range(n)]
    TN = FP = TP = FN = 0
    pairs = []
    for i, A in enumerate(apps):
        for j, B in enumerate(apps):
            fB = wl[B]
            passed = sum(1 for t in fB if t in wl[A])
            blocked = len(fB) - passed
            overlap[i][j] = passed / len(fB) if fB else 0.0
            if A == B:
                TN += passed; FP += blocked           # légitime : devrait passer
            else:
                TP += blocked; FN += passed           # étranger : devrait être bloqué
                pairs.append({"chain": A, "replay": B, "n": len(fB),
                              "passed": passed, "blocked": blocked,
                              "block_rate": round(blocked / len(fB), 4) if fB else 0})

    acc = (TP + TN) / (TP + TN + FP + FN)
    prec = TP / (TP + FP) if (TP + FP) else float("nan")
    rec = TP / (TP + FN) if (TP + FN) else float("nan")
    spec = TN / (TN + FP) if (TN + FP) else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else float("nan")
    fpr = FP / (FP + TN) if (FP + TN) else float("nan")
    fnr = FN / (FN + TP) if (FN + TP) else float("nan")
    M = {"TN": TN, "FP": FP, "TP": TP, "FN": FN, "accuracy": acc, "precision": prec,
         "recall": rec, "specificity": spec, "f1": f1, "fpr": fpr, "fnr": fnr}

    print("=== MATRICE DE CONFUSION (par déviation, flux réels) ===")
    print(f"  Légitime  (diagonale) : {TN} passent (TN) · {FP} bloqués à tort (FP)")
    print(f"  Étranger  (hors diag) : {TP} bloqués (TP) · {FN} passent = fuite (FN)")
    print(f"  accuracy={acc*100:.1f}%  precision={prec*100:.1f}%  recall={rec*100:.1f}%  "
          f"specificity={spec*100:.1f}%  F1={f1*100:.1f}%  FPR={fpr*100:.1f}%  FNR={fnr*100:.1f}%")
    print("\n  Fuites (recouvrement d'infrastructure) :")
    for p in sorted(pairs, key=lambda x: -x["passed"]):
        if p["passed"]:
            print(f"    chaîne {p['chain']:<11} · trafic {p['replay']:<11} "
                  f"→ {p['passed']}/{p['n']} flux partagés ({(1-p['block_rate'])*100:.1f}%)")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"apps": apps, "overlap": overlap, "metrics": M,
                               "pairs": pairs}, indent=2, ensure_ascii=False))
    print(f"\n✔ {OUT}")

    # ── figures ──
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        # 1) heatmap de recouvrement
        arr = np.array(overlap) * 100
        fig, ax = plt.subplots(figsize=(7.2, 6))
        im = ax.imshow(arr, cmap="magma_r", vmin=0, vmax=100)
        ax.set_xticks(range(n)); ax.set_yticks(range(n))
        ax.set_xticklabels(apps, rotation=45, ha="right"); ax.set_yticklabels(apps)
        ax.set_xlabel("trafic rejoué (application B)")
        ax.set_ylabel("chaîne déployée (application A)")
        ax.set_title("Recouvrement : % des flux de B qui passent la chaîne de A")
        for i in range(n):
            for j in range(n):
                v = arr[i][j]
                ax.text(j, i, f"{v:.0f}", ha="center", va="center",
                        color="white" if v > 50 else "black", fontsize=8)
        fig.colorbar(im, label="% de flux qui passent")
        fig.tight_layout(); fig.savefig(OUT.with_name("deviation_overlap.png"), dpi=130)
        print(f"✔ {OUT.with_name('deviation_overlap.png')}")

        # 2) matrice de confusion 2×2
        fig2, ax2 = plt.subplots(figsize=(6.4, 5.4))
        cm = np.array([[TN, FP], [FN, TP]])
        ax2.imshow([[1, 0], [0, 1]], cmap="RdYlGn", vmin=0, vmax=1, alpha=.35)
        labels = [[f"TN = {TN}\n(légitime laissé passer)", f"FP = {FP}\n(légitime bloqué)"],
                  [f"FN = {FN}\n(étranger passé = fuite)", f"TP = {TP}\n(étranger bloqué)"]]
        for i in range(2):
            for j in range(2):
                ax2.text(j, i, labels[i][j], ha="center", va="center", fontsize=12, fontweight="bold")
        ax2.set_xticks([0, 1]); ax2.set_xticklabels(["laissé passer", "bloqué"])
        ax2.set_yticks([0, 1]); ax2.set_yticklabels(["réel\nLÉGITIME", "réel\nÉTRANGER"])
        ax2.set_title("Matrice de confusion par déviation (flux réels)")
        fig2.text(0.5, 0.02,
                  f"accuracy {acc*100:.1f}%  ·  precision {prec*100:.1f}%  ·  recall {rec*100:.1f}%  "
                  f"·  F1 {f1*100:.1f}%  ·  FPR {fpr*100:.1f}%  ·  FNR {fnr*100:.1f}%",
                  ha="center", fontsize=9)
        fig2.tight_layout(rect=[0, 0.05, 1, 1])
        fig2.savefig(OUT.with_suffix(".png"), dpi=130)
        print(f"✔ {OUT.with_suffix('.png')}")
    except Exception as e:
        print(f"(figure : {e})")


if __name__ == "__main__":
    main()
