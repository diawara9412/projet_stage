#!/usr/bin/env python3
"""
benchmark/make_figures.py — PART A : figures + tableaux pour la soutenance.
  1) Tableau métriques par clé (acc/prec/recall/F1/FPR/FNR, moy±écart-type) → PNG + CSV + MD
  2) Courbe ROC (balayage préfixe + clés comme points) → PNG
  3) Matrice de confusion du LIVE (TP13/FP0/TN10/FN8) → PNG
Sobre, peu de couleurs, lisible en projection. Offline déterministe.
"""
from __future__ import annotations
import ipaddress
import json
import pathlib
import statistics
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from benchmark.eval_malware import APPS, asn, regdom, load_named, gen_malware, SEED

FIG = _ROOT / "benchmark" / "figures"
FIG.mkdir(parents=True, exist_ok=True)
REAL = [(c["c2_ip"], c.get("c2_domain"))
        for c in json.loads((_ROOT / "benchmark/results/mischief_c2.json").read_text())]
plt.rcParams.update({"font.size": 12, "axes.grid": True, "grid.alpha": 0.3})


def pmask(ip, b):
    return int(ipaddress.ip_address(ip)) & ((0xFFFFFFFF << (32 - b)) & 0xFFFFFFFF)


def cm_for(keyfn, profset, data, apps):
    """matrice par app → listes de métriques."""
    rows = []
    for app in apps:
        ips = sorted(data[app]); names = data[app]
        train, drift = ips[::2], ips[1::2]
        mal = REAL + gen_malware(train, len(drift), SEED)
        ps = profset(train, names)
        TN = sum(1 for ip in drift if keyfn(ip, names.get(ip)) in ps)
        FP = len(drift) - TN
        TP = sum(1 for ip, dom in mal if keyfn(ip, dom) not in ps)
        FN = len(mal) - TP
        acc = (TP + TN) / (TP + TN + FP + FN)
        prec = TP / (TP + FP) if TP + FP else 0
        rec = TP / (TP + FN) if TP + FN else 0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
        fpr = FP / (FP + TN) if FP + TN else 0
        fnr = FN / (FN + TP) if FN + TP else 0
        rows.append((acc, prec, rec, f1, fpr, fnr))
    return rows


def msd(xs):
    return statistics.mean(xs), (statistics.stdev(xs) if len(xs) > 1 else 0.0)


KEYS = {
    "IP exacte": (lambda ip, nm: ip,            lambda tr, nm: set(tr)),
    "/24":       (lambda ip, nm: pmask(ip, 24), lambda tr, nm: {pmask(x, 24) for x in tr}),
    "/16":       (lambda ip, nm: pmask(ip, 16), lambda tr, nm: {pmask(x, 16) for x in tr}),
    "ASN":       (lambda ip, nm: asn(ip),       lambda tr, nm: {asn(x) for x in tr} - {None}),
    "domaine/SNI": (lambda ip, nm: regdom(nm),  lambda tr, nm: {regdom(nm[x]) for x in tr} - {None}),
}
COLS = ["accuracy", "precision", "recall", "F1", "FPR", "FNR"]


def main():
    data = {a: load_named(a) for a in APPS}
    data = {a: d for a, d in data.items() if d}
    apps = [a for a in APPS if a in data and len(data[a]) >= 16]

    # ── 1. Tableau métriques ────────────────────────────────────────────────
    table = {}
    for k, (kf, pf) in KEYS.items():
        rows = cm_for(kf, pf, data, apps)
        table[k] = [msd([r[i] for r in rows]) for i in range(6)]

    # CSV + MD
    csv = ["cle," + ",".join(f"{c}_moy,{c}_std" for c in COLS)]
    md = ["| clé | " + " | ".join(COLS) + " |", "|" + "---|" * (len(COLS) + 1)]
    for k, vals in table.items():
        csv.append(k + "," + ",".join(f"{m:.3f},{s:.3f}" for m, s in vals))
        md.append("| " + k + " | " + " | ".join(f"{m:.2f}±{s:.2f}" for m, s in vals) + " |")
    (FIG / "metrics_table.csv").write_text("\n".join(csv))
    (FIG / "metrics_table.md").write_text("\n".join(md))

    # PNG tableau
    fig, ax = plt.subplots(figsize=(11, 2.6)); ax.axis("off")
    cell = [[f"{m:.2f}±{s:.2f}" for m, s in vals] for vals in table.values()]
    t = ax.table(cellText=cell, rowLabels=list(table.keys()), colLabels=COLS,
                 cellLoc="center", rowLoc="center", loc="center")
    t.auto_set_font_size(False); t.set_fontsize(12); t.scale(1, 1.7)
    for (r, c), cellobj in t.get_celld().items():
        if r == 0 or c == -1:
            cellobj.set_text_props(weight="bold"); cellobj.set_facecolor("#e8e8e8")
    # (titre retiré — à mettre dans le rapport/slide)
    fig.tight_layout(); fig.savefig(FIG / "metrics_table.png", dpi=300, bbox_inches="tight")
    plt.close(fig)

    # ── 2. Courbe ROC (balayage préfixe + clés comme points) ────────────────
    fig, ax = plt.subplots(figsize=(7, 6))
    xs, ys = [], []
    for b in [8, 12, 16, 20, 24, 28, 32]:
        kf = (lambda bb: (lambda ip, nm: pmask(ip, bb)))(b)
        pf = (lambda bb: (lambda tr, nm: {pmask(x, bb) for x in tr}))(b)
        rows = cm_for(kf, pf, data, apps)
        ys.append(statistics.mean([r[2] for r in rows]))  # recall = TPR
        xs.append(statistics.mean([r[4] for r in rows]))  # FPR
    ax.plot(xs, ys, "-o", color="#333", label="balayage préfixe /8→/32")
    for b, x, y in zip([8, 12, 16, 20, 24, 28, 32], xs, ys):
        ax.annotate(f"/{b}", (x, y), textcoords="offset points", xytext=(6, -4), fontsize=10)
    # clés non-préfixe (ASN, domaine) comme points
    for k, mark, col in [("ASN", "s", "#c00"), ("domaine/SNI", "^", "#06c")]:
        kf, pf = KEYS[k]; rows = cm_for(kf, pf, data, apps)
        ax.scatter(statistics.mean([r[4] for r in rows]), statistics.mean([r[2] for r in rows]),
                   marker=mark, s=120, color=col, zorder=5, label=k)
    ax.plot([0, 1], [0, 1], "--", color="#aaa", label="aléatoire")
    ax.set_xlabel("FPR (bénin bloqué à tort)"); ax.set_ylabel("TPR / recall (malware détecté)")
    # (titre retiré — à mettre dans le rapport/slide)
    ax.set_xlim(-0.02, 1.02); ax.set_ylim(-0.02, 1.02); ax.legend(loc="lower right", fontsize=10)
    fig.tight_layout(); fig.savefig(FIG / "roc_curve.png", dpi=300, bbox_inches="tight"); plt.close(fig)

    # ── 3. Matrice de confusion du LIVE ─────────────────────────────────────
    TP, FP, FN, TN = 13, 0, 8, 10
    fig, ax = plt.subplots(figsize=(6.2, 5.4))
    M = [[TP, FN], [FP, TN]]
    ax.imshow(M, cmap="Blues", alpha=0.55)
    labels = [["TP = 13", "FN = 8"], ["FP = 0", "TN = 10"]]
    for i in range(2):
        for j in range(2):
            ax.text(j, i, labels[i][j], ha="center", va="center", fontsize=18, fontweight="bold")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["prédit BLOCK", "prédit ALLOW"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["réel MALVEILLANT", "réel BÉNIN"])
    # (titre et légende sous l'image retirés — à mettre dans le rapport/slide)
    fig.tight_layout(); fig.savefig(FIG / "confusion_live.png", dpi=300, bbox_inches="tight")
    plt.close(fig)

    print("✅ Figures générées dans", FIG)
    for f in sorted(FIG.glob("*")):
        print("   -", f.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
