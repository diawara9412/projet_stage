#!/usr/bin/env python3
"""Image : deux matrices de confusion (bout en bout) — IP vs port. Colorées."""
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

# (label, TN, FP, FN, TP, acc, prec, rec, FPR, FNR)
DATA = [
    ("Clé = IP  (liste blanche par adresse)",  222, 30,   0, 477, 95.9, 94.1, 100.0, 11.9,  0.0),
    ("Clé = port  (liste blanche par service)", 249,  3, 474,   3, 34.6, 50.0,   0.6,  1.2, 99.4),
]
GREEN, RED = "#2e7d46", "#c0392b"


def cell_color(kind, n, rowtot):
    frac = 0.18 + 0.72 * (n / rowtot if rowtot else 0)
    base = GREEN if kind == "ok" else RED
    r, g, b = tuple(int(base[i:i+2], 16) / 255 for i in (1, 3, 5))
    # éclaircir vers le blanc selon (1-frac)
    return (r + (1-r)*(1-frac), g + (1-g)*(1-frac), b + (1-b)*(1-frac))


fig, axes = plt.subplots(1, 2, figsize=(13.5, 5.6))
for ax, (lbl, TN, FP, FN, TP, acc, prec, rec, fpr, fnr) in zip(axes, DATA):
    rn, rd = TN + FP, FN + TP                     # totaux de ligne
    # cellules : [ [TN(ok), FP(err)], [FN(err), TP(ok)] ]
    cells = [[("ok", TN, "TN", rn), ("err", FP, "FP", rn)],
             [("err", FN, "FN", rd), ("ok", TP, "TP", rd)]]
    for i in range(2):
        for j in range(2):
            kind, n, name, rt = cells[i][j]
            ax.add_patch(Rectangle((j, 1-i), 1, 1, facecolor=cell_color(kind, n, rt),
                                    edgecolor="white", linewidth=3))
            ax.text(j+0.5, 1-i+0.60, f"{name} = {n}", ha="center", va="center",
                    fontsize=17, fontweight="bold", color="#12242a")
            ax.text(j+0.5, 1-i+0.34, f"{100*n/rt:.0f}%" if rt else "—", ha="center",
                    va="center", fontsize=12, color="#33474d")
    ax.set_xlim(0, 2); ax.set_ylim(0, 2); ax.set_aspect("equal")
    ax.set_xticks([0.5, 1.5]); ax.set_xticklabels(["laissé passer", "bloqué"], fontsize=12)
    ax.set_yticks([1.5, 0.5]); ax.set_yticklabels(["réel\nNORMAL", "réel\nDÉVIATION"], fontsize=12)
    ax.xaxis.tick_top(); ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.text(1, -0.28, lbl, ha="center", fontsize=13, fontweight="bold", color="#12242a")
    ax.text(1, -0.62,
            f"exactitude {acc}%   précision {prec}%   rappel {rec}%",
            ha="center", fontsize=11.5, color="#333")
    ax.text(1, -0.90,
            f"FPR {fpr}% (fausses alertes)   ·   FNR {fnr}% (déviations ratées)",
            ha="center", fontsize=11.5, color="#333")

plt.tight_layout(pad=1.2)
plt.subplots_adjust(bottom=0.20, wspace=0.35)
fig.savefig("/home/kali/Desktop/confusion_bout_en_bout.png", dpi=300,
            bbox_inches="tight", facecolor="white")
print("ok confusion_bout_en_bout.png")
