#!/usr/bin/env python3
"""Figures de l'évaluation C — style publication (article / rapport de stage), FR + EN.

- Matrice de confusion : heatmap 2×2 à la scikit-learn (imshow + colorbar),
  axes « Prédiction » / « Réel », comptes + pourcentages dans les cases.
- Répartition des attaques bloquées : barres horizontales sobres, dépouillées.

Réf. style : scikit-learn ConfusionMatrixDisplay ; matplotlib for papers (Mouret).
Les comptes sont des constantes en tête de fichier — faciles à ajuster.
"""
import pathlib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = pathlib.Path("/home/kali/Desktop/tables"); OUT.mkdir(exist_ok=True)

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.edgecolor": "#40505f", "axes.linewidth": 0.9,
    "xtick.color": "#40505f", "ytick.color": "#40505f",
    "text.color": "#233240", "axes.labelcolor": "#233240",
})

# ═══════════════ COMPTES MESURÉS (chaîne de viber déployée) ═══════════════
TN, FP = 29, 0     # trafic légitime : laissé passer / bloqué à tort
FN, TP = 0, 80     # trafic malveillant : laissé passer / bloqué (15+30+25+10)

# libellés bilingues
T = {
 "fr": dict(
    mfile="matrice_malveillance.png", bfile="graphe_attaques_bloquees.png",
    title="Matrice de confusion — chaîne de viber",
    xlab="Décision de la chaîne déployée", ylab="Nature réelle du trafic",
    xt=["Laissé passer", "Bloqué"], yt=["Légitime", "Malveillant"],
    corner=[["Vrais négatifs", "Faux positifs"], ["Faux négatifs", "Vrais positifs"]],
    cbar="Nombre de flux",
    metrics=lambda a, p, r, s, f, fpr, fnr:
        f"Exactitude {a:.0%}  ·  Précision {p:.0%}  ·  Rappel {r:.0%}  ·  "
        f"Spécificité {s:.0%}  ·  F1 {f:.0%}   |   FPR {fpr:.0%}  ·  FNR {fnr:.0%}",
    btitle="Trafic malveillant contre la chaîne de viber — blocage par famille d'attaque",
    bxlab="Nombre de flux malveillants (tous rejetés par la fermeture par défaut)",
    fam=[("Exfiltration de données", 15), ("Balise C2 (beaconing)", 30),
         ("Balayage de ports", 25), ("Port inconnu (IRC)", 10)],
    blk="{c} flux · 100 % bloqués"),
 "en": dict(
    mfile="matrice_malveillance_en.png", bfile="graphe_attaques_bloquees_en.png",
    title="Confusion matrix — viber chain",
    xlab="Decision of the deployed chain", ylab="True nature of the traffic",
    xt=["Allowed", "Blocked"], yt=["Legitimate", "Malicious"],
    corner=[["True negatives", "False positives"], ["False negatives", "True positives"]],
    cbar="Number of flows",
    metrics=lambda a, p, r, s, f, fpr, fnr:
        f"Accuracy {a:.0%}  ·  Precision {p:.0%}  ·  Recall {r:.0%}  ·  "
        f"Specificity {s:.0%}  ·  F1 {f:.0%}   |   FPR {fpr:.0%}  ·  FNR {fnr:.0%}",
    btitle="Malicious traffic against the viber chain — blocking by attack family",
    bxlab="Number of malicious flows (all rejected by default-deny)",
    fam=[("Data exfiltration", 15), ("C2 beacon (beaconing)", 30),
         ("Port scan", 25), ("Unknown port (IRC)", 10)],
    blk="{c} flows · 100% blocked"),
}


def confusion_matrix(lang):
    t = T[lang]
    cm = np.array([[TN, FP], [FN, TP]]); total = cm.sum()
    fig, ax = plt.subplots(figsize=(5.6, 5.0))
    im = ax.imshow(cm, cmap="Blues", vmin=0, vmax=cm.max())
    thresh = cm.max() * 0.55
    for i in range(2):
        for j in range(2):
            c = cm[i, j]
            col = "white" if c > thresh else "#1b2a3a"
            ax.text(j, i - 0.16, f"{c}", ha="center", va="center",
                    fontsize=26, fontweight="bold", color=col)
            ax.text(j, i + 0.14, f"{100*c/total:.1f} %", ha="center", va="center",
                    fontsize=11, color=col)
            ax.text(j, i + 0.34, t["corner"][i][j], ha="center", va="center",
                    fontsize=8.5, style="italic",
                    color=(col if c > thresh else "#5b6b7a"))
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(t["xt"], fontsize=10.5)
    ax.set_yticklabels(t["yt"], fontsize=10.5, rotation=90, va="center")
    ax.set_xlabel(t["xlab"], fontsize=11, labelpad=8)
    ax.set_ylabel(t["ylab"], fontsize=11, labelpad=8)
    ax.set_title(t["title"], fontsize=12.5, fontweight="bold", pad=12)
    ax.set_xticks([0.5], minor=True); ax.set_yticks([0.5], minor=True)
    ax.grid(which="minor", color="white", linewidth=2.5)
    ax.tick_params(which="both", length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    cb = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cb.outline.set_edgecolor("#c9d2dc"); cb.ax.tick_params(length=0, labelsize=8)
    cb.set_label(t["cbar"], fontsize=9)
    acc = (TP + TN) / total
    prec = TP / (TP + FP) if TP + FP else 1.0
    rec = TP / (TP + FN) if TP + FN else 1.0
    spec = TN / (TN + FP) if TN + FP else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 1.0
    fig.text(0.5, 0.015, t["metrics"](acc, prec, rec, spec, f1,
             FP/(FP+TN), FN/(FN+TP)), ha="center", fontsize=8.8, color="#5b6b7a")
    plt.tight_layout(rect=(0, 0.04, 1, 1))
    p = OUT / t["mfile"]
    fig.savefig(p, dpi=200, bbox_inches="tight", facecolor="white"); plt.close(fig)
    print("ok", p)
    return p


def attacks_bar(lang):
    t = T[lang]
    names = [f[0] for f in t["fam"]]; counts = [f[1] for f in t["fam"]]
    y = np.arange(len(names))[::-1]
    fig, ax = plt.subplots(figsize=(8.4, 3.9))
    ax.barh(y, counts, height=0.62, color="#4C72B0", edgecolor="#33507a", linewidth=0.8)
    for yi, c in zip(y, counts):
        ax.text(c + max(counts) * 0.015, yi, t["blk"].format(c=c),
                va="center", ha="left", fontsize=9.5, color="#33404f")
    ax.set_yticks(y); ax.set_yticklabels(names, fontsize=10.5)
    ax.set_xlabel(t["bxlab"], fontsize=10, labelpad=8)
    ax.set_xlim(0, max(counts) * 1.42)
    ax.set_title(t["btitle"], fontsize=12, fontweight="bold", pad=12)
    ax.grid(axis="x", color="#e2e7ee", linewidth=0.9, zorder=0)
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.tick_params(length=0)
    plt.tight_layout()
    p = OUT / t["bfile"]
    fig.savefig(p, dpi=200, bbox_inches="tight", facecolor="white"); plt.close(fig)
    print("ok", p)
    return p


if __name__ == "__main__":
    for lg in ("fr", "en"):
        confusion_matrix(lg)
        attacks_bar(lg)
