#!/usr/bin/env python3
"""Tableau-image de l'éval génération (pipeline 2 agents) — colonnes colorées."""
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import cm, colors

# (modèle, appels, reprises, repli, tokens, temps_s, couverture, action, erreurs)
ROWS = [
    ("gpt-oss-120b",           2, 0, False, 2112,  2.5, 1.00, 1.00, "—"),
    ("gpt-oss-safeguard-20b",  2, 0, False, 2285,  2.0, 1.00, 1.00, "—"),
    ("gpt-oss-20b",            2, 0, False, 2036,  1.6, 1.00, 0.86, "—"),
    ("llama-3.3-70b",          3, 1, False, 1567,  1.0, 1.00, 0.71, "inspect-sans-sig. ×2"),
    ("llama-3.1-8b",           2, 0, False, 1635,  0.9, 1.00, 0.57, "—"),
    ("qwen3.6-27b",            5, 4, True, 12157, 26.7, None, None, "illisible ×4 + RateLimit"),
]
COLS = ["Modèle", "Appels", "Reprises", "Repli", "Tokens", "Temps (s)",
        "Couv.", "Action", "Erreurs (→ reprise)"]
COLW = [0.20, 0.07, 0.09, 0.07, 0.10, 0.09, 0.07, 0.08, 0.23]

toks = [r[4] for r in ROWS]; secs = [r[5] for r in ROWS]
blues = cm.get_cmap("Blues"); oranges = cm.get_cmap("Oranges"); rdylgn = cm.get_cmap("RdYlGn")
n_tok = colors.Normalize(min(toks), max(toks)); n_sec = colors.Normalize(min(secs), max(secs))

def txt_on(rgba):
    lum = 0.299*rgba[0] + 0.587*rgba[1] + 0.114*rgba[2]
    return "white" if lum < 0.5 else "black"

fig, ax = plt.subplots(figsize=(16, 3.2)); ax.axis("off")
cells = [[r[0], str(r[1]), str(r[2]), "OUI" if r[3] else "non", f"{r[4]:,}".replace(",", " "),
          f"{r[5]:.1f}", "—" if r[6] is None else f"{r[6]:.2f}",
          "—" if r[7] is None else f"{r[7]:.2f}", r[8]] for r in ROWS]
tbl = ax.table(cellText=cells, colLabels=COLS, colWidths=COLW, cellLoc="center", loc="center")
tbl.auto_set_font_size(False); tbl.set_fontsize(11); tbl.scale(1, 1.9)

HEAD = "#2b3038"
for (r, c), cell in tbl.get_celld().items():
    cell.set_edgecolor("#cfd6de"); cell.set_linewidth(0.8)
    if r == 0:
        cell.set_facecolor(HEAD); cell.set_text_props(color="white", fontweight="bold"); continue
    row = ROWS[r-1]
    if c == 0:
        cell.set_text_props(ha="left", fontweight="bold"); cell.get_text().set_x(0.03)
    if c == 8:
        cell.set_text_props(ha="left", fontsize=9); cell.get_text().set_x(0.03)
    # Reprises : orange = plus de corrections
    if c == 2 and row[2] > 0:
        rgba = oranges(0.25 + 0.6*min(1, row[2]/4)); cell.set_facecolor(rgba)
        cell.set_text_props(color=txt_on(rgba), fontweight="bold")
    # Repli : rouge = échec (le code a produit la chaîne, pas le modèle)
    if c == 3:
        if row[3]:
            cell.set_facecolor("#c0392b"); cell.set_text_props(color="white", fontweight="bold")
        else:
            cell.set_facecolor("#eafbea")
    # Tokens : bleu foncé = coûteux
    if c == 4:
        rgba = blues(0.12 + 0.8*n_tok(row[4])); cell.set_facecolor(rgba)
        cell.set_text_props(color=txt_on(rgba), fontweight="bold" if n_tok(row[4]) > 0.5 else "normal")
    # Temps : bleu foncé = lent
    if c == 5:
        rgba = blues(0.12 + 0.8*n_sec(row[5])); cell.set_facecolor(rgba)
        cell.set_text_props(color=txt_on(rgba), fontweight="bold" if n_sec(row[5]) > 0.5 else "normal")
    # Action : vert = bon jugement, rouge = mauvais (— si repli)
    if c == 7 and row[7] is not None:
        rgba = rdylgn(colors.Normalize(0.5, 1.0)(row[7])); cell.set_facecolor(rgba)
        cell.set_text_props(color=txt_on(rgba), fontweight="bold")
    if c == 7 and row[7] is None:
        cell.set_facecolor("#e8e8e8"); cell.set_text_props(color="#888", fontstyle="italic")
    if c == 6 and row[6] is not None:
        cell.set_facecolor("#eafbea"); cell.set_text_props(fontweight="bold")
    if c == 6 and row[6] is None:
        cell.set_facecolor("#e8e8e8"); cell.set_text_props(color="#888", fontstyle="italic")
    # ligne repli grisée sur couv/action pour signaler « valeurs du code, pas du modèle »
    if row[3] and c in (6, 7):
        cell.get_text().set_text("(repli)")

fig.savefig("/home/kali/Desktop/eval_generation_2agents.png", dpi=300,
            bbox_inches="tight", facecolor="white")
print("ok eval_generation_2agents.png")
