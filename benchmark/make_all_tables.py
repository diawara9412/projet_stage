#!/usr/bin/env python3
"""Génère les images de tableaux : 7 apps (génération) + 1 bout-en-bout (%)."""
import json, pathlib, re
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import cm, colors

OUT = pathlib.Path("/home/kali/Desktop/tables")
OUT.mkdir(exist_ok=True)
F = pathlib.Path("/home/kali/Desktop/projet_chaine/benchmark/figures")
DEMO = pathlib.Path("/home/kali/Desktop/demo_run")

SIZE = {"disneyland": 1, "dropbox": 1, "faceswitch": 3, "ratp": 3,
        "lequipe": 3, "pokemongo": 5, "viber": 7}
ORDER = ["openai/gpt-oss-120b", "openai/gpt-oss-safeguard-20b", "openai/gpt-oss-20b",
         "llama-3.3-70b-versatile", "llama-3.1-8b-instant", "qwen/qwen3.6-27b"]
short = lambda m: m.split("/")[-1].replace("-instant", "").replace("-versatile", "")
HEAD = "#2b3038"
blues, oranges, rdylgn = cm.get_cmap("Blues"), cm.get_cmap("Oranges"), cm.get_cmap("RdYlGn")
greens, reds = cm.get_cmap("Greens"), cm.get_cmap("Reds")


def txt_on(c):
    return "white" if (0.299*c[0] + 0.587*c[1] + 0.114*c[2]) < 0.5 else "black"


def shorten(e):
    e = (e or "—").replace("json-illisible", "illisible").replace("couverture", "couv.")
    e = e.replace("invention", "invent.").replace("inspect-sans-signature", "inspect-sans-sig.")
    e = re.sub(r"llm_error:(\w+?)Error", r"\1", e)
    return e if len(e) < 46 else e[:44] + "…"


# ─────────────────────────── 1) tableaux par app ───────────────────────────
def table_app(app, rows):
    rr = [next((x for x in rows if x["app"] == app and x["model"] == m), None) for m in ORDER]
    rr = [r for r in rr if r]
    toks = [r["tokens"] for r in rr]; secs = [r["seconds"] for r in rr]
    ntok = colors.Normalize(min(toks), max(toks)); nsec = colors.Normalize(min(secs), max(secs))

    COLS = ["Modèle", "Appels\nFIREWALL", "Appels\nIDS", "Reprises", "Repli", "Tokens",
            "Temps (s)", "Couv.", "Action", "Erreurs (→ reprise)"]
    COLW = [0.185, 0.075, 0.062, 0.078, 0.062, 0.085, 0.078, 0.062, 0.070, 0.243]
    cells = []
    for r in rr:
        fb = r["fell_back"]
        relances = (r["fw_calls"] - 1) + (r["ids_calls"] - 1)
        cells.append([short(r["model"]), str(r["fw_calls"]), str(r["ids_calls"]),
                      str(relances),
                      "OUI" if fb else "non", f"{r['tokens']:,}".replace(",", " "),
                      f"{r['seconds']:.1f}",
                      "(repli)" if fb else f"{r['coverage']:.2f}",
                      "(repli)" if fb else (f"{r['action']:.2f}" if r["action"] is not None else "—"),
                      shorten(r["errors"])])

    fig, ax = plt.subplots(figsize=(16, 0.62 * len(rr) + 0.9)); ax.axis("off")
    t = ax.table(cellText=cells, colLabels=COLS, colWidths=COLW, cellLoc="center", loc="center")
    t.auto_set_font_size(False); t.set_fontsize(11); t.scale(1, 1.85)
    for (i, c), cell in t.get_celld().items():
        cell.set_edgecolor("#cfd6de"); cell.set_linewidth(0.8)
        if i == 0:
            cell.set_facecolor(HEAD); cell.set_text_props(color="white", fontweight="bold"); continue
        r = rr[i-1]; fb = r["fell_back"]
        if c == 0:
            cell.set_text_props(ha="left", fontweight="bold"); cell.get_text().set_x(0.03)
        if c == 9:
            cell.set_text_props(ha="left", fontsize=9); cell.get_text().set_x(0.03)
        # FW / IDS : orange dès qu'un agent a été rappelé (> 1 appel)
        if c in (1, 2):
            n = r["fw_calls"] if c == 1 else r["ids_calls"]
            if n > 1:
                g = oranges(0.25 + 0.6*min(1, (n-1)/3)); cell.set_facecolor(g)
                cell.set_text_props(color=txt_on(g), fontweight="bold")
            else:
                cell.set_facecolor("#eafbea")
        rel = (r["fw_calls"] - 1) + (r["ids_calls"] - 1)
        if c == 3 and rel > 0:
            g = oranges(0.25 + 0.6*min(1, rel/4)); cell.set_facecolor(g)
            cell.set_text_props(color=txt_on(g), fontweight="bold")
        if c == 4:
            if fb: cell.set_facecolor("#c0392b"); cell.set_text_props(color="white", fontweight="bold")
            else: cell.set_facecolor("#eafbea")
        if c == 5:
            g = blues(0.12 + 0.8*ntok(r["tokens"])); cell.set_facecolor(g)
            cell.set_text_props(color=txt_on(g), fontweight="bold" if ntok(r["tokens"]) > .5 else "normal")
        if c == 6:
            g = blues(0.12 + 0.8*nsec(r["seconds"])); cell.set_facecolor(g)
            cell.set_text_props(color=txt_on(g), fontweight="bold" if nsec(r["seconds"]) > .5 else "normal")
        if c in (7, 8):
            if fb:
                cell.set_facecolor("#e8e8e8"); cell.set_text_props(color="#888", fontstyle="italic")
            elif c == 8 and r["action"] is not None:
                g = rdylgn(colors.Normalize(0.5, 1.0)(r["action"])); cell.set_facecolor(g)
                cell.set_text_props(color=txt_on(g), fontweight="bold")
            elif c == 7:
                cell.set_facecolor("#eafbea"); cell.set_text_props(fontweight="bold")
    p = OUT / f"gen_{app}.png"
    fig.savefig(p, dpi=200, bbox_inches="tight", facecolor="white"); plt.close(fig)
    return p


# ─────────────────────── 2) tableau bout-en-bout (%) ───────────────────────
def table_e2e(rows):
    COLS = ["Chaîne déployée", "Déviation", "TN %", "FP %", "FN %", "TP %",
            "Exactitude", "Précision", "Rappel", "FPR", "FNR"]
    COLW = [0.13, 0.11, 0.075, 0.075, 0.075, 0.075, 0.095, 0.09, 0.085, 0.075, 0.075]
    cells = [[r["chaine"], r["deviation"], f"{r['TN%']}", f"{r['FP%']}", f"{r['FN%']}",
              f"{r['TP%']}", f"{r['exactitude']}", f"{r['precision']}", f"{r['rappel']}",
              f"{r['FPR']}", f"{r['FNR']}"] for r in rows]
    fig, ax = plt.subplots(figsize=(16, 0.62*len(rows) + 0.9)); ax.axis("off")
    t = ax.table(cellText=cells, colLabels=COLS, colWidths=COLW, cellLoc="center", loc="center")
    t.auto_set_font_size(False); t.set_fontsize(11.5); t.scale(1, 1.9)
    # « Parfait » = 100 pour les bonnes colonnes, 0 pour les mauvaises. On laisse
    # ces valeurs en NEUTRE et on ne met en couleur QUE les chiffres remarquables
    # (ceux qui s'écartent du parfait) → l'œil va droit aux exceptions.
    GOODC = {2: "TN%", 5: "TP%", 8: "rappel", 7: "precision", 6: "exactitude"}
    BADC = {3: "FP%", 4: "FN%", 9: "FPR", 10: "FNR"}
    for (i, c), cell in t.get_celld().items():
        cell.set_edgecolor("#cfd6de"); cell.set_linewidth(0.8)
        if i == 0:
            cell.set_facecolor(HEAD); cell.set_text_props(color="white", fontweight="bold"); continue
        cell.set_facecolor("white"); cell.set_text_props(color="#233", fontweight="normal")
        r = rows[i-1]
        if c in (0, 1):
            cell.set_text_props(ha="left", fontweight="bold" if c == 0 else "normal",
                                color="#233")
            cell.get_text().set_x(0.04); continue
        if c in GOODC and r[GOODC[c]] < 100:          # une bonne métrique < 100 → à noter
            cell.set_facecolor("#fbeed2"); cell.set_text_props(color="#9a6b00", fontweight="bold")
        elif c in BADC and r[BADC[c]] > 0:            # une mauvaise métrique > 0 → à noter
            cell.set_facecolor("#fadbd6"); cell.set_text_props(color="#b03a2e", fontweight="bold")
    p = OUT / "e2e_pourcentage.png"
    fig.savefig(p, dpi=200, bbox_inches="tight", facecolor="white"); plt.close(fig)
    return p


if __name__ == "__main__":
    rows = json.loads((F / "evalC_all.json").read_text())
    for app in sorted(SIZE, key=lambda a: (SIZE[a], a)):
        if any(r["app"] == app for r in rows):
            print("ok", table_app(app, rows))
    e2e = []
    for f in ["e2e_matrix_p1.json", "e2e_matrix.json"]:
        p = DEMO / f
        if p.exists():
            e2e += json.loads(p.read_text())
    seen = {}
    for r in e2e:
        seen[(r["chaine"], r["deviation"])] = r
    e2e = sorted(seen.values(), key=lambda r: -r["rappel"])
    print("ok", table_e2e(e2e), f"({len(e2e)} paires)")
