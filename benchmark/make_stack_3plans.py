#!/usr/bin/env python3
"""Pile technique — UNIQUEMENT les trois plans (intelligent · contrôle · données).
Sans « Outils des agents », « Jeux de données » ni « Outillage » (consigne du prof)."""
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import pathlib

OUT = pathlib.Path("/home/kali/Desktop/tables"); OUT.mkdir(exist_ok=True)

CARD_FC = "#232C39"      # navy des cartes
CARD_EC = "#33404f"
SUB_C = "#9aa7b4"        # sous-titre gris

# (titre du plan, couleur d'accent, fond pastel du panneau, couleur du titre du plan)
_PLANS = {
 "fr": [
    ("Plan intelligent  (Agents)", "#3B6FD4", "#EBF0FB", "#2E5BB8", [
        ("LangGraph", "orchestre les agents\net l'état partagé"),
        ("LangChain", "couche modèles + outils\n(sous LangGraph)"),
        ("LLM — 6 modèles", "Llama · GPT-OSS · Qwen\n(via API Groq)"),
        ("Pydantic", "valide les schémas\nde la chaîne"),
    ]),
    ("Plan de contrôle", "#2E7D46", "#EAF2E7", "#2E7D46", [
        ("os-ken (Ryu)", "contrôleur SDN :\napplique les règles"),
        ("OpenFlow 1.3", "langage contrôleur\n↔ switches"),
    ]),
    ("Plan de données  (Réseau)", "#D4A017", "#FBF3DD", "#B8860B", [
        ("Mininet", "émule le réseau :\ntéléphone, switches, Internet"),
        ("Open vSwitch", "les switches programmables\n(s1 pare-feu, s2 IDS)"),
    ]),
 ],
 "en": [
    ("Intelligence plane  (Agents)", "#3B6FD4", "#EBF0FB", "#2E5BB8", [
        ("LangGraph", "orchestrates the agents\nand the shared state"),
        ("LangChain", "model + tools layer\n(under LangGraph)"),
        ("LLM — 6 models", "Llama · GPT-OSS · Qwen\n(via Groq API)"),
        ("Pydantic", "validates the chain\nschemas"),
    ]),
    ("Control plane", "#2E7D46", "#EAF2E7", "#2E7D46", [
        ("os-ken (Ryu)", "SDN controller:\napplies the rules"),
        ("OpenFlow 1.3", "controller ↔ switches\nprotocol"),
    ]),
    ("Data plane  (Network)", "#D4A017", "#FBF3DD", "#B8860B", [
        ("Mininet", "emulates the network:\nphone, switches, Internet"),
        ("Open vSwitch", "the programmable switches\n(s1 firewall, s2 IDS)"),
    ]),
 ],
}
_FILE = {"fr": "schema_stack_3plans.png", "en": "schema_stack_3plans_en.png"}


def card(ax, x, y, w, h, title, sub, accent):
    # corps sombre
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.9",
                                linewidth=1.4, edgecolor=CARD_EC, facecolor=CARD_FC, zorder=3))
    # liseré coloré en haut
    bar_h = 1.15
    ax.add_patch(FancyBboxPatch((x + 0.6, y + 0.35), w - 1.2, bar_h,
                                boxstyle="round,pad=0,rounding_size=0.5",
                                linewidth=0, facecolor=accent, zorder=4))
    cx = x + w / 2
    ax.text(cx, y + h * 0.40, title, ha="center", va="center", fontsize=13.5,
            fontweight="bold", color="white", zorder=5)
    ax.text(cx, y + h * 0.74, sub, ha="center", va="center", fontsize=9.3,
            color=SUB_C, zorder=5, linespacing=1.4)


def build(lang="fr"):
    fig, ax = plt.subplots(figsize=(14.5, 9.6))
    ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off"); ax.invert_yaxis()

    PANEL_H = 28.0
    GAP = 3.5
    top = 2.0
    inner_x0, inner_x1 = 4.0, 96.0
    inner_w = inner_x1 - inner_x0
    card_h = 15.5

    for ptitle, accent, panel_bg, ptitle_c, cards in _PLANS[lang]:
        y = top
        # panneau pastel
        ax.add_patch(FancyBboxPatch((1.5, y), 97, PANEL_H,
                                    boxstyle="round,pad=0,rounding_size=1.6",
                                    linewidth=1.4, edgecolor=accent, facecolor=panel_bg,
                                    alpha=0.95, zorder=1))
        ax.text(inner_x0 + 0.5, y + 4.4, ptitle, fontsize=16, fontweight="bold",
                color=ptitle_c, zorder=6)

        n = len(cards)
        gap = 2.6
        w = (inner_w - gap * (n - 1)) / n
        # centrer si peu de cartes (max 4 largeur de référence)
        if n < 4:
            w = min(w, 25.0)
            row_w = w * n + gap * (n - 1)
            x = inner_x0 + (inner_w - row_w) / 2
        else:
            x = inner_x0
        cy = y + 8.5
        for title, sub in cards:
            card(ax, x, cy, w, card_h, title, sub, accent)
            x += w + gap

        top += PANEL_H + GAP

    plt.tight_layout(pad=0.4)
    p = OUT / _FILE[lang]
    fig.savefig(p, dpi=200, bbox_inches="tight", facecolor="#F3F5FA"); plt.close(fig)
    print("ok", p)
    return p


if __name__ == "__main__":
    build("fr")
    build("en")
