#!/usr/bin/env python3
"""Schémas à jour : anatomie des agents, phase proactive, algorithme."""
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Polygon, Ellipse
import pathlib

OUT = pathlib.Path("/home/kali/Desktop/tables"); OUT.mkdir(exist_ok=True)
LLM_C, DET_C, DEP_C = "#2f6fb3", "#455160", "#455160"
GREY, RED, ORANGE = "#7a8794", "#b03a2e", "#7a8794"


def box(ax, x, y, w, h, title, sub="", fc="white", ec="#3B6FD4", lw=2,
        tfs=12, sfs=9, tc=None, r=0.9):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={r}",
                                linewidth=lw, edgecolor=ec, facecolor=fc, zorder=2))
    cx = x + w / 2
    if sub:
        ax.text(cx, y + h * 0.36, title, ha="center", va="center", fontsize=tfs,
                fontweight="bold", color=tc or ec, zorder=3)
        ax.text(cx, y + h * 0.70, sub, ha="center", va="center", fontsize=sfs,
                color="#40505f", zorder=3, linespacing=1.35)
    else:
        ax.text(cx, y + h / 2, title, ha="center", va="center", fontsize=tfs,
                fontweight="bold", color=tc or ec, zorder=3)


def arrow(ax, x1, y1, x2, y2, c="#40505f", lw=2.2, style="-|>", ls="-", rad=0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=17,
                                 linewidth=lw, color=c, linestyle=ls, zorder=4,
                                 connectionstyle=f"arc3,rad={rad}"))


# ══════════════ 1) ANATOMIE DES AGENTS (bilingue FR / EN) ══════════════
_ANAT = {
 "fr": dict(
    file="schema_anatomie_agents.png",
    L_title="AGENTS PORTÉS PAR UN LLM",
    L_sub="AgentParefeu  ·  AgentIDS   → les deux seules étapes de JUGEMENT",
    inp="Entrée : le profil comportemental",
    p1="①  Prompt système", p1s="sa consigne : quoi décider, dans quel format",
    p2="②  LLM (ChatGroq)", p2s="produit une décision en JSON",
    p3="③  Contrôle — fonctions Python", p3s="couverture · invention · default-deny · signatures",
    p4="④  Boucle de correction", p4s="erreur ? → retour ciblé au même LLM (max 3 fois)",
    regen="re-génère",
    out="Sortie validée  →  vers l'agent suivant",
    p5="⑤  Repli déterministe", p5s="si les 3 tentatives échouent : le code produit la chaîne",
    after="après\n3 échecs",
    R_title="AGENTS DÉTERMINISTES (sans LLM)",
    R_sub="aucun jugement : lecture, contrôle, exécution",
    sup="AgentSuperviseur", sups="consulte l'état partagé · route vers le volet\nmanquant · RE-ROUTE vers l'agent fautif",
    ana="AgentAnalyseur", anas="automate (.dot) + traces → états, boucles,\ncadences, transitions rares",
    ver="AgentVérificateur", vers="cohérence globale · erreur → nomme l'agent\nfautif (le Superviseur le rappelle)",
    dep="AgentDéployeur", deps="assemble la chaîne · REST → contrôleur SDN\n→ règles sur s1, signatures sur s2",
    foot="Le LLM ne sert qu'à JUGER ; lire, contrôler et exécuter restent déterministes."),
 "en": dict(
    file="schema_anatomie_agents_en.png",
    L_title="LLM-POWERED AGENTS",
    L_sub="FirewallAgent  ·  IDSAgent   → the only two JUDGMENT steps",
    inp="Input: the behavioral profile",
    p1="①  System prompt", p1s="its instruction: what to decide, in what format",
    p2="②  LLM (ChatGroq)", p2s="produces a decision in JSON",
    p3="③  Check — Python functions", p3s="coverage · invention · default-deny · signatures",
    p4="④  Correction loop", p4s="error? → targeted feedback to the same LLM (up to 3×)",
    regen="re-generate",
    out="Validated output  →  to the next agent",
    p5="⑤  Deterministic fallback", p5s="if all 3 attempts fail: the code produces the chain",
    after="after\n3 failures",
    R_title="DETERMINISTIC AGENTS (no LLM)",
    R_sub="no judgment: reading, checking, executing",
    sup="SupervisorAgent", sups="reads the shared state · routes to the missing\npart · RE-ROUTES to the faulty agent",
    ana="AnalyzerAgent", anas="automaton (.dot) + traces → states, loops,\ncadences, rare transitions",
    ver="VerifierAgent", vers="global consistency · error → names the faulty\nagent (the Supervisor recalls it)",
    dep="DeployerAgent", deps="assembles the chain · REST → SDN controller\n→ rules on s1, signatures on s2",
    foot="The LLM only JUDGES; reading, checking and executing stay deterministic."),
}


def anatomie(lang="fr"):
    T = _ANAT[lang]
    fig, ax = plt.subplots(figsize=(15, 8.9))
    ax.set_xlim(0, 100); ax.set_ylim(0, 61); ax.axis("off"); ax.invert_yaxis()

    # panneau gauche — agents LLM
    ax.add_patch(FancyBboxPatch((2, 2), 46, 57, boxstyle="round,pad=0,rounding_size=1.4",
                                linewidth=2, edgecolor=LLM_C, facecolor="#EDF2FC", zorder=1))
    ax.text(4.5, 5.4, T["L_title"], fontsize=13.5, fontweight="bold", color=LLM_C)
    ax.text(4.5, 8.4, T["L_sub"], fontsize=10, color="#4a5b6d", style="italic")

    box(ax, 6, 11, 38, 5.4, T["inp"], fc="#e9edf2", ec="#8a97a6", tfs=11, tc="#40505f")
    arrow(ax, 25, 16.4, 25, 18.4)
    box(ax, 6, 18.4, 38, 5.4, T["p1"], T["p1s"], ec=LLM_C)
    arrow(ax, 25, 23.8, 25, 25.8)
    box(ax, 6, 25.8, 38, 5.4, T["p2"], T["p2s"], ec=LLM_C, lw=2.6)
    arrow(ax, 25, 31.2, 25, 33.2)
    box(ax, 6, 33.2, 38, 5.4, T["p3"], T["p3s"], ec=DET_C)
    arrow(ax, 25, 38.6, 25, 40.6)
    box(ax, 6, 40.6, 38, 5.4, T["p4"], T["p4s"], ec=ORANGE)
    # flèche de re-génération
    arrow(ax, 6, 43.3, 3.4, 43.3, c=ORANGE, lw=1.8)
    arrow(ax, 3.4, 43.3, 3.4, 28.5, c=ORANGE, lw=1.8, style="-")
    arrow(ax, 3.4, 28.5, 6, 28.5, c=ORANGE, lw=1.8)
    ax.text(4.7, 36, T["regen"], fontsize=8, color=ORANGE, rotation=90,
            ha="center", va="center", fontweight="bold")
    arrow(ax, 25, 46, 25, 48)
    box(ax, 6, 48, 38, 4.6, T["out"], fc="#eef1f4", ec=DEP_C, tfs=11)
    box(ax, 6, 53.6, 38, 4.6, T["p5"], T["p5s"], fc="#fdecea", ec=RED, tfs=10.5, sfs=8.6)
    # de ④ → ⑤ (routée, sens explicite)
    arrow(ax, 44, 44.6, 46, 44.6, c=RED, lw=1.6, ls="--")
    arrow(ax, 46, 44.6, 46, 55.2, c=RED, lw=1.6, ls="--", style="-")
    arrow(ax, 46, 55.2, 44, 55.2, c=RED, lw=1.6, ls="--", style="-|>")
    ax.text(47.1, 49.9, T["after"], fontsize=7.3, color=RED, rotation=90,
            ha="center", va="center", fontweight="bold", linespacing=1.1)

    # panneau droit — agents déterministes
    ax.add_patch(FancyBboxPatch((52, 2), 46, 57, boxstyle="round,pad=0,rounding_size=1.4",
                                linewidth=2, edgecolor=DET_C, facecolor="#eef1f4", zorder=1))
    ax.text(54.5, 5.4, T["R_title"], fontsize=13.5, fontweight="bold", color=DET_C)
    ax.text(54.5, 8.4, T["R_sub"], fontsize=10, color="#4a5b6d", style="italic")

    box(ax, 56, 11, 38, 8.6, T["sup"], T["sups"], ec=DET_C)
    box(ax, 56, 21.2, 38, 8.6, T["ana"], T["anas"], ec=DET_C)
    box(ax, 56, 31.4, 38, 8.6, T["ver"], T["vers"], ec=RED)
    box(ax, 56, 41.6, 38, 8.6, T["dep"], T["deps"], ec=DEP_C)

    ax.text(50, 60.4, T["foot"], ha="center", fontsize=11, style="italic", color="#40505f")
    plt.tight_layout(pad=0.5)
    p = OUT / T["file"]
    fig.savefig(p, dpi=200, bbox_inches="tight", facecolor="white"); plt.close(fig)
    return p


# ══════════════ 2) PHASE PROACTIVE — ORCHESTRÉE PAR LE SUPERVISEUR ══════════════
def proactif():
    fig, ax = plt.subplots(figsize=(14.5, 12))
    ax.set_xlim(0, 100); ax.set_ylim(0, 88); ax.axis("off"); ax.invert_yaxis()

    # ── entrée ──
    box(ax, 3, 2, 60, 6.5, "Automate comportemental (.dot)  +  traces réseau",
        "le comportement NORMAL de l'application", fc="#e9edf2", ec="#8a97a6", tc="#40505f")
    arrow(ax, 19, 8.5, 19, 12.5)   # vers le Superviseur

    # ── le SUPERVISEUR (le hub) ──
    SX, SW = 3, 33
    ax.add_patch(FancyBboxPatch((SX, 12.5), SW, 55.5, boxstyle="round,pad=0,rounding_size=1.3",
                                linewidth=2.4, edgecolor=DET_C, facecolor="#eef1f4", zorder=2))
    ax.text(SX + SW/2, 17, "AgentSuperviseur", ha="center", fontsize=13, fontweight="bold", color=DET_C)
    ax.text(SX + SW/2, 22.5,
            "consulte l'ÉTAT PARTAGÉ\n(mémoire LangGraph)\n\n➊ regarde quel volet\n     est manquant\n➋ donne l'ordre à\n     l'agent concerné\n➌ l'agent rend la main\n     et met l'état à jour",
            ha="center", va="top", fontsize=9.4, color="#40505f", linespacing=1.35)
    ax.text(SX + SW/2, 64.5, "aucun travail métier :\nil ne fait qu'AIGUILLER",
            ha="center", va="center", fontsize=8.6, color=DET_C, style="italic", linespacing=1.3)

    # ── les agents (les rayons), empilés à droite ──
    AX, AW, AH, STEP, Y0 = 52, 45, 8.6, 11.0, 12.5
    AG = [
        ("①", "AgentAnalyseur   (déterministe)",
         "lit l'automate + les traces →\nservices · boucles · cadences · rares", DET_C),
        ("②", "AgentParefeu   (LLM)",
         "ALLOW / ALLOW_AND_INSPECT · défaut DENY\nboucle de correction INTERNE (max 3)", LLM_C),
        ("③", "AgentIDS   (LLM)",
         "signatures de beaconing (seuil = cadence)\nboucle de correction INTERNE (max 3)", LLM_C),
        ("④", "AgentVérificateur   (déterministe)",
         "contrôle la chaîne ENTIÈRE · erreur →\nécrit « fault_agent » dans l'état", RED),
        ("⑤", "AgentDéployeur   (déterministe)",
         "assemble la chaîne → contrôleur SDN (REST)", DEP_C),
    ]
    centers = []
    for i, (num, title, sub, c) in enumerate(AG):
        y = Y0 + i * STEP
        cy = y + AH / 2
        centers.append(cy)
        box(ax, AX, y, AW, AH, f"{num}  {title}", sub, ec=c,
            lw=2.6 if c == LLM_C else 2.0, tfs=11.2, sfs=8.5)
        # ordre : Superviseur → agent
        arrow(ax, SX + SW, cy - 1.5, AX, cy - 1.5, c=c, lw=2.0)
        ax.text((SX + SW + AX) / 2, cy - 2.9, f"ordre {num}", ha="center", fontsize=8,
                color=c, fontweight="bold")
        # retour : agent → Superviseur (écrit l'état)
        rc = RED if title.startswith("VÉRIFICATEUR") else GREY
        arrow(ax, AX, cy + 1.7, SX + SW, cy + 1.7, c=rc, lw=1.5, ls="--")

    # étiquette du retour normal
    ax.text((SX + SW + AX) / 2, centers[0] + 3.0, "rend la main\n+ écrit l'état",
            ha="center", va="center", fontsize=7.2, color=GREY, style="italic", linespacing=1.15)
    # étiquette du retour du Vérificateur (la reprise ciblée)
    ax.text((SX + SW + AX) / 2, centers[3] + 3.2,
            "si INVALIDE :\nfault_agent",
            ha="center", va="center", fontsize=7.6, color=RED, fontweight="bold", linespacing=1.15)
    ax.text(SX + SW/2, 60.3,
            "reçoit « fault_agent » → efface ce\nvolet → renvoie l'ordre à ② ou ③",
            ha="center", va="center", fontsize=7.8, color=RED, linespacing=1.25)

    # ── déploiement sur les commutateurs ──
    arrow(ax, 74, Y0 + 4 * STEP + AH, 74, 74.5, c=DEP_C, lw=2.2)   # depuis le Déployeur
    box(ax, 6, 78, 44, 7.2, "s1  —  PARE-FEU",
        "règles ALLOW par adresse · conntrack (stateful)\ntout le reste : DENY par défaut", ec=DEP_C, tfs=11, sfs=8.5)
    box(ax, 52, 78, 44, 7.2, "s2  —  IDS",
        "duplication du trafic surveillé vers le contrôleur\nanalyse du domaine · détection de beaconing", ec=ORANGE, tfs=11, sfs=8.5)
    arrow(ax, 66, 74.5, 40, 78, c=DEP_C, lw=1.8)
    arrow(ax, 78, 74.5, 74, 78, c=DEP_C, lw=1.8)

    ax.text(50, 71.5, "Aucun lien direct entre agents : tout passe par l'état partagé et le Superviseur.",
            ha="center", fontsize=10, style="italic", color="#40505f")
    plt.tight_layout(pad=0.5)
    p = OUT / "schema_phase_proactive.png"
    fig.savefig(p, dpi=200, bbox_inches="tight", facecolor="white"); plt.close(fig)
    return p


# ══════════════ 3) ALGORITHME — ORGANIGRAMME ══════════════
def _term(ax, cx, cy, text, c):
    """Terminateur (début/fin) : ellipse."""
    ax.add_patch(Ellipse((cx, cy), 22, 7.2, facecolor=c, edgecolor="none", zorder=3))
    ax.text(cx, cy, text, ha="center", va="center", fontsize=12, fontweight="bold",
            color="white", zorder=4)


def _proc(ax, cx, cy, w, h, text, c, fc="white"):
    """Traitement : rectangle."""
    ax.add_patch(FancyBboxPatch((cx - w/2, cy - h/2), w, h,
                                boxstyle="round,pad=0,rounding_size=0.6",
                                linewidth=2.2, edgecolor=c, facecolor=fc, zorder=3))
    ax.text(cx, cy, text, ha="center", va="center", fontsize=11.5, fontweight="bold",
            color=c, zorder=4)


def algo():
    fig, ax = plt.subplots(figsize=(11.5, 13.5))
    ax.set_xlim(0, 100); ax.set_ylim(0, 116); ax.axis("off"); ax.invert_yaxis()
    CX = 46          # colonne centrale
    W, H = 46, 8.5   # taille des traitements

    _term(ax, CX, 5, "DÉBUT", GREY)
    ax.text(CX, 5, "", ha="center")
    arrow(ax, CX, 8.6, CX, 12.5)

    _proc(ax, CX, 17, W, H, "Analyser le comportement", DET_C, fc="white")
    arrow(ax, CX, 21.3, CX, 25.3)

    _proc(ax, CX, 30, W, H, "AgentParefeu : ALLOW / ALLOW_AND_INSPECT", LLM_C, fc="white")
    arrow(ax, CX, 34.3, CX, 38.3)

    _proc(ax, CX, 43, W, H, "AgentIDS : signatures de beaconing", LLM_C, fc="white")
    arrow(ax, CX, 47.3, CX, 51.3)

    _proc(ax, CX, 56, W, H, "Assembler la chaîne", DEP_C, fc="white")
    arrow(ax, CX, 60.3, CX, 66)

    # losange de décision
    d = Polygon([(CX, 66), (CX + 26, 76), (CX, 86), (CX - 26, 76)], closed=True,
                facecolor="#fdecea", edgecolor=RED, linewidth=2.2, zorder=3)
    ax.add_patch(d)
    ax.text(CX, 76, "Chaîne\ncohérente ?", ha="center", va="center", fontsize=11.5,
            fontweight="bold", color=RED, zorder=4)

    # branche OUI → déployer → fin
    arrow(ax, CX, 86, CX, 91.5, c=DEP_C)
    ax.text(CX + 2.5, 89, "oui", fontsize=11, color=DEP_C, fontweight="bold", va="center")
    _proc(ax, CX, 96, W, H, "Déployer  →  s1 (pare-feu) · s2 (IDS)", DEP_C, fc="white")
    arrow(ax, CX, 100.3, CX, 104.5, c=DEP_C)
    _term(ax, CX, 108.5, "FIN", GREY)

    # branche NON → renvoyer l'agent fautif (retour vers Firewall / IDS)
    LX = 8
    arrow(ax, CX - 26, 76, LX, 76, c=RED, lw=2.2)
    arrow(ax, LX, 76, LX, 30, c=RED, lw=2.2, style="-")
    arrow(ax, LX, 30, CX - W/2, 30, c=RED, lw=2.2)   # retour vers Pare-feu
    ax.add_patch(FancyArrowPatch((LX, 43), (CX - W/2, 43), arrowstyle="-|>", mutation_scale=15,
                                 linewidth=2.2, color=RED, zorder=3))  # ...ou vers IDS
    ax.text(CX - 30, 73, "non", fontsize=11, color=RED, fontweight="bold")
    ax.text(LX - 1.5, 55, "le Superviseur renvoie\nl'agent fautif  (max 3)", fontsize=9,
            color=RED, rotation=90, ha="center", va="center", style="italic", linespacing=1.3)

    # petites annotations « boucle interne » sur les 2 agents LLM
    for cy in (30, 43):
        ax.add_patch(FancyArrowPatch((CX + W/2, cy - 2.4), (CX + W/2, cy + 2.4),
                                     arrowstyle="-|>", mutation_scale=11, linewidth=1.5,
                                     color=LLM_C, connectionstyle="arc3,rad=-1.4", zorder=2))
        ax.text(CX + W/2 + 6.5, cy, "correction\ninterne ×3", fontsize=8, color=LLM_C,
                ha="center", va="center", style="italic", linespacing=1.2)

    ax.text(CX, 113.5, "Organigramme — génération proactive d'une chaîne de sécurité",
            ha="center", fontsize=11.5, style="italic", color="#40505f")
    plt.tight_layout(pad=0.4)
    p = OUT / "schema_algorithme.png"
    fig.savefig(p, dpi=200, bbox_inches="tight", facecolor="white"); plt.close(fig)
    return p


if __name__ == "__main__":
    for f in (anatomie, proactif, algo):
        print("ok", f())
