#!/usr/bin/env python3
"""
benchmark/count_llm_calls.py — Compte et compare les appels LLM RÉELS des deux
architectures (baseline linéaire vs superviseur).

Méthode
-------
On installe le compteur (benchmark/llm_counter.py) qui enveloppe ChatGroq.invoke,
PARTAGÉ par les deux architectures → comptage strictement identique des deux côtés.

Pour chaque automate :
  1. BASELINE  : build_phase2_graph(include_deployer=False) — produit la chaîne
     validée SANS déploiement (pas de réseau). reset → invoke → snapshot.
  2. SUPERVISEUR : build_supervisor_graph(deploy=False) — assemble la chaîne
     SANS déploiement réel (pas de Mininet). reset → invoke → snapshot.

On mesure aussi le temps mural (dominé par la latence réseau vers Groq).

Lancer depuis la racine du projet :
    python3 benchmark/count_llm_calls.py
"""

import logging
import pathlib
import sys
import time

# ── Rendre le projet importable ──────────────────────────────────────────────
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from benchmark.llm_counter import install, reset, snapshot

# IMPORTANT : installer le compteur AVANT d'exécuter quoi que ce soit.
install()

from graph_phase2 import build_phase2_graph
from architectures.supervisor.graph_supervisor import build_supervisor_graph
from state import GraphState
from architectures.supervisor.supervisor_agent import SupervisorState

# Automates candidats (on ne teste que ceux réellement présents)
_CANDIDATE_AUTOMATES = ["pokemon_go", "banking_app", "malware_app"]


def _run_baseline(automate_path: pathlib.Path) -> tuple[int, dict, float]:
    """Exécute la baseline (sans déploiement) et retourne (total, ventilation, durée)."""
    graph = build_phase2_graph(include_deployer=False)
    reset()
    t0 = time.perf_counter()
    graph.invoke(GraphState(user_request="benchmark", automate_path=str(automate_path)))
    dt = time.perf_counter() - t0
    total, by_caller = snapshot()
    return total, by_caller, dt


def _run_supervisor(automate_path: pathlib.Path) -> tuple[int, dict, float]:
    """Exécute le superviseur (assemble seulement) et retourne (total, ventilation, durée)."""
    graph = build_supervisor_graph(deploy=False)
    reset()
    t0 = time.perf_counter()
    graph.invoke(SupervisorState(user_request="benchmark", automate_path=str(automate_path)))
    dt = time.perf_counter() - t0
    total, by_caller = snapshot()
    return total, by_caller, dt


def _short(by_caller: dict) -> str:
    """Formate la ventilation {module: n} en court (dernier segment du module)."""
    return ", ".join(
        f"{mod.split('.')[-1]}={n}" for mod, n in sorted(by_caller.items())
    ) or "(aucun)"


def main() -> int:
    # On réduit le bruit des logs INFO des agents pour garder une sortie lisible.
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    automates = [
        (name, _PROJECT_ROOT / "automates" / f"{name}.json")
        for name in _CANDIDATE_AUTOMATES
    ]
    automates = [(n, p) for (n, p) in automates if p.exists()]
    if not automates:
        print("❌ Aucun automate trouvé dans automates/")
        return 1

    print("=" * 78)
    print("  BENCHMARK — Appels LLM RÉELS : baseline linéaire vs superviseur")
    print("  (baseline = sans déploiement ; superviseur = assemble, deploy=False)")
    print("=" * 78)

    rows: list[tuple] = []
    for name, path in automates:
        print(f"\n### Automate : {name}")

        b_total, b_by, b_dt = _run_baseline(path)
        print(f"  Baseline    : {b_total} appel(s) LLM  [{_short(b_by)}]  — {b_dt:.1f}s")

        s_total, s_by, s_dt = _run_supervisor(path)
        print(f"  Superviseur : {s_total} appel(s) LLM  [{_short(s_by)}]  — {s_dt:.1f}s")

        rows.append((name, b_total, b_dt, s_total, s_dt))

    # ── Tableau comparatif final ─────────────────────────────────────────────
    print("\n" + "=" * 78)
    print("  TABLEAU COMPARATIF — appels LLM réels")
    print("=" * 78)
    header = f"  {'Automate':<14}{'Baseline':>10}{'  (s)':>8}{'Superviseur':>14}{'  (s)':>8}{'Δ appels':>10}"
    print(header)
    print("  " + "-" * 64)
    tot_b = tot_s = 0
    for name, b_total, b_dt, s_total, s_dt in rows:
        delta = s_total - b_total
        print(f"  {name:<14}{b_total:>10}{b_dt:>8.1f}{s_total:>14}{s_dt:>8.1f}{('+' + str(delta)) if delta >= 0 else str(delta):>10}")
        tot_b += b_total
        tot_s += s_total
    print("  " + "-" * 64)
    print(f"  {'TOTAL':<14}{tot_b:>10}{'':>8}{tot_s:>14}{'':>8}{('+' + str(tot_s - tot_b)) if tot_s >= tot_b else str(tot_s - tot_b):>10}")

    # ── Synthèse ─────────────────────────────────────────────────────────────
    if rows:
        name, b_total, _, s_total, _ = rows[0]
        print("\n  Synthèse (par automate) :")
        print(f"    • Baseline    : {b_total} appels LLM")
        print(f"    • Superviseur : {s_total} appels LLM  (Δ = {s_total - b_total:+d})")
        print("    • Le surcoût superviseur = résumés narratifs par agent")
        print("      (firewall + ids + ips = 3 résumés) vs 1 résumé generator baseline,")
        print("      sans résumé de validation côté superviseur (Déployeur déterministe).")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
