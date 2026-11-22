#!/usr/bin/env python3
"""
architectures/supervisor/test_firewall_agent_llm.py — Test de recherche du
FirewallAgent « vrai agent » (LLM décisionnaire + outils de vérification).

Objectif : mesurer si le LLM est CAPABLE de générer les bonnes règles firewall,
et quelle est sa STABILITÉ (non-déterminisme).

Le test isole le FirewallAgent :
  1. Produit le diagnostic de façon DÉTERMINISTE (_analyze_deterministic) pour
     que la SEULE source de variabilité soit le LLM du Firewall.
  2. Calcule l'oracle de référence (generate_chain_from_analysis → 11 règles).
  3. Lance le FirewallAgent LLM 3 FOIS et compare chaque run à l'oracle
     (écarts, oublis, IPs en trop), affiche le rapport de vérification, et
     mesure si les 3 runs sont STABLES ou VARIABLES.

Lancer depuis la racine du projet :
    python3 architectures/supervisor/test_firewall_agent_llm.py
"""

import logging
import pathlib
import sys

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from architectures.supervisor.firewall_agent import firewall_node
from architectures.supervisor.supervisor_agent import SupervisorState

N_RUNS = 3


def _sig(rule) -> tuple:
    """Signature comparable d'une règle : (action, dst_ip, dst_port, protocole)."""
    proto = (getattr(rule, "protocol", None) or "").upper()
    return (rule.action, rule.dst_ip, rule.dst_port, proto)


def _counts(rules) -> tuple[int, int, int]:
    """(nb_block, nb_allow, nb_lan) d'une liste de règles."""
    nb_block = sum(1 for r in rules if r.action == "BLOCK")
    nb_allow = sum(1 for r in rules if r.action in ("ALLOW", "ALLOW_AND_INSPECT"))
    nb_lan = sum(1 for r in rules if (r.protocol or "").upper() == "ARP" or r.dst_ip == "10.0.0.0/24")
    return nb_block, nb_allow, nb_lan


def main() -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    automate_path = _PROJECT_ROOT / "automates" / "pokemon_go.json"
    if not automate_path.exists():
        print(f"❌ Automate introuvable : {automate_path}")
        return 1

    # ── 1. Diagnostic déterministe (isole la variabilité au seul LLM Firewall) ─
    import warnings
    warnings.filterwarnings("ignore")
    from tools.chain_tools import load_automate, generate_chain_from_analysis
    from agents.chain_analyzer import _analyze_deterministic

    automate = load_automate.invoke({"path": str(automate_path)})["automate"]
    analysis = _analyze_deterministic(automate)

    # ── 2. Oracle de référence (déterministe) ────────────────────────────────
    ref_rules = list(generate_chain_from_analysis(analysis).firewall_rules)
    ref_sigs = {_sig(r) for r in ref_rules}
    rb, ra, rl = _counts(ref_rules)

    print("=" * 78)
    print("  TEST FIREWALLAGENT LLM — Pokemon GO (LLM décide, outils vérifient)")
    print("=" * 78)
    print(f"\n▶ Oracle déterministe de référence : {len(ref_rules)} règles "
          f"({rb} BLOCK, {ra} ALLOW dont {rl} LAN)")

    # ── 3. N runs du FirewallAgent LLM ───────────────────────────────────────
    run_sigsets: list[frozenset] = []
    for run in range(1, N_RUNS + 1):
        print("\n" + "-" * 78)
        print(f"  RUN {run}/{N_RUNS}")
        print("-" * 78)

        state = SupervisorState(
            user_request="Test FirewallAgent LLM",
            automate_path=str(automate_path),
            automate_analysis=analysis,   # diagnostic injecté → firewall isolé
        )
        updates = firewall_node(state)
        rules = updates.get("firewall_rules") or []
        report = updates.get("firewall_verification_report") or {}

        nb_block, nb_allow, nb_lan = _counts(rules)
        print(f"  Source           : {report.get('source')}")
        print(f"  Règles produites : {len(rules)}  ({nb_block} BLOCK, {nb_allow} ALLOW, {nb_lan} LAN)")
        if report.get("source") == "llm":
            print(f"  LLM brut/gardées/rejetées : "
                  f"{report.get('rules_from_llm')}/{report.get('rules_kept')}/{report.get('rules_rejected')}")

        # ── Rapport de vérification (résultat de recherche) ──────────────────
        print("  Rapport de vérification :")
        print(f"    • hallucinations : {len(report.get('hallucinations', []))}")
        for m in report.get("hallucinations", []):
            print(f"        - {m}")
        print(f"    • conflits       : {len(report.get('conflicts', []))}")
        for m in report.get("conflicts", []):
            print(f"        - {m}")
        print(f"    • doublons       : {len(report.get('redundancies', []))}")
        print(f"    • champs manqués : {len(report.get('missing_fields', [])) + len(report.get('build_errors', []))}")
        lan_pb = report.get("lan_problems", [])
        print(f"    • LAN OK ?       : {'OUI' if not lan_pb else 'NON — ' + '; '.join(lan_pb)}")

        # ── Comparaison à l'oracle ───────────────────────────────────────────
        sigs = {_sig(r) for r in rules}
        missing = ref_sigs - sigs        # règles attendues que le LLM a oubliées
        extra = sigs - ref_sigs          # règles que le LLM a produites en trop
        print("  Comparaison à l'oracle (11 règles) :")
        print(f"    • oublis (manquantes vs oracle) : {len(missing)}")
        for s in sorted(missing, key=str):
            print(f"        - MANQUE {s[0]} {s[1]}:{s[2]}/{s[3]}")
        print(f"    • en trop (absentes de l'oracle): {len(extra)}")
        for s in sorted(extra, key=str):
            print(f"        - EN TROP {s[0]} {s[1]}:{s[2]}/{s[3]}")
        verdict = "✅ IDENTIQUE à l'oracle" if not missing and not extra else "⚠️ DIFFÉRENT de l'oracle"
        print(f"    • verdict : {verdict}")

        run_sigsets.append(frozenset(sigs))

    # ── 4. Stabilité entre runs ──────────────────────────────────────────────
    print("\n" + "=" * 78)
    print("  STABILITÉ ENTRE LES 3 RUNS (mesure du non-déterminisme LLM)")
    print("=" * 78)
    stable = all(s == run_sigsets[0] for s in run_sigsets)
    if stable:
        print("  ✅ STABLE : les 3 runs produisent EXACTEMENT le même ensemble de règles.")
    else:
        print("  ⚠️ VARIABLE : les runs diffèrent entre eux.")
        for i, s in enumerate(run_sigsets, start=1):
            print(f"    • run {i} : {len(s)} règles")
        # Différences symétriques entre run 1 et les autres
        for i in range(2, len(run_sigsets) + 1):
            diff = run_sigsets[0] ^ run_sigsets[i - 1]
            if diff:
                print(f"    • run1 vs run{i} : {len(diff)} règle(s) divergente(s)")

    matches_oracle = all(s == ref_sigs for s in run_sigsets)
    print("\n  Conformité à l'oracle sur les 3 runs : "
          + ("✅ tous identiques à l'oracle" if matches_oracle else "⚠️ au moins un run diffère de l'oracle"))
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
