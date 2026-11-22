#!/usr/bin/env python3
"""
test_chain_analyzer.py — Test standalone du ChainAnalyzer.

Usage :
    python3 test_chain_analyzer.py [automate_path]

Par défaut teste sur automates/pokemon_go.json.
Fonctionne sans clé GROQ (mode fallback déterministe).
"""

import json
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s",
)

from agents.chain_analyzer import chain_analyzer_node
from state import GraphState


def _print_section(title: str) -> None:
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print('═' * 60)


def main() -> None:
    automate_path = sys.argv[1] if len(sys.argv) > 1 else "automates/pokemon_go.json"

    print(f"\n ChainAnalyzer — Test sur : {automate_path}")

    state = GraphState(
        user_request=f"Analyser l'automate {automate_path} pour générer une chaîne de sécurité",
        automate_path=automate_path,
    )

    updates = chain_analyzer_node(state)

    if not updates or "automate_analysis" not in updates:
        print("\nERREUR : aucune analyse produite (vérifiez les logs ci-dessus)")
        sys.exit(1)

    analysis = updates["automate_analysis"]

    # ── Résumé global ──────────────────────────────────────────────────────
    _print_section("RÉSUMÉ GLOBAL")
    print(f"  Application  : {analysis.app_name}")
    print(f"  Automate ID  : {analysis.automate_id}")
    print(f"  Analysé à    : {analysis.analyzed_at}")
    print(f"  États        : {analysis.nb_states}")
    print(f"  Transitions  : {analysis.nb_transitions}")
    print(f"  Score global : {analysis.global_suspicion_score:.2f} / 10")
    print(f"  Niveau risque: {analysis.risk_level.upper()}")
    print(f"  Suspects     : {analysis.nb_suspicious}")

    # ── LLM Summary ───────────────────────────────────────────────────────
    if analysis.llm_summary:
        _print_section("RÉSUMÉ LLM")
        # Wrap long lines
        for line in analysis.llm_summary.split(". "):
            if line:
                print(f"  {line.strip()}.")

    # ── Transitions suspectes ─────────────────────────────────────────────
    _print_section(f"TRANSITIONS SUSPECTES ({analysis.nb_suspicious})")
    if not analysis.suspicious_transitions:
        print("  (aucune)")
    for t in analysis.suspicious_transitions:
        print(f"\n  [{t.transition_id}] {t.label}")
        print(f"    {t.from_state} → {t.to_state}")
        print(f"    Destination  : {t.dst_ip}:{t.dst_port} / {t.protocol}")
        print(f"    Score        : {t.suspicion_score}/10")
        print(f"    Catégorie    : {t.risk_category}")
        print(f"    Flags        : {', '.join(t.flags) or '—'}")
        if t.explanation:
            expl = t.explanation[:160] + ("…" if len(t.explanation) > 160 else "")
            print(f"    Note         : {expl}")

    # ── Services légitimes ────────────────────────────────────────────────
    _print_section(f"SERVICES LÉGITIMES ({len(analysis.legitimate_services)})")
    if not analysis.legitimate_services:
        print("  (aucun)")
    for s in analysis.legitimate_services:
        ips = ", ".join(s.ips[:3]) + ("…" if len(s.ips) > 3 else "")
        ports = ", ".join(str(p) for p in s.ports[:3])
        print(f"  {s.name:35s} {s.service_type:12s} IPs=[{ips}] ports=[{ports}]")

    # ── Recommandations ───────────────────────────────────────────────────
    _print_section(f"RECOMMANDATIONS POUR LE CHAINGENERATOR ({len(analysis.recommended_actions)})")
    for i, action in enumerate(analysis.recommended_actions, 1):
        print(f"  {i:2d}. {action}")

    # ── Export JSON ───────────────────────────────────────────────────────
    out_path = f"chains/analysis_{analysis.automate_id}.json"
    try:
        import pathlib
        pathlib.Path("chains").mkdir(exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(analysis.model_dump(), fh, indent=2, ensure_ascii=False)
        print(f"\n  Analyse exportée → {out_path}")
    except Exception as exc:
        print(f"\n  Impossible d'exporter l'analyse : {exc}")

    print()


if __name__ == "__main__":
    main()
