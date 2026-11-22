#!/usr/bin/env python3
"""
architectures/supervisor/test_ids_agent_llm.py — Test de recherche de l'IDSAgent
« vrai agent » (LLM décisionnaire + outils de vérification).

Mesure : le LLM est-il capable de générer les bonnes signatures IDS, est-il
stable, les outils détectent-ils les problèmes, et les IDs sont-ils bien au
format IDS-001… (critique pour la future référence IPS) ?

Le test isole l'IDSAgent : diagnostic produit de façon DÉTERMINISTE pour que la
seule source de variabilité soit le LLM de l'IDS.

Lancer depuis la racine du projet :
    python3 architectures/supervisor/test_ids_agent_llm.py
"""

import logging
import pathlib
import re
import sys

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from architectures.supervisor.ids_agent import ids_node
from architectures.supervisor.supervisor_agent import SupervisorState

N_RUNS = 3
_ID_RE = re.compile(r"^IDS-\d{3}$")


def _sig(s) -> tuple:
    """Signature comparable : (pattern_type, dst_ip, dst_port)."""
    mc = s.match_criteria or {}
    return (s.pattern_type, mc.get("dst_ip"), mc.get("dst_port"))


def main() -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    automate_path = _PROJECT_ROOT / "automates" / "pokemon_go.json"
    if not automate_path.exists():
        print(f"❌ Automate introuvable : {automate_path}")
        return 1

    import warnings
    warnings.filterwarnings("ignore")
    from tools.chain_tools import load_automate, generate_chain_from_analysis
    from agents.chain_analyzer import _analyze_deterministic

    automate = load_automate.invoke({"path": str(automate_path)})["automate"]
    analysis = _analyze_deterministic(automate)

    # ── Oracle déterministe de référence ─────────────────────────────────────
    ref_sigs_obj = list(generate_chain_from_analysis(analysis).ids_signatures)
    ref_sigs = {_sig(s) for s in ref_sigs_obj}

    print("=" * 78)
    print("  TEST IDSAGENT LLM — Pokemon GO (LLM décide, outils vérifient)")
    print("=" * 78)
    print(f"\n▶ Oracle déterministe : {len(ref_sigs_obj)} signatures")
    for s in ref_sigs_obj:
        print(f"    - {s.id} {s.pattern_type} [{s.severity}] → {s.match_criteria.get('dst_ip')}")

    run_sigsets: list[frozenset] = []
    run_ids_ok: list[bool] = []
    for run in range(1, N_RUNS + 1):
        print("\n" + "-" * 78)
        print(f"  RUN {run}/{N_RUNS}")
        print("-" * 78)

        state = SupervisorState(
            user_request="Test IDSAgent LLM",
            automate_path=str(automate_path),
            automate_analysis=analysis,
        )
        updates = ids_node(state)
        sigs = updates.get("ids_signatures") or []
        report = updates.get("ids_verification_report") or {}

        print(f"  Source            : {report.get('source')}")
        print(f"  Signatures        : {len(sigs)}  types={report.get('by_pattern_type', {})}")
        if report.get("source") == "llm":
            print(f"  LLM brut/gardées/rejetées : "
                  f"{report.get('sigs_from_llm')}/{report.get('sigs_kept')}/{report.get('sigs_rejected')}")
        for s in sigs:
            print(f"    - {s.id} {s.pattern_type} [{s.severity}] → {s.match_criteria.get('dst_ip')}")

        # ── Rapport de vérification ──────────────────────────────────────────
        print("  Rapport de vérification :")
        print(f"    • hallucinations    : {len(report.get('hallucinations', []))}")
        for m in report.get("hallucinations", []):
            print(f"        - {m}")
        print(f"    • doublons          : {len(report.get('redundancies', []))}")
        print(f"    • champs manqués    : {len(report.get('missing_fields', [])) + len(report.get('build_errors', []))}")
        cov = report.get("coverage", [])
        print(f"    • couverture OK ?   : {'OUI' if not cov else 'NON — ' + '; '.join(cov)}")

        # ── Format des IDs (critique pour l'IPS) ─────────────────────────────
        ids_list = [s.id for s in sigs]
        ids_format_ok = all(_ID_RE.match(i) for i in ids_list)
        contiguous = ids_list == [f"IDS-{i:03d}" for i in range(1, len(sigs) + 1)]
        run_ids_ok.append(ids_format_ok and contiguous)
        print(f"  IDs au format IDS-001… : {ids_list} → {'✅' if ids_format_ok and contiguous else '❌'}")

        # ── Comparaison à l'oracle ───────────────────────────────────────────
        sigs_set = {_sig(s) for s in sigs}
        missing = ref_sigs - sigs_set
        extra = sigs_set - ref_sigs
        print("  Comparaison à l'oracle (5 signatures) :")
        print(f"    • oublis  : {len(missing)}")
        for s in sorted(missing, key=str):
            print(f"        - MANQUE {s[0]} → {s[1]}:{s[2]}")
        print(f"    • en trop : {len(extra)}")
        for s in sorted(extra, key=str):
            print(f"        - EN TROP {s[0]} → {s[1]}:{s[2]}")
        print(f"    • verdict : {'✅ IDENTIQUE' if not missing and not extra else '⚠️ DIFFÉRENT'}")

        run_sigsets.append(frozenset(sigs_set))

    # ── Stabilité + conformité ───────────────────────────────────────────────
    print("\n" + "=" * 78)
    print("  STABILITÉ ENTRE LES 3 RUNS")
    print("=" * 78)
    stable = all(s == run_sigsets[0] for s in run_sigsets)
    print("  ✅ STABLE : ensembles de signatures identiques sur les 3 runs."
          if stable else "  ⚠️ VARIABLE : les runs diffèrent.")
    matches_oracle = all(s == ref_sigs for s in run_sigsets)
    print("  Conformité oracle : "
          + ("✅ tous identiques à l'oracle" if matches_oracle else "⚠️ au moins un run diffère"))
    print(f"  IDs au format IDS-001… sur les 3 runs : {'✅ OUI' if all(run_ids_ok) else '❌ NON'}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
