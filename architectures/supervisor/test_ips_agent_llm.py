#!/usr/bin/env python3
"""
architectures/supervisor/test_ips_agent_llm.py — Test de recherche de l'IPSAgent
« vrai agent » (LLM décisionnaire + outils de vérification).

Deux parties :
  PARTIE A — INTÉGRATION : lance la chaîne complète Analyzer → Firewall(LLM)
    → IDS(LLM) → IPS(LLM) → Déployeur via le graphe superviseur (deploy=False).
    C'est la PREMIÈRE fois que les 3 agents LLM tournent ENSEMBLE. On vérifie
    zéro orphelin et que la SecurityChain assemblée valide toujours 100/100.

  PARTIE B — STABILITÉ : isole l'IPS (signatures IDS fixées) et le lance 3 fois
    pour mesurer son non-déterminisme et comparer à l'oracle.

Lancer depuis la racine du projet :
    python3 architectures/supervisor/test_ips_agent_llm.py
"""

import logging
import pathlib
import sys

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from architectures.supervisor.ips_agent import ips_node
from architectures.supervisor.supervisor_agent import SupervisorState

N_RUNS = 3


def _get(result, field):
    if isinstance(result, dict):
        return result.get(field)
    return getattr(result, field, None)


def _f(obj, name):
    """Accès tolérant à un champ (objet Pydantic OU dict)."""
    if obj is None:
        return None
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


# ===========================================================================
# PARTIE A — Intégration des 3 agents LLM via le graphe complet
# ===========================================================================

def partie_a(automate_path) -> bool:
    from architectures.supervisor.graph_supervisor import build_supervisor_graph

    print("=" * 78)
    print("  PARTIE A — CHAÎNE COMPLÈTE : Analyzer → Firewall(LLM) → IDS(LLM) → IPS(LLM)")
    print("=" * 78)

    graph = build_supervisor_graph(deploy=False)
    state = SupervisorState(
        user_request="Test intégration 3 agents LLM",
        automate_path=str(automate_path),
    )
    result = graph.invoke(state)

    agents = _get(result, "agents_invoked") or []
    fw = _get(result, "firewall_rules") or []
    ids = _get(result, "ids_signatures") or []
    ips = _get(result, "ips_actions") or []
    chain = _get(result, "security_chain")
    report = _get(result, "validation_report")

    print(f"\n  Ordre des agents : {' → '.join(agents)} → (end)")
    print(f"  Firewall(LLM) : {len(fw)} règles | IDS(LLM) : {len(ids)} sigs | IPS(LLM) : {len(ips)} actions")

    # Zéro orphelin : chaque on_signature des IPS pointe vers un id IDS réel
    ids_ids = {_f(s, "id") for s in ids}
    orphans = [_f(a, "on_signature") for a in ips if _f(a, "on_signature") not in ids_ids]
    print(f"  Références IPS → IDS : {sorted(ids_ids)}")
    print(f"  Orphelins : {orphans if orphans else 'AUCUN ✅'}")

    score = _f(report, "quality_score")
    valid = _f(report, "is_valid")
    print(f"  SecurityChain assemblée : {_f(chain, 'chain_id')} — validation {score}/100 (valide={valid})")

    ok = (
        agents == ["analyzer", "firewall", "ids", "ips", "deployer"]
        and not orphans and chain is not None and score == 100
    )
    print("\n  " + ("✅ INTÉGRATION OK : 3 agents LLM ensemble, 0 orphelin, chaîne 100/100."
                    if ok else "❌ INTÉGRATION KO (voir détails ci-dessus)."))
    return ok


# ===========================================================================
# PARTIE B — Stabilité de l'IPS isolé (signatures IDS fixées)
# ===========================================================================

def partie_b(automate_path) -> bool:
    import warnings
    warnings.filterwarnings("ignore")
    from tools.chain_tools import load_automate, generate_chain_from_analysis
    from agents.chain_analyzer import _analyze_deterministic

    automate = load_automate.invoke({"path": str(automate_path)})["automate"]
    analysis = _analyze_deterministic(automate)

    # Entrée FIXE : signatures IDS déterministes (IDS-001…005) → isole l'IPS.
    fixed_chain = generate_chain_from_analysis(analysis)
    fixed_ids = list(fixed_chain.ids_signatures)
    # Oracle IPS : map on_signature → action
    oracle = {a.on_signature: a.action for a in fixed_chain.ips_actions}

    print("\n" + "=" * 78)
    print("  PARTIE B — STABILITÉ IPS (signatures IDS fixées IDS-001…005)")
    print("=" * 78)
    print(f"\n  Oracle déterministe ({len(oracle)} actions) :")
    for sid, act in sorted(oracle.items()):
        print(f"    - {sid} → {act}")

    run_sets: list[frozenset] = []
    all_zero_orphans = True
    for run in range(1, N_RUNS + 1):
        print("\n" + "-" * 78)
        print(f"  RUN {run}/{N_RUNS}")
        print("-" * 78)

        state = SupervisorState(
            user_request="Test IPS isolé",
            automate_path=str(automate_path),
            automate_analysis=analysis,
            ids_signatures=fixed_ids,   # entrée fixe → seule variabilité = LLM IPS
        )
        updates = ips_node(state)
        acts = updates.get("ips_actions") or []
        report = updates.get("ips_verification_report") or {}

        print(f"  Source       : {report.get('source')}")
        print(f"  Actions      : {len(acts)}  répartition={report.get('by_action', {})}")
        for a in acts:
            print(f"    - {a.id} {a.action:<12} → {a.on_signature}")

        n_orphans = len(report.get("orphans", []))
        print("  Rapport de vérification :")
        print(f"    • ORPHELINS (clé)   : {n_orphans}")
        for m in report.get("orphans", []):
            print(f"        - {m}")
        print(f"    • doublons          : {len(report.get('redundancies', []))}")
        print(f"    • actions invalides : {len(report.get('invalid_actions', []))}")
        print(f"    • champs manqués    : {len(report.get('missing_fields', [])) + len(report.get('build_errors', []))}")
        cov = report.get("coverage", [])
        print(f"    • couverture OK ?   : {'OUI' if not cov else 'NON — ' + '; '.join(cov)}")
        if n_orphans:
            all_zero_orphans = False

        # Comparaison à l'oracle (par on_signature → action)
        produced = {a.on_signature: a.action for a in acts}
        same_targets = set(produced) == set(oracle)
        diffs = [(sid, oracle[sid], produced.get(sid)) for sid in oracle if produced.get(sid) != oracle[sid]]
        print("  Comparaison à l'oracle :")
        print(f"    • mêmes signatures armées : {'OUI' if same_targets else 'NON'}")
        if diffs:
            print(f"    • différences de TYPE d'action : {len(diffs)}")
            for sid, exp, got in diffs:
                print(f"        - {sid} : oracle={exp}  LLM={got}")
        else:
            print("    • types d'action identiques à l'oracle ✅")

        run_sets.append(frozenset(produced.items()))

    print("\n" + "=" * 78)
    print("  STABILITÉ ENTRE LES 3 RUNS")
    print("=" * 78)
    stable = all(s == run_sets[0] for s in run_sets)
    print("  ✅ STABLE : mêmes actions sur les 3 runs." if stable
          else "  ⚠️ VARIABLE : les runs diffèrent.")
    print(f"  Zéro orphelin sur les 3 runs : {'✅ OUI' if all_zero_orphans else '❌ NON'}")
    print("=" * 78)
    return all_zero_orphans


def main() -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    automate_path = _PROJECT_ROOT / "automates" / "pokemon_go.json"
    if not automate_path.exists():
        print(f"❌ Automate introuvable : {automate_path}")
        return 1

    ok_a = partie_a(automate_path)
    ok_b = partie_b(automate_path)

    print("\n" + "#" * 78)
    print(f"  BILAN : intégration {'✅' if ok_a else '❌'} | "
          f"IPS zéro orphelin {'✅' if ok_b else '❌'}")
    print("#" * 78)
    return 0 if (ok_a and ok_b) else 1


if __name__ == "__main__":
    sys.exit(main())
