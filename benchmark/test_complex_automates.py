#!/usr/bin/env python3
"""
benchmark/test_complex_automates.py — Teste les 3 agents LLM (Firewall, IDS, IPS)
sur des automates de complexité croissante.

But : vérifier si la fiabilité observée sur pokemon_go (2 menaces) tient sur des
cas plus durs — banking_app (1 menace) et surtout malware_app (5 menaces), où
l'IPS doit lier 5 actions à 5 signatures (risque d'orphelins / sous-couverture).

Méthode : pour chaque automate, on lance N fois la chaîne complète
Analyzer → Firewall → IDS → IPS → Déployeur (graphe superviseur, deploy=False,
SANS réseau) et on LIT les rapports de vérification déjà produits par les agents
(aucune nouvelle vérification recodée). On compare aux compteurs de l'oracle
déterministe (generate_chain_from_analysis), hors du chemin des agents.

Usage :
    python3 benchmark/test_complex_automates.py                         # les 3
    python3 benchmark/test_complex_automates.py --automates malware_app --runs 2
    python3 benchmark/test_complex_automates.py --yes
"""

import argparse
import logging
import pathlib
import sys
import time

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import warnings
warnings.filterwarnings("ignore")

from architectures.supervisor.graph_supervisor import build_supervisor_graph
from architectures.supervisor.supervisor_agent import SupervisorState

_LLM_CALLS_PER_RUN = 4  # analyzer + firewall + ids + ips (déployeur = 0)


def _get(result, field):
    if isinstance(result, dict):
        return result.get(field)
    return getattr(result, field, None)


def _f(obj, name, default=None):
    if obj is None:
        return default
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def _rule_sig(r):
    return (_f(r, "action"), _f(r, "dst_ip"), _f(r, "dst_port"), (_f(r, "protocol") or "").upper())


def _ids_sig(s):
    mc = _f(s, "match_criteria") or {}
    ip = mc.get("dst_ip") if isinstance(mc, dict) else None
    return (_f(s, "pattern_type"), ip)


def _ips_sig(a):
    return (_f(a, "on_signature"), _f(a, "action"))


def _count_errors(result) -> dict:
    """Agrège les erreurs depuis les rapports DÉJÀ produits par les agents."""
    fw = _get(result, "firewall_verification_report") or {}
    ids = _get(result, "ids_verification_report") or {}
    ips = _get(result, "ips_verification_report") or {}

    def n(rep, key):
        return len(rep.get(key, []) or [])

    return {
        "hallucinations": n(fw, "hallucinations") + n(ids, "hallucinations"),
        "orphans": n(ips, "orphans"),
        "redundancies": n(fw, "redundancies") + n(ids, "redundancies") + n(ips, "redundancies"),
        "missing_fields": (
            n(fw, "missing_fields") + n(fw, "build_errors")
            + n(ids, "missing_fields") + n(ids, "build_errors")
            + n(ips, "missing_fields") + n(ips, "build_errors")
        ),
        "coverage": n(ids, "coverage") + n(ips, "coverage"),
        "conflicts": n(fw, "conflicts"),
        "lan_problems": n(fw, "lan_problems"),
        "invalid_actions": n(ips, "invalid_actions"),
    }


def _used_fallback(result) -> bool:
    for fld in ("firewall_verification_report", "ids_verification_report", "ips_verification_report"):
        if (_get(result, fld) or {}).get("source") == "fallback_deterministic":
            return True
    return False


def _run_once(automate_path) -> dict:
    graph = build_supervisor_graph(deploy=False)
    state = SupervisorState(user_request="Test complexité", automate_path=str(automate_path))
    t0 = time.perf_counter()
    result = graph.invoke(state)
    dt = time.perf_counter() - t0

    fw = _get(result, "firewall_rules") or []
    ids = _get(result, "ids_signatures") or []
    ips = _get(result, "ips_actions") or []
    report = _get(result, "validation_report")

    return {
        "errors": _count_errors(result),
        "fallback": _used_fallback(result),
        "score": _f(report, "quality_score"),
        "nb_fw": len(fw), "nb_ids": len(ids), "nb_ips": len(ips),
        "fingerprint": (
            frozenset(_rule_sig(r) for r in fw),
            frozenset(_ids_sig(s) for s in ids),
            frozenset(_ips_sig(a) for a in ips),
        ),
        "duration": dt,
    }


def _oracle(automate_path) -> dict:
    """Compteurs de référence déterministes (hors chemin des agents)."""
    from tools.chain_tools import load_automate, generate_chain_from_analysis
    from agents.chain_analyzer import _analyze_deterministic

    automate = load_automate.invoke({"path": str(automate_path)})["automate"]
    analysis = _analyze_deterministic(automate)
    chain = generate_chain_from_analysis(analysis)
    return {
        "threats": analysis.nb_suspicious,
        "fw": len(chain.firewall_rules),
        "ids": len(chain.ids_signatures),
        "ips": len(chain.ips_actions),
    }


def _test_automate(name: str, automate_path, runs: int) -> dict:
    print(f"\n{'#' * 78}\n  AUTOMATE : {name}\n{'#' * 78}")
    ora = _oracle(automate_path)
    print(f"  Oracle déterministe : {ora['threats']} menace(s) → "
          f"{ora['fw']} FW / {ora['ids']} IDS / {ora['ips']} IPS")

    run_results: list[dict] = []
    for r in range(1, runs + 1):
        try:
            res = _run_once(automate_path)
            run_results.append(res)
            e = res["errors"]
            print(f"  run {r}/{runs} : {res['nb_fw']} FW / {res['nb_ids']} IDS / {res['nb_ips']} IPS "
                  f"| orphelins={e['orphans']} halluc={e['hallucinations']} "
                  f"couvert.manq={e['coverage']} | fallback={'oui' if res['fallback'] else 'non'} "
                  f"| score={res['score']} | {res['duration']:.1f}s")
        except Exception as exc:
            logging.error("  run %d/%d ÉCHOUÉ (%s) — ignoré", r, runs, exc)

    if not run_results:
        return {"name": name, "threats": ora["threats"], "runs_ok": 0, "oracle": ora}

    err_types = run_results[0]["errors"].keys()
    avg_err = {k: sum(rr["errors"][k] for rr in run_results) / len(run_results) for k in err_types}
    fingerprints = {rr["fingerprint"] for rr in run_results}
    scores = [rr["score"] for rr in run_results if rr["score"] is not None]

    # Moyennes de production
    avg_fw = sum(rr["nb_fw"] for rr in run_results) / len(run_results)
    avg_ids = sum(rr["nb_ids"] for rr in run_results) / len(run_results)
    avg_ips = sum(rr["nb_ips"] for rr in run_results) / len(run_results)

    return {
        "name": name,
        "threats": ora["threats"],
        "oracle": ora,
        "runs_ok": len(run_results),
        "avg_fw": avg_fw, "avg_ids": avg_ids, "avg_ips": avg_ips,
        "avg_err": avg_err,
        "stable": len(fingerprints) == 1,
        "n_distinct": len(fingerprints),
        "fallback": any(rr["fallback"] for rr in run_results),
        "avg_score": (sum(scores) / len(scores)) if scores else None,
    }


def _print_table(rows: list[dict]) -> None:
    print("\n" + "=" * 104)
    print("  TABLEAU — Agents LLM sur automates de complexité croissante")
    print("=" * 104)
    print(f"  {'Automate':<13}{'menaces':>8}{'FW/IDS/IPS (vs oracle)':>26}{'orphel':>8}"
          f"{'autres err':>11}{'stable':>14}{'fallback':>10}{'score':>7}")
    print("  " + "-" * 100)
    for r in rows:
        if not r.get("runs_ok"):
            print(f"  {r['name']:<13}{r['threats']:>8}   (aucun run réussi)")
            continue
        o = r["oracle"]
        prod = f"{r['avg_fw']:.0f}/{r['avg_ids']:.0f}/{r['avg_ips']:.0f} (vs {o['fw']}/{o['ids']}/{o['ips']})"
        e = r["avg_err"]
        autres = e["hallucinations"] + e["redundancies"] + e["missing_fields"] + e["coverage"] + e["conflicts"] + e["invalid_actions"]
        stab = "stable" if r["stable"] else f"variable {r['n_distinct']}/{r['runs_ok']}"
        score = f"{r['avg_score']:.0f}" if r["avg_score"] is not None else "—"
        print(f"  {r['name']:<13}{r['threats']:>8}{prod:>26}{e['orphans']:>8.1f}"
              f"{autres:>11.1f}{stab:>14}{('oui' if r['fallback'] else 'non'):>10}{score:>7}")
    print("=" * 104)
    print("  'autres err' = halluc + doublons + champs + couverture + conflits + actions invalides (moyenne/run).")


def main() -> int:
    parser = argparse.ArgumentParser(description="Test des agents LLM sur automates complexes")
    parser.add_argument("--automates", default="pokemon_go,banking_app,malware_app",
                        help="liste d'automates (noms sans .json), séparés par des virgules")
    parser.add_argument("--runs", type=int, default=3, help="nb de runs par automate")
    parser.add_argument("--yes", action="store_true", help="ne pas demander de confirmation")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    names = [n.strip() for n in args.automates.split(",") if n.strip()]
    automates: list[tuple[str, pathlib.Path]] = []
    for n in names:
        p = _PROJECT_ROOT / "automates" / f"{n}.json"
        if p.exists():
            automates.append((n, p))
        else:
            print(f"⚠️ Automate ignoré (introuvable) : {p}")
    if not automates:
        print("❌ Aucun automate valide.")
        return 1

    est = len(automates) * args.runs * _LLM_CALLS_PER_RUN
    print("=" * 70)
    print("  TEST AGENTS LLM SUR AUTOMATES COMPLEXES")
    print("=" * 70)
    print(f"  Automates : {[n for n, _ in automates]}")
    print(f"  Runs/auto.: {args.runs}")
    print(f"  Appels LLM estimés : {len(automates)} × {args.runs} × {_LLM_CALLS_PER_RUN} ≈ {est} (hors retries)")
    print("=" * 70)
    if not args.yes:
        if input("  Lancer ? [o/N] ").strip().lower() not in ("o", "oui", "y", "yes"):
            print("  Annulé.")
            return 0

    rows = [_test_automate(name, path, args.runs) for name, path in automates]
    _print_table(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
