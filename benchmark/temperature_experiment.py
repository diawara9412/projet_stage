#!/usr/bin/env python3
"""
benchmark/temperature_experiment.py — Effet de la TEMPÉRATURE sur la fiabilité
des agents LLM (Firewall, IDS, IPS).

But scientifique : provoquer des erreurs en augmentant la température, et MESURER
ce que les outils de vérification attrapent (hallucinations, orphelins, doublons,
champs manquants, couverture), la stabilité entre runs, le recours au fallback
déterministe, et le score de validation de la chaîne finale.

Méthode : pour chaque température, on lance N fois la chaîne complète
Analyzer → Firewall → IDS → IPS → Déployeur (graphe superviseur, deploy=False,
PAS de réseau). On NE recode AUCUNE vérification : on lit les rapports déjà
produits par les agents et stockés dans l'état
(firewall/ids/ips_verification_report) + le validation_report du Déployeur.

Usage :
    python3 benchmark/temperature_experiment.py                       # défaut
    python3 benchmark/temperature_experiment.py --temperatures 0.1,0.9 --runs 2
    python3 benchmark/temperature_experiment.py --yes                 # sans confirmation
"""

import argparse
import logging
import pathlib
import sys
import time

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from architectures.supervisor.llm_runtime import set_temperature, reset_temperature
from architectures.supervisor.graph_supervisor import build_supervisor_graph
from architectures.supervisor.supervisor_agent import SupervisorState

# 4 appels LLM par run : analyzer + firewall + ids + ips (déployeur = 0).
_LLM_CALLS_PER_RUN = 4


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
    """Compte les erreurs par type en LISANT les rapports déjà produits.

    Aucune nouvelle vérification : on agrège ce que les agents ont déjà détecté.
    """
    fw = _get(result, "firewall_verification_report") or {}
    ids = _get(result, "ids_verification_report") or {}
    ips = _get(result, "ips_verification_report") or {}

    def n(rep, key):
        return len(rep.get(key, []) or [])

    return {
        # hallucinations : firewall + ids
        "hallucinations": n(fw, "hallucinations") + n(ids, "hallucinations"),
        # orphelins : ips (métrique critique)
        "orphans": n(ips, "orphans"),
        # doublons : les 3 agents
        "redundancies": n(fw, "redundancies") + n(ids, "redundancies") + n(ips, "redundancies"),
        # champs manquants / build invalides : les 3 agents
        "missing_fields": (
            n(fw, "missing_fields") + n(fw, "build_errors")
            + n(ids, "missing_fields") + n(ids, "build_errors")
            + n(ips, "missing_fields") + n(ips, "build_errors")
        ),
        # couverture manquante : ids + ips
        "coverage": n(ids, "coverage") + n(ips, "coverage"),
        # autres firewall : conflits + lan manquantes ; ips : actions invalides
        "conflicts": n(fw, "conflicts"),
        "lan_problems": n(fw, "lan_problems"),
        "invalid_actions": n(ips, "invalid_actions"),
    }


def _used_fallback(result) -> bool:
    """Vrai si AU MOINS un agent a basculé sur son fallback déterministe."""
    for rep_field in ("firewall_verification_report", "ids_verification_report", "ips_verification_report"):
        rep = _get(result, rep_field) or {}
        if rep.get("source") == "fallback_deterministic":
            return True
    return False


def _run_once(automate_path) -> dict:
    """Lance la chaîne complète une fois et collecte les métriques du run."""
    graph = build_supervisor_graph(deploy=False)
    state = SupervisorState(
        user_request="Expérience température",
        automate_path=str(automate_path),
    )
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
        # Signatures canoniques pour la mesure de stabilité
        "fingerprint": (
            frozenset(_rule_sig(r) for r in fw),
            frozenset(_ids_sig(s) for s in ids),
            frozenset(_ips_sig(a) for a in ips),
        ),
        "duration": dt,
    }


def _experiment(automate_path, temperatures: list[float], runs: int) -> list[dict]:
    """Lance l'expérience complète et retourne une ligne agrégée par température."""
    rows: list[dict] = []
    for temp in temperatures:
        print(f"\n### Température {temp} — {runs} run(s)")
        set_temperature(temp)
        run_results: list[dict] = []
        for r in range(1, runs + 1):
            try:
                res = _run_once(automate_path)
                run_results.append(res)
                err_total = sum(res["errors"].values())
                print(f"  run {r}/{runs} : fw={res['nb_fw']} ids={res['nb_ids']} ips={res['nb_ips']} "
                      f"| erreurs={err_total} | fallback={'oui' if res['fallback'] else 'non'} "
                      f"| score={res['score']} | {res['duration']:.1f}s")
            except Exception as exc:  # robustesse quota/timeout : on continue
                logging.error("  run %d/%d ÉCHOUÉ (%s) — ignoré", r, runs, exc)
        reset_temperature()

        if not run_results:
            rows.append({"temp": temp, "runs_ok": 0})
            continue

        # ── Agrégation des erreurs (moyenne par type) ───────────────────────
        err_types = run_results[0]["errors"].keys()
        avg_err = {
            k: sum(rr["errors"][k] for rr in run_results) / len(run_results)
            for k in err_types
        }
        # ── Stabilité : nb d'empreintes distinctes ──────────────────────────
        fingerprints = {rr["fingerprint"] for rr in run_results}
        stable = len(fingerprints) == 1
        # ── Fallback / score ────────────────────────────────────────────────
        any_fallback = any(rr["fallback"] for rr in run_results)
        scores = [rr["score"] for rr in run_results if rr["score"] is not None]
        avg_score = sum(scores) / len(scores) if scores else None

        rows.append({
            "temp": temp,
            "runs_ok": len(run_results),
            "avg_err": avg_err,
            "stable": stable,
            "n_distinct": len(fingerprints),
            "fallback": any_fallback,
            "avg_score": avg_score,
        })
    return rows


def _print_table(rows: list[dict], runs: int) -> None:
    print("\n" + "=" * 100)
    print("  TABLEAU — Effet de la température sur la fiabilité des agents LLM")
    print("=" * 100)
    head = (f"  {'Temp':>5} {'runs':>5} {'halluc':>7} {'orphel':>7} {'doublon':>8} "
            f"{'champs':>7} {'couvert':>8} {'stable':>14} {'fallback':>9} {'score':>7}")
    print(head)
    print("  " + "-" * 96)
    for r in rows:
        if not r.get("runs_ok"):
            print(f"  {r['temp']:>5} {'0':>5}   (aucun run réussi)")
            continue
        e = r["avg_err"]
        stab = "stable" if r["stable"] else f"variable {r['n_distinct']}/{r['runs_ok']}"
        score = f"{r['avg_score']:.0f}" if r["avg_score"] is not None else "—"
        print(f"  {r['temp']:>5} {r['runs_ok']:>5} {e['hallucinations']:>7.1f} {e['orphans']:>7.1f} "
              f"{e['redundancies']:>8.1f} {e['missing_fields']:>7.1f} {e['coverage']:>8.1f} "
              f"{stab:>14} {('oui' if r['fallback'] else 'non'):>9} {score:>7}")
    print("=" * 100)
    print("  Légende : halluc=hallucinations(fw+ids), orphel=orphelins(ips), doublon, champs=champs"
          " manquants/invalides, couvert=couverture manquante. Valeurs = moyenne par run.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Expérience température sur les agents LLM")
    parser.add_argument("--temperatures", default="0.1,0.5,0.9,1.2",
                        help="liste de températures séparées par des virgules")
    parser.add_argument("--runs", type=int, default=3, help="nb de runs par température")
    parser.add_argument("--yes", action="store_true", help="ne pas demander de confirmation")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    try:
        temperatures = [float(t) for t in args.temperatures.split(",") if t.strip()]
    except ValueError:
        print("❌ --temperatures invalide (ex: 0.1,0.9)")
        return 1

    automate_path = _PROJECT_ROOT / "automates" / "pokemon_go.json"
    if not automate_path.exists():
        print(f"❌ Automate introuvable : {automate_path}")
        return 1

    # ── Tâche 4 : estimation du coût + confirmation ─────────────────────────
    est_calls = len(temperatures) * args.runs * _LLM_CALLS_PER_RUN
    print("=" * 70)
    print("  EXPÉRIENCE TEMPÉRATURE")
    print("=" * 70)
    print(f"  Températures : {temperatures}")
    print(f"  Runs/temp.   : {args.runs}")
    print(f"  Appels LLM estimés : {len(temperatures)} temp × {args.runs} runs × "
          f"{_LLM_CALLS_PER_RUN} agents ≈ {est_calls} appels (hors retries)")
    print("=" * 70)
    if not args.yes:
        rep = input("  Lancer l'expérience ? [o/N] ").strip().lower()
        if rep not in ("o", "oui", "y", "yes"):
            print("  Annulé.")
            return 0

    rows = _experiment(automate_path, temperatures, args.runs)
    _print_table(rows, args.runs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
