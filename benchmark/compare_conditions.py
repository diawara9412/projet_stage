#!/usr/bin/env python3
"""
benchmark/compare_conditions.py — Comparaison A / B-det / B-llm sur les apps
disposant à la fois d'un *_enriched.json (A) ET de traces brutes (DOT+CSV) pour B.

Métriques (par app × condition)
-------------------------------
- COUVERTURE : nb destinations classées / nb réelles (référence A = univers).
- Séparation des écarts vs A (par destination) :
    * manquée   : jamais classée (problème de COUVERTURE)
    * divergente: classée mais flags/score ≠ A (problème de RAISONNEMENT — B-llm)
    * correcte  : flags ET score == A
  (B-det ne devrait JAMAIS avoir de "divergente" : assemblage déterministe.)
- Flags vs A : precision / recall sur les paires (ip, flag) positives.
- Catégories / risque : risk_level B vs A, écart de score global.
- STABILITÉ inter-runs : les R runs donnent-ils EXACTEMENT le même résultat ?
- COÛT : nb d'appels LLM, nb de tool_calls, temps (s).
- AVAL (optionnel) : nb FW / IDS / IPS de la SecurityChain (graphe complet), vs A.

Lancer :
    python3 benchmark/compare_conditions.py                 # 7 apps, 3 runs, + aval
    python3 benchmark/compare_conditions.py --runs 3 --no-downstream
    python3 benchmark/compare_conditions.py --apps pokemongo ratp
"""

from __future__ import annotations

import argparse
import json
import logging
import pathlib
import statistics
import sys
import time

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agents.chain_analyzer import _analyze_deterministic
from agents.chain_analyzer_b import run_analyzer_b

logger = logging.getLogger("compare")

# Apps avec enriched.json ET traces brutes (cf. inventaire du repo).
DEFAULT_APPS = ["pokemongo", "dropbox", "disneyland", "faceswitch", "lequipe", "ratp", "viber"]


# ---------------------------------------------------------------------------
# Référence A (pipeline hors-ligne déjà calculé)
# ---------------------------------------------------------------------------

def reference_A(app: str) -> dict:
    """Référence A : décisions par IP + analyse, depuis le *_enriched.json."""
    path = _ROOT / "automates" / f"{app}_enriched.json"
    automate = json.loads(path.read_text(encoding="utf-8"))
    decisions = {}
    for t in automate.get("transitions", []):
        ip = (t.get("network_call") or {}).get("ip")
        if not ip:
            continue
        susp = t.get("suspicion") or {}
        decisions[ip] = {"flags": sorted(susp.get("flags") or []),
                         "score": int(susp.get("score") or 0)}
    analysis = _analyze_deterministic(automate)
    return {"decisions": decisions, "analysis": analysis,
            "universe": sorted(decisions.keys())}


# ---------------------------------------------------------------------------
# Comparaison d'un run B vs référence A
# ---------------------------------------------------------------------------

def compare_run(ref: dict, b_decisions: dict) -> dict:
    """Sépare manquée / divergente / correcte + precision/recall des flags."""
    universe = ref["universe"]
    ref_dec = ref["decisions"]
    missed = divergent = correct = div_flags = div_score = 0
    for ip in universe:
        if ip not in b_decisions:
            missed += 1
            continue
        bf = sorted(b_decisions[ip].get("flags") or [])
        bs = int(b_decisions[ip].get("score") or 0)
        rf = ref_dec[ip]["flags"]
        rs = ref_dec[ip]["score"]
        if bf == rf and bs == rs:
            correct += 1
        else:
            divergent += 1
            if bf != rf:
                div_flags += 1
            if bs != rs:
                div_score += 1

    # Flags : precision/recall sur paires (ip, flag) positives
    a_pos = {(ip, f) for ip, d in ref_dec.items() for f in d["flags"]}
    b_pos = {(ip, f) for ip, d in b_decisions.items() if ip in ref_dec
             for f in (d.get("flags") or [])}
    tp = len(a_pos & b_pos)
    fp = len(b_pos - a_pos)
    fn = len(a_pos - b_pos)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0

    return {"missed": missed, "divergent": divergent, "correct": correct,
            "div_flags": div_flags, "div_score": div_score,
            "precision": round(precision, 3), "recall": round(recall, 3),
            "a_pos": len(a_pos), "b_pos": len(b_pos)}


def _decisions_signature(dec: dict) -> tuple:
    """Signature canonique pour comparer la stabilité inter-runs."""
    return tuple(sorted((ip, tuple(sorted(d.get("flags") or [])), int(d.get("score") or 0))
                        for ip, d in dec.items()))


# ---------------------------------------------------------------------------
# Aval (graphe complet) — optionnel
# ---------------------------------------------------------------------------

def downstream_counts(app: str, condition: str) -> dict:
    """Lance le graphe superviseur complet et compte FW/IDS/IPS de la chaîne.

    condition : 'A' (automate_path enrichi) | 'B-det' | 'B-llm' (raw_app)."""
    from architectures.supervisor.graph_supervisor import build_supervisor_graph
    from architectures.supervisor.supervisor_agent import SupervisorState
    graph = build_supervisor_graph(deploy=False)
    if condition == "A":
        init = SupervisorState(user_request=f"Sécuriser {app} (A)",
                               automate_path=str(_ROOT / "automates" / f"{app}_enriched.json"))
    else:
        mode = "deterministic" if condition == "B-det" else "llm"
        init = SupervisorState(user_request=f"Sécuriser {app} ({condition})",
                               raw_app=app, assembly_mode=mode)
    try:
        res = graph.invoke(init)
    except Exception as exc:
        logger.warning("Aval %s/%s : échec graphe : %s", app, condition, exc)
        return {"fw": None, "ids": None, "ips": None, "error": str(exc)[:120]}
    chain = res.get("security_chain") if isinstance(res, dict) else getattr(res, "security_chain", None)
    if chain is None:
        return {"fw": 0, "ids": 0, "ips": 0, "error": "pas de chaîne"}
    return {"fw": len(chain.firewall_rules), "ids": len(chain.ids_signatures),
            "ips": len(chain.ips_actions), "error": None}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def eval_condition(app: str, ref: dict, mode: str, runs: int) -> dict:
    """Évalue B-det ou B-llm sur `runs` runs et agrège."""
    per_run = []
    signatures = set()
    for r in range(1, runs + 1):
        out = run_analyzer_b(app, assembly_mode=mode)
        dec = out["decisions"]
        cmp = compare_run(ref, dec)
        risk = out["automate_analysis"].risk_level if out["automate_analysis"] else None
        score = out["automate_analysis"].global_suspicion_score if out["automate_analysis"] else None
        per_run.append({**cmp, "coverage": out["coverage"]["ratio"],
                        "risk": risk, "score": score,
                        "llm_calls": out["llm_calls"], "tool_calls": out["tool_calls"],
                        "elapsed_s": out["elapsed_s"], "source": out["source"]})
        signatures.add(_decisions_signature(dec))
        logger.info("  %s/%s run %d/%d : cov=%.0f%% correct=%d div=%d miss=%d P=%.2f R=%.2f",
                    app, mode, r, runs, 100 * cmp_cov(per_run[-1]),
                    cmp["correct"], cmp["divergent"], cmp["missed"],
                    cmp["precision"], cmp["recall"])

    def mean(k):
        vals = [pr[k] for pr in per_run if pr[k] is not None]
        return round(statistics.mean(vals), 3) if vals else None

    def pstdev(k):
        vals = [pr[k] for pr in per_run if pr[k] is not None]
        return round(statistics.pstdev(vals), 3) if len(vals) > 1 else 0.0

    risks = [pr["risk"] for pr in per_run]
    return {
        "runs": runs,
        "coverage_mean": mean("coverage"), "coverage_std": pstdev("coverage"),
        "missed_mean": mean("missed"), "divergent_mean": mean("divergent"),
        "correct_mean": mean("correct"),
        "div_flags_mean": mean("div_flags"), "div_score_mean": mean("div_score"),
        "precision_mean": mean("precision"), "recall_mean": mean("recall"),
        "risk_modes": risks, "risk_A": ref["analysis"].risk_level,
        "score_mean": mean("score"), "score_A": ref["analysis"].global_suspicion_score,
        "stable": len(signatures) == 1,
        "llm_calls_mean": mean("llm_calls"), "tool_calls_mean": mean("tool_calls"),
        "elapsed_mean": mean("elapsed_s"),
        "per_run": per_run,
    }


def cmp_cov(pr):
    return pr["coverage"]


def print_table(results: dict, downstream: dict | None):
    apps = list(results.keys())
    print("\n" + "=" * 110)
    print("  TABLEAU RÉCAPITULATIF — A vs B-det vs B-llm")
    print("=" * 110)
    hdr = (f"{'app':<11}{'cond':<7}{'cov%':>5}{'corr':>5}{'div':>5}{'miss':>5}"
           f"{'P':>6}{'R':>6}{'risk':>9}{'scoreΔ':>8}{'stab':>6}"
           f"{'LLM':>5}{'tool':>5}{'sec':>6}")
    print(hdr)
    print("-" * 110)
    for app in apps:
        ref = results[app]["_ref"]
        # Ligne A (référence)
        a = ref
        print(f"{app:<11}{'A':<7}{'100':>5}{'—':>5}{'—':>5}{'—':>5}"
              f"{'1.00':>6}{'1.00':>6}{a['risk']:>9}{a['score']:>8}{'—':>6}"
              f"{'0':>5}{'0':>5}{'~0':>6}")
        for cond in ("B-det", "B-llm"):
            d = results[app][cond]
            tot = a["total"]
            covpct = f"{100*d['coverage_mean']:.0f}" if d['coverage_mean'] is not None else "?"
            risk = d["risk_modes"][0] if d["risk_modes"] else "?"
            risk_disp = risk if all(r == risk for r in d["risk_modes"]) else "var"
            dscore = (round(d["score_mean"] - a["score"], 2)
                      if d["score_mean"] is not None else "?")
            stab = "oui" if d["stable"] else "NON"
            print(f"{'':<11}{cond:<7}{covpct:>5}{d['correct_mean']:>5}{d['divergent_mean']:>5}"
                  f"{d['missed_mean']:>5}{d['precision_mean']:>6}{d['recall_mean']:>6}"
                  f"{risk_disp:>9}{str(dscore):>8}{stab:>6}"
                  f"{d['llm_calls_mean']:>5}{d['tool_calls_mean']:>5}{d['elapsed_mean']:>6}")
        print("-" * 110)

    print("\n  Légende : cov%=couverture moyenne | corr/div/miss=destinations correctes/"
          "divergentes/manquées (moy.) | P,R=precision,recall flags vs A |")
    print("            scoreΔ=écart score global vs A | stab=3 runs identiques | "
          "LLM,tool=appels moyens | sec=temps moyen.")
    print("            (div doit être 0 pour B-det par construction ; >0 pour B-llm = "
          "erreur de raisonnement LLM.)")

    if downstream:
        print("\n" + "=" * 70)
        print("  AVAL (SecurityChain via graphe complet) — FW / IDS / IPS")
        print("=" * 70)
        print(f"{'app':<11}{'A (FW/IDS/IPS)':>18}{'B-det':>16}{'B-llm':>16}")
        for app in apps:
            ds = downstream.get(app, {})
            def fmt(c):
                x = ds.get(c)
                if not x:
                    return "—"
                if x.get("error"):
                    return f"err"
                return f"{x['fw']}/{x['ids']}/{x['ips']}"
            print(f"{app:<11}{fmt('A'):>18}{fmt('B-det'):>16}{fmt('B-llm'):>16}")

    # Synthèse stabilité
    print("\n  STABILITÉ globale (apps dont les 3 runs sont identiques) :")
    for cond in ("B-det", "B-llm"):
        n_stable = sum(1 for app in apps if results[app][cond]["stable"])
        print(f"    {cond:<7}: {n_stable}/{len(apps)} apps stables sur 3 runs")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    # Réduire le bruit des libs
    for noisy in ("httpx", "enrichment", "agents.chain_analyzer", "agents.chain_analyzer_b"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    ap = argparse.ArgumentParser()
    ap.add_argument("--apps", nargs="*", default=DEFAULT_APPS)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--no-downstream", action="store_true")
    ap.add_argument("--resume", action="store_true",
                    help="reprend depuis --out : saute les apps déjà complétées (économise les tokens).")
    ap.add_argument("--out", default=str(_ROOT / "benchmark" / "compare_results.json"))
    args = ap.parse_args()

    results: dict = {}
    if args.resume and pathlib.Path(args.out).exists():
        results = json.loads(pathlib.Path(args.out).read_text(encoding="utf-8"))
        logger.info("Reprise : %d app(s) déjà dans %s", len(results), args.out)
    downstream: dict = {}
    t0 = time.perf_counter()

    for app in args.apps:
        # Reprise : on saute une app si ses 2 conditions ont déjà `runs` runs.
        done = results.get(app, {})
        if (args.resume and "B-det" in done and "B-llm" in done
                and len(done["B-det"].get("per_run", [])) >= args.runs
                and len(done["B-llm"].get("per_run", [])) >= args.runs):
            logger.info("═══ APP %s déjà complétée (--resume) — saut", app)
            continue
        logger.info("═══════════ APP : %s ═══════════", app)
        ref = reference_A(app)
        results[app] = {"_ref": {"risk": ref["analysis"].risk_level,
                                 "score": ref["analysis"].global_suspicion_score,
                                 "total": len(ref["universe"])}}
        results[app]["B-det"] = eval_condition(app, ref, "deterministic", args.runs)
        results[app]["B-llm"] = eval_condition(app, ref, "llm", args.runs)
        # Sauvegarde incrémentale (résilience aux rate-limits)
        pathlib.Path(args.out).write_text(
            json.dumps(results, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    if not args.no_downstream:
        logger.info("═══════════ AVAL (graphe complet) ═══════════")
        for app in args.apps:
            downstream[app] = {}
            for cond in ("A", "B-det", "B-llm"):
                downstream[app][cond] = downstream_counts(app, cond)
            pathlib.Path(str(args.out).replace(".json", "_downstream.json")).write_text(
                json.dumps(downstream, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    print_table(results, downstream or None)
    print(f"\n  Durée totale : {round(time.perf_counter()-t0,1)}s — résultats : {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
