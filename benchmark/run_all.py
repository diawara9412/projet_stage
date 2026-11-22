#!/usr/bin/env python3
"""
benchmark/run_all.py — Tableau croisé : 3 automates × 2 architectures.

Orchestrateur qui RÉUTILISE les briques existantes (ne modifie aucun script) :
  - build_phase2_graph (archi 1, pipeline linéaire) / build_supervisor_graph (archi 2)
  - benchmark/llm_counter (appels LLM + tokens + détection 401), mêmes sources
    que count_llm_calls.py
  - perf_counter pour la latence (comme test_complex_automates.py)

Métriques par (automate × architecture) :
  - nb règles FW / IDS / IPS (depuis security_chain)
  - doublons / orphelins / score : SOURCE UNIFIÉE = validation_report (validate_chain),
    présent dans les DEUX architectures → comparaison stricte
  - colonnes SUPPLÉMENTAIRES pour l'archi 2 : doublons/orphelins vus par les OUTILS
    des agents (check_redundancy / check_orphan_references) → montre la concordance
  - appels LLM, latence (s), tokens (N/A si non fournis)

Options :
  --runs N            répète chaque (automate×archi) N fois (stabilité)
  --automate <nom>    cible un seul automate (ex: malware_app)
  --arch 1|2|both     cible une seule architecture
  --yes               ne pas demander confirmation (quota Groq)

Sorties : tableau terminal + benchmark/results_all.json

Garde-fou quota : si un 401 / clé invalide / quota épuisé est détecté, on ARRÊTE
tout immédiatement (pas de boucle de retry).
"""

import argparse
import datetime
import json
import logging
import pathlib
import sys
import time

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import warnings
warnings.filterwarnings("ignore")

from benchmark.llm_counter import install, reset, snapshot, token_snapshot, had_auth_error

install()  # enveloppe ChatGroq.invoke AVANT toute exécution

from graph_phase2 import build_phase2_graph
from architectures.supervisor.graph_supervisor import build_supervisor_graph
from state import GraphState
from architectures.supervisor.supervisor_agent import SupervisorState

_ALL_AUTOMATES = ["pokemon_go", "banking_app", "malware_app"]
# Appels LLM estimés par run : archi 1 ≈ 3 (résumés), archi 2 ≈ 4 (décisions).
_EST_CALLS = {1: 3, 2: 4}


def _get(result, field):
    if isinstance(result, dict):
        return result.get(field)
    return getattr(result, field, None)


def _f(obj, name, default=None):
    if obj is None:
        return default
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def _extract_metrics(result) -> dict:
    """Extrait les métriques d'un run. SOURCE UNIFIÉE = validation_report."""
    chain = _get(result, "security_chain")
    fw = _f(chain, "firewall_rules") or []
    ids = _f(chain, "ids_signatures") or []
    ips = _f(chain, "ips_actions") or []

    # ── Source UNIFIÉE (les 2 archis) : validate_chain → validation_report ──
    vr = _get(result, "validation_report")
    issues = _f(vr, "issues") or []

    def _cat(c):
        return sum(1 for i in issues if _f(i, "category") == c)

    dup_vc = _cat("redundancy")
    orph_vc = _cat("orphan_reference")
    score = _f(vr, "quality_score")

    # ── Source AGENTS (archi 2 uniquement) : outils check_* ────────────────
    fwr = _get(result, "firewall_verification_report")
    idsr = _get(result, "ids_verification_report")
    ipsr = _get(result, "ips_verification_report")
    dup_ag = orph_ag = None
    if fwr or idsr or ipsr:
        def n(rep, k):
            return len((rep or {}).get(k, []) or [])
        dup_ag = n(fwr, "redundancies") + n(idsr, "redundancies") + n(ipsr, "redundancies")
        orph_ag = n(ipsr, "orphans")

    # ── Boucle de correction + erreurs LLM AVANT correction (archi 2) ───────
    attempts_max = 0
    eb = {"doublons": 0, "hallucinations": 0, "orphelins": 0, "actions_invalides": 0,
          "champs_manquants": 0, "conflits": 0, "couverture": 0, "lan_manquantes": 0}
    eb_total = 0
    for fld in ("firewall_verification_report", "ids_verification_report", "ips_verification_report"):
        rep = _get(result, fld) or {}
        attempts_max = max(attempts_max, rep.get("attempts", 0) or 0)
        d = rep.get("errors_before_correction") or {}
        eb["doublons"] += d.get("redundancies", 0)
        eb["hallucinations"] += d.get("hallucinations", 0)
        eb["orphelins"] += d.get("orphans", 0)
        eb["actions_invalides"] += d.get("invalid_actions", 0)
        eb["champs_manquants"] += d.get("missing_fields", 0)
        eb["conflits"] += d.get("conflicts", 0)
        eb["couverture"] += d.get("coverage", 0)
        eb["lan_manquantes"] += d.get("lan_problems", 0)
        eb_total += int(rep.get("total_erreurs_llm_avant_correction", 0) or 0)

    # Détail par agent (messages exacts) pour l'export JSON et le log
    detail_by_agent: dict = {}
    for fld, name in (("firewall_verification_report", "firewall"),
                      ("ids_verification_report", "ids"),
                      ("ips_verification_report", "ips")):
        d = (_get(result, fld) or {}).get("errors_before_correction_detail") or {}
        if d:
            detail_by_agent[name] = d

    return {
        "nb_fw": len(fw), "nb_ids": len(ids), "nb_ips": len(ips),
        "dup_vc": dup_vc, "orph_vc": orph_vc, "score": score,
        "dup_ag": dup_ag, "orph_ag": orph_ag,
        "attempts_max": attempts_max,
        "errors_before": eb,
        "errors_before_total": eb_total,
        "errors_before_detail": detail_by_agent,
        "fingerprint": (len(fw), len(ids), len(ips), dup_vc, orph_vc, score),
    }


def _run_once(arch: int, automate_path: pathlib.Path) -> dict:
    """Lance une fois (archi, automate). Mesure latence + LLM + tokens."""
    if arch == 1:
        graph = build_phase2_graph(include_deployer=False)  # dry-run, pas de réseau
        state = GraphState(user_request="benchmark run_all", automate_path=str(automate_path))
    else:
        graph = build_supervisor_graph(deploy=False)
        state = SupervisorState(user_request="benchmark run_all", automate_path=str(automate_path))

    reset()
    t0 = time.perf_counter()
    result = graph.invoke(state)
    dt = time.perf_counter() - t0
    calls, _by = snapshot()
    toks = token_snapshot()

    m = _extract_metrics(result)
    m.update({"llm_calls": calls, "latency": dt, "tokens": toks})
    return m


def _aggregate(runs: list[dict]) -> dict:
    """Agrège N runs : moyennes + indicateur de stabilité."""
    k = len(runs)
    avg = lambda key: sum(r[key] for r in runs) / k
    fps = {r["fingerprint"] for r in runs}
    tokens_avail = any(r["tokens"]["available"] for r in runs)
    avg_tokens = (sum(r["tokens"]["total"] for r in runs) / k) if tokens_avail else None
    # dup/orph/score : on prend le run 1 comme représentatif (entiers) + stable flag
    rep = runs[0]
    return {
        "nb_fw": rep["nb_fw"], "nb_ids": rep["nb_ids"], "nb_ips": rep["nb_ips"],
        "dup_vc": rep["dup_vc"], "orph_vc": rep["orph_vc"], "score": rep["score"],
        "dup_ag": rep["dup_ag"], "orph_ag": rep["orph_ag"],
        "llm_calls": avg("llm_calls"),
        "latency": avg("latency"),
        "tokens": avg_tokens,
        "stable": len(fps) == 1,
        "n_distinct": len(fps),
        "runs": k,
    }


def _print_table(rows: list[dict]) -> None:
    print("\n" + "=" * 110)
    print("  TABLEAU CROISÉ — 3 automates × 2 architectures")
    print("  (doublons/orphelins/score = source UNIFIÉE validate_chain ; "
          "tokens N/A si non fournis)")
    print("=" * 110)
    h = (f"  {'Automate':<12}{'Arch':>5}{'FW/IDS/IPS':>12}{'dup':>5}{'orph':>5}"
         f"{'score':>7}{'LLM':>5}{'lat(s)':>8}{'tokens':>9}{'stable':>9}{'dup/orph(agents)':>18}")
    print(h)
    print("  " + "-" * 106)
    for r in rows:
        a = r["agg"]
        prod = f"{a['nb_fw']}/{a['nb_ids']}/{a['nb_ips']}"
        score = "—" if a["score"] is None else f"{a['score']}"
        toks = "N/A" if a["tokens"] is None else f"{a['tokens']:.0f}"
        # Avec un seul run, la stabilité n'est pas mesurable → "n=1" (et non "stable").
        if a["runs"] < 2:
            stable = "n=1"
        else:
            stable = "stable" if a["stable"] else f"var {a['n_distinct']}/{a['runs']}"
        if a["dup_ag"] is None:
            agents = "—"  # archi 1 : pas d'outils d'agent
        else:
            agents = f"{a['dup_ag']}/{a['orph_ag']}"
        print(f"  {r['automate']:<12}{r['arch']:>5}{prod:>12}{a['dup_vc']:>5}{a['orph_vc']:>5}"
              f"{score:>7}{a['llm_calls']:>5.0f}{a['latency']:>8.1f}{toks:>9}{stable:>9}{agents:>18}")
    print("=" * 110)
    print("  'dup/orph(agents)' = doublons/orphelins vus par les outils des agents "
          "(archi 2 seulement) ; doivent concorder avec dup/orph (validate_chain).")


def _write_log(raw_runs: list[dict]) -> pathlib.Path:
    """Écrit un log lisible par invocation : détail des fautes LLM avant correction."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = _PROJECT_ROOT / "benchmark" / "logs"
    log_dir.mkdir(exist_ok=True)
    path = log_dir / f"run_{ts}.txt"
    with path.open("w", encoding="utf-8") as fh:
        fh.write(f"Détail des erreurs LLM AVANT correction — {ts}\n")
        fh.write("=" * 70 + "\n\n")
        for r in raw_runs:
            fh.write(f"=== archi {r['arch']} | {r['automate']} | run {r['run']} "
                     f"| total_avant_corr={r.get('errors_before_total', 0)} "
                     f"| attempts(max)={r.get('attempts_max', 0)} ===\n")
            detail = r.get("errors_before_detail") or {}
            if not detail:
                fh.write("  (aucune erreur LLM avant correction)\n")
            for agent, cats in detail.items():
                for cat, msgs in cats.items():
                    for m in msgs:
                        fh.write(f"  [{agent}][{cat}] {m}\n")
            fh.write("\n")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark croisé automates × architectures")
    parser.add_argument("--runs", type=int, default=1, help="répétitions par (automate×archi)")
    parser.add_argument("--automate", default=None, help="cibler un seul automate (ex: malware_app)")
    parser.add_argument("--arch", choices=["1", "2", "both"], default="both", help="cibler une archi")
    parser.add_argument("--yes", action="store_true", help="ne pas demander confirmation")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    # ── Sélection des automates / architectures ─────────────────────────────
    names = [args.automate] if args.automate else _ALL_AUTOMATES
    automates = []
    for n in names:
        p = _PROJECT_ROOT / "automates" / f"{n}.json"
        if p.exists():
            automates.append((n, p))
        else:
            print(f"⚠️ Automate introuvable, ignoré : {p}")
    if not automates:
        print("❌ Aucun automate valide.")
        return 1
    archs = [1, 2] if args.arch == "both" else [int(args.arch)]

    # ── Estimation quota + confirmation ─────────────────────────────────────
    est = sum(_EST_CALLS[a] for a in archs) * len(automates) * args.runs
    print("=" * 70)
    print("  BENCHMARK run_all — automates × architectures")
    print("=" * 70)
    print(f"  Automates : {[n for n, _ in automates]}")
    print(f"  Archis    : {archs}   Runs : {args.runs}")
    print(f"  Appels LLM estimés ≈ {est} (archi1≈3/run, archi2≈4/run)")
    print("=" * 70)
    if not args.yes:
        if input("  Lancer ? [o/N] ").strip().lower() not in ("o", "oui", "y", "yes"):
            print("  Annulé.")
            return 0

    # ── Exécution ────────────────────────────────────────────────────────────
    rows: list[dict] = []
    raw_runs: list[dict] = []
    aborted = False
    for arch in archs:
        for name, path in automates:
            print(f"\n### Archi {arch} — {name}")
            runs: list[dict] = []
            for r in range(1, args.runs + 1):
                try:
                    m = _run_once(arch, path)
                except Exception as exc:
                    logging.error("  run %d ÉCHOUÉ (%s)", r, exc)
                    if had_auth_error():
                        aborted = True
                    break
                runs.append(m)
                raw_runs.append({"arch": arch, "automate": name, "run": r, **{k: v for k, v in m.items() if k != "fingerprint"}})
                toks = "N/A" if not m["tokens"]["available"] else m["tokens"]["total"]
                print(f"  run {r}/{args.runs} : {m['nb_fw']}/{m['nb_ids']}/{m['nb_ips']} FW/IDS/IPS "
                      f"| dup={m['dup_vc']} orph={m['orph_vc']} score={m['score']} "
                      f"| LLM={m['llm_calls']} | {m['latency']:.1f}s | tokens={toks}")
                _eb = m["errors_before"]
                print(f"           ↳ attempts(max)={m['attempts_max']} | "
                      f"err_LLM_avant_corr={m['errors_before_total']} "
                      f"(dup={_eb['doublons']}, hall={_eb['hallucinations']}, "
                      f"orph={_eb['orphelins']}, inval={_eb['actions_invalides']}, "
                      f"champs={_eb['champs_manquants']}, couv={_eb['couverture']})")
                # ── Garde-fou 401 : on arrête TOUT ──────────────────────────
                if had_auth_error():
                    print("\n  ⛔ ERREUR D'AUTHENTIFICATION GROQ (401 / clé invalide / quota).")
                    print("     Arrêt immédiat, aucune relance. Vérifie ta clé / ton quota.")
                    aborted = True
                    break
            if runs:
                rows.append({"automate": name, "arch": arch, "agg": _aggregate(runs)})
            if aborted:
                break
        if aborted:
            break

    # ── Tableau + export (même partiel) ─────────────────────────────────────
    if rows:
        _print_table(rows)
    out = _PROJECT_ROOT / "benchmark" / "results_all.json"
    with out.open("w", encoding="utf-8") as fh:
        json.dump({"aborted_on_auth_error": aborted, "rows": rows, "raw_runs": raw_runs},
                  fh, indent=2, ensure_ascii=False, default=str)
    print(f"\n  Export → {out}")
    log_path = _write_log(raw_runs)
    print(f"  Log détaillé → {log_path}")

    if aborted:
        print("  (Résultats PARTIELS — interrompu sur erreur d'authentification.)")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
