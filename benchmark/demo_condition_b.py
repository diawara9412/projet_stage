#!/usr/bin/env python3
"""
benchmark/demo_condition_b.py — Démo d'UNE app en Condition B-det, comparée à A.

Condition A : lit automates/<app>_enriched.json (pipeline hors-ligne) → _analyze_deterministic.
Condition B-det : Analyzer-B (tool-calling LLM) → assemblage déterministe.

Affiche : couverture, flags par IP (A vs B), catégories/risque/score, et le diff.

Lancer :  python3 benchmark/demo_condition_b.py [app]   (défaut: pokemongo)
"""

import json
import logging
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agents.chain_analyzer import _analyze_deterministic
from agents.chain_analyzer_b import run_analyzer_b


def _analysis_A(app: str):
    """Condition A : analyse du JSON enrichi déjà produit par le pipeline."""
    path = _ROOT / "automates" / f"{app}_enriched.json"
    automate = json.loads(path.read_text(encoding="utf-8"))
    return _analyze_deterministic(automate)


def _flags_by_ip(analysis) -> dict[str, list[str]]:
    return {t.dst_ip: sorted(t.flags) for t in analysis.suspicious_transitions}


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    app = sys.argv[1] if len(sys.argv) > 1 else "pokemongo"

    print("=" * 74)
    print(f"  DÉMO Condition B-det vs A — app = {app}")
    print("=" * 74)

    # ── Condition A ──────────────────────────────────────────────────────────
    a = _analysis_A(app)
    print(f"\n[A] enriched.json : {a.nb_transitions} transitions, "
          f"{a.nb_suspicious} suspectes, risque={a.risk_level}, "
          f"score={a.global_suspicion_score}")

    # ── Condition B-det ──────────────────────────────────────────────────────
    out = run_analyzer_b(app, assembly_mode="deterministic")
    b = out["automate_analysis"]
    cov = out["coverage"]
    print(f"\n[B-det] source={out['source']} steps={out['steps']} "
          f"tool_calls={out['tool_calls']}")
    print(f"        COUVERTURE = {cov['classified']}/{cov['total']} "
          f"({100*cov['ratio']:.0f}%)" + (f"  MANQUÉES={cov['missed']}" if cov['missed'] else ""))
    if b is None:
        print("  ❌ B-det n'a produit aucune analyse.")
        return 1
    print(f"        {b.nb_transitions} transitions, {b.nb_suspicious} suspectes, "
          f"risque={b.risk_level}, score={b.global_suspicion_score}")

    # ── Comparaison flags par IP ─────────────────────────────────────────────
    fa, fb = _flags_by_ip(a), _flags_by_ip(b)
    ips = sorted(set(fa) | set(fb))
    print(f"\n  Comparaison des flags par IP suspecte ({len(ips)} IP) :")
    n_match = n_diff = 0
    for ip in ips:
        va, vb = fa.get(ip), fb.get(ip)
        if va == vb:
            n_match += 1
            continue
        n_diff += 1
        print(f"    ✗ {ip:<18} A={va}  B={vb}")
    print(f"    → {n_match} identiques, {n_diff} différentes")

    # ── Verdict ──────────────────────────────────────────────────────────────
    full_cov = cov["ratio"] == 1.0
    same_risk = a.risk_level == b.risk_level
    same_susp = a.nb_suspicious == b.nb_suspicious
    print("\n" + "=" * 74)
    if full_cov and n_diff == 0 and same_risk and same_susp:
        print("  ✅ B-det == A : couverture pleine, flags/risque/suspectes identiques.")
    else:
        print(f"  ⚠️ Écarts : couverture_pleine={full_cov}, flags_diff={n_diff}, "
              f"même_risque={same_risk}, mêmes_suspectes={same_susp}")
        print("     (attendu si le LLM a sauté des destinations — c'est le signal mesuré.)")
    print("=" * 74)
    if b.llm_summary:
        print("\n  Synthèse MITRE (LLM) :\n  " + b.llm_summary[:400])
    return 0


if __name__ == "__main__":
    sys.exit(main())
