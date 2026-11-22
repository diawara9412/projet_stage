#!/usr/bin/env python3
"""
benchmark/enrich_b.py — Enrichissement PAR L'ARCHITECTURE (Condition B).

L'Analyzer-B (bind_tools, LLM ; repli déterministe si pas de quota) enrichit lui-même
les traces brutes et SAUVEGARDE un JSON enrichi au MÊME SCHÉMA que le pipeline (A),
dans automates/<app>_enriched_b.json (stockage SÉPARÉ — n'écrase JAMAIS les A).

Ces fichiers _b sont ensuite évaluables (benchmark/eval_supervisor.py --variant b) et
déployables (run_supervisor_test.py --automate <app>_enriched_b) sans modification.

NE TOUCHE PAS à enrichment/ ni aux automates/*_enriched.json (Condition A).

Usage :
    python3 benchmark/enrich_b.py ratp              # une app
    python3 benchmark/enrich_b.py                   # les 7 apps
    python3 benchmark/enrich_b.py ratp pokemongo    # sous-ensemble
"""

import json
import logging
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agents.chain_analyzer_b import enrich_app_b

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("enrich_b")

ALL_APPS = ["pokemongo", "dropbox", "disneyland", "faceswitch", "lequipe", "ratp", "viber"]


def main() -> int:
    apps = sys.argv[1:] or ALL_APPS
    print("=" * 70)
    print("  ENRICHISSEMENT PAR L'ARCHITECTURE (Analyzer-B) — Condition B")
    print(f"  apps : {apps}")
    print("  ⚠️ utilise le LLM (bind_tools) ; repli déterministe si pas de quota Groq.")
    print("=" * 70)

    for app in apps:
        out_path = _ROOT / "automates" / f"{app}_enriched_b.json"
        try:
            res = enrich_app_b(app)
        except Exception as exc:
            log.error("%s : échec enrichissement (%s)", app, exc)
            continue
        out_path.write_text(json.dumps(res["enriched"], indent=2, ensure_ascii=False),
                            encoding="utf-8")
        cov = res["coverage"]
        cc = res["enriched"]["metadata"]["category_counts"]
        print(f"  ✅ {app:<11} → {out_path.name}  "
              f"couverture={cov['classified']}/{cov['total']} ({100*cov['ratio']:.0f}%)  "
              f"catégories={cc}  source={res['source']}")
        print(f"     paquets={res.get('n_chunks')}  appels_LLM={res.get('llm_calls')}  "
              f"tool_calls={res.get('tool_calls')}  temps={res.get('elapsed_s')}s")
        if cov["missed"]:
            print(f"     ⚠️ destinations NON enrichies par l'architecture : {cov['missed']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
