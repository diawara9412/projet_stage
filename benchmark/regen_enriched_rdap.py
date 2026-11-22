#!/usr/bin/env python3
"""
benchmark/regen_enriched_rdap.py — Régénère les automates/*_enriched.json (Condition A)
avec RDAP activé (whois) et une ÉDITION RÉSEAU DATÉE FIGÉE, afin que A et B partagent
EXACTEMENT la même source de résolution (équité de la comparaison).

BGP reste OFF (seuil non calibré, invariance prouvée).
Réseau : RDAP uniquement (gratuit) ; aucun appel LLM. Le net_cache daté est sauvegardé
pour que les runs suivants (A régénéré ET B) rejouent le même snapshot, déterministe.

Lancer :  python3 benchmark/regen_enriched_rdap.py
"""

import json
import logging
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from enrichment.asn_resolver import AsnResolver
from enrichment.json_builder import build_automate_json
from agents.chain_analyzer_b import RDAP_ENABLED, BGP_ENABLED, EDITION_DATE

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("regen")

APPS = ["pokemongo", "dropbox", "disneyland", "faceswitch", "lequipe", "ratp", "viber"]


def main() -> int:
    # Résolveur PARTAGÉ entre apps → un seul net_cache daté, réutilisé/complété.
    resolver = AsnResolver(enable_rdap=RDAP_ENABLED, enable_bgp=BGP_ENABLED,
                           edition_date=EDITION_DATE)
    log.info("Source : RDAP=%s BGP=%s édition=%s | MaxMind=%s | net_cache=%d entrées",
             RDAP_ENABLED, BGP_ENABLED, EDITION_DATE, resolver.maxmind_status,
             resolver.net_cache_size)

    for app in APPS:
        try:
            js = build_automate_json(app, resolver=resolver, enable_rdap=RDAP_ENABLED,
                                     enable_bgp=BGP_ENABLED, edition_date=EDITION_DATE)
        except Exception as exc:
            log.error("%s : échec build (%s)", app, exc)
            continue
        out = _ROOT / "automates" / f"{app}_enriched.json"
        out.write_text(json.dumps(js, indent=2, ensure_ascii=False), encoding="utf-8")
        cc = js["metadata"]["category_counts"]
        log.info("%-11s → %d transitions | catégories=%s | src=%s",
                 app, len(js["transitions"]), cc, js["metadata"]["source"])
        resolver.save_net_cache()  # fige l'édition au fur et à mesure

    resolver.save_net_cache()
    log.info("net_cache figé : %d entrées (%s)", resolver.net_cache_size, EDITION_DATE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
