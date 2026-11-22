"""
enrichment/ — Couche d'ENRICHISSEMENT des automates bruts (DOT) → JSON exploitable
par le pipeline existant.

Module ISOLÉ : il ne modifie ni n'importe le pipeline (state.py, agents/, graph_*).
Il produira, à terme, un JSON au format attendu par _analyze_deterministic.

Étapes (implémentées une par une, validées séparément) :
  1. dot_parser    : parser les fichiers DOT (CETTE étape)
  2. csv_reader    : lire les flux CSV par application
  3. asn_resolver  : résoudre IP → ASN/org (offline-first)
  4. classifier    : classer chaque destination en 6 catégories
  5. json_builder  : assembler le JSON cible
"""
