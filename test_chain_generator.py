#!/usr/bin/env python3
"""
test_chain_generator.py — Test standalone du ChainGenerator sur les 3 analyses.

Usage :
    python3 test_chain_generator.py

Charge les 3 analyses depuis chains/analysis_*.json, génère les chaînes de
sécurité correspondantes, les sauvegarde dans chains/chain_*.json, et affiche
un tableau récapitulatif.
"""

import json
import logging
import pathlib
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s",
)

from agents.chain_generator import chain_generator_node
from state import AutomateAnalysis, GraphState

CHAINS_DIR = pathlib.Path("chains")

ANALYSIS_FILES = [
    ("chains/analysis_pokemon_go_v1.json",  "pokemon_go"),
    ("chains/analysis_banking_app_v1.json", "banking_app"),
    ("chains/analysis_malware_app_v1.json", "malware_app"),
]


def _print_section(title: str) -> None:
    print(f"\n{'═' * 65}")
    print(f"  {title}")
    print('═' * 65)


def _load_analysis(path: str) -> AutomateAnalysis | None:
    """Charge une AutomateAnalysis depuis un fichier JSON."""
    p = pathlib.Path(path)
    if not p.exists():
        print(f"  ERREUR : fichier introuvable — {p}")
        return None
    with p.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return AutomateAnalysis.model_validate(data)


def _verify_chain(chain, app_key: str) -> list[str]:
    """Vérifie les conditions minimales selon l'application. Retourne les échecs."""
    failures: list[str] = []
    block = [r for r in chain.firewall_rules if r.action == "BLOCK"]
    allow = [r for r in chain.firewall_rules if r.action in ("ALLOW", "ALLOW_AND_INSPECT")]
    ids_types = {s.pattern_type for s in chain.ids_signatures}
    ips_types = {a.action for a in chain.ips_actions}

    if app_key == "pokemon_go":
        if len(block) < 2:
            failures.append(f"Attend ≥2 règles BLOCK, obtenu {len(block)}")
        if len(allow) < 6:
            failures.append(f"Attend ≥6 règles ALLOW, obtenu {len(allow)}")
        if "beaconing" not in ids_types:
            failures.append("Signature IDS 'beaconing' manquante")
        if "data_exfiltration" not in ids_types:
            failures.append("Signature IDS 'data_exfiltration' manquante")
        if len(chain.ips_actions) < 2:
            failures.append(f"Attend ≥2 actions IPS, obtenu {len(chain.ips_actions)}")

    elif app_key == "banking_app":
        if len(block) < 1:
            failures.append("Attend ≥1 règle BLOCK")
        if len(allow) < 4:
            failures.append(f"Attend ≥4 règles ALLOW, obtenu {len(allow)}")
        if "data_exfiltration" not in ids_types:
            failures.append("Signature IDS 'data_exfiltration' manquante")
        if "dga_dns" not in ids_types:
            failures.append("Signature IDS 'dga_dns' manquante")

    elif app_key == "malware_app":
        if len(block) < 2:
            failures.append(f"Attend ≥2 règles BLOCK (dédupliquées), obtenu {len(block)}")
        if len(allow) < 2:
            failures.append(f"Attend ≥2 règles ALLOW, obtenu {len(allow)}")
        expected_ids = {"beaconing", "tor_communication", "data_exfiltration", "dga_dns", "suspicious_url"}
        missing_ids = expected_ids - ids_types
        if missing_ids:
            failures.append(f"Signatures IDS manquantes : {missing_ids}")
        if "QUARANTINE" not in ips_types:
            failures.append("Action IPS QUARANTINE manquante (attendue car risque=HIGH)")

    return failures


def process_one(analysis_path: str, app_key: str) -> dict | None:
    """Génère et sauvegarde la chaîne pour une analyse."""
    _print_section(f"{app_key.upper()} — {analysis_path}")

    analysis = _load_analysis(analysis_path)
    if analysis is None:
        return None

    print(f"  Application  : {analysis.app_name}")
    print(f"  Risque       : {analysis.risk_level.upper()} (score={analysis.global_suspicion_score:.2f})")
    print(f"  Suspects     : {analysis.nb_suspicious} transition(s)")

    state = GraphState(
        user_request=f"Générer la chaîne de sécurité pour {analysis.app_name}",
        automate_analysis=analysis,
    )

    updates = chain_generator_node(state)
    if not updates or "security_chain" not in updates:
        print("  ERREUR : aucune chaîne produite")
        return None

    chain = updates["security_chain"]

    # Statistiques
    block = [r for r in chain.firewall_rules if r.action == "BLOCK"]
    allow = [r for r in chain.firewall_rules if r.action in ("ALLOW", "ALLOW_AND_INSPECT")]
    print(f"\n  Résultats :")
    print(f"    Firewall BLOCK    : {len(block)}")
    print(f"    Firewall ALLOW    : {len(allow)}")
    print(f"    Signatures IDS    : {len(chain.ids_signatures)}")
    print(f"    Actions IPS       : {len(chain.ips_actions)}")
    print(f"    Risque global     : {chain.global_risk_level}")

    # Détail des règles BLOCK
    print(f"\n  Règles BLOCK :")
    for r in block:
        print(f"    [{r.id}] {r.dst_ip}:{r.dst_port}/{r.protocol} priorité={r.priority}")
    if not block:
        print("    (aucune)")

    # Détail IDS + IPS
    print(f"\n  Signatures IDS / Actions IPS :")
    ips_by_sig = {a.on_signature: a for a in chain.ips_actions}
    for s in chain.ids_signatures:
        ips_a = ips_by_sig.get(s.id)
        ips_str = f"→ {ips_a.action}" if ips_a else "→ (pas d'action)"
        print(f"    [{s.id}] {s.severity:8s} {s.pattern_type:20s} {ips_str}")

    # Résumé LLM
    print(f"\n  Résumé : {chain.generation_summary[:160]}{'…' if len(chain.generation_summary) > 160 else ''}")

    # Vérification des conditions
    failures = _verify_chain(chain, app_key)
    if failures:
        print(f"\n  ⚠ VÉRIFICATIONS ÉCHOUÉES :")
        for f in failures:
            print(f"    ✗ {f}")
    else:
        print(f"\n  ✓ Toutes les vérifications passées")

    # Sauvegarde
    out_path = CHAINS_DIR / f"chain_{app_key}.json"
    CHAINS_DIR.mkdir(exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(chain.model_dump(), fh, indent=2, ensure_ascii=False)
    print(f"  Chaîne exportée → {out_path}")

    return {
        "app": analysis.app_name,
        "risk": chain.global_risk_level,
        "block": len(block),
        "allow": len(allow),
        "ids": len(chain.ids_signatures),
        "ips": len(chain.ips_actions),
        "ok": not failures,
    }


def main() -> None:
    print("\n ChainGenerator — Génération des 3 chaînes de sécurité")

    results = []
    for analysis_path, app_key in ANALYSIS_FILES:
        r = process_one(analysis_path, app_key)
        if r:
            results.append(r)

    # Tableau récapitulatif
    _print_section("TABLEAU RÉCAPITULATIF")
    print(f"  {'Application':<35} {'Risque':<8} {'BLOCK':<6} {'ALLOW':<6} {'IDS':<5} {'IPS':<5} {'Statut'}")
    print(f"  {'-'*35} {'-'*8} {'-'*6} {'-'*6} {'-'*5} {'-'*5} {'-'*8}")
    all_ok = True
    for r in results:
        status = "✓ OK" if r["ok"] else "✗ FAIL"
        if not r["ok"]:
            all_ok = False
        print(
            f"  {r['app']:<35} {r['risk']:<8} {r['block']:<6} {r['allow']:<6} "
            f"{r['ids']:<5} {r['ips']:<5} {status}"
        )

    print()
    if all_ok:
        print("  ✓ Toutes les chaînes générées avec succès.")
    else:
        print("  ✗ Certaines vérifications ont échoué (voir détails ci-dessus).")
        sys.exit(1)
    print()


if __name__ == "__main__":
    main()
