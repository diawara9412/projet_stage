#!/usr/bin/env python3
"""
test_chain_validator.py — Test standalone du ChainValidator.

Tests :
  1. Validation des 3 chaînes correctes (pokemon_go, banking_app, malware_app)
  2. Validation d'une chaîne intentionnellement défectueuse (chain_BROKEN_test)

Usage :
    python3 test_chain_validator.py
"""

import json
import logging
import pathlib
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s",
)

from agents.chain_validator import chain_validator_node
from state import (
    FirewallRule, GraphState, IdsSignature, IpsAction,
    SecurityChain, ValidationReport,
)

CHAINS_DIR = pathlib.Path("chains")

CHAIN_FILES = [
    ("chains/chain_pokemon_go.json",  "pokemon_go"),
    ("chains/chain_banking_app.json", "banking_app"),
    ("chains/chain_malware_app.json", "malware_app"),
]


def _print_section(title: str) -> None:
    print(f"\n{'═' * 65}")
    print(f"  {title}")
    print('═' * 65)


def _load_chain(path: str) -> SecurityChain | None:
    p = pathlib.Path(path)
    if not p.exists():
        print(f"  ERREUR : fichier introuvable — {p}")
        return None
    with p.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return SecurityChain.model_validate(data)


def _check_minimums(report: ValidationReport, app_key: str) -> list[str]:
    """Vérifie les conditions minimales attendues par application."""
    failures: list[str] = []
    if app_key in ("pokemon_go", "banking_app"):
        if report.quality_score < 80:
            failures.append(f"Attend quality_score ≥ 80, obtenu {report.quality_score}")
        if not report.is_valid:
            failures.append("Attend is_valid=True (aucune ERROR)")
    elif app_key == "malware_app":
        if report.quality_score < 70:
            failures.append(f"Attend quality_score ≥ 70, obtenu {report.quality_score}")
    elif app_key == "BROKEN_test":
        nb_errors = sum(1 for i in report.issues if i.severity == "ERROR")
        if report.is_valid:
            failures.append("Attend is_valid=False (des ERRORs doivent être détectées)")
        if report.quality_score >= 60:
            failures.append(f"Attend quality_score < 60, obtenu {report.quality_score}")
        if nb_errors < 2:
            failures.append(f"Attend ≥ 2 ERRORs, obtenu {nb_errors}")
    return failures


def process_one(chain_path: str, app_key: str) -> dict | None:
    _print_section(f"{app_key.upper()} — {chain_path}")

    chain = _load_chain(chain_path)
    if chain is None:
        return None

    print(f"  Chaîne      : {chain.chain_id}")
    print(f"  App         : {chain.source_app_name}")
    print(f"  Risque      : {chain.global_risk_level}")
    print(f"  FW rules    : {len(chain.firewall_rules)} | IDS : {len(chain.ids_signatures)} | IPS : {len(chain.ips_actions)}")

    state = GraphState(
        user_request=f"Valider la chaîne de sécurité pour {chain.source_app_name}",
        security_chain=chain,
    )

    updates = chain_validator_node(state)
    if not updates or "validation_report" not in updates:
        print("  ERREUR : aucun rapport produit")
        return None

    corrected: SecurityChain = updates["security_chain"]
    report: ValidationReport = updates["validation_report"]

    # ── Résultats ──────────────────────────────────────────────────────────
    print(f"\n  Score qualité   : {report.quality_score}/100")
    print(f"  is_valid        : {report.is_valid}")
    nb_e = report.stats.get("nb_errors", 0)
    nb_w = report.stats.get("nb_warnings", 0)
    nb_dup = report.stats.get("duplicates_removed", 0)
    print(f"  Erreurs         : {nb_e} | Avertissements : {nb_w}")
    print(f"  Doublons supprimés : {nb_dup}")

    # Top 3 issues
    top = report.issues[:3]
    if top:
        print(f"\n  Problèmes détectés (top {len(top)}) :")
        for issue in top:
            icon = "✗" if issue.severity == "ERROR" else "⚠"
            print(f"    {icon} [{issue.severity}] [{issue.category}] {issue.message}")
            if issue.suggested_fix:
                print(f"       → {issue.suggested_fix}")
    else:
        print("\n  Aucun problème détecté.")

    print(f"\n  Résumé : {report.validation_summary[:180]}{'…' if len(report.validation_summary) > 180 else ''}")

    # Vérifications
    failures = _check_minimums(report, app_key)
    if failures:
        print(f"\n  ⚠ VÉRIFICATIONS ÉCHOUÉES :")
        for f in failures:
            print(f"    ✗ {f}")
    else:
        print(f"\n  ✓ Toutes les vérifications passées")

    # Sauvegarde chaîne corrigée
    CHAINS_DIR.mkdir(exist_ok=True)
    validated_path = CHAINS_DIR / f"validated_chain_{app_key}.json"
    with validated_path.open("w", encoding="utf-8") as fh:
        json.dump(corrected.model_dump(), fh, indent=2, ensure_ascii=False)
    print(f"  Chaîne corrigée  → {validated_path}")

    # Sauvegarde rapport
    report_path = CHAINS_DIR / f"validation_{app_key}.json"
    with report_path.open("w", encoding="utf-8") as fh:
        json.dump(report.model_dump(), fh, indent=2, ensure_ascii=False)
    print(f"  Rapport          → {report_path}")

    return {
        "app": chain.source_app_name,
        "score": report.quality_score,
        "valid": report.is_valid,
        "errors": nb_e,
        "warnings": nb_w,
        "dups": nb_dup,
        "ok": not failures,
    }


def create_broken_chain() -> str:
    """Crée chains/chain_BROKEN_test.json avec des erreurs volontaires."""
    path = CHAINS_DIR / "chain_BROKEN_test.json"
    if path.exists():
        return str(path)

    # Construire via les modèles Pydantic pour garantir un JSON valide structurellement
    chain = SecurityChain(
        chain_id="chain_broken_test",
        source_automate_id="broken_test",
        source_app_name="Broken Test App",
        generated_at="2024-04-16T08:00:00Z",
        global_risk_level="HIGH",
        firewall_rules=[
            FirewallRule(
                id="FW-001",
                action="BLOCK",
                direction="outbound",
                dst_ip="192.168.1.100",
                dst_port=80,
                protocol="HTTP",
                priority=900,
                source_transition_id=None,
                comment="BLOCK l'IP suspecte",
            ),
            FirewallRule(
                id="FW-002",
                action="ALLOW",
                direction="outbound",
                dst_ip="192.168.1.100",  # CONFLICT avec FW-001 : même IP
                dst_port=80,
                protocol="HTTP",
                priority=100,
                source_transition_id=None,
                comment="CONFLIT : ALLOW sur la même IP que FW-001",
            ),
            FirewallRule(
                id="FW-003",
                action="BLOCK",
                direction="outbound",
                dst_ip="10.0.0.5",
                dst_port=443,
                protocol="HTTPS",
                priority=900,
                source_transition_id=None,
                comment="BLOCK IP secondaire",
            ),
            FirewallRule(
                id="FW-004",
                action="BLOCK",
                direction="outbound",
                dst_ip="10.0.0.5",   # REDONDANCE : doublon exact de FW-003
                dst_port=443,
                protocol="HTTPS",
                priority=900,
                source_transition_id=None,
                comment="REDONDANCE : doublon exact de FW-003",
            ),
        ],
        ids_signatures=[
            IdsSignature(
                id="IDS-001",
                name="TEST_BEACONING_192_168_1_100_80",
                pattern_type="beaconing",
                match_criteria={"dst_ip": "192.168.1.100", "frequency_threshold_per_min": 6},
                severity="HIGH",
                source_transition_id=None,
                comment="Signature de test valide",
            ),
        ],
        ips_actions=[
            IpsAction(
                id="IPS-001",
                on_signature="IDS-001",   # référence valide
                action="ALERT_ONLY",
                duration_seconds=None,
                rate_limit_pps=None,
                comment="Action valide sur IDS-001",
            ),
            IpsAction(
                id="IPS-002",
                on_signature="IDS-999",   # ORPHELIN : IDS-999 n'existe pas
                action="DROP_SOURCE",
                duration_seconds=None,
                rate_limit_pps=None,
                comment="ORPHELIN : référence vers IDS-999 inexistant",
            ),
        ],
        deployment_target={"ryu_endpoint": "http://localhost:8080"},
        generation_summary="Chaîne de test intentionnellement défectueuse.",
    )

    CHAINS_DIR.mkdir(exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(chain.model_dump(), fh, indent=2, ensure_ascii=False)
    print(f"\n  Chaîne défectueuse créée → {path}")
    return str(path)


def main() -> None:
    print("\n ChainValidator — Test sur les 3 chaînes correctes + 1 chaîne cassée")

    results = []

    # ── Tests normaux ──────────────────────────────────────────────────────
    for chain_path, app_key in CHAIN_FILES:
        r = process_one(chain_path, app_key)
        if r:
            results.append(r)

    # ── Test chaîne défectueuse ────────────────────────────────────────────
    _print_section("CRÉATION ET VALIDATION DE LA CHAÎNE DÉFECTUEUSE")
    broken_path = create_broken_chain()
    r_broken = process_one(broken_path, "BROKEN_test")
    if r_broken:
        results.append(r_broken)

    # ── Tableau récapitulatif ──────────────────────────────────────────────
    _print_section("TABLEAU RÉCAPITULATIF")
    print(f"  {'Application':<35} {'Score':>5} {'Valid':<6} {'Err':<4} {'Warn':<5} {'Dup':<4} {'Statut'}")
    print(f"  {'-'*35} {'-----':>5} {'------':<6} {'----':<4} {'-----':<5} {'----':<4} {'--------'}")
    all_ok = True
    for r in results:
        status = "✓ OK" if r["ok"] else "✗ FAIL"
        if not r["ok"]:
            all_ok = False
        print(
            f"  {r['app']:<35} {r['score']:>5} "
            f"{'Oui' if r['valid'] else 'Non':<6} "
            f"{r['errors']:<4} {r['warnings']:<5} {r['dups']:<4} {status}"
        )

    print()
    if all_ok:
        print("  ✓ Tous les tests passés avec succès.")
    else:
        print("  ✗ Certains tests ont échoué (voir détails ci-dessus).")
        sys.exit(1)
    print()


if __name__ == "__main__":
    main()
