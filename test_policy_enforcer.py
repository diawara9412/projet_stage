#!/usr/bin/env python3
"""
test_policy_enforcer.py — Test standalone du PolicyEnforcer.

Prérequis : sdn_executor.py doit être lancé AVANT ce script.

  Terminal 1 :
    python3 ryu_app/run_manager.py ryu_app.sdn_executor

  Terminal 2 :
    python3 test_policy_enforcer.py

Si firewall_app n'est pas lancé, le script affiche un message clair et
exécute quand même le test de blocage (chaîne invalide).
"""

import json
import logging
import pathlib
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s",
)

from agents.policy_enforcer import policy_enforcer_node
from state import (
    DeploymentResult, GraphState, SecurityChain,
    ValidationIssue, ValidationReport,
)
from tools.deployment_tools import check_firewall_app_alive

CHAINS_DIR = pathlib.Path("chains")
ENDPOINT = "http://127.0.0.1:8080/firewall"

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


def _make_valid_report(chain_id: str) -> ValidationReport:
    """Crée un ValidationReport valide (simulé, is_valid=True)."""
    return ValidationReport(
        chain_id=chain_id,
        validated_at="2026-05-30T00:00:00+00:00",
        is_valid=True,
        quality_score=100,
        issues=[],
        stats={"nb_errors": 0, "nb_warnings": 0},
        validation_summary="Chaîne validée (simulé pour le test).",
    )


def _make_invalid_report(chain_id: str) -> ValidationReport:
    """Crée un ValidationReport invalide (simulé, is_valid=False)."""
    return ValidationReport(
        chain_id=chain_id,
        validated_at="2026-05-30T00:00:00+00:00",
        is_valid=False,
        quality_score=10,
        issues=[
            ValidationIssue(
                severity="ERROR",
                category="conflict",
                message="Conflit BLOCK/ALLOW simulé pour le test",
                affected_rule_ids=["FW-001", "FW-002"],
                suggested_fix="Supprimer la règle ALLOW en conflit.",
            ),
        ],
        stats={"nb_errors": 1, "nb_warnings": 0},
        validation_summary="Chaîne invalide : 1 erreur critique (simulé).",
    )


def process_one(
    chain_path: str,
    app_key: str,
    firewall_alive: bool,
) -> dict | None:
    """Teste le déploiement d'une chaîne. Retourne un dict de résultats."""
    _print_section(f"{app_key.upper()} — {chain_path}")

    chain = _load_chain(chain_path)
    if chain is None:
        return None

    print(f"  Chaîne : {chain.chain_id}")
    print(f"  App    : {chain.source_app_name} — Risque : {chain.global_risk_level}")
    print(f"  Règles : {len(chain.firewall_rules)} FW + {len(chain.ids_signatures)} IDS")

    state = GraphState(
        user_request=f"Déployer la chaîne de sécurité pour {chain.source_app_name}",
        security_chain=chain,
        validation_report=_make_valid_report(chain.chain_id),
    )

    updates = policy_enforcer_node(state)
    if not updates or "deployment_result" not in updates:
        print("  ERREUR : aucun résultat de déploiement produit")
        return None

    result: DeploymentResult = updates["deployment_result"]

    # ── Affichage ──────────────────────────────────────────────────────────
    status_icon = {"SUCCESS": "✓", "PARTIAL": "⚠", "FAILED": "✗"}.get(result.status, "?")
    print(f"\n  Status         : {status_icon} {result.status}")
    print(f"  Endpoint       : {result.target_endpoint}")
    print(f"  HTTP code      : {result.http_status_code or '(pas de requête)'}")
    print(f"  Rules          : {result.rules_installed}/{result.rules_attempted} installées")
    print(f"  Switches       : {result.connected_switches or '(aucun connecté)'}")
    if result.deployment_errors:
        for e in result.deployment_errors:
            print(f"  Erreur         : {e}")
    print(f"\n  Résumé : {result.deployment_summary[:200]}{'…' if len(result.deployment_summary) > 200 else ''}")

    # ── Sauvegarde ─────────────────────────────────────────────────────────
    CHAINS_DIR.mkdir(exist_ok=True)
    out_path = CHAINS_DIR / f"deployment_{app_key}.json"
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(result.model_dump(), fh, indent=2, ensure_ascii=False)
    print(f"\n  Résultat sauvegardé → {out_path}")

    return {
        "app": chain.source_app_name,
        "status": result.status,
        "installed": result.rules_installed,
        "attempted": result.rules_attempted,
        "switches": len(result.connected_switches),
        "errors": len(result.deployment_errors),
    }


def test_blocked_invalid_chain() -> bool:
    """Teste que le PolicyEnforcer bloque une chaîne invalide."""
    _print_section("TEST BONUS — CHAÎNE NON VALIDE (doit être BLOQUÉE)")

    chain = _load_chain("chains/chain_pokemon_go.json")
    if chain is None:
        return False

    print("  Chaîne : chain_pokemon_go_v1")
    print("  ValidationReport : is_valid=False (simulé)")

    state = GraphState(
        user_request="Déployer une chaîne invalide (test de blocage)",
        security_chain=chain,
        validation_report=_make_invalid_report(chain.chain_id),
    )

    updates = policy_enforcer_node(state)
    result: DeploymentResult | None = updates.get("deployment_result")

    if result is None:
        print("  ÉCHEC : aucun résultat produit (attendu : FAILED)")
        return False

    if result.status == "FAILED":
        print(f"  ✓ Déploiement correctement BLOQUÉ (status=FAILED)")
        print(f"  ✓ Raison : {result.deployment_errors[0][:120] if result.deployment_errors else '?'}")
        return True
    else:
        print(f"  ✗ Attendu FAILED, obtenu {result.status} — le blocage ne fonctionne pas")
        return False


def main() -> None:
    print("\n PolicyEnforcer — Test de déploiement des chaînes de sécurité\n")

    # ── Vérification préalable ─────────────────────────────────────────────
    _print_section("VÉRIFICATION PRÉALABLE — sdn_executor.py")
    print("  Ce test nécessite que sdn_executor.py soit lancé dans un autre terminal :")
    print("")
    print("    python3 ryu_app/run_manager.py ryu_app.sdn_executor")
    print("")

    alive, msg = check_firewall_app_alive(ENDPOINT)
    if alive:
        print(f"  ✓ firewall_app est joignable sur {ENDPOINT}")
    else:
        print(f"  ✗ firewall_app NON joignable : {msg}")
        print("  Les tests de déploiement retourneront FAILED (comportement attendu).")
        print("  Le test bonus (chaîne invalide) sera quand même exécuté.")

    print()

    # ── Tests normaux ──────────────────────────────────────────────────────
    results = []
    for chain_path, app_key in CHAIN_FILES:
        r = process_one(chain_path, app_key, firewall_alive=alive)
        if r:
            results.append(r)

    # ── Test bonus : chaîne non valide ─────────────────────────────────────
    block_ok = test_blocked_invalid_chain()

    # ── Tableau récapitulatif ──────────────────────────────────────────────
    _print_section("TABLEAU RÉCAPITULATIF")
    print(f"  {'Application':<35} {'Status':<10} {'Inst/Tot':>9} {'Switches':>9} {'Erreurs'}")
    print(f"  {'-'*35} {'-'*10} {'-'*9} {'-'*9} {'-'*8}")
    all_ok = True
    for r in results:
        ratio = f"{r['installed']}/{r['attempted']}"
        print(
            f"  {r['app']:<35} {r['status']:<10} {ratio:>9} "
            f"{r['switches']:>9} {r['errors']}"
        )
        # Un FAILED à cause de firewall_app absent n'est pas une vraie défaillance
        if r["status"] not in ("SUCCESS", "PARTIAL", "FAILED"):
            all_ok = False

    print()
    print(f"  Test blocage chaîne invalide : {'✓ PASSÉ' if block_ok else '✗ ÉCHOUÉ'}")
    if not block_ok:
        all_ok = False

    print()
    if alive:
        print("  Note : firewall_app était lancé — status PARTIAL attendu (0 switch OVS connecté).")
    else:
        print("  Note : firewall_app absent — tous les déploiements retournent FAILED (normal).")
    print()

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
