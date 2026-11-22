#!/usr/bin/env python3
"""
architectures/supervisor/run_supervisor_test.py — Test de bout en bout du
graphe Superviseur (étape 5 — architecture COMPLÈTE).

Deux modes :

  MODE 1 (défaut, SANS réseau) — deploy=False :
    Lance le superviseur sur pokemon_go.json, vérifie l'ordre
    analyzer → firewall → ids → ips → deployer → end, vérifie que
    security_chain est ASSEMBLÉE (plus None), affiche sa composition,
    compare les nombres et le SCORE DE VALIDATION à la baseline linéaire.
    Ne déploie PAS (aucun contrôleur requis).

  MODE 2 (option --deploy, AVEC réseau) — deploy=True :
    Assemble PUIS déploie réellement via REST sur le sdn_executor.
    Nécessite sdn_executor + Mininet lancés. Affiche le DeploymentResult.

Lancer depuis la racine du projet :
    python3 architectures/supervisor/run_supervisor_test.py            # MODE 1
    python3 architectures/supervisor/run_supervisor_test.py --deploy   # MODE 2
"""

import argparse
import logging
import pathlib
import sys

# ── Rendre les imports « state », « agents », « architectures » résolvables ──
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from architectures.supervisor.graph_supervisor import build_supervisor_graph
from architectures.supervisor.supervisor_agent import SupervisorState


def _get(result, field):
    """Accès tolérant : le résultat LangGraph peut être un dict OU un modèle."""
    if isinstance(result, dict):
        return result.get(field)
    return getattr(result, field, None)


def _field(obj, name):
    """Accès tolérant à un champ d'objet/dict (Pydantic OU dict)."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _run_graph(automate_path, deploy: bool):
    """Construit le graphe (mode choisi) et l'exécute sur l'automate."""
    graph = build_supervisor_graph(deploy=deploy)
    initial = SupervisorState(
        user_request=f"Sécuriser {pathlib.Path(automate_path).stem} via l'architecture Superviseur",
        automate_path=str(automate_path),
    )
    print("\n--- Exécution du graphe ---\n")
    return graph.invoke(initial)


# ===========================================================================
# Résolution de l'automate + helpers d'affichage détaillé (modes 1 & 2)
# ===========================================================================

def _resolve_automate(name: str):
    """Résout un automate par nom court (ex. malware_app) ou chemin .json.

    Returns le Path si trouvé, sinon None (après message d'erreur).
    """
    p = pathlib.Path(name)
    if name.endswith(".json") and p.exists():
        return p
    candidate = _PROJECT_ROOT / "automates" / f"{name}.json"
    if candidate.exists():
        return candidate
    print(f"❌ Automate introuvable : '{name}' "
          f"(ni chemin .json existant, ni automates/{name}.json)")
    return None


def _print_chain_detail(chain) -> None:
    """Affiche le détail de chaque règle FW / signature IDS / action IPS."""
    fw = _field(chain, "firewall_rules") or []
    ids = _field(chain, "ids_signatures") or []
    ips = _field(chain, "ips_actions") or []

    print(f"\n▶ Détail Firewall ({len(fw)}) :")
    for r in fw:
        comment = (_field(r, "comment") or "")[:50]
        print(f"    [{_field(r, 'id')}] {str(_field(r, 'action')):<6} "
              f"{_field(r, 'dst_ip')}:{_field(r, 'dst_port')}/{_field(r, 'protocol')}  "
              f"prio={_field(r, 'priority')}  — {comment}")

    print(f"\n▶ Détail IDS ({len(ids)}) :")
    for s in ids:
        mc = _field(s, "match_criteria") or {}
        dip = mc.get("dst_ip") if isinstance(mc, dict) else None
        dport = mc.get("dst_port") if isinstance(mc, dict) else None
        print(f"    [{_field(s, 'id')}] {_field(s, 'pattern_type')} → {dip}:{dport}  "
              f"[{_field(s, 'severity')}]")

    print(f"\n▶ Détail IPS ({len(ips)}) :")
    for a in ips:
        print(f"    [{_field(a, 'id')}] {_field(a, 'action')}  ← arme {_field(a, 'on_signature')}")


def _print_agent_reports(result) -> None:
    """Affiche les compteurs errors_before_correction des 3 agents (si dispo)."""
    specs = [("firewall", "firewall_verification_report"),
             ("ids", "ids_verification_report"),
             ("ips", "ips_verification_report")]
    print("\n▶ Fiabilité brute du LLM (avant correction) :")
    any_rep = False
    total_all = 0
    for label, fld in specs:
        rep = _get(result, fld)
        if not rep:
            continue
        any_rep = True
        eb = _field(rep, "errors_before_correction") or {}
        tot = _field(rep, "total_erreurs_llm_avant_correction") or 0
        total_all += tot
        cats = ", ".join(f"{k}={v}" for k, v in eb.items() if v) or "—"
        print(f"    {label:<8}: total={tot}  ({cats})  "
              f"attempts={_field(rep, 'attempts')}  source={_field(rep, 'source')}")
    if not any_rep:
        print("    (aucun rapport d'agent disponible)")
    else:
        print(f"    → TOTAL erreurs LLM avant correction : {total_all}")


def _print_install_detail(deployment) -> None:
    """En mode --deploy : détail par règle hardware_installed via GET /firewall/rules.

    Appel REST en LECTURE SEULE depuis ce script (ne modifie aucun agent/outil).
    Fallback tolérant si l'endpoint ne répond pas.
    """
    endpoint = _field(deployment, "target_endpoint")
    print("\n▶ Détail installation sur le switch (GET /firewall/rules) :")
    if not endpoint or str(endpoint).startswith("(bloqué"):
        print(f"    (endpoint indisponible : {endpoint!r})")
        return
    try:
        import requests
        url = f"{str(endpoint).rstrip('/')}/rules"
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            print(f"    (détail par règle indisponible : HTTP {resp.status_code})")
            return
        rules = resp.json().get("rules", [])
        if not rules:
            print("    (aucune règle rapportée par le contrôleur)")
            return
        for r in rules:
            print(f"    {str(r.get('rule_id')):<10} {str(r.get('type')):<6} "
                  f"{r.get('dst_ip')}:{r.get('dst_port')}/{r.get('protocol')}  "
                  f"hardware_installed={r.get('hardware_installed')}")
    except Exception as exc:
        print(f"    (détail par règle indisponible : {exc})")


# ===========================================================================
# MODE 1 — assemble seulement (sans réseau)
# ===========================================================================

def mode_assemble(automate_path) -> int:
    print("=" * 72)
    print("  TEST SUPERVISEUR — MODE 1 : ASSEMBLAGE seul (deploy=False, sans réseau)")
    print("=" * 72)
    print(f"  Automate : {automate_path}\n")

    result = _run_graph(automate_path, deploy=False)

    # ── Routage ──────────────────────────────────────────────────────────────
    agents_invoked = _get(result, "agents_invoked") or []
    print("\n" + "=" * 72)
    print("  RÉSULTATS")
    print("=" * 72)
    print("\n▶ Ordre des sous-agents routés :")
    print("    " + " → ".join(agents_invoked) + " → (end)" if agents_invoked else "    (aucun)")

    # ── Volets partiels ──────────────────────────────────────────────────────
    fw_rules = _get(result, "firewall_rules") or []
    ids_sigs = _get(result, "ids_signatures") or []
    ips_acts = _get(result, "ips_actions") or []
    nb_block = sum(1 for r in fw_rules if _field(r, "action") == "BLOCK")
    nb_allow = sum(1 for r in fw_rules if _field(r, "action") in ("ALLOW", "ALLOW_AND_INSPECT"))

    # ── Chaîne assemblée (le cœur de l'étape 5) ──────────────────────────────
    chain = _get(result, "security_chain")
    print("\n▶ SecurityChain assemblée par le Déployeur :")
    if chain is None:
        print("    ❌ security_chain est None — l'assemblage a échoué.")
        return 1

    c_fw = _field(chain, "firewall_rules") or []
    c_ids = _field(chain, "ids_signatures") or []
    c_ips = _field(chain, "ips_actions") or []
    print(f"    • chain_id        : {_field(chain, 'chain_id')}")
    print(f"    • application     : {_field(chain, 'source_app_name')}")
    print(f"    • risque global   : {_field(chain, 'global_risk_level')}")
    print(f"    • firewall_rules  : {len(c_fw)}  ({nb_block} BLOCK, {nb_allow} ALLOW)")
    print(f"    • ids_signatures  : {len(c_ids)}")
    print(f"    • ips_actions     : {len(c_ips)}")

    # ── Détail complet de la chaîne + fiabilité brute du LLM ─────────────────
    _print_chain_detail(chain)
    _print_agent_reports(result)

    # ── Validation + comparaison baseline ────────────────────────────────────
    report = _get(result, "validation_report")
    score = _field(report, "quality_score")
    is_valid = _field(report, "is_valid")
    print("\n▶ Validation de la chaîne (validate_chain) :")
    print(f"    • score qualité : {score}/100   valide : {is_valid}")

    # Baseline : régénère la chaîne complète depuis le MÊME diagnostic et valide.
    from tools.chain_tools import generate_chain_from_analysis, validate_chain
    analysis = _get(result, "automate_analysis")
    baseline_chain = generate_chain_from_analysis(analysis)
    _, baseline_report = validate_chain(baseline_chain)

    print("\n▶ Comparaison équitable avec la baseline linéaire :")
    print(f"    • firewall : superviseur={len(c_fw)}  baseline={len(baseline_chain.firewall_rules)}")
    print(f"    • IDS      : superviseur={len(c_ids)}  baseline={len(baseline_chain.ids_signatures)}")
    print(f"    • IPS      : superviseur={len(c_ips)}  baseline={len(baseline_chain.ips_actions)}")
    print(f"    • score    : superviseur={score}/100  baseline={baseline_report.quality_score}/100")

    same_fw = len(c_fw) == len(baseline_chain.firewall_rules)
    same_ids = len(c_ids) == len(baseline_chain.ids_signatures)
    same_ips = len(c_ips) == len(baseline_chain.ips_actions)
    same_score = score == baseline_report.quality_score

    # ── Pas de déploiement en MODE 1 ─────────────────────────────────────────
    deployment = _get(result, "deployment_result")
    print(f"\n▶ Déploiement : {deployment!r} (attendu : None en MODE 1)")
    no_deploy = deployment is None

    # ── Verdict ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    order_ok = agents_invoked == ["analyzer", "firewall", "ids", "ips", "deployer"]
    counts_ok = same_fw and same_ids and same_ips and same_score and len(c_fw) > 0

    if order_ok and counts_ok and no_deploy:
        print("  ✅ SUCCÈS : analyzer → firewall → ids → ips → deployer → end,")
        print(f"     chaîne assemblée ({len(c_fw)} FW / {len(c_ids)} IDS / {len(c_ips)} IPS),")
        print(f"     score {score}/100 IDENTIQUE à la baseline, aucun déploiement (MODE 1).")
        print("=" * 72)
        return 0

    if not order_ok:
        print(f"  ❌ ÉCHEC : ordre inattendu : {agents_invoked} "
              "(attendu : analyzer, firewall, ids, ips, deployer).")
    if not counts_ok:
        print("  ❌ ÉCHEC : composition ou score différent de la baseline.")
    if not no_deploy:
        print("  ❌ ÉCHEC : un déploiement a eu lieu en MODE 1 (deploy=False).")
    print("=" * 72)
    return 1


# ===========================================================================
# MODE 2 — assemble + déploie (avec réseau)
# ===========================================================================

def mode_deploy(automate_path) -> int:
    print("=" * 72)
    print("  TEST SUPERVISEUR — MODE 2 : ASSEMBLAGE + DÉPLOIEMENT (deploy=True)")
    print("=" * 72)
    print("  ⚠️  Ce mode nécessite que sdn_executor + Mininet soient LANCÉS :")
    print("      Terminal 1 : sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor")
    print("      Terminal 2 : sudo python3 deploy_mini_demo.py   (ou une topo Mininet)")
    print("      Terminal 3 : python3 architectures/supervisor/run_supervisor_test.py --deploy")
    print(f"\n  Automate : {automate_path}\n")

    result = _run_graph(automate_path, deploy=True)

    agents_invoked = _get(result, "agents_invoked") or []
    print("\n" + "=" * 72)
    print("  RÉSULTATS")
    print("=" * 72)
    print("\n▶ Ordre des sous-agents routés :")
    print("    " + " → ".join(agents_invoked) + " → (end)" if agents_invoked else "    (aucun)")

    chain = _get(result, "security_chain")
    if chain is None:
        print("    ❌ security_chain est None — l'assemblage a échoué.")
        return 1
    print(f"\n▶ Chaîne déployée : {_field(chain, 'chain_id')}")

    # ── Détail complet de la chaîne + fiabilité brute du LLM ─────────────────
    _print_chain_detail(chain)
    _print_agent_reports(result)

    deployment = _get(result, "deployment_result")
    print("\n▶ DeploymentResult :")
    if deployment is None:
        print("    ❌ Aucun DeploymentResult — le déploiement n'a pas eu lieu.")
        return 1

    status = _field(deployment, "status")
    print(f"    • status            : {status}")
    print(f"    • endpoint          : {_field(deployment, 'target_endpoint')}")
    print(f"    • règles tentées    : {_field(deployment, 'rules_attempted')}")
    print(f"    • règles installées : {_field(deployment, 'rules_installed')}")
    print(f"    • switches connectés: {_field(deployment, 'connected_switches')}")
    errs = _field(deployment, "deployment_errors") or []
    if errs:
        print(f"    • erreurs           : {errs}")
    print(f"    • résumé            : {_field(deployment, 'deployment_summary')}")

    # ── Réponse brute du sdn_executor (le plus fin disponible dans le résultat) ──
    body = _field(deployment, "response_body")
    if body:
        print("\n▶ Réponse brute du contrôleur (POST /firewall/install) :")
        for k, v in (body.items() if isinstance(body, dict) else []):
            print(f"    • {k} : {v}")

    # ── Détail par règle réellement posée sur le switch (GET /firewall/rules) ──
    _print_install_detail(deployment)

    print("\n" + "=" * 72)
    # SUCCESS ou PARTIAL = le déploiement REST a fonctionné (PARTIAL = 0 switch OVS).
    if status in ("SUCCESS", "PARTIAL"):
        print(f"  ✅ Déploiement abouti (status={status}).")
        print("=" * 72)
        return 0
    print(f"  ❌ Déploiement en échec (status={status}). Vérifier que sdn_executor tourne.")
    print("=" * 72)
    return 1


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(
        description="Test/déploiement de l'architecture Superviseur sur un automate.")
    parser.add_argument("--automate", default="pokemon_go",
                        help="nom court (ex. malware_app) ou chemin .json (défaut: pokemon_go)")
    parser.add_argument("--deploy", action="store_true",
                        help="assemble PUIS déploie via REST sur le sdn_executor")
    args = parser.parse_args()

    automate_path = _resolve_automate(args.automate)
    if automate_path is None:
        return 1

    return mode_deploy(automate_path) if args.deploy else mode_assemble(automate_path)


if __name__ == "__main__":
    sys.exit(main())
