#!/usr/bin/env python3
"""
main_phase2.py — Point d'entrée du pipeline Phase 2 : chaînes de sécurité SDN.

Lance le pipeline LangGraph complet :
  automate JSON → ChainAnalyzer → ChainGenerator → ChainValidator → PolicyEnforcer

Usage :
    python3 main_phase2.py --automate automates/pokemon_go.json
    python3 main_phase2.py --automate automates/malware_app.json --endpoint http://127.0.0.1:8080/firewall
    python3 main_phase2.py --automate automates/banking_app.json --skip-deploy

Arguments :
    --automate      (obligatoire) chemin vers le fichier automate JSON
    --endpoint      URL de base de firewall_app.py (défaut: http://127.0.0.1:8080/firewall)
    --skip-deploy   mode dry-run : saute le PolicyEnforcer (analyse + génération + validation)
"""

import argparse
import json
import logging
import pathlib
import sys
import warnings

warnings.filterwarnings("ignore", category=RuntimeWarning)

logging.basicConfig(
    level=logging.WARNING,  # Silencer les logs internes, sauf erreurs
    format="%(levelname)s %(name)s: %(message)s",
)
# Logger principal plus verbeux
logger = logging.getLogger("main_phase2")
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Affichage du rapport final
# ---------------------------------------------------------------------------

def _print_section(icon: str, title: str) -> None:
    print(f"\n{icon}  {title}")
    print("─" * 60)


def _print_report(state) -> None:
    """Affiche le rapport final formaté depuis le GraphState résultant."""

    print("\n" + "═" * 60)
    print("  RAPPORT PIPELINE PHASE 2")
    print("═" * 60)

    # ── Analyse ────────────────────────────────────────────────────────────
    analysis = state.get("automate_analysis") if isinstance(state, dict) else getattr(state, "automate_analysis", None)

    _print_section("📊", "ANALYSE")
    if analysis:
        nb_susp = analysis.get("nb_suspicious", "?") if isinstance(analysis, dict) else analysis.nb_suspicious
        nb_trans = analysis.get("nb_transitions", "?") if isinstance(analysis, dict) else analysis.nb_transitions
        app_name = analysis.get("app_name", "?") if isinstance(analysis, dict) else analysis.app_name
        score = analysis.get("global_suspicion_score", "?") if isinstance(analysis, dict) else analysis.global_suspicion_score
        risk = analysis.get("risk_level", "?") if isinstance(analysis, dict) else analysis.risk_level
        nb_legit = len(analysis.get("legitimate_services", []) if isinstance(analysis, dict) else analysis.legitimate_services)
        susp_cats = list({
            (t.get("risk_category") if isinstance(t, dict) else t.risk_category)
            for t in (analysis.get("suspicious_transitions", []) if isinstance(analysis, dict) else analysis.suspicious_transitions)
        })
        print(f"   Application         : {app_name}")
        print(f"   Score suspicion     : {score} / 10")
        print(f"   Niveau de risque    : {str(risk).upper()}")
        print(f"   Transitions         : {nb_trans} total ({nb_susp} suspectes, {nb_legit} services légitimes)")
        if susp_cats:
            print(f"   Catégories suspectes: {', '.join(susp_cats)}")
    else:
        print("   (analyse non disponible)")

    # ── Chaîne générée ─────────────────────────────────────────────────────
    chain = state.get("security_chain") if isinstance(state, dict) else getattr(state, "security_chain", None)

    _print_section("🛡️ ", "CHAÎNE GÉNÉRÉE")
    if chain:
        fw = chain.get("firewall_rules", []) if isinstance(chain, dict) else chain.firewall_rules
        ids_ = chain.get("ids_signatures", []) if isinstance(chain, dict) else chain.ids_signatures
        ips_ = chain.get("ips_actions", []) if isinstance(chain, dict) else chain.ips_actions
        risk_lv = chain.get("global_risk_level", "?") if isinstance(chain, dict) else chain.global_risk_level
        chain_id = chain.get("chain_id", "?") if isinstance(chain, dict) else chain.chain_id

        def _action(r):
            return r.get("action") if isinstance(r, dict) else r.action

        nb_block = sum(1 for r in fw if _action(r) == "BLOCK")
        nb_allow = sum(1 for r in fw if _action(r) in ("ALLOW", "ALLOW_AND_INSPECT"))

        print(f"   Chaîne ID           : {chain_id}")
        print(f"   Règles firewall     : {len(fw)} ({nb_block} BLOCK, {nb_allow} ALLOW)")
        print(f"   Signatures IDS      : {len(ids_)}")
        print(f"   Actions IPS         : {len(ips_)}")
        print(f"   Niveau de risque    : {risk_lv}")
    else:
        print("   (chaîne non générée)")

    # ── Validation ─────────────────────────────────────────────────────────
    report = state.get("validation_report") if isinstance(state, dict) else getattr(state, "validation_report", None)

    _print_section("✅", "VALIDATION")
    if report:
        score_q = report.get("quality_score", "?") if isinstance(report, dict) else report.quality_score
        is_valid = report.get("is_valid", "?") if isinstance(report, dict) else report.is_valid
        issues = report.get("issues", []) if isinstance(report, dict) else report.issues
        nb_err = sum(1 for i in issues if (i.get("severity") if isinstance(i, dict) else i.severity) == "ERROR")
        nb_warn = sum(1 for i in issues if (i.get("severity") if isinstance(i, dict) else i.severity) == "WARNING")
        valid_icon = "✓" if is_valid else "✗"
        print(f"   Score qualité       : {score_q} / 100")
        print(f"   Valide              : {valid_icon} {is_valid}")
        print(f"   Erreurs             : {nb_err}")
        print(f"   Avertissements      : {nb_warn}")
        if not is_valid:
            for i in issues:
                sev = i.get("severity") if isinstance(i, dict) else i.severity
                msg = i.get("message") if isinstance(i, dict) else i.message
                if sev == "ERROR":
                    print(f"   ✗ [ERROR] {msg}")
    else:
        print("   (validation non effectuée)")

    # ── Déploiement ────────────────────────────────────────────────────────
    deploy = state.get("deployment_result") if isinstance(state, dict) else getattr(state, "deployment_result", None)

    _print_section("🚀", "DÉPLOIEMENT")
    if deploy:
        status = deploy.get("status", "?") if isinstance(deploy, dict) else deploy.status
        inst = deploy.get("rules_installed", 0) if isinstance(deploy, dict) else deploy.rules_installed
        att = deploy.get("rules_attempted", 0) if isinstance(deploy, dict) else deploy.rules_attempted
        switches = deploy.get("connected_switches", []) if isinstance(deploy, dict) else deploy.connected_switches
        errs = deploy.get("deployment_errors", []) if isinstance(deploy, dict) else deploy.deployment_errors
        summary = deploy.get("deployment_summary", "") if isinstance(deploy, dict) else deploy.deployment_summary

        status_icon = {"SUCCESS": "✓", "PARTIAL": "⚠", "FAILED": "✗"}.get(status, "?")
        print(f"   Status              : {status_icon} {status}")
        print(f"   Règles installées   : {inst} / {att}")
        print(f"   Switches connectés  : {switches or '(aucun)'}")
        if errs:
            for e in errs:
                print(f"   Erreur              : {e[:100]}{'…' if len(e) > 100 else ''}")
        if summary:
            print(f"\n   {summary[:200]}{'…' if len(summary) > 200 else ''}")
    else:
        print("   (déploiement sauté — mode dry-run)")

    print("\n" + "═" * 60)


# ---------------------------------------------------------------------------
# Sauvegarde de l'état final
# ---------------------------------------------------------------------------

def _save_result(state, app_name: str) -> pathlib.Path:
    """Sérialise l'état Phase 2 final dans chains/pipeline_result_<app>.json."""
    chains_dir = pathlib.Path("chains")
    chains_dir.mkdir(exist_ok=True)

    slug = app_name.lower().replace(" ", "_").replace("(", "").replace(")", "")
    out_path = chains_dir / f"pipeline_result_{slug}.json"

    # Extraire uniquement les champs Phase 2 (évite de sérialiser toute la Phase 1)
    phase2_fields = [
        "automate_path", "automate_analysis", "security_chain",
        "validation_report", "deployment_result",
    ]

    if isinstance(state, dict):
        result = {k: state.get(k) for k in phase2_fields if state.get(k) is not None}
    else:
        result = {}
        for field in phase2_fields:
            val = getattr(state, field, None)
            if val is not None:
                result[field] = val.model_dump() if hasattr(val, "model_dump") else val

    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False, default=str)

    return out_path


# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pipeline Phase 2 : analyse → génération → validation → déploiement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python3 main_phase2.py --automate automates/pokemon_go.json
  python3 main_phase2.py --automate automates/malware_app.json --skip-deploy
  python3 main_phase2.py --automate automates/banking_app.json --endpoint http://10.0.0.1:8080/firewall
        """,
    )
    parser.add_argument(
        "--automate", required=True,
        help="Chemin vers le fichier automate JSON (ex: automates/pokemon_go.json)",
    )
    parser.add_argument(
        "--endpoint",
        default="http://127.0.0.1:8080/firewall",
        help="URL de base de firewall_app.py (défaut: http://127.0.0.1:8080/firewall)",
    )
    parser.add_argument(
        "--skip-deploy", action="store_true",
        help="Mode dry-run : saute le PolicyEnforcer (pas d'appel REST)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    automate_path = pathlib.Path(args.automate)
    if not automate_path.exists():
        print(f"[ERREUR] Fichier automate introuvable : {automate_path}")
        sys.exit(1)

    # Lire le nom de l'app depuis le fichier
    try:
        with automate_path.open(encoding="utf-8") as fh:
            automate_meta = json.load(fh)
        app_name = automate_meta.get("app_name", automate_path.stem)
    except Exception:
        app_name = automate_path.stem

    mode = "dry-run (sans déploiement)" if args.skip_deploy else f"complet → {args.endpoint}"
    print(f"\n Pipeline Phase 2 — {app_name}")
    print(f" Mode    : {mode}")
    print(f" Automate: {automate_path}")
    print()

    # ── Construire le graphe ───────────────────────────────────────────────
    from graph_phase2 import build_phase2_graph
    from state import GraphState

    graph = build_phase2_graph(include_deployer=not args.skip_deploy)

    # ── État initial ───────────────────────────────────────────────────────
    initial_state = GraphState(
        user_request=f"Génère et déploie une chaîne de sécurité pour {automate_path}",
        automate_path=str(automate_path),
        # Injecter l'endpoint dans deployment_target si le PolicyEnforcer est actif
        # Cela se fait via la SecurityChain.deployment_target — on le passe
        # en surchargeant l'endpoint via une variable d'env ou via le GraphState.
        # Comme deployment_target est dans SecurityChain (produite par ChainGenerator),
        # on ne peut pas l'injecter ici directement. On utilise donc une approche
        # simple : patcher l'endpoint via un module de configuration.
    )

    # Patch de l'endpoint pour le PolicyEnforcer (si déploiement activé)
    if not args.skip_deploy and args.endpoint != "http://127.0.0.1:8080/firewall":
        import agents.policy_enforcer as pe_module
        pe_module.DEFAULT_ENDPOINT = args.endpoint
        logger.info("Endpoint PolicyEnforcer patché : %s", args.endpoint)

    # ── Exécution ──────────────────────────────────────────────────────────
    print(" Lancement du pipeline…\n")

    try:
        final_state = graph.invoke(initial_state)
    except Exception as exc:
        print(f"\n[ERREUR] Le pipeline a échoué : {exc}")
        logger.error("Pipeline Phase 2 échoué", exc_info=True)
        sys.exit(1)

    # ── Rapport ────────────────────────────────────────────────────────────
    _print_report(final_state)

    # ── Sauvegarde ─────────────────────────────────────────────────────────
    out_path = _save_result(final_state, app_name)
    print(f" Résultat sauvegardé → {out_path}\n")


if __name__ == "__main__":
    main()
