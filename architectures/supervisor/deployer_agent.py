"""
architectures/supervisor/deployer_agent.py — Agent DÉPLOYEUR de l'architecture
Superviseur (étape 5, dernière).

Double rôle (différent des autres agents)
-----------------------------------------
1. ASSEMBLAGE (toujours) : recompose une SecurityChain COMPLÈTE à partir des
   volets partiels accumulés dans l'état par les agents précédents :
     - firewall_rules   (agent Firewall, étape 2)
     - ids_signatures   (agent IDS, étape 3)
     - ips_actions      (agent IPS, étape 4)
   + métadonnées issues de automate_analysis (chain_id, app, risk level).
   C'est le PREMIER agent qui écrit ``state.security_chain``.
   Puis validation (validate_chain) : on logge le score SANS bloquer.

2. DÉPLOIEMENT (conditionnel, selon le paramètre ``deploy``) :
   envoie la chaîne au sdn_executor via REST (réutilise deployment_tools, ne
   duplique pas la logique REST) et produit un DeploymentResult.

Modes
-----
- deploy=False (défaut) : ASSEMBLE seulement → testable SANS contrôleur ni Mininet.
- deploy=True           : ASSEMBLE puis DÉPLOIE → nécessite sdn_executor + Mininet.

Le nœud est produit par une FABRIQUE ``make_deployer_node(deploy, endpoint)`` :
LangGraph appelle un nœud avec le seul argument ``state``, donc on capture
``deploy``/``endpoint`` dans une clôture.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from state import DeploymentResult, SecurityChain
from tools.chain_tools import _norm_risk, validate_chain
from tools.deployment_tools import (
    check_firewall_app_alive,
    fetch_deployment_stats,
    install_chain_via_rest,
    verify_chain_installed,
)

logger = logging.getLogger(__name__)

# Endpoint REST par défaut du sdn_executor (identique à la baseline).
DEFAULT_ENDPOINT = "http://127.0.0.1:8080/firewall"
OPENFLOW_CONVERGENCE_DELAY = 2  # secondes entre POST et vérification


# ---------------------------------------------------------------------------
# Partie 1 — ASSEMBLAGE de la SecurityChain à partir des volets partiels
# ---------------------------------------------------------------------------

def assemble_security_chain(state) -> SecurityChain:
    """Reconstruit une SecurityChain complète depuis les volets de l'état.

    Les 3 listes proviennent des agents précédents (déjà dans l'état) ; les
    métadonnées proviennent de ``automate_analysis``. Aucune règle n'est
    régénérée : on ASSEMBLE simplement ce que les agents ont produit.

    Args:
        state: SupervisorState contenant firewall_rules, ids_signatures,
               ips_actions et automate_analysis.

    Returns:
        SecurityChain complète (non encore validée).
    """
    analysis = state.automate_analysis
    fw_rules = state.firewall_rules or []
    ids_sigs = state.ids_signatures or []
    ips_acts = state.ips_actions or []

    nb_block = sum(1 for r in fw_rules if r.action == "BLOCK")
    nb_allow = sum(1 for r in fw_rules if r.action in ("ALLOW", "ALLOW_AND_INSPECT"))

    generation_summary = (
        f"Chaîne assemblée par le Déployeur pour {analysis.app_name} "
        f"(risque={analysis.risk_level}, score={analysis.global_suspicion_score}/10) "
        f"à partir des volets produits par les agents : "
        f"{nb_block} BLOCK + {nb_allow} ALLOW, {len(ids_sigs)} signature(s) IDS, "
        f"{len(ips_acts)} action(s) IPS."
    )

    return SecurityChain(
        chain_id=f"chain_{analysis.automate_id}",
        source_automate_id=analysis.automate_id,
        source_app_name=analysis.app_name,
        generated_at=datetime.now(timezone.utc).isoformat(),
        # _norm_risk : même normalisation que la baseline (low→LOW, critical→HIGH)
        global_risk_level=_norm_risk(analysis.risk_level),
        firewall_rules=fw_rules,
        ids_signatures=ids_sigs,
        ips_actions=ips_acts,
        deployment_target={
            "ryu_endpoint": "http://localhost:8080",
            "target_switches": ["s0", "s1", "s2"],
            "openflow_version": "1.3",
        },
        generation_summary=generation_summary,
    )


# ---------------------------------------------------------------------------
# Partie 2 — DÉPLOIEMENT via REST (réutilise deployment_tools)
# ---------------------------------------------------------------------------

def _deploy_chain(chain: SecurityChain, endpoint_url: str) -> DeploymentResult:
    """Déploie la SecurityChain via REST et construit un DeploymentResult.

    Réutilise les 4 primitives REST de ``deployment_tools`` (pas de duplication
    de la logique HTTP). Logique de statut alignée sur le PolicyEnforcer baseline.

    Args:
        chain: SecurityChain à déployer.
        endpoint_url: URL de base de l'API sdn_executor (terminée par /firewall).

    Returns:
        DeploymentResult (SUCCESS / PARTIAL / FAILED).
    """
    now = datetime.now(timezone.utc)
    deployment_id = f"deploy_{chain.source_automate_id}_{now.strftime('%Y%m%dT%H%M%S')}"
    chain_dict = chain.model_dump()
    nb_total = len(chain.firewall_rules) + len(chain.ids_signatures)
    errors: list[str] = []

    def _failed(summary: str, errs: list[str]) -> DeploymentResult:
        return DeploymentResult(
            deployment_id=deployment_id,
            chain_id=chain.chain_id,
            deployed_at=now.isoformat(),
            status="FAILED",
            target_endpoint=endpoint_url,
            http_status_code=None,
            response_body=None,
            rules_attempted=nb_total,
            rules_installed=0,
            connected_switches=[],
            deployment_errors=errs,
            deployment_summary=summary,
        )

    # ── 1. sdn_executor joignable ? ─────────────────────────────────────────
    alive, alive_msg = check_firewall_app_alive(endpoint_url)
    if not alive:
        logger.error("Déployeur : sdn_executor non joignable — %s", alive_msg)
        return _failed(
            f"Déploiement ÉCHOUÉ : sdn_executor non joignable sur {endpoint_url} ({alive_msg}).",
            [alive_msg],
        )
    logger.info("Déployeur : sdn_executor joignable sur %s", endpoint_url)

    # ── 2. POST /firewall/install ───────────────────────────────────────────
    ok, response = install_chain_via_rest(chain_dict, endpoint_url)
    if not ok:
        logger.error("Déployeur : install_chain_via_rest échoué — %s", response)
        return _failed(
            f"Déploiement ÉCHOUÉ pour '{chain.chain_id}'. Erreur POST /install : {response}",
            [str(response)],
        )
    response_body = response if isinstance(response, dict) else {}
    logger.info("Déployeur : chaîne '%s' acceptée (%s switch(es) au POST)",
                chain.chain_id, response_body.get("switches_connected", 0))

    # ── 3. convergence OpenFlow ─────────────────────────────────────────────
    logger.info("Déployeur : attente %ds (convergence OpenFlow)…", OPENFLOW_CONVERGENCE_DELAY)
    time.sleep(OPENFLOW_CONVERGENCE_DELAY)

    # ── 4. stats + 5. vérification hardware ─────────────────────────────────
    stats = fetch_deployment_stats(endpoint_url)
    connected_switches: list[str] = stats.get("connected_switches", [])
    nb_attempted, nb_installed = verify_chain_installed(chain_dict, endpoint_url)
    logger.info("Déployeur : %d/%d règle(s) installée(s), switches=%s",
                nb_installed, nb_attempted, connected_switches)

    # ── 6. statut final ─────────────────────────────────────────────────────
    if not connected_switches:
        status = "PARTIAL"
        errors.append("Aucun switch OVS connecté — la chaîne sera appliquée à la prochaine connexion.")
    elif nb_installed == nb_attempted and nb_attempted > 0:
        status = "SUCCESS"
    elif nb_installed > 0:
        status = "PARTIAL"
        errors.append(f"Seulement {nb_installed}/{nb_attempted} règles installées.")
    else:
        status = "FAILED"
        errors.append(f"Aucune règle installée ({nb_attempted} tentées).")

    summary = (
        f"Déploiement {status} pour '{chain.chain_id}' ({chain.source_app_name}) : "
        f"{nb_installed}/{nb_attempted} règle(s) sur {len(connected_switches)} switch(es). "
        f"Risque global : {chain.global_risk_level}."
        + (f" Causes : {'; '.join(errors)}" if errors else "")
    )

    return DeploymentResult(
        deployment_id=deployment_id,
        chain_id=chain.chain_id,
        deployed_at=now.isoformat(),
        status=status,
        target_endpoint=endpoint_url,
        http_status_code=None,
        response_body=response_body,
        rules_attempted=nb_attempted,
        rules_installed=nb_installed,
        connected_switches=connected_switches,
        deployment_errors=errors,
        deployment_summary=summary,
    )


# ---------------------------------------------------------------------------
# Fabrique du nœud Déployeur (capture deploy / endpoint dans une clôture)
# ---------------------------------------------------------------------------

def make_deployer_node(deploy: bool = False, endpoint: str = DEFAULT_ENDPOINT):
    """Crée le nœud Déployeur paramétré par le mode.

    Args:
        deploy: False = assemble seulement ; True = assemble puis déploie via REST.
        endpoint: URL de base de l'API sdn_executor (mode deploy=True).

    Returns:
        Une fonction ``deployer_node(state) -> dict`` compatible LangGraph.
    """

    def deployer_node(state) -> dict:
        """Nœud Déployeur : assemble la SecurityChain puis (optionnellement) déploie.

        Idempotent : si ``security_chain`` est déjà rempli, ne réassemble pas.

        Returns:
            dict de mises à jour : ``security_chain`` + ``validation_report``
            (toujours), et ``deployment_result`` si deploy=True.
        """
        logger.info("═══ Déployeur : démarrage (mode=%s) ═══",
                    "assemble+déploie" if deploy else "assemble seulement")

        # Garde 1 : pas d'analyse → impossible d'assembler les métadonnées
        if state.automate_analysis is None:
            logger.error("Déployeur : automate_analysis vide — assemblage impossible")
            return {}

        # Garde 2 : idempotence sur l'assemblage
        if state.security_chain is not None:
            logger.info("Déployeur : security_chain déjà assemblée — passage de la main")
            # En mode deploy, on pourrait re-tenter le déploiement, mais on reste
            # idempotent pour cette étape (le routage gère la fin).
            return {}

        # ── PARTIE 1 : ASSEMBLAGE (toujours) ────────────────────────────────
        chain = assemble_security_chain(state)
        logger.info(
            "Déployeur : chaîne '%s' assemblée — %d firewall, %d IDS, %d IPS",
            chain.chain_id, len(chain.firewall_rules),
            len(chain.ids_signatures), len(chain.ips_actions),
        )

        # ── Validation (logge le score, NE bloque PAS) ──────────────────────
        corrected, report = validate_chain(chain)
        logger.info(
            "Déployeur : validation — score=%d/100, valide=%s, %d doublon(s) supprimé(s)",
            report.quality_score, report.is_valid,
            report.stats.get("duplicates_removed", 0),
        )
        if not report.is_valid:
            logger.warning(
                "Déployeur : chaîne marquée INVALIDE (%d erreur(s)) — on continue "
                "quand même (logging seulement, pas de blocage à ce stade)",
                report.stats.get("nb_errors", "?"),
            )

        updates: dict = {
            "security_chain": corrected,
            "validation_report": report,
        }

        # ── PARTIE 2 : DÉPLOIEMENT (conditionnel) ───────────────────────────
        if deploy:
            logger.info("Déployeur : déploiement REST vers %s", endpoint)
            result = _deploy_chain(corrected, endpoint)
            logger.info("Déployeur : status=%s (%d/%d installées)",
                        result.status, result.rules_installed, result.rules_attempted)
            updates["deployment_result"] = result
        else:
            logger.info("Déployeur : mode assemble seulement — pas de déploiement REST")

        logger.info("═══ Déployeur : terminé ═══")
        return updates

    deployer_node.__name__ = "deployer_node"
    return deployer_node
