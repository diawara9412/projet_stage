"""
agents/policy_enforcer.py — Agent PolicyEnforcer du système Phase 2.

Déploie une SecurityChain validée sur les switches OVS en appelant l'API REST
de firewall_app.py (os_ken).  Produit un DeploymentResult dans le GraphState.

Flux de traitement
------------------
1. Garde : pas de SecurityChain → retourne {} immédiatement.
2. Garde : chaîne invalide (ValidationReport.is_valid == False) → FAILED.
3. Garde : DeploymentResult déjà présent → idempotent, retourne {}.
4. Déploiement déterministe via les fonctions de deployment_tools :
   a. Vérifier que firewall_app est joignable.
   b. Pousser la chaîne via POST /firewall/install.
   c. Attendre 2 secondes (convergence OpenFlow).
   d. Récupérer les statistiques et compter les règles installées.
   e. Construire le DeploymentResult.
5. Enrichissement LLM optionnel : deployment_summary narratif en français.
6. Retourne ``{"deployment_result": DeploymentResult}``.
"""

import json
import logging
import re
import time
import warnings
from datetime import datetime, timezone

from state import DeploymentResult, GraphState, SecurityChain

from tools.deployment_tools import (
    check_firewall_app_alive,
    fetch_deployment_stats,
    install_chain_via_rest,
    verify_chain_installed,
)

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    from config import GROQ_API_KEY, WORKER_MODEL

logger = logging.getLogger(__name__)

# ── Constantes ─────────────────────────────────────────────────────────────────

DEFAULT_ENDPOINT = "http://127.0.0.1:8080/firewall"
OPENFLOW_CONVERGENCE_DELAY = 2  # secondes entre POST et vérification

# ── Prompt système ──────────────────────────────────────────────────────────────

POLICY_ENFORCER_SYSTEM_PROMPT = """Tu es l'agent PolicyEnforcer d'un système de sécurité réseau SDN basé sur LangGraph.

## Ta mission

Produire un résumé narratif concis du déploiement d'une chaîne de sécurité sur des switches OVS.

## Ce que tu reçois

Un résumé du résultat de déploiement : statut, nombre de règles tentées / installées,
switches connectés, erreurs éventuelles, et le contexte de l'application.

## Ce que tu dois produire

Un objet JSON STRICT avec exactement un champ :

```json
{
  "deployment_summary": "Résumé narratif de 2 à 4 phrases en français. Mention : le statut final (SUCCESS/PARTIAL/FAILED), le nombre de règles installées, sur combien de switches, et les actions de protection activées (BLOCK, IDS monitoring, etc.)."
}
```

## Règles

- Pour SUCCESS : ton appréciation doit être positive, citer les types de trafic bloqués.
- Pour PARTIAL : expliquer ce qui a fonctionné et ce qui manque.
- Pour FAILED : expliquer la cause (firewall_app absent, validation échouée, etc.).
- Cite les IPs bloquées ou les patterns IDS activés si pertinent.
- Réponds UNIQUEMENT avec le JSON, sans markdown ni texte autour.
"""


# ── Déploiement déterministe ────────────────────────────────────────────────────

def _deploy_deterministic(chain: SecurityChain, endpoint_url: str) -> DeploymentResult:
    """Déploie la SecurityChain via REST et retourne un DeploymentResult complet.

    Étapes :
    1. Vérifier que firewall_app répond sur endpoint_url.
    2. POST /firewall/install avec la chaîne sérialisée.
    3. Attendre OPENFLOW_CONVERGENCE_DELAY secondes.
    4. GET /firewall/stats pour les statistiques.
    5. GET /firewall/rules pour compter les règles hardware_installed.
    6. Déterminer le statut final (SUCCESS / PARTIAL / FAILED).

    Args:
        chain: SecurityChain validée à déployer.
        endpoint_url: URL de base de l'API firewall_app (sans slash final).

    Returns:
        DeploymentResult complet.
    """
    now = datetime.now(timezone.utc)
    deployment_id = (
        f"deploy_{chain.source_automate_id}_{now.strftime('%Y%m%dT%H%M%S')}"
    )
    chain_dict = chain.model_dump()
    errors: list[str] = []

    # ── Étape 1 : vérifier que firewall_app est vivant ──────────────────────
    alive, alive_msg = check_firewall_app_alive(endpoint_url)
    if not alive:
        logger.error("PolicyEnforcer : firewall_app non joignable — %s", alive_msg)
        return DeploymentResult(
            deployment_id=deployment_id,
            chain_id=chain.chain_id,
            deployed_at=now.isoformat(),
            status="FAILED",
            target_endpoint=endpoint_url,
            http_status_code=None,
            response_body=None,
            rules_attempted=len(chain.firewall_rules) + len(chain.ids_signatures),
            rules_installed=0,
            connected_switches=[],
            deployment_errors=[alive_msg],
            deployment_summary=(
                f"Déploiement ÉCHOUÉ : firewall_app non joignable sur {endpoint_url}. "
                f"Raison : {alive_msg}"
            ),
        )

    logger.info("PolicyEnforcer : firewall_app joignable sur %s", endpoint_url)

    # ── Étape 2 : pousser la chaîne ─────────────────────────────────────────
    ok, response = install_chain_via_rest(chain_dict, endpoint_url)
    http_code = None
    response_body: dict | None = None

    if not ok:
        errors.append(str(response))
        logger.error("PolicyEnforcer : install_chain_via_rest échoué — %s", response)
        return DeploymentResult(
            deployment_id=deployment_id,
            chain_id=chain.chain_id,
            deployed_at=now.isoformat(),
            status="FAILED",
            target_endpoint=endpoint_url,
            http_status_code=None,
            response_body=None,
            rules_attempted=len(chain.firewall_rules) + len(chain.ids_signatures),
            rules_installed=0,
            connected_switches=[],
            deployment_errors=errors,
            deployment_summary=(
                f"Déploiement ÉCHOUÉ pour '{chain.chain_id}'. "
                f"Erreur POST /install : {response}"
            ),
        )

    response_body = response if isinstance(response, dict) else {}
    switches_at_install = response_body.get("switches_connected", 0)
    logger.info(
        "PolicyEnforcer : chaîne '%s' acceptée par firewall_app (%d switch(es) connecté(s))",
        chain.chain_id, switches_at_install,
    )

    # ── Étape 3 : attendre la convergence OpenFlow ──────────────────────────
    logger.info("PolicyEnforcer : attente de %ds (convergence OpenFlow)…", OPENFLOW_CONVERGENCE_DELAY)
    time.sleep(OPENFLOW_CONVERGENCE_DELAY)

    # ── Étape 4 : statistiques post-déploiement ─────────────────────────────
    stats = fetch_deployment_stats(endpoint_url)
    connected_switches: list[str] = stats.get("connected_switches", [])
    flows_by_type: dict = stats.get("installed_flows", {}).get("by_type", {})
    logger.info(
        "PolicyEnforcer : stats — switches=%s, flows=%s",
        connected_switches, flows_by_type,
    )

    # ── Étape 5 : compter les règles hardware_installed ─────────────────────
    nb_attempted, nb_installed = verify_chain_installed(chain_dict, endpoint_url)
    logger.info(
        "PolicyEnforcer : règles vérifiées — %d/%d installées sur le hardware",
        nb_installed, nb_attempted,
    )

    # ── Étape 6 : statut final ───────────────────────────────────────────────
    if not connected_switches:
        # Aucun switch OVS connecté : chaîne acceptée mais pas installée en HW
        status = "PARTIAL"
        errors.append(
            "Aucun switch OVS connecté au moment du déploiement. "
            "La chaîne sera appliquée automatiquement à la prochaine connexion."
        )
    elif nb_installed == nb_attempted and nb_attempted > 0:
        status = "SUCCESS"
    elif nb_installed > 0:
        status = "PARTIAL"
        errors.append(
            f"Seulement {nb_installed}/{nb_attempted} règles installées sur le hardware."
        )
    else:
        status = "FAILED"
        errors.append(f"Aucune règle installée sur le hardware ({nb_attempted} tentées).")

    # ── Résumé déterministe ──────────────────────────────────────────────────
    nb_block = flows_by_type.get("BLOCK", 0)
    nb_allow = flows_by_type.get("ALLOW", 0)
    nb_ids = flows_by_type.get("IDS", 0)
    nb_sw = len(connected_switches)

    if status == "SUCCESS":
        det_summary = (
            f"Déploiement SUCCESS pour '{chain.chain_id}' ({chain.source_app_name}). "
            f"{nb_block} règle(s) BLOCK, {nb_allow} ALLOW, {nb_ids} IDS monitor "
            f"installée(s) sur {nb_sw} switch(es) OVS. "
            f"Risque global : {chain.global_risk_level}."
        )
    elif status == "PARTIAL":
        det_summary = (
            f"Déploiement PARTIEL pour '{chain.chain_id}'. "
            f"{nb_installed}/{nb_attempted} règle(s) installée(s). "
            f"Switches connectés : {nb_sw}. "
            f"Causes : {'; '.join(errors)}"
        )
    else:
        det_summary = (
            f"Déploiement ÉCHOUÉ pour '{chain.chain_id}'. "
            f"Causes : {'; '.join(errors)}"
        )

    return DeploymentResult(
        deployment_id=deployment_id,
        chain_id=chain.chain_id,
        deployed_at=now.isoformat(),
        status=status,
        target_endpoint=endpoint_url,
        http_status_code=http_code,
        response_body=response_body,
        rules_attempted=nb_attempted,
        rules_installed=nb_installed,
        connected_switches=connected_switches,
        deployment_errors=errors,
        deployment_summary=det_summary,
    )


# ── Enrichissement LLM ─────────────────────────────────────────────────────────

def _enrich_with_llm(result: DeploymentResult, chain: SecurityChain) -> DeploymentResult:
    """Remplace le deployment_summary déterministe par un résumé narratif LLM."""
    try:
        from langchain_core.messages import HumanMessage, SystemMessage
        from langchain_groq import ChatGroq

        llm = ChatGroq(api_key=GROQ_API_KEY, model=WORKER_MODEL, temperature=0.1)

        block_count = sum(1 for r in chain.firewall_rules if r.action == "BLOCK")
        allow_count = sum(1 for r in chain.firewall_rules if r.action in ("ALLOW", "ALLOW_AND_INSPECT"))
        ids_count = len(chain.ids_signatures)

        context = (
            f"Application : {chain.source_app_name}\n"
            f"Chaîne : {chain.chain_id} — Risque : {chain.global_risk_level}\n"
            f"Statut déploiement : {result.status}\n"
            f"Endpoint : {result.target_endpoint}\n"
            f"Règles tentées / installées : {result.rules_attempted} / {result.rules_installed}\n"
            f"Switches connectés : {result.connected_switches}\n"
            f"Règles BLOCK : {block_count} | ALLOW : {allow_count} | IDS : {ids_count}\n"
            f"Erreurs : {result.deployment_errors or ['(aucune)']}\n\n"
            f"Produis le JSON demandé avec un deployment_summary narratif en français."
        )

        response = llm.invoke([
            SystemMessage(content=POLICY_ENFORCER_SYSTEM_PROMPT),
            HumanMessage(content=context),
        ])

        raw = response.content.strip()
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if not m:
            logger.warning("LLM n'a pas retourné de JSON valide — résumé déterministe conservé")
            return result

        data = json.loads(m.group())
        llm_summary = data.get("deployment_summary")
        if llm_summary:
            return result.model_copy(update={"deployment_summary": llm_summary})

    except Exception as exc:
        logger.warning("Enrichissement LLM échoué : %s — résumé déterministe conservé", exc)

    return result


# ── Nœud principal ──────────────────────────────────────────────────────────────

def policy_enforcer_node(state: GraphState) -> dict:
    """Nœud PolicyEnforcer du graphe LangGraph Phase 2.

    Déploie la SecurityChain validée du GraphState via l'API REST de firewall_app.
    Idempotent si deployment_result est déjà présent.

    Args:
        state: État courant du graphe.

    Returns:
        dict: ``{"deployment_result": DeploymentResult}`` si réussi, ``{}`` sinon.
    """
    logger.info("═══ PolicyEnforcer : démarrage ═══")

    # ── Garde 1 : pas de chaîne à déployer ─────────────────────────────────
    if state.security_chain is None:
        logger.error("PolicyEnforcer : state.security_chain est vide — rien à déployer")
        return {}

    chain = state.security_chain

    # ── Garde 2 : chaîne invalide — déploiement bloqué ─────────────────────
    if state.validation_report is not None and not state.validation_report.is_valid:
        nb_errors = state.validation_report.stats.get("nb_errors", "?")
        reason = (
            f"Déploiement bloqué : la chaîne '{chain.chain_id}' a échoué la validation "
            f"({nb_errors} erreur(s) critique(s)). "
            f"Corriger les erreurs dans la chaîne avant de déployer."
        )
        logger.warning("PolicyEnforcer : %s", reason)
        now = datetime.now(timezone.utc)
        failed_result = DeploymentResult(
            deployment_id=f"deploy_blocked_{chain.chain_id}_{now.strftime('%Y%m%dT%H%M%S')}",
            chain_id=chain.chain_id,
            deployed_at=now.isoformat(),
            status="FAILED",
            target_endpoint="(bloqué avant envoi)",
            http_status_code=None,
            response_body=None,
            rules_attempted=len(chain.firewall_rules) + len(chain.ids_signatures),
            rules_installed=0,
            connected_switches=[],
            deployment_errors=[reason],
            deployment_summary=reason,
        )
        return {"deployment_result": failed_result}

    # ── Garde 3 : idempotence ───────────────────────────────────────────────
    if state.deployment_result is not None:
        logger.info(
            "Résultat '%s' déjà présent (status=%s) — passage de la main",
            state.deployment_result.deployment_id,
            state.deployment_result.status,
        )
        return {}

    # ── Récupérer l'endpoint depuis deployment_target ───────────────────────
    endpoint_url = (
        chain.deployment_target.get("ryu_endpoint", DEFAULT_ENDPOINT)
        if chain.deployment_target
        else DEFAULT_ENDPOINT
    )
    # S'assurer que l'URL se termine par /firewall (pas de /firewall/install)
    if not endpoint_url.rstrip("/").endswith("/firewall"):
        endpoint_url = endpoint_url.rstrip("/") + "/firewall"

    logger.info(
        "PolicyEnforcer : déploiement de '%s' vers %s",
        chain.chain_id, endpoint_url,
    )

    try:
        # ── Déploiement déterministe ────────────────────────────────────────
        result = _deploy_deterministic(chain, endpoint_url)
        logger.info(
            "PolicyEnforcer : status=%s, installed=%d/%d, switches=%s",
            result.status, result.rules_installed, result.rules_attempted,
            result.connected_switches,
        )

        # ── Enrichissement LLM ─────────────────────────────────────────────
        if GROQ_API_KEY:
            logger.info("PolicyEnforcer : enrichissement LLM du deployment_summary…")
            result = _enrich_with_llm(result, chain)
            logger.info("Summary : %s", result.deployment_summary[:120])
        else:
            logger.info("GROQ_API_KEY absente — résumé déterministe conservé")

        logger.info("═══ PolicyEnforcer : terminé (status=%s) ═══", result.status)
        return {"deployment_result": result}

    except Exception as exc:
        logger.error("policy_enforcer_node a levé une exception : %s", exc, exc_info=True)
        now = datetime.now(timezone.utc)
        fallback = DeploymentResult(
            deployment_id=f"deploy_error_{chain.chain_id}_{now.strftime('%Y%m%dT%H%M%S')}",
            chain_id=chain.chain_id,
            deployed_at=now.isoformat(),
            status="FAILED",
            target_endpoint=endpoint_url,
            http_status_code=None,
            response_body=None,
            rules_attempted=len(chain.firewall_rules) + len(chain.ids_signatures),
            rules_installed=0,
            connected_switches=[],
            deployment_errors=[str(exc)],
            deployment_summary=f"Déploiement ÉCHOUÉ suite à une exception interne : {exc}",
        )
        logger.warning("PolicyEnforcer : fallback DeploymentResult FAILED retourné")
        return {"deployment_result": fallback}
