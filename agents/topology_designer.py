"""
agents/topology_designer.py — Agent TopologyDesigner du système multi-agents SDN.

Sélectionne et déploie une topologie depuis le Topology Zoo dans Mininet,
en choisissant la topologie la plus pertinente selon la demande utilisateur.
"""

import logging
import warnings
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage, SystemMessage

from agents._tool_executor import get_tool_results, run_agentic_loop
from state import DeployedTopology, GraphState
from tools.topology_tools import (
    deploy_topology_in_mininet,
    inspect_topology,
    list_available_topologies,
)

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    from config import GROQ_API_KEY, WORKER_MODEL, WORKER_TEMPERATURE

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Outils exposés à ce worker
# ---------------------------------------------------------------------------

WORKER_TOOLS = [
    list_available_topologies,
    inspect_topology,
    deploy_topology_in_mininet,
]

# ---------------------------------------------------------------------------
# Prompt système
# ---------------------------------------------------------------------------

TOPOLOGY_DESIGNER_SYSTEM_PROMPT = """Tu es l'agent TopologyDesigner d'un système multi-agents de simulation réseau SDN.

## Ta mission

À partir d'une demande en langage naturel, choisir la topologie réseau la plus pertinente parmi celles disponibles dans le Topology Zoo, puis la déployer dans Mininet.

## Tes 3 outils

1. **list_available_topologies()** — Liste toutes les topologies .graphml disponibles avec le nombre de nœuds et de liens. À appeler EN PREMIER pour voir ce qui est disponible.

2. **inspect_topology(topology_name)** — Analyse une topologie en détail : diamètre du réseau, degré moyen, nœud le plus connecté. Utile pour confirmer un choix.

3. **deploy_topology_in_mininet(topology_name)** — Déploie la topologie choisie dans Mininet : crée les hosts, les switches OVS et les liens. Retourne les noms et IPs des hosts créés.

## Stratégie à suivre

1. Appelle `list_available_topologies()` pour voir les topologies disponibles.
2. Choisis la topologie selon les critères ci-dessous.
3. Si utile, appelle `inspect_topology()` pour valider le choix.
4. Appelle `deploy_topology_in_mininet()` avec la topologie choisie.

## Critères de sélection selon la taille demandée

| Taille demandée                        | Critère          | Topologie idéale     |
|----------------------------------------|------------------|----------------------|
| "petit" / "small" / "rapide" / "demo" | < 15 nœuds       | Abilene (11 nœuds)   |
| "moyen" / "medium"                     | 15 à 50 nœuds    | Geant2012 (40 nœuds) |
| "grand" / "large"                      | > 50 nœuds       | plus grande dispo    |
| Aucune précision                       | par défaut       | Abilene (rapide)     |

## Règles importantes

- Ne génère PAS de trafic — c'est le rôle du TrafficGenerator.
- Ne lance PAS d'attaques — c'est le rôle de l'AttackSimulator.
- Si le déploiement réussit, ton travail est terminé, arrête-toi.
- Si le déploiement échoue, essaie une topologie plus petite (Abilene).
- Le déploiement peut prendre 5 à 30 secondes selon la taille de la topologie.
"""

# ---------------------------------------------------------------------------
# Helpers d'extraction
# ---------------------------------------------------------------------------

def _extract_deployed_topology(messages: list) -> DeployedTopology | None:
    """Extrait le résultat du dernier deploy_topology_in_mininet réussi.

    Args:
        messages: Messages issus de la boucle agentique.

    Returns:
        DeployedTopology ou None si aucun déploiement réussi trouvé.
    """
    results = get_tool_results(messages, "deploy_topology_in_mininet")
    for result in reversed(results):  # on prend le dernier succès
        if result.get("status") == "success":
            try:
                return DeployedTopology(
                    topology_name=result["topology_name"],
                    nb_hosts=result["nb_hosts"],
                    nb_switches=result["nb_switches"],
                    nb_links=result["nb_links"],
                    hosts=result["hosts"],
                    host_ips=result["host_ips"],
                    deployed_at=datetime.now(timezone.utc).isoformat(),
                )
            except (KeyError, TypeError) as exc:
                logger.warning("Impossible d'extraire DeployedTopology : %s", exc)
    return None


# ---------------------------------------------------------------------------
# Fallback déterministe (sans LLM)
# ---------------------------------------------------------------------------

def _fallback_deploy(state: GraphState) -> dict:
    """Déploie Abilene directement sans LLM (quand la clé API est absente).

    Utilisé quand GROQ_API_KEY est manquante ou quand le LLM produit une erreur.

    Args:
        state: État courant (pour lire target_topology_hint).

    Returns:
        dict avec "deployed_topology" si succès, sinon dict vide.
    """
    # Choisir la topologie selon l'indice de taille
    hint = (state.target_topology_hint or "").lower()
    if any(k in hint for k in ("medium", "moyen", "geant")):
        topology_name = "Geant2012"
    else:
        topology_name = "Abilene"  # défaut sûr et rapide

    logger.info("Fallback : déploiement de '%s' sans LLM", topology_name)
    try:
        result = deploy_topology_in_mininet.invoke({"topology_name": topology_name})
        if result.get("status") == "success":
            topo = DeployedTopology(
                topology_name=result["topology_name"],
                nb_hosts=result["nb_hosts"],
                nb_switches=result["nb_switches"],
                nb_links=result["nb_links"],
                hosts=result["hosts"],
                host_ips=result["host_ips"],
                deployed_at=datetime.now(timezone.utc).isoformat(),
            )
            logger.info("Fallback : topologie '%s' déployée avec succès", topology_name)
            return {"deployed_topology": topo}
        else:
            logger.error("Fallback : déploiement échoué — %s", result.get("message"))
            return {}
    except BaseException as exc:  # inclut SystemExit levé par Mininet sans sudo
        logger.error("Fallback deploy_topology_in_mininet a levé une exception : %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Nœud principal
# ---------------------------------------------------------------------------

def topology_designer_node(state: GraphState) -> dict:
    """Nœud TopologyDesigner du graphe LangGraph.

    Choisit et déploie une topologie dans Mininet selon la demande utilisateur.
    Si une topologie est déjà déployée, ne fait rien (idempotent).

    Args:
        state: État courant du graphe.

    Returns:
        dict: Mise à jour partielle du GraphState :
            - ``deployed_topology`` (DeployedTopology) si déploiement réussi
            - ``{}`` si topologie déjà présente ou déploiement échoué
    """
    logger.info("═══ TopologyDesigner : démarrage ═══")

    # Idempotence : ne rien faire si déjà déployé
    if state.deployed_topology is not None:
        logger.info(
            "Topologie '%s' déjà déployée — passage de la main au Supervisor",
            state.deployed_topology.topology_name,
        )
        return {}

    # Fallback si pas de clé API
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY absente — mode fallback déterministe")
        return _fallback_deploy(state)

    # --- Boucle agentique LLM ---
    try:
        from langchain_groq import ChatGroq

        context = f"Demande utilisateur : {state.user_request}\n"
        if state.target_topology_hint:
            context += f"Indice de taille souhaité : {state.target_topology_hint}\n"

        llm = ChatGroq(
            api_key=GROQ_API_KEY,
            model=WORKER_MODEL,
            temperature=WORKER_TEMPERATURE,
        ).bind_tools(WORKER_TOOLS)

        logger.info("Lancement de la boucle agentique TopologyDesigner")
        messages = run_agentic_loop(
            llm=llm,
            system_prompt=TOPOLOGY_DESIGNER_SYSTEM_PROMPT,
            context=context,
            tools=WORKER_TOOLS,
            max_iterations=5,
        )

        topo = _extract_deployed_topology(messages)
        if topo:
            logger.info(
                "TopologyDesigner terminé : '%s' (%d hosts, %d switches)",
                topo.topology_name, topo.nb_hosts, topo.nb_switches,
            )
            return {"deployed_topology": topo}
        else:
            logger.warning("TopologyDesigner : aucun déploiement réussi — tentative fallback")
            return _fallback_deploy(state)

    except Exception as exc:
        logger.error("topology_designer_node a levé une exception : %s", exc)
        return _fallback_deploy(state)
