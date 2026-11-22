"""
architectures/supervisor/graph_supervisor.py — Construction du graphe LangGraph
de l'architecture SUPERVISEUR.

Topologie du graphe (étape 5 — architecture COMPLÈTE)
-----------------------------------------------------

        START
          │
          ▼
    ┌─────────────┐   route_from_supervisor (CONDITIONNEL)
    │ supervisor  │──────────────┬── "analyzer" ─▶ ┌──────────┐
    └─────────────┘              │                 │ analyzer │──┐
          ▲                      ├── "firewall" ─▶ ┌──────────┐  │
          │                      │                 │ firewall │──┤
          │                      ├── "ids" ──────▶ ┌──────────┐  │
          │                      │                 │   ids    │──┤
          │                      ├── "ips" ──────▶ ┌──────────┐  │
          │                      │                 │   ips    │──┤
          │                      ├── "deployer" ─▶ ┌──────────┐  │
          │ (arêtes fixes retour)│                 │ deployer │──┤
          │                      │                 └──────────┘  │
          └──────────────────────┼───────────────────────────────┘
                                  │
                                  └── "end" ─▶ END

Flux concret avec UN seul automate :
    START → supervisor → analyzer → supervisor → firewall → supervisor
          → ids → supervisor → ips → supervisor → deployer → supervisor
          → (décide "end") → END

Le nœud Déployeur ASSEMBLE la SecurityChain (toujours) puis la DÉPLOIE si le
paramètre ``deploy=True`` a été passé à ``build_supervisor_graph``.

C'est l'``add_conditional_edges`` sur le nœud ``supervisor`` qui distingue
cette architecture de la linéaire : la destination dépend de l'état, pas d'un
ordre figé.
"""

import logging

from langgraph.graph import END, START, StateGraph

from agents.chain_analyzer import chain_analyzer_node
from agents.chain_analyzer_b import chain_analyzer_b_node
from architectures.supervisor.deployer_agent import DEFAULT_ENDPOINT, make_deployer_node
from architectures.supervisor.firewall_agent import firewall_node
from architectures.supervisor.ids_agent import ids_node
from architectures.supervisor.ips_agent import ips_node
from architectures.supervisor.supervisor_agent import (
    SupervisorState,
    route_from_supervisor,
    supervisor_node,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Wrapper de sous-agent — capture d'erreurs + trace
# ---------------------------------------------------------------------------

def _wrap_subagent(node_fn):
    """Enveloppe un sous-agent pour journaliser et neutraliser les exceptions.

    Le sous-agent (ex. ``chain_analyzer_node``) retourne un dict de mises à
    jour partielles que LangGraph applique directement à l'état (last-value).
    Pas de fusion manuelle nécessaire ici : les champs écrits par l'Analyzer
    (``automate_analysis``) sont scalaires.

    Si le sous-agent lève une exception, on retourne ``{}`` pour ne pas casser
    le graphe — le Superviseur reverra l'état inchangé au tour suivant.
    """
    def wrapped(state: SupervisorState) -> dict:
        try:
            return node_fn(state) or {}
        except Exception as exc:
            logger.error(
                "Erreur dans le sous-agent '%s' : %s",
                node_fn.__name__, exc, exc_info=True,
            )
            return {}

    wrapped.__name__ = node_fn.__name__
    return wrapped


# ---------------------------------------------------------------------------
# Construction du graphe
# ---------------------------------------------------------------------------

def build_supervisor_graph(deploy: bool = False, endpoint: str = DEFAULT_ENDPOINT):
    """Construit et compile le graphe Superviseur (étape 5 — architecture complète).

    Args:
        deploy: Si False (défaut), le Déployeur ASSEMBLE seulement la
                SecurityChain (testable sans contrôleur ni Mininet). Si True,
                il assemble PUIS déploie via REST sur le sdn_executor.
        endpoint: URL de base de l'API sdn_executor (utilisée si deploy=True).

    Returns:
        ``CompiledStateGraph`` prêt pour ``.invoke()`` / ``.stream()``,
        opérant sur un ``SupervisorState``.
    """
    builder = StateGraph(SupervisorState)

    # ── Nœuds ───────────────────────────────────────────────────────────────
    builder.add_node("supervisor", supervisor_node)
    # On RÉUTILISE l'agent Analyzer existant tel quel, simplement enveloppé.
    builder.add_node("analyzer", _wrap_subagent(chain_analyzer_node))
    # Analyzer-B (Condition B) : enrichit lui-même via tool-calling depuis raw_app.
    builder.add_node("analyzer_b", _wrap_subagent(chain_analyzer_b_node))
    # Agent Firewall (étape 2) — propre à l'architecture superviseur.
    builder.add_node("firewall", _wrap_subagent(firewall_node))
    # Agent IDS (étape 3) — propre à l'architecture superviseur.
    builder.add_node("ids", _wrap_subagent(ids_node))
    # Agent IPS (étape 4) — propre à l'architecture superviseur.
    builder.add_node("ips", _wrap_subagent(ips_node))
    # Agent Déployeur (étape 5) — assemble (+ déploie si deploy=True).
    # Le nœud est fabriqué avec les paramètres deploy/endpoint capturés.
    builder.add_node("deployer", _wrap_subagent(make_deployer_node(deploy, endpoint)))

    # ── Entrée ───────────────────────────────────────────────────────────────
    builder.add_edge(START, "supervisor")

    # ── Arêtes CONDITIONNELLES depuis le Superviseur ─────────────────────────
    # route_from_supervisor renvoie l'une des clés ci-dessous ; le mapping les
    # traduit en destinations réelles du graphe. C'est ce branchement
    # conditionnel qui distingue l'archi superviseur de la baseline linéaire.
    builder.add_conditional_edges(
        "supervisor",
        route_from_supervisor,
        {
            "analyzer": "analyzer",
            "analyzer_b": "analyzer_b",
            "firewall": "firewall",
            "ids": "ids",
            "ips": "ips",
            "deployer": "deployer",
            "end": END,
        },
    )

    # ── Retour des sous-agents vers le Superviseur ───────────────────────────
    # Après avoir travaillé, chaque sous-agent REDONNE la main au Superviseur,
    # qui décidera de la suite (autre agent, ou fin). C'est la boucle
    # caractéristique de l'architecture superviseur.
    builder.add_edge("analyzer", "supervisor")
    builder.add_edge("analyzer_b", "supervisor")
    builder.add_edge("firewall", "supervisor")
    builder.add_edge("ids", "supervisor")
    builder.add_edge("ips", "supervisor")
    builder.add_edge("deployer", "supervisor")

    compiled = builder.compile()
    logger.info(
        "Graphe Superviseur compilé (étape 5 : Analyzer+Firewall+IDS+IPS+Déployeur, deploy=%s)",
        deploy,
    )
    return compiled


# ---------------------------------------------------------------------------
# Test rapide de compilation
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    print("Compilation du graphe Superviseur…")
    graph = build_supervisor_graph()
    print("Graphe compilé ✅")
    try:
        print(f"Nœuds : {list(graph.nodes.keys())}")
    except AttributeError:
        print("Nœuds : supervisor, analyzer, firewall, ids, ips, deployer")
