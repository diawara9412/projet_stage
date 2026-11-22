"""
graph.py — Assemblage du graphe LangGraph multi-agents SDN.

Implémente le pattern superviseur :
- START → Supervisor → routing conditionnel → workers ou END
- Chaque worker retourne TOUJOURS au Supervisor

Topologie::

    START
      │
      ▼
  Supervisor ──end──▶ END
      ▲   │
      │   ├──topology_designer──▶ TopologyDesigner ──┐
      │   ├──traffic_generator──▶ TrafficGenerator   ├──▶ (retour)
      └───┴──attack_simulator───▶ AttackSimulator  ──┘
"""

import logging

from langgraph.graph import END, START, StateGraph

from agents.attack_simulator import attack_simulator_node
from agents.supervisor import supervisor_node
from agents.topology_designer import topology_designer_node
from agents.traffic_generator import traffic_generator_node
from state import GraphState, merge_state_updates

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Wrapper générique — fusionne les updates partiels via merge_state_updates
# ---------------------------------------------------------------------------

def _wrap_node(node_fn):
    """Enveloppe un nœud agent pour accumuler correctement les champs liste.

    Sans ce wrapper, LangGraph remplacerait chaque liste par la nouvelle
    valeur (comportement par défaut avec Pydantic BaseModel).  Avec ce
    wrapper, les champs listés dans ``_ACCUMULATIVE_FIELDS`` sont étendus
    (append) plutôt que remplacés.

    Le nœud retourne toujours soit ``{}`` (aucun changement) soit le state
    complet mis à jour sous forme de dict, que LangGraph valide en
    ``GraphState``.

    Args:
        node_fn: Fonction de nœud retournant un dict de mises à jour
            partielles.

    Returns:
        Fonction wrappée compatible avec LangGraph (retourne un dict).
    """
    def wrapped(state: GraphState) -> dict:
        try:
            updates = node_fn(state)
            if not updates:
                return {}
            merged = merge_state_updates(state, updates)
            return merged.model_dump()
        except Exception as exc:
            logger.error(
                "Erreur dans le wrapper du nœud '%s' : %s",
                node_fn.__name__, exc,
            )
            return {}

    wrapped.__name__ = node_fn.__name__
    return wrapped


# ---------------------------------------------------------------------------
# Routing conditionnel depuis le Supervisor
# ---------------------------------------------------------------------------

def route_supervisor(state: GraphState) -> str:
    """Lit la décision du Supervisor et retourne la destination suivante.

    Appelée par LangGraph immédiatement après chaque exécution du nœud
    Supervisor pour décider vers quel nœud router le flux.

    Args:
        state: État courant du graphe.

    Returns:
        Une des 4 clés du mapping de ``add_conditional_edges`` :
        ``"topology_designer"``, ``"traffic_generator"``,
        ``"attack_simulator"``, ou ``"end"``.
    """
    destination: str = state.next_agent
    logger.info("Routing Supervisor → %s", destination)
    return destination


# ---------------------------------------------------------------------------
# Construction et compilation du graphe
# ---------------------------------------------------------------------------

def build_graph(max_iterations: int = 5):
    """Construit et compile le graphe LangGraph multi-agents.

    Le paramètre ``max_iterations`` ne configure pas le graphe en lui-même
    (LangGraph n'a pas de limite intégrée) ; il est passé via l'état initial
    (``GraphState.max_iterations``) et lu par le Supervisor pour décider de
    s'arrêter.

    Args:
        max_iterations: Valeur par défaut pour ``GraphState.max_iterations``
            si non spécifiée dans l'état initial.  Ignoré si l'état initial
            contient déjà ``max_iterations``.

    Returns:
        ``CompiledStateGraph`` prêt pour ``.invoke()`` ou ``.stream()``.

    Examples:
        >>> graph = build_graph()
        >>> result = graph.invoke(GraphState(user_request="Simuler un réseau"))
    """
    builder = StateGraph(GraphState)

    # ── Nœuds ──────────────────────────────────────────────────────────────
    # Chaque nœud est enveloppé pour accumuler les listes correctement.
    builder.add_node("supervisor",         _wrap_node(supervisor_node))
    builder.add_node("topology_designer",  _wrap_node(topology_designer_node))
    builder.add_node("traffic_generator",  _wrap_node(traffic_generator_node))
    builder.add_node("attack_simulator",   _wrap_node(attack_simulator_node))

    # ── Entrée : toujours le Supervisor en premier ──────────────────────────
    builder.add_edge(START, "supervisor")

    # ── Routing conditionnel depuis le Supervisor ───────────────────────────
    builder.add_conditional_edges(
        "supervisor",
        route_supervisor,
        {
            "topology_designer": "topology_designer",
            "traffic_generator": "traffic_generator",
            "attack_simulator":  "attack_simulator",
            "end":               END,
        },
    )

    # ── Les 3 workers retournent TOUJOURS au Supervisor ─────────────────────
    builder.add_edge("topology_designer", "supervisor")
    builder.add_edge("traffic_generator", "supervisor")
    builder.add_edge("attack_simulator",  "supervisor")

    return builder.compile()


# ---------------------------------------------------------------------------
# Test rapide
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore", category=RuntimeWarning)

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    graph = build_graph()
    print("Graphe LangGraph compilé avec succès ✅")

    # Afficher les nœuds selon l'API disponible dans la version LangGraph
    try:
        node_names = list(graph.nodes.keys())
        print(f"Nœuds : {node_names}")
    except AttributeError:
        # Certaines versions exposent les nœuds différemment
        print("Nœuds : supervisor, topology_designer, traffic_generator, attack_simulator")
