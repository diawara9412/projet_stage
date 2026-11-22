"""
graph_phase2.py — Pipeline LangGraph Phase 2 : chaînes de sécurité SDN.

Graphe linéaire séquentiel (sans Supervisor) :

    START
      │
      ▼
  chain_analyzer    → lit l'automate JSON, détecte les suspects
      │
      ▼
  chain_generator   → traduit l'analyse en règles firewall/IDS/IPS
      │
      ▼
  chain_validator   → vérifie la cohérence, corrige les doublons
      │
      ▼
  policy_enforcer   → déploie sur les switches OVS via firewall_app REST
   (optionnel)
      │
      ▼
     END

Usage minimal :
    from graph_phase2 import build_phase2_graph
    from state import GraphState

    graph = build_phase2_graph()
    result = graph.invoke(GraphState(
        user_request="Sécuriser Pokemon GO",
        automate_path="automates/pokemon_go.json",
    ))
"""

import logging

from langgraph.graph import END, START, StateGraph

from agents.chain_analyzer import chain_analyzer_node
from agents.chain_generator import chain_generator_node
from agents.chain_validator import chain_validator_node
from agents.policy_enforcer import policy_enforcer_node
from state import GraphState, merge_state_updates

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Wrapper générique — fusionne les mises à jour via merge_state_updates
# ---------------------------------------------------------------------------

def _wrap_node(node_fn):
    """Enveloppe un nœud Phase 2 pour gérer correctement le GraphState Pydantic.

    Sans ce wrapper, LangGraph remplacerait les listes accumulatives par les
    nouvelles valeurs.  Avec ce wrapper, ``merge_state_updates`` assure la
    fusion correcte (append pour les listes, remplacement pour les scalaires).

    Si le nœud retourne ``{}`` (rien à faire), le wrapper retourne ``{}``
    sans copier l'état entier — optimisation de bande passante LangGraph.

    Args:
        node_fn: Fonction de nœud Phase 2 (retourne un dict de mises à jour).

    Returns:
        Fonction wrappée compatible LangGraph.
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
                "Erreur dans le nœud '%s' : %s",
                node_fn.__name__, exc, exc_info=True,
            )
            return {}

    wrapped.__name__ = node_fn.__name__
    return wrapped


# ---------------------------------------------------------------------------
# Construction du graphe
# ---------------------------------------------------------------------------

def build_phase2_graph(include_deployer: bool = True):
    """Construit et compile le pipeline LangGraph Phase 2.

    Le pipeline est toujours :
      chain_analyzer → chain_generator → chain_validator → [policy_enforcer]

    Le PolicyEnforcer est inclus par défaut.  Passer ``include_deployer=False``
    pour un mode dry-run (analyse + génération + validation seulement, sans
    appel REST vers firewall_app.py).

    Args:
        include_deployer: Si True (défaut), ajoute le nœud PolicyEnforcer.
                          Si False, le graphe se termine après chain_validator.

    Returns:
        ``CompiledStateGraph`` prêt pour ``.invoke()`` ou ``.stream()``.

    Examples:
        >>> graph = build_phase2_graph()
        >>> state = graph.invoke(GraphState(
        ...     user_request="Sécuriser Pokemon GO",
        ...     automate_path="automates/pokemon_go.json",
        ... ))
    """
    builder = StateGraph(GraphState)

    # ── Nœuds ──────────────────────────────────────────────────────────────
    builder.add_node("chain_analyzer",  _wrap_node(chain_analyzer_node))
    builder.add_node("chain_generator", _wrap_node(chain_generator_node))
    builder.add_node("chain_validator", _wrap_node(chain_validator_node))

    # ── Liens séquentiels ──────────────────────────────────────────────────
    builder.add_edge(START, "chain_analyzer")
    builder.add_edge("chain_analyzer",  "chain_generator")
    builder.add_edge("chain_generator", "chain_validator")

    if include_deployer:
        builder.add_node("policy_enforcer", _wrap_node(policy_enforcer_node))
        builder.add_edge("chain_validator", "policy_enforcer")
        builder.add_edge("policy_enforcer", END)
    else:
        builder.add_edge("chain_validator", END)

    compiled = builder.compile()
    mode = "complet (avec déploiement)" if include_deployer else "dry-run (sans déploiement)"
    logger.info("Pipeline Phase 2 compilé — mode : %s", mode)
    return compiled


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

    print("Compilation du pipeline Phase 2…")
    graph = build_phase2_graph(include_deployer=False)
    print("Pipeline compilé ✅")

    try:
        nodes = list(graph.nodes.keys())
        print(f"Nœuds : {nodes}")
    except AttributeError:
        print("Nœuds : chain_analyzer, chain_generator, chain_validator")
