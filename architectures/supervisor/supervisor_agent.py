"""
architectures/supervisor/supervisor_agent.py — Le nœud « chef » de
l'architecture Superviseur, et sa logique de routage CONDITIONNEL.

Différence fondamentale avec l'architecture linéaire
----------------------------------------------------
Dans le graphe linéaire (``graph_phase2.py``), l'ordre des agents est figé par
des arêtes fixes : analyzer → generator → validator → enforcer.

Ici, c'est le Superviseur qui DÉCIDE à chaque tour quel sous-agent appeler,
en regardant l'état courant. Le graphe utilise donc des arêtes CONDITIONNELLES
(``add_conditional_edges``) branchées sur la fonction ``route_from_supervisor``.

Étape 1 (actuelle)
------------------
Le Superviseur ne connaît qu'UN sous-agent : l'Analyzer
(``agents/chain_analyzer.py``). Sa logique :

    - automate pas encore analysé  → router vers "analyzer"
    - automate analysé             → router vers "end"

La fonction de décision est volontairement écrite comme un PIPELINE de règles
ordonnées, pour qu'on ajoute le prochain agent (Firewall) en insérant une
seule règle (voir le commentaire « ÉTAPE SUIVANTE » plus bas).
"""

from __future__ import annotations

import logging
from typing import Literal

from pydantic import Field

from state import FirewallRule, GraphState, IdsSignature, IpsAction

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Destinations de routage possibles pour CETTE architecture
# ---------------------------------------------------------------------------
# On NE réutilise PAS le Literal AgentName de state.py (qui liste les agents
# Phase 1 : topology_designer, traffic_generator, ...). Le Superviseur de
# sécurité a son propre vocabulaire de routage, qui grandit à chaque étape.
#
# Étape 1 : "analyzer", "end".
# Étape 2 : ajout de "firewall".
# Étape 3 : ajout de "ids".
# Étape 4 : ajout de "ips".
# Étape 5 (actuelle, dernière) : ajout de "deployer".
SupervisorRoute = Literal["analyzer", "analyzer_b", "firewall", "ids", "ips", "deployer", "end"]


# ---------------------------------------------------------------------------
# État partagé de l'architecture Superviseur
# ---------------------------------------------------------------------------

class SupervisorState(GraphState):
    """État du graphe Superviseur — étend le GraphState existant.

    On RÉUTILISE tels quels les champs de GraphState :
      - ``automate_path``     : l'automate à analyser (entrée)
      - ``automate_analysis`` : le diagnostic produit par l'Analyzer (sortie)

    On AJOUTE ce qui est propre à l'orchestration par superviseur :
      - ``next_agent``      : prochaine destination de routage (redéfini ici
                              avec le vocabulaire du Superviseur de sécurité).
      - ``agents_invoked``  : trace ordonnée des sous-agents routés (preuve du
                              routage, affichée par le test).
      - ``supervisor_log``  : journal des raisonnements du Superviseur.
      - ``firewall_rules``  : règles firewall PARTIELLES produites par l'agent
                              Firewall (étape 2). On les stocke séparément car
                              la SecurityChain complète n'existe pas encore :
                              les IDS/IPS seront ajoutés par de futurs agents.
                              None = pas encore produites ; liste = produites
                              (même vide). Sert au routage (« firewall fait ? »).
      - ``firewall_summary``: résumé narratif de la politique firewall (LLM si
                              dispo, sinon résumé déterministe).
      - ``ids_signatures``  : signatures IDS PARTIELLES produites par l'agent
                              IDS (étape 3). Stockées séparément (la chaîne
                              complète n'existe pas encore). None = pas encore
                              produites ; liste = produites (même vide). Sert
                              au routage (« IDS fait ? »).
      - ``ids_summary``     : résumé narratif de la couverture de détection IDS.
      - ``ips_actions``     : actions IPS PARTIELLES produites par l'agent IPS
                              (étape 4). Chaque action référence une signature
                              IDS via on_signature. None = pas encore produites ;
                              liste = produites. Sert au routage (« IPS fait ? »).
      - ``ips_summary``     : résumé narratif de la réactivité de la défense IPS.

    NOTE étape 5 : ``security_chain``, ``validation_report`` et
    ``deployment_result`` sont DÉJÀ hérités de GraphState — l'agent Déployeur
    les remplit (assemblage + validation + déploiement). Rien à ajouter ici.
    ``security_chain is None`` sert de garde de routage (« assemblé ? »).
    """

    # On redéfinit next_agent pour qu'il accepte le vocabulaire de routage de
    # cette architecture (et non les agents Phase 1). Valeur initiale :
    # "analyzer" car c'est toujours la première chose à faire.
    next_agent: SupervisorRoute = "analyzer"  # type: ignore[assignment]

    # ── Condition B (traces brutes) ───────────────────────────────────────────
    # raw_app : nom d'app brute (ex. "pokemongo"). S'il est renseigné, le
    # Superviseur route vers l'Analyzer-B (tool-calling) au lieu de l'Analyzer A
    # (qui lit un *_enriched.json via automate_path). Mutuellement exclusif en
    # pratique avec automate_path.
    raw_app: str | None = None
    # Mode d'assemblage de l'Analyzer-B : "deterministic" (B-det) | "llm" (B-llm).
    assembly_mode: str = "deterministic"
    # Rapport de l'Analyzer-B (couverture, source, steps, tool_calls). None en A.
    analyzer_b_report: dict | None = None

    # Trace de l'orchestration (accumulée par le Superviseur à chaque décision)
    agents_invoked: list[str] = Field(default_factory=list)
    supervisor_log: list[str] = Field(default_factory=list)

    # Sortie de l'agent Firewall (chaîne PARTIELLE — firewall seul pour l'instant).
    # None tant que l'agent Firewall n'a pas tourné ; sert au routage idempotent.
    firewall_rules: list[FirewallRule] | None = None
    firewall_summary: str | None = None
    # Rapport de VÉRIFICATION du FirewallAgent LLM (résultat de recherche) :
    # source (llm/fallback), nb règles gardées/rejetées, hallucinations, conflits,
    # doublons, champs manquants, LAN manquantes. None si l'agent n'a pas tourné.
    firewall_verification_report: dict | None = None

    # Sortie de l'agent IDS (signatures de détection seules).
    # None tant que l'agent IDS n'a pas tourné ; sert au routage idempotent.
    ids_signatures: list[IdsSignature] | None = None
    ids_summary: str | None = None
    # Rapport de VÉRIFICATION de l'IDSAgent LLM (résultat de recherche) :
    # source, nb gardées/rejetées, hallucinations, doublons, champs, couverture.
    ids_verification_report: dict | None = None

    # Sortie de l'agent IPS (actions de prévention seules).
    # Chaque action référence une signature via on_signature → IdsSignature.id.
    # None tant que l'agent IPS n'a pas tourné ; sert au routage idempotent.
    ips_actions: list[IpsAction] | None = None
    ips_summary: str | None = None
    # Rapport de VÉRIFICATION de l'IPSAgent LLM (résultat de recherche) :
    # source, nb gardées/rejetées, ORPHELINS (clé), doublons, actions invalides,
    # couverture. None si l'agent n'a pas tourné.
    ips_verification_report: dict | None = None


# ---------------------------------------------------------------------------
# Logique de décision — le cœur extensible du Superviseur
# ---------------------------------------------------------------------------

def _decide_next_agent(state: SupervisorState) -> tuple[SupervisorRoute, str]:
    """Décide quel sous-agent appeler ensuite, selon l'état courant.

    Écrit comme un PIPELINE de règles ordonnées : on parcourt les étapes de la
    chaîne de sécurité dans l'ordre ; la première étape « pas encore faite »
    détermine l'agent à appeler. Quand tout est fait, on termine.

    Pour AJOUTER un agent (ex. Firewall à l'étape suivante), il suffit
    d'insérer une règle au bon endroit du pipeline :

        if state.security_chain is None:
            return "firewall", "Analyse prête mais aucune chaîne générée → Firewall."

    Returns:
        tuple (route, raisonnement) où route ∈ SupervisorRoute.
    """
    # ── Règle 1 : l'automate n'est pas encore analysé → Analyzer ──────────
    # Condition B : si une app BRUTE est fournie (raw_app), on route vers
    # l'Analyzer-B (tool-calling), qui enrichit lui-même. Sinon Analyzer A
    # (lecture d'un *_enriched.json déjà annoté).
    if state.automate_analysis is None:
        if state.raw_app:
            return (
                "analyzer_b",
                f"Traces brutes fournies (raw_app={state.raw_app}) → routage vers "
                "l'Analyzer-B (tool-calling, Condition B).",
            )
        return (
            "analyzer",
            "L'automate n'est pas encore analysé → routage vers l'Analyzer (Condition A).",
        )

    # ── Règle 2 : analyse prête mais firewall pas encore produit → Firewall ─
    # (firewall_rules is None signifie « l'agent Firewall n'a pas tourné ».)
    if state.firewall_rules is None:
        return (
            "firewall",
            "Analyse disponible mais règles firewall non produites → routage "
            "vers l'agent Firewall.",
        )

    # ── Règle 3 : firewall fait mais signatures IDS pas encore produites → IDS ─
    # (ids_signatures is None signifie « l'agent IDS n'a pas tourné ».)
    if state.ids_signatures is None:
        return (
            "ids",
            "Firewall produit mais aucune signature IDS → routage vers l'agent IDS.",
        )

    # ── Règle 4 : IDS fait mais actions IPS pas encore produites → IPS ──────
    # (ips_actions is None signifie « l'agent IPS n'a pas tourné ».)
    if state.ips_actions is None:
        return (
            "ips",
            "IDS produit mais aucune action IPS → routage vers l'agent IPS.",
        )

    # ── Règle 5 : volets prêts mais chaîne pas encore assemblée → Déployeur ─
    # (security_chain is None signifie « l'agent Déployeur n'a pas tourné ».)
    if state.security_chain is None:
        return (
            "deployer",
            "Firewall + IDS + IPS prêts mais chaîne non assemblée → routage vers "
            "le Déployeur (assemblage + déploiement).",
        )

    # ── Règle terminale : tout le travail est fait → fin ──────────────────
    nb_block = sum(1 for r in state.firewall_rules if r.action == "BLOCK")
    nb_allow = sum(
        1 for r in state.firewall_rules
        if r.action in ("ALLOW", "ALLOW_AND_INSPECT")
    )
    deploy_info = ""
    if state.deployment_result is not None:
        deploy_info = f", déploiement={state.deployment_result.status}"
    return (
        "end",
        f"Chaîne complète assemblée (risque={state.automate_analysis.risk_level}, "
        f"{nb_block} BLOCK / {nb_allow} ALLOW, {len(state.ids_signatures)} IDS, "
        f"{len(state.ips_actions)} IPS{deploy_info}) "
        "— pipeline de sécurité terminé → fin.",
    )


# ---------------------------------------------------------------------------
# Le nœud Superviseur
# ---------------------------------------------------------------------------

def supervisor_node(state: SupervisorState) -> dict:
    """Nœud chef du graphe : décide du prochain sous-agent et met à jour l'état.

    Ne fait AUCUN travail métier lui-même : il lit l'état, appelle
    ``_decide_next_agent`` et écrit sa décision dans ``next_agent``. Le graphe
    se charge ensuite du routage via ``route_from_supervisor``.

    Returns:
        dict de mises à jour partielles :
          - ``next_agent``     : la route choisie ("analyzer" | "end")
          - ``agents_invoked`` : trace mise à jour (append du sous-agent routé)
          - ``supervisor_log`` : journal mis à jour (append du raisonnement)
    """
    turn = len(state.supervisor_log) + 1
    route, reasoning = _decide_next_agent(state)

    logger.info("═══ Superviseur (tour %d) → %s ═══", turn, route)
    logger.info("    Raison : %s", reasoning)

    # On accumule en recalculant la liste complète : avec le schéma Pydantic de
    # LangGraph, le champ est remplacé par la valeur retournée (last-value-wins),
    # donc on renvoie « ancien + nouveau » pour obtenir l'accumulation.
    log_entry = f"[tour {turn}] décision={route} — {reasoning}"
    new_log = state.supervisor_log + [log_entry]

    # On ne trace dans agents_invoked QUE les vrais sous-agents (pas "end").
    new_invoked = state.agents_invoked
    if route != "end":
        new_invoked = state.agents_invoked + [route]

    return {
        "next_agent": route,
        "supervisor_log": new_log,
        "agents_invoked": new_invoked,
    }


# ---------------------------------------------------------------------------
# Fonction de routage — branchée sur add_conditional_edges
# ---------------------------------------------------------------------------

def route_from_supervisor(state: SupervisorState) -> str:
    """Lit la décision du Superviseur et renvoie le nom de l'arête à suivre.

    LangGraph appelle cette fonction APRÈS le nœud Superviseur. La chaîne
    retournée doit correspondre à une clé du mapping passé à
    ``add_conditional_edges`` dans ``graph_supervisor.py``.

    Returns:
        "analyzer" pour aller au nœud Analyzer, "end" pour terminer.
    """
    return state.next_agent
