"""
agents/supervisor.py — Agent Supervisor du système multi-agents SDN.

Orchestre les trois workers (TopologyDesigner, TrafficGenerator,
AttackSimulator) en décidant à chaque tour quel agent appeler en fonction
de l'état courant de la simulation.

Flux de décision
----------------
1. Règle dure : aucune topologie déployée → topology_designer (sans LLM).
2. Limite d'itérations atteinte → end.
3. Sinon : appel LLM Llama 3.3 70B via Groq.
4. Fallback déterministe si le LLM est indisponible ou produit une erreur.
"""

import json
import logging
import re
import warnings

from langchain_core.messages import HumanMessage, SystemMessage

from state import AgentName, GraphState, SupervisorDecision, merge_state_updates

# Import de la config — ne lève pas d'exception si la clé manque
with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    from config import (
        GROQ_API_KEY,
        MAX_ITERATIONS,
        SUPERVISOR_MODEL,
        SUPERVISOR_TEMPERATURE,
    )

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt système du Supervisor
# ---------------------------------------------------------------------------

SUPERVISOR_SYSTEM_PROMPT = """Tu es le Supervisor d'un système multi-agents de simulation réseau SDN (Software Defined Networking).

## Ton rôle

Orchestrer trois agents workers pour réaliser une simulation complète d'un réseau SDN :
générer du trafic légitime, injecter des attaques, et produire des captures PCAP annotées.

## Les 3 agents workers

1. **topology_designer**
   - Sélectionne et déploie une topologie réseau réelle depuis le Topology Zoo (ex. Abilene, GEANT).
   - Crée le réseau dans Mininet : hosts, switches OVS, liens.
   - DOIT être appelé EN PREMIER, avant tout autre agent.

2. **traffic_generator**
   - Génère du trafic réseau légitime sur la topologie déployée.
   - Lance des flux HTTP (curl), iperf3 (bande passante), DNS.
   - Démarre les captures PCAP via tcpdump.
   - DOIT être appelé APRÈS topology_designer.

3. **attack_simulator**
   - Injecte du trafic malveillant sur la topologie active.
   - Lance des SYN floods (hping3) et des scans de ports (nmap).
   - Mesure l'impact sur les hosts victimes (latence, perte de paquets).
   - DOIT être appelé APRÈS traffic_generator (pour avoir un trafic de référence).

## Les 4 décisions possibles

| Décision             | Quand l'utiliser                                             |
|----------------------|--------------------------------------------------------------|
| topology_designer    | Aucune topologie déployée — toujours la première étape.      |
| traffic_generator    | Topologie présente, mais aucun flux légitime généré.         |
| attack_simulator     | Topologie + trafic présents, mais aucune attaque lancée.     |
| end                  | Simulation complète (attaques lancées) ou limite atteinte.   |

## Règles absolues

1. Si aucune topologie n'est déployée → TOUJOURS topology_designer (règle dure, non négociable).
2. Ne jamais sauter traffic_generator avant attack_simulator.
3. Si iteration_count >= max_iterations → end (sécurité anti-boucle).

## Format de réponse OBLIGATOIRE

Réponds UNIQUEMENT avec un objet JSON valide, sans balises markdown, sans texte avant ou après :

{
  "reasoning": "Explication courte de ta décision (1-2 phrases).",
  "decision": "topology_designer"
}

La valeur de "decision" doit être EXACTEMENT l'une de ces chaînes :
"topology_designer", "traffic_generator", "attack_simulator", "end"
"""


# ---------------------------------------------------------------------------
# Helpers internes
# ---------------------------------------------------------------------------

def _build_context_message(state: GraphState) -> str:
    """Construit le message de contexte envoyé au LLM à chaque tour.

    Résume l'état courant de la simulation de façon concise pour que le LLM
    puisse prendre une décision informée.

    Args:
        state: État courant du graphe.

    Returns:
        str: Texte structuré décrivant la situation de la simulation.
    """
    lines = [
        f"## Demande utilisateur",
        f"{state.user_request}",
        "",
        f"## État de la simulation (tour {state.iteration_count + 1}/{state.max_iterations})",
        "",
    ]

    # Topologie
    if state.deployed_topology:
        t = state.deployed_topology
        lines.append(
            f"✅ Topologie déployée : **{t.topology_name}** "
            f"({t.nb_hosts} hosts, {t.nb_switches} switches, {t.nb_links} liens)"
        )
    else:
        lines.append("❌ Aucune topologie déployée")

    # Trafic légitime
    if state.generated_traffic_flows:
        lines.append(f"✅ Trafic légitime : {len(state.generated_traffic_flows)} flux générés")
        for flow in state.generated_traffic_flows:
            lines.append(f"   - [{flow.flow_type}] {flow.source} → {flow.destination} ({flow.duration_s:.0f}s)")
    else:
        lines.append("❌ Aucun trafic légitime généré")

    # Attaques
    if state.attack_scenarios:
        lines.append(f"✅ Attaques lancées : {len(state.attack_scenarios)}")
        for att in state.attack_scenarios:
            target = att.victim or att.target_subnet or "N/A"
            lines.append(f"   - [{att.attack_type}] {att.attacker} → {target}")
    else:
        lines.append("❌ Aucune attaque lancée")

    # Dernière observation réseau
    if state.network_observations:
        obs = state.network_observations[-1]
        lines.append(
            f"📊 Dernière observation réseau : **{obs.assessment}** "
            f"(perte={obs.loss_percent}%, RTT={obs.avg_rtt_ms} ms)"
        )

    # Attaques demandées par l'utilisateur
    if state.requested_attacks:
        lines.append(f"\n🎯 Attaques demandées : {', '.join(state.requested_attacks)}")

    # Indice topologie
    if state.target_topology_hint:
        lines.append(f"💡 Taille souhaitée : {state.target_topology_hint}")

    lines.append(f"\n⚠️  Itérations : {state.iteration_count}/{state.max_iterations}")

    return "\n".join(lines)


def _parse_supervisor_response(raw: str) -> tuple[str, str]:
    """Parse la réponse JSON du LLM Supervisor.

    Gère les cas où le LLM entoure le JSON de balises markdown (```json…```).

    Args:
        raw: Réponse brute du LLM.

    Returns:
        tuple[str, str]: (decision, reasoning)

    Raises:
        ValueError: Si le JSON est invalide ou si la décision est inconnue.
    """
    text = raw.strip()

    # Extrait le JSON si encapsulé dans des balises code markdown
    fence_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    data = json.loads(text)

    decision: str = str(data.get("decision", "")).strip()
    reasoning: str = str(data.get("reasoning", "Décision LLM.")).strip()

    valid: set[str] = {
        "topology_designer",
        "traffic_generator",
        "attack_simulator",
        "end",
    }
    if decision not in valid:
        raise ValueError(f"Décision inconnue : '{decision}' — attendu l'une de {valid}")

    return decision, reasoning


def _fallback_decision(state: GraphState) -> tuple[str, str]:
    """Décision déterministe utilisée si le LLM est indisponible ou en erreur.

    Applique la logique séquentielle naturelle de la simulation :
    topology → trafic → attaques → fin.

    Args:
        state: État courant du graphe.

    Returns:
        tuple[str, str]: (decision, reasoning)
    """
    if state.deployed_topology is None:
        return (
            "topology_designer",
            "Fallback : aucune topologie déployée, topology_designer requis.",
        )
    if not state.generated_traffic_flows:
        return (
            "traffic_generator",
            "Fallback : topologie présente mais aucun trafic légitime généré.",
        )
    if not state.attack_scenarios:
        return (
            "attack_simulator",
            "Fallback : trafic présent mais aucune attaque lancée.",
        )
    return "end", "Fallback : simulation complète (topologie + trafic + attaques)."


def _call_llm(state: GraphState) -> tuple[str, str]:
    """Appelle le LLM Groq pour obtenir la décision du Supervisor.

    En l'absence de clé API ou en cas d'erreur réseau/LLM, bascule
    automatiquement sur _fallback_decision.

    Args:
        state: État courant du graphe.

    Returns:
        tuple[str, str]: (decision, reasoning)
    """
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY absente — mode fallback déterministe activé.")
        return _fallback_decision(state)

    try:
        from langchain_groq import ChatGroq

        llm = ChatGroq(
            api_key=GROQ_API_KEY,
            model=SUPERVISOR_MODEL,
            temperature=SUPERVISOR_TEMPERATURE,
        )

        context = _build_context_message(state)
        messages = [
            SystemMessage(content=SUPERVISOR_SYSTEM_PROMPT),
            HumanMessage(content=context),
        ]

        logger.debug("Appel LLM Supervisor — contexte (%d chars)", len(context))
        response = llm.invoke(messages)
        raw: str = response.content

        logger.debug("Réponse LLM brute : %s", raw[:300])

        decision, reasoning = _parse_supervisor_response(raw)
        logger.info("LLM → décision='%s' | %s", decision, reasoning)
        return decision, reasoning

    except Exception as exc:
        logger.error("Erreur LLM (%s) — bascule sur fallback : %s", type(exc).__name__, exc)
        return _fallback_decision(state)


def _compute_simulation_report(state: GraphState) -> str:
    """Génère le rapport Markdown de fin de simulation.

    Agrège toutes les informations accumulées dans le GraphState pour
    produire un résumé lisible des actions réalisées.

    Args:
        state: État final du graphe.

    Returns:
        str: Rapport en Markdown.
    """
    lines = [
        "# Rapport de simulation SDN",
        f"**Demande** : {state.user_request}",
        "",
    ]

    # Topologie
    if state.deployed_topology:
        t = state.deployed_topology
        lines += [
            "## Topologie déployée",
            f"- Nom : **{t.topology_name}**",
            f"- Hosts : {t.nb_hosts}  |  Switches : {t.nb_switches}  |  Liens : {t.nb_links}",
            f"- Déployée le : {t.deployed_at}",
            "",
        ]

    # Trafic légitime
    if state.generated_traffic_flows:
        lines += [f"## Trafic légitime ({len(state.generated_traffic_flows)} flux)", ""]
        for flow in state.generated_traffic_flows:
            lines.append(
                f"- **{flow.flow_type}** : {flow.source} → {flow.destination} "
                f"({flow.duration_s:.1f}s) — {flow.metrics}"
            )
        lines.append("")

    # Attaques
    if state.attack_scenarios:
        lines += [f"## Attaques simulées ({len(state.attack_scenarios)})", ""]
        for att in state.attack_scenarios:
            target = att.victim or att.target_subnet or "N/A"
            lines.append(
                f"- **{att.attack_type}** : {att.attacker} → {target} "
                f"({att.duration_s:.1f}s) — {att.metrics}"
            )
        lines.append("")

    # Observations réseau
    if state.network_observations:
        lines += ["## Observations réseau", ""]
        for obs in state.network_observations:
            lines.append(
                f"- [{obs.timestamp}] {obs.victim} : **{obs.assessment}** "
                f"(perte={obs.loss_percent}%, RTT={obs.avg_rtt_ms} ms)"
            )
        lines.append("")

    # PCAP
    if state.final_pcap_path:
        lines += ["## Capture PCAP", f"Fichier : `{state.final_pcap_path}`", ""]

    # Historique des décisions
    if state.supervisor_decisions:
        lines += ["## Décisions du Supervisor", ""]
        for dec in state.supervisor_decisions:
            lines.append(f"- Tour {dec.turn} → **{dec.agent_called}** : {dec.reasoning}")
        lines.append("")

    lines.append(f"*Itérations totales : {state.iteration_count}/{state.max_iterations}*")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Nœud principal — appelé par LangGraph à chaque itération
# ---------------------------------------------------------------------------

def supervisor_node(state: GraphState) -> dict:
    """Nœud Supervisor du graphe LangGraph.

    Décide quel agent worker invoquer à chaque tour en lisant l'état courant.
    Applique d'abord les règles déterministes, puis consulte le LLM si nécessaire.

    Args:
        state: État courant du graphe (GraphState Pydantic).

    Returns:
        dict: Mises à jour partielles à fusionner dans le GraphState :
            - next_agent (str): prochain agent à router
            - supervisor_decisions (list[SupervisorDecision]): nouvelle décision
            - iteration_count (int): incrémenté de 1
            - simulation_report (str|None): rapport final si decision == "end"
    """
    turn = len(state.supervisor_decisions) + 1
    logger.info("═══ Supervisor : tour %d/%d ═══", turn, state.max_iterations)

    # ------------------------------------------------------------------
    # Règle dure 1 : limite d'itérations atteinte → end (priorité max)
    # Utilise `turn` plutôt qu'`iteration_count` : plus fiable car basé
    # sur len(supervisor_decisions) qui s'accumule même si _wrap_node
    # retourne {} sur exception (iteration_count resterait alors bloqué).
    # ------------------------------------------------------------------
    if turn > state.max_iterations:
        decision: AgentName = "end"
        reasoning = (
            f"Max iterations atteint ({state.max_iterations}) — arrêt forcé de la simulation."
        )
        logger.warning("Max iterations atteint (%d) — fin forcée", state.max_iterations)

    # ------------------------------------------------------------------
    # Règle dure 2 : aucune topologie déployée → topology_designer
    # ------------------------------------------------------------------
    elif state.deployed_topology is None:
        decision = "topology_designer"
        reasoning = (
            "Règle dure : aucune topologie n'est déployée — "
            "topology_designer doit être appelé en premier."
        )
        logger.info("Règle dure appliquée → %s", decision)

    # ------------------------------------------------------------------
    # Décision LLM (avec fallback déterministe si indisponible)
    # ------------------------------------------------------------------
    else:
        raw_decision, reasoning = _call_llm(state)
        decision = raw_decision  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Rapport final si la simulation se termine
    # ------------------------------------------------------------------
    simulation_report: str | None = None
    if decision == "end":
        simulation_report = _compute_simulation_report(state)
        logger.info("Rapport final généré (%d caractères)", len(simulation_report))

    # ------------------------------------------------------------------
    # Construction de la mise à jour
    # ------------------------------------------------------------------
    new_decision = SupervisorDecision(
        turn=turn,
        agent_called=decision,
        reasoning=reasoning,
        iteration_count=state.iteration_count,
    )

    logger.info("Supervisor → **%s** | %s", decision, reasoning)

    updates: dict = {
        "next_agent": decision,
        "supervisor_decisions": [new_decision],
        "iteration_count": state.iteration_count + 1,
    }
    if simulation_report is not None:
        updates["simulation_report"] = simulation_report

    return updates
