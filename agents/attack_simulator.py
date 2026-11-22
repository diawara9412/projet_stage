"""
agents/attack_simulator.py — Agent AttackSimulator du système multi-agents SDN.

Injecte du trafic malveillant (SYN flood, port scan) sur la topologie Mininet
et mesure l'impact réseau avant et après les attaques.
"""

import logging
import warnings
from datetime import datetime, timezone

from agents._tool_executor import get_tool_results, run_agentic_loop
from state import AttackScenario, GraphState, NetworkObservation
from tools.attack_tools import (
    launch_port_scan,
    launch_syn_flood,
    measure_attack_impact,
)
from tools.traffic_tools import list_hosts_in_network

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    from config import GROQ_API_KEY, WORKER_MODEL, WORKER_TEMPERATURE

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Outils exposés à ce worker
# ---------------------------------------------------------------------------

WORKER_TOOLS = [
    list_hosts_in_network,
    launch_syn_flood,
    launch_port_scan,
    measure_attack_impact,
]

# ---------------------------------------------------------------------------
# Prompt système
# ---------------------------------------------------------------------------

ATTACK_SIMULATOR_SYSTEM_PROMPT = """Tu es l'agent AttackSimulator d'un système multi-agents de simulation réseau SDN.

## Ta mission

Injecter du trafic malveillant réaliste sur la topologie Mininet active pour simuler des scénarios d'attaque réseau. L'objectif est de générer des traces PCAP annotées avec du trafic d'attaque mesurable et visible dans Wireshark.

## Tes 4 outils

1. **list_hosts_in_network()** — Liste tous les hosts actifs avec leur nom et IP. À appeler EN PREMIER.

2. **launch_syn_flood(attacker_host, victim_host, duration, packets_per_second)** — SYN flood hping3 depuis l'attaquant vers la victime. `duration` en secondes, `packets_per_second` par défaut 10000.

3. **launch_port_scan(attacker_host, target_subnet)** — Scan nmap -sS depuis l'attaquant sur le sous-réseau cible. `target_subnet` exemple : "10.0.0.0/8".

4. **measure_attack_impact(victim_host, baseline_duration)** — Mesure la latence et la perte de paquets ICMP sur un host. Appelle cet outil **avant** et **après** l'attaque.

## Stratégie à suivre

1. Appelle `list_hosts_in_network()` pour voir les hosts et leurs IPs.
2. Mesure la latence de base avec `measure_attack_impact()` sur la future victime (`baseline_duration=3`).
3. Lance l'attaque appropriée.
4. Mesure l'impact post-attaque avec `measure_attack_impact()` sur la même victime.

## Choix de l'attaque selon la demande

| Demande utilisateur                            | Attaque à lancer          |
|------------------------------------------------|---------------------------|
| "DDoS" / "déni de service" / "flood" / "SYN"  | launch_syn_flood          |
| "scan" / "reconnaissance" / "nmap" / "port"   | launch_port_scan          |
| Plusieurs attaques demandées                   | syn_flood d'abord, puis scan |
| Aucune précision                               | launch_syn_flood (défaut) |

## Choix des hosts

- **Attaquant** : choisir h0 (ou le premier host listé).
- **Victime SYN flood** : choisir h1 ou h2 (pas le même que l'attaquant).
- **Cible port scan** : utiliser "10.0.0.0/8" pour scanner tous les hosts.

## Paramètres recommandés pour la démo

| Paramètre                     | Valeur recommandée       |
|-------------------------------|--------------------------|
| SYN flood duration            | 15 secondes              |
| SYN flood packets_per_second  | 10000 (défaut)           |
| Port scan target              | "10.0.0.0/8"             |
| measure baseline_duration     | 3 secondes               |

## Règles importantes

- Toujours mesurer **avant** et **après** l'attaque pour quantifier l'impact.
- Ne pas attaquer pendant plus de 30 secondes (limite de la démo).
- Une fois les attaques lancées et l'impact mesuré, ton travail est terminé.
"""

# ---------------------------------------------------------------------------
# Helpers d'extraction
# ---------------------------------------------------------------------------

def _extract_attack_scenarios(messages: list) -> list[AttackScenario]:
    """Extrait les AttackScenario depuis les résultats des outils d'attaque.

    Args:
        messages: Messages issus de la boucle agentique.

    Returns:
        list[AttackScenario]: Attaques réalisées avec succès.
    """
    attacks: list[AttackScenario] = []

    # SYN flood
    for result in get_tool_results(messages, "launch_syn_flood"):
        if result.get("status") == "success":
            try:
                attacks.append(AttackScenario(
                    attack_type="syn_flood",
                    attacker=result["attacker"],
                    victim=result.get("victim"),
                    target_subnet=None,
                    duration_s=float(result.get("duration_s", 0)),
                    metrics={
                        "packets_sent": result.get("packets_sent", -1),
                        "mode": result.get("mode", ""),
                        "victim_ip": result.get("victim_ip", ""),
                        "attacker_ip": result.get("attacker_ip", ""),
                    },
                ))
                logger.info(
                    "SYN flood extrait : %s → %s (%d paquets)",
                    result["attacker"], result.get("victim"),
                    result.get("packets_sent", -1),
                )
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("Impossible d'extraire AttackScenario syn_flood : %s", exc)

    # Port scan
    for result in get_tool_results(messages, "launch_port_scan"):
        if result.get("status") == "success":
            try:
                attacks.append(AttackScenario(
                    attack_type="port_scan",
                    attacker=result["attacker"],
                    victim=None,
                    target_subnet=result.get("target_subnet"),
                    duration_s=float(result.get("duration_s", 0)),
                    metrics={
                        "hosts_scanned": result.get("hosts_scanned", 0),
                        "open_ports": result.get("open_ports", []),
                        "raw_summary": result.get("raw_summary", ""),
                    },
                ))
                logger.info(
                    "Port scan extrait : %s → %s (%d hosts up)",
                    result["attacker"], result.get("target_subnet"),
                    result.get("hosts_scanned", 0),
                )
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("Impossible d'extraire AttackScenario port_scan : %s", exc)

    return attacks


def _extract_network_observations(messages: list) -> list[NetworkObservation]:
    """Extrait les NetworkObservation depuis les résultats de measure_attack_impact.

    Args:
        messages: Messages issus de la boucle agentique.

    Returns:
        list[NetworkObservation]: Mesures d'impact réseau.
    """
    observations: list[NetworkObservation] = []

    for result in get_tool_results(messages, "measure_attack_impact"):
        if result.get("status") == "success":
            try:
                observations.append(NetworkObservation(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    victim=result["victim"],
                    loss_percent=float(result.get("loss_percent", 0.0)),
                    avg_rtt_ms=float(result.get("avg_rtt_ms", -1.0)),
                    assessment=result.get("assessment", "unknown"),
                ))
                logger.info(
                    "Observation réseau : %s → %s (perte=%.1f%%, RTT=%.2f ms)",
                    result.get("observer", "?"), result["victim"],
                    result.get("loss_percent", 0),
                    result.get("avg_rtt_ms", -1),
                )
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("Impossible d'extraire NetworkObservation : %s", exc)

    return observations


# ---------------------------------------------------------------------------
# Fallback déterministe (sans LLM)
# ---------------------------------------------------------------------------

def _fallback_attack(state: GraphState) -> dict:
    """Lance un SYN flood et mesure l'impact directement sans LLM.

    Utilisé quand GROQ_API_KEY est absente ou quand le LLM produit une erreur.

    Args:
        state: État courant (deployed_topology pour les noms de hosts).

    Returns:
        dict avec attack_scenarios et network_observations si succès.
    """
    if state.deployed_topology is None or len(state.deployed_topology.hosts) < 2:
        logger.warning("Fallback : pas assez de hosts pour lancer une attaque")
        return {}

    hosts = state.deployed_topology.hosts
    attacker = hosts[0]
    victim = hosts[1]

    attacks: list[AttackScenario] = []
    observations: list[NetworkObservation] = []

    # Mesure baseline
    logger.info("Fallback : mesure baseline sur %s", victim)
    baseline = measure_attack_impact.invoke({
        "victim_host": victim,
        "baseline_duration": 3,
    })
    if baseline.get("status") == "success":
        observations.append(NetworkObservation(
            timestamp=datetime.now(timezone.utc).isoformat(),
            victim=victim,
            loss_percent=float(baseline.get("loss_percent", 0.0)),
            avg_rtt_ms=float(baseline.get("avg_rtt_ms", -1.0)),
            assessment=baseline.get("assessment", "unknown"),
        ))

    # SYN flood
    logger.info("Fallback : SYN flood %s → %s (15s)", attacker, victim)
    flood = launch_syn_flood.invoke({
        "attacker_host": attacker,
        "victim_host": victim,
        "duration": 15,
    })
    if flood.get("status") == "success":
        attacks.append(AttackScenario(
            attack_type="syn_flood",
            attacker=attacker,
            victim=victim,
            duration_s=15.0,
            metrics={
                "packets_sent": flood.get("packets_sent", -1),
                "mode": flood.get("mode", ""),
            },
        ))

    # Mesure post-attaque
    logger.info("Fallback : mesure post-attaque sur %s", victim)
    impact = measure_attack_impact.invoke({
        "victim_host": victim,
        "baseline_duration": 3,
    })
    if impact.get("status") == "success":
        observations.append(NetworkObservation(
            timestamp=datetime.now(timezone.utc).isoformat(),
            victim=victim,
            loss_percent=float(impact.get("loss_percent", 0.0)),
            avg_rtt_ms=float(impact.get("avg_rtt_ms", -1.0)),
            assessment=impact.get("assessment", "unknown"),
        ))

    updates: dict = {}
    if attacks:
        updates["attack_scenarios"] = attacks
    if observations:
        updates["network_observations"] = observations
    return updates


# ---------------------------------------------------------------------------
# Nœud principal
# ---------------------------------------------------------------------------

def attack_simulator_node(state: GraphState) -> dict:
    """Nœud AttackSimulator du graphe LangGraph.

    Lance des attaques réseau sur la topologie Mininet et mesure leur impact.
    Retourne {} si aucune topologie n'est disponible.

    Args:
        state: État courant du graphe.

    Returns:
        dict: Mise à jour partielle du GraphState :
            - ``attack_scenarios`` (list[AttackScenario]) : attaques accumulées
            - ``network_observations`` (list[NetworkObservation]) : mesures accumulées
            - ``{}`` si pas de topologie déployée
    """
    logger.info("═══ AttackSimulator : démarrage ═══")

    # Pré-requis : topologie déployée
    if state.deployed_topology is None:
        logger.warning("AttackSimulator : aucune topologie déployée — rien à faire")
        return {}

    topo = state.deployed_topology
    logger.info(
        "Topologie active : %s (%d hosts) | Attaques demandées : %s",
        topo.topology_name, topo.nb_hosts,
        state.requested_attacks or ["auto"],
    )

    # Fallback si pas de clé API
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY absente — mode fallback déterministe")
        return _fallback_attack(state)

    # --- Boucle agentique LLM ---
    try:
        from langchain_groq import ChatGroq

        requested = state.requested_attacks if state.requested_attacks else ["auto"]
        context = (
            f"Demande utilisateur : {state.user_request}\n\n"
            f"Topologie : {topo.topology_name} ({topo.nb_hosts} hosts)\n"
            f"Attaques demandées : {', '.join(requested)}\n"
            f"Hosts disponibles : {topo.hosts[:8]}"
            f"{'...' if len(topo.hosts) > 8 else ''}\n"
            f"IPs (extrait) : {dict(list(topo.host_ips.items())[:4])}\n"
        )
        if state.generated_traffic_flows:
            context += (
                f"\nTrafic légitime en cours : {len(state.generated_traffic_flows)} flux — "
                "l'attaque s'injecte par-dessus ce trafic de référence."
            )

        llm = ChatGroq(
            api_key=GROQ_API_KEY,
            model=WORKER_MODEL,
            temperature=WORKER_TEMPERATURE,
        ).bind_tools(WORKER_TOOLS)

        logger.info("Lancement de la boucle agentique AttackSimulator")
        messages = run_agentic_loop(
            llm=llm,
            system_prompt=ATTACK_SIMULATOR_SYSTEM_PROMPT,
            context=context,
            tools=WORKER_TOOLS,
            max_iterations=8,  # plus d'itérations : mesure avant + attaque + mesure après
        )

        new_attacks = _extract_attack_scenarios(messages)
        new_observations = _extract_network_observations(messages)

        logger.info(
            "AttackSimulator terminé : %d attaque(s), %d observation(s)",
            len(new_attacks), len(new_observations),
        )

        updates: dict = {}
        if new_attacks:
            updates["attack_scenarios"] = new_attacks
        if new_observations:
            updates["network_observations"] = new_observations
        return updates if updates else _fallback_attack(state)

    except BaseException as exc:
        logger.error("attack_simulator_node a levé une exception : %s", exc)
        return _fallback_attack(state)
