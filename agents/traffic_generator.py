"""
agents/traffic_generator.py — Agent TrafficGenerator du système multi-agents SDN.

Génère du trafic réseau légitime et réaliste sur la topologie Mininet déployée :
flux HTTP, bande passante iperf3, captures PCAP optionnelles.
"""

import logging
import warnings
from datetime import datetime, timezone

from agents._tool_executor import get_tool_results, run_agentic_loop
from state import GraphState, TrafficFlow
from tools.traffic_tools import (
    generate_http_flow,
    generate_iperf_flow,
    list_hosts_in_network,
    start_traffic_capture,
)

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    from config import GROQ_API_KEY, WORKER_MODEL, WORKER_TEMPERATURE

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Outils exposés à ce worker
# ---------------------------------------------------------------------------

WORKER_TOOLS = [
    list_hosts_in_network,
    generate_http_flow,
    generate_iperf_flow,
    start_traffic_capture,
]

# ---------------------------------------------------------------------------
# Prompt système
# ---------------------------------------------------------------------------

TRAFFIC_GENERATOR_SYSTEM_PROMPT = """Tu es l'agent TrafficGenerator d'un système multi-agents de simulation réseau SDN.

## Ta mission

Générer du trafic réseau légitime et réaliste sur la topologie Mininet active, afin de constituer la partie "trafic normal" des captures PCAP qui seront analysées.

## Tes 4 outils

1. **list_hosts_in_network()** — Liste tous les hosts actifs avec leur nom, IP et MAC. À appeler EN PREMIER pour connaître les hosts disponibles.

2. **generate_http_flow(source_host, destination_host, duration)** — Génère des requêtes HTTP curl en boucle depuis source vers destination. `duration` est en secondes.

3. **generate_iperf_flow(source_host, destination_host, duration, bandwidth)** — Génère un flux de bande passante mesuré avec iperf3. `bandwidth` : "10M", "100M", etc.

4. **start_traffic_capture(host_name, output_filename)** — Lance tcpdump sur un host pour capturer tout le trafic dans un fichier .pcap.

## Stratégie à suivre

1. Appelle `list_hosts_in_network()` pour voir les hosts disponibles et leurs IPs.
2. Génère au moins 2 flux variés :
   - Un flux **HTTP** avec `generate_http_flow`
   - Un flux **iperf3** avec `generate_iperf_flow`
3. Optionnellement, lance une capture PCAP avec `start_traffic_capture`.

## Paramètres recommandés pour la démo

| Paramètre         | Valeur recommandée                      |
|-------------------|-----------------------------------------|
| duration HTTP     | 10 à 15 secondes                        |
| duration iperf3   | 5 à 10 secondes                         |
| bandwidth iperf3  | "10M" (standard)                        |
| capture host      | le host qui reçoit le plus de trafic    |
| capture filename  | "capture_<topologie>_<horodatage>"      |

## Choix des hosts

- Diversifier les paires source/destination (éviter toujours h0→h1).
- Pour 2 flux : (h0→h1 HTTP) + (h1→h2 iperf) si au moins 3 hosts disponibles.
- Pour 2 hosts seulement : (h0→h1 HTTP) + (h1→h0 iperf) en sens inverse.

## Règles importantes

- Ne lance PAS d'attaques — c'est le rôle de l'AttackSimulator.
- Si un flux échoue (serveur non démarré, timeout), continue avec les autres.
- Varie les types de trafic pour que les captures soient représentatives.
- Une fois les flux générés, ton travail est terminé.
"""

# ---------------------------------------------------------------------------
# Helpers d'extraction
# ---------------------------------------------------------------------------

def _extract_traffic_flows(messages: list) -> list[TrafficFlow]:
    """Extrait les TrafficFlow depuis les résultats des outils de trafic.

    Collecte les résultats réussis de generate_http_flow et
    generate_iperf_flow et les convertit en objets TrafficFlow.

    Args:
        messages: Messages issus de la boucle agentique.

    Returns:
        list[TrafficFlow]: Flux légitimes générés avec succès.
    """
    flows: list[TrafficFlow] = []

    # Flux HTTP
    for result in get_tool_results(messages, "generate_http_flow"):
        if result.get("status") == "success":
            try:
                flows.append(TrafficFlow(
                    flow_type="http",
                    source=result["source"],
                    destination=result["destination"],
                    duration_s=float(result.get("actual_duration_s", 0)),
                    metrics={
                        "total_requests": result.get("total_requests", 0),
                        "total_bytes": result.get("total_bytes", 0),
                        "requests_per_second": result.get("requests_per_second", 0.0),
                        "destination_ip": result.get("destination_ip", ""),
                    },
                ))
                logger.info(
                    "Flux HTTP extrait : %s → %s (%d req)",
                    result["source"], result["destination"],
                    result.get("total_requests", 0),
                )
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("Impossible d'extraire TrafficFlow HTTP : %s", exc)

    # Flux iperf3
    for result in get_tool_results(messages, "generate_iperf_flow"):
        if result.get("status") == "success":
            try:
                flows.append(TrafficFlow(
                    flow_type="iperf",
                    source=result["source"],
                    destination=result["destination"],
                    duration_s=float(result.get("duration_s", 0)),
                    metrics={
                        "avg_mbps": result.get("avg_mbps", 0.0),
                        "lost_percent": result.get("lost_percent", 0.0),
                        "requested_bandwidth": result.get("requested_bandwidth", ""),
                        "destination_ip": result.get("destination_ip", ""),
                    },
                ))
                logger.info(
                    "Flux iperf3 extrait : %s → %s (%.2f Mbit/s)",
                    result["source"], result["destination"],
                    result.get("avg_mbps", 0),
                )
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("Impossible d'extraire TrafficFlow iperf3 : %s", exc)

    return flows


def _extract_pcap_path(messages: list) -> str | None:
    """Extrait le chemin du fichier PCAP si une capture a été lancée.

    Args:
        messages: Messages issus de la boucle agentique.

    Returns:
        str chemin absolu du fichier .pcap, ou None si pas de capture.
    """
    for result in get_tool_results(messages, "start_traffic_capture"):
        if result.get("status") == "success":
            path = result.get("output_file")
            if path:
                logger.info("Capture PCAP démarrée : %s (PID %s)", path, result.get("pid"))
                return path
    return None


# ---------------------------------------------------------------------------
# Fallback déterministe (sans LLM)
# ---------------------------------------------------------------------------

def _fallback_generate(state: GraphState) -> dict:
    """Génère un flux HTTP et un flux iperf3 directement sans LLM.

    Utilisé quand GROQ_API_KEY est absente ou quand le LLM produit une erreur.

    Args:
        state: État courant (deployed_topology pour les noms de hosts).

    Returns:
        dict avec "generated_traffic_flows" si succès, sinon dict vide.
    """
    if state.deployed_topology is None or len(state.deployed_topology.hosts) < 2:
        logger.warning("Fallback : pas assez de hosts pour générer du trafic")
        return {}

    hosts = state.deployed_topology.hosts
    src, dst = hosts[0], hosts[1]
    # Pour l'iperf, on inverse la direction si on a au moins 3 hosts
    iperf_src = hosts[2] if len(hosts) > 2 else hosts[1]
    iperf_dst = hosts[0]

    flows: list[TrafficFlow] = []

    logger.info("Fallback : génération HTTP %s → %s", src, dst)
    http_result = generate_http_flow.invoke({
        "source_host": src,
        "destination_host": dst,
        "duration": 10,
    })
    if http_result.get("status") == "success":
        flows.append(TrafficFlow(
            flow_type="http",
            source=src,
            destination=dst,
            duration_s=float(http_result.get("actual_duration_s", 10)),
            metrics={
                "total_requests": http_result.get("total_requests", 0),
                "total_bytes": http_result.get("total_bytes", 0),
            },
        ))

    logger.info("Fallback : génération iperf3 %s → %s", iperf_src, iperf_dst)
    iperf_result = generate_iperf_flow.invoke({
        "source_host": iperf_src,
        "destination_host": iperf_dst,
        "duration": 5,
        "bandwidth": "10M",
    })
    if iperf_result.get("status") == "success":
        flows.append(TrafficFlow(
            flow_type="iperf",
            source=iperf_src,
            destination=iperf_dst,
            duration_s=float(iperf_result.get("duration_s", 5)),
            metrics={
                "avg_mbps": iperf_result.get("avg_mbps", 0.0),
                "lost_percent": iperf_result.get("lost_percent", 0.0),
            },
        ))

    return {"generated_traffic_flows": flows} if flows else {}


# ---------------------------------------------------------------------------
# Nœud principal
# ---------------------------------------------------------------------------

def traffic_generator_node(state: GraphState) -> dict:
    """Nœud TrafficGenerator du graphe LangGraph.

    Génère du trafic HTTP et iperf3 sur la topologie Mininet déployée.
    Retourne {} si aucune topologie n'est disponible.

    Args:
        state: État courant du graphe.

    Returns:
        dict: Mise à jour partielle du GraphState :
            - ``generated_traffic_flows`` (list[TrafficFlow]) : flux accumulés
            - ``final_pcap_path`` (str|None) : chemin capture PCAP si démarrée
            - ``{}`` si pas de topologie déployée
    """
    logger.info("═══ TrafficGenerator : démarrage ═══")

    # Pré-requis : topologie déployée
    if state.deployed_topology is None:
        logger.warning("TrafficGenerator : aucune topologie déployée — rien à faire")
        return {}

    topo = state.deployed_topology
    logger.info("Topologie active : %s (%d hosts)", topo.topology_name, topo.nb_hosts)

    # Fallback si pas de clé API
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY absente — mode fallback déterministe")
        return _fallback_generate(state)

    # --- Boucle agentique LLM ---
    try:
        from langchain_groq import ChatGroq

        context = (
            f"Demande utilisateur : {state.user_request}\n\n"
            f"Topologie déployée : {topo.topology_name} "
            f"({topo.nb_hosts} hosts, {topo.nb_switches} switches)\n"
            f"Hosts disponibles : {topo.hosts[:10]}"
            f"{'...' if len(topo.hosts) > 10 else ''}\n"
            f"IPs (extrait) : "
            f"{dict(list(topo.host_ips.items())[:5])}\n"
        )
        if state.generated_traffic_flows:
            context += f"\nTrafic déjà généré : {len(state.generated_traffic_flows)} flux (ne pas redupliquer)"

        llm = ChatGroq(
            api_key=GROQ_API_KEY,
            model=WORKER_MODEL,
            temperature=WORKER_TEMPERATURE,
        ).bind_tools(WORKER_TOOLS)

        logger.info("Lancement de la boucle agentique TrafficGenerator")
        messages = run_agentic_loop(
            llm=llm,
            system_prompt=TRAFFIC_GENERATOR_SYSTEM_PROMPT,
            context=context,
            tools=WORKER_TOOLS,
            max_iterations=6,
        )

        new_flows = _extract_traffic_flows(messages)
        pcap_path = _extract_pcap_path(messages)

        logger.info(
            "TrafficGenerator terminé : %d nouveaux flux générés", len(new_flows)
        )

        updates: dict = {}
        if new_flows:
            updates["generated_traffic_flows"] = new_flows
        if pcap_path:
            updates["final_pcap_path"] = pcap_path
        return updates if updates else _fallback_generate(state)

    except BaseException as exc:
        logger.error("traffic_generator_node a levé une exception : %s", exc)
        return _fallback_generate(state)
