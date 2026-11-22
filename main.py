"""
main.py — Point d'entrée CLI du système multi-agents SDN.

Lance une simulation complète :
  1. TopologyDesigner  → déploie une topologie Mininet depuis le Topology Zoo
  2. TrafficGenerator  → génère du trafic HTTP et iperf3
  3. AttackSimulator   → injecte des attaques (SYN flood, port scan)
  4. Supervisor        → orchestre les agents et arrête quand c'est terminé

Usage::

    sudo python3 main.py --request "Simuler un réseau avec attaque DDoS"
    sudo python3 main.py --request "Réseau moyen avec port scan" \\
        --topology-hint medium --attacks port_scan --max-iterations 6
    sudo python3 main.py --request "Demo rapide" --stream

Notes:
    - Requiert sudo pour Mininet (création d'interfaces réseau).
    - GROQ_API_KEY dans .env pour le mode LLM (sinon fallback déterministe).
    - Les rapports sont sauvegardés dans captures/simulation_report_*.md.
"""

import argparse
import logging
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

warnings.filterwarnings("ignore", category=RuntimeWarning)

from config import LOG_LEVEL, MAX_ITERATIONS
from graph import build_graph
from state import GraphState

logger = logging.getLogger(__name__)

CAPTURES_DIR = Path(__file__).parent / "captures"


# ---------------------------------------------------------------------------
# Sauvegarde du rapport
# ---------------------------------------------------------------------------

def _save_report(report: str, timestamp: str) -> Path:
    """Sauvegarde le rapport de simulation dans captures/.

    Args:
        report: Contenu Markdown du rapport.
        timestamp: Horodatage ISO pour le nom de fichier (ex: 20260520_143022).

    Returns:
        Path: Chemin absolu du fichier créé.
    """
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    path = CAPTURES_DIR / f"simulation_report_{timestamp}.md"
    path.write_text(report, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Résumé des décisions Supervisor
# ---------------------------------------------------------------------------

def _log_supervisor_summary(state: GraphState) -> None:
    """Affiche un résumé des décisions prises par le Supervisor.

    Args:
        state: État final du graphe après simulation.
    """
    decisions = state.supervisor_decisions
    if not decisions:
        logger.info("Aucune décision Supervisor enregistrée.")
        return

    logger.info("── Décisions Supervisor (%d) ──────────────────", len(decisions))
    for i, d in enumerate(decisions, 1):
        logger.info(
            "  [%d] → %-20s | %s",
            i, d.decision, (d.reasoning or "")[:80],
        )
    logger.info("───────────────────────────────────────────────")


# ---------------------------------------------------------------------------
# Résultat final — extrait GraphState depuis le retour du graphe
# ---------------------------------------------------------------------------

def _extract_final_state(result: dict | GraphState) -> GraphState:
    """Convertit le résultat du graphe en GraphState typé.

    LangGraph peut retourner un dict ou un objet Pydantic selon la version.

    Args:
        result: Valeur retournée par ``graph.invoke()``.

    Returns:
        GraphState: État final de la simulation.
    """
    if isinstance(result, GraphState):
        return result
    if isinstance(result, dict):
        return GraphState.model_validate(result)
    raise TypeError(f"Type de retour inattendu du graphe : {type(result)}")


# ---------------------------------------------------------------------------
# Affichage console du résumé de simulation
# ---------------------------------------------------------------------------

def _print_summary(state: GraphState) -> None:
    """Affiche un résumé lisible de la simulation sur stdout.

    Args:
        state: État final de la simulation.
    """
    sep = "═" * 60
    print(f"\n{sep}")
    print("  RÉSUMÉ DE SIMULATION")
    print(sep)
    print(f"  Requête     : {state.user_request}")

    if state.deployed_topology:
        t = state.deployed_topology
        print(f"  Topologie   : {t.topology_name}  ({t.nb_hosts} hosts, {t.nb_switches} switches)")
    else:
        print("  Topologie   : aucune déployée")

    print(f"  Trafic      : {len(state.generated_traffic_flows)} flux générés")
    print(f"  Attaques    : {len(state.attack_scenarios)} scénario(s)")
    print(f"  Mesures     : {len(state.network_observations)} observation(s) réseau")
    print(f"  Itérations  : {state.iteration_count}")

    if state.final_pcap_path:
        print(f"  PCAP        : {state.final_pcap_path}")

    if state.attack_scenarios:
        print("\n  Attaques réalisées :")
        for a in state.attack_scenarios:
            if a.attack_type == "syn_flood":
                pkts = a.metrics.get("packets_sent", "?")
                print(f"    • SYN flood  {a.attacker} → {a.victim}  ({pkts} paquets, {a.duration_s:.0f}s)")
            elif a.attack_type == "port_scan":
                hosts = a.metrics.get("hosts_scanned", "?")
                print(f"    • Port scan  {a.attacker} → {a.target_subnet}  ({hosts} hosts up)")

    if state.network_observations:
        print("\n  Observations réseau :")
        for obs in state.network_observations:
            print(
                f"    • {obs.victim:6s}  loss={obs.loss_percent:.1f}%  "
                f"RTT={obs.avg_rtt_ms:.2f} ms  [{obs.assessment}]"
            )

    print(sep)


# ---------------------------------------------------------------------------
# Fonction principale
# ---------------------------------------------------------------------------

def main() -> int:
    """Point d'entrée principal.

    Returns:
        int: Code de retour (0 = succès, 1 = erreur).
    """
    # ── Argparse ──────────────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        description="Système multi-agents SDN : simulation réseau + attaques via LangGraph",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  sudo python3 main.py --request 'Simuler un réseau avec DDoS'\n"
            "  sudo python3 main.py --request 'Réseau moyen, port scan' "
            "--topology-hint medium --attacks port_scan\n"
            "  sudo python3 main.py --request 'Demo rapide' --stream\n"
        ),
    )
    parser.add_argument(
        "--request",
        type=str,
        default="Simuler un réseau SDN avec génération de trafic et attaque",
        help="Requête en langage naturel décrivant la simulation souhaitée",
    )
    parser.add_argument(
        "--topology-hint",
        choices=["small", "medium", "large"],
        default=None,
        dest="topology_hint",
        help="Taille indicative de la topologie (small=Abilene, medium=Geant2012, large=plus grande)",
    )
    parser.add_argument(
        "--attacks",
        nargs="*",
        default=[],
        metavar="ATTACK",
        help="Types d'attaques à simuler (ex: syn_flood port_scan). Vide = auto.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=MAX_ITERATIONS,
        dest="max_iterations",
        help=f"Nombre maximum d'itérations du Supervisor (défaut : {MAX_ITERATIONS})",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Mode streaming : affiche les mises à jour de chaque nœud en temps réel",
    )

    args = parser.parse_args()

    # ── Logging ───────────────────────────────────────────────────────────────
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── État initial ──────────────────────────────────────────────────────────
    initial_state = GraphState(
        user_request=args.request,
        target_topology_hint=args.topology_hint,
        requested_attacks=args.attacks or [],
        max_iterations=args.max_iterations,
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    logger.info("Démarrage de la simulation")
    logger.info("  Requête          : %s", args.request)
    logger.info("  Topology hint    : %s", args.topology_hint or "auto")
    logger.info("  Attaques         : %s", args.attacks or ["auto"])
    logger.info("  Max itérations   : %d", args.max_iterations)
    logger.info("  Mode streaming   : %s", args.stream)

    # ── Construction du graphe ────────────────────────────────────────────────
    try:
        graph = build_graph(max_iterations=args.max_iterations)
        logger.info("Graphe LangGraph compilé")
    except Exception as exc:
        logger.error("Impossible de compiler le graphe : %s", exc)
        return 1

    # ── Exécution ─────────────────────────────────────────────────────────────
    final_state: GraphState | None = None

    try:
        if args.stream:
            # Mode streaming : chaque événement de nœud est logué en temps réel
            logger.info("Mode streaming activé — suivi nœud par nœud")
            accumulated: dict = {}
            for event in graph.stream(initial_state):
                for node_name, node_output in event.items():
                    if isinstance(node_output, dict) and node_output:
                        keys = list(node_output.keys())
                        logger.info("  [stream] %-20s → champs mis à jour : %s", node_name, keys)
                        accumulated.update(node_output)
            # Reconstruit l'état final depuis les champs accumulés
            if accumulated:
                final_state = _extract_final_state(accumulated)
        else:
            # Mode synchrone classique
            result = graph.invoke(initial_state)
            final_state = _extract_final_state(result)

    except KeyboardInterrupt:
        print("\n\nSimulation interrompue par l'utilisateur.")
        return 130
    except BaseException as exc:
        logger.error("Erreur durant la simulation : %s", exc)
        return 1

    # ── Résultats ─────────────────────────────────────────────────────────────
    if final_state is None:
        logger.error("La simulation n'a produit aucun état final.")
        return 1

    _log_supervisor_summary(final_state)
    _print_summary(final_state)

    # ── Sauvegarde du rapport ─────────────────────────────────────────────────
    if final_state.simulation_report:
        report_path = _save_report(final_state.simulation_report, timestamp)
        print(f"\n  Rapport sauvegardé : {report_path}")
        logger.info("Rapport sauvegardé : %s", report_path)
    else:
        logger.info("Pas de rapport textuel généré par le Supervisor.")

    return 0


# ---------------------------------------------------------------------------
# Lancement
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())
