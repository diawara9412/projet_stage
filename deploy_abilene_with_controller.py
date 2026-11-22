"""
deploy_abilene_with_controller.py — Abilene connectée au contrôleur os-ken.

Lance la topologie Abilene (11 switches OVS, 11 hosts) en mode RemoteController,
connectée au contrôleur os-ken / sdn_executor.py qui tourne sur 127.0.0.1:6653.

ATTENTION :
  Ce script requiert deux prérequis AVANT d'être lancé :
  1. os-ken / firewall_app doit tourner sur le port 6653 :
       python3 ryu_app/run_manager.py ryu_app.sdn_executor
  2. Ce script doit être lancé avec sudo :
       sudo python3 deploy_abilene_with_controller.py

Le script vérifie que le port 6653 répond avant de créer le réseau.
"""

import socket
import sys
from functools import partial

import networkx as nx
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653
TOPOLOGY_FILE = "/home/kali/Desktop/projet/topologies/Abilene.graphml"


def _check_controller_alive(ip: str, port: int, timeout: int = 3) -> bool:
    """Vérifie que le contrôleur os-ken écoute sur ip:port."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False


def main() -> None:
    setLogLevel("info")

    print("=" * 65)
    print("  Déploiement Abilene + contrôleur os-ken (sdn_executor.py)")
    print("=" * 65)
    print(f"  Contrôleur attendu : {CONTROLLER_IP}:{CONTROLLER_PORT}")
    print()

    # ── Vérification préalable du contrôleur ──────────────────────────────
    print(f"  Vérification du contrôleur os-ken sur {CONTROLLER_IP}:{CONTROLLER_PORT}…")
    if not _check_controller_alive(CONTROLLER_IP, CONTROLLER_PORT):
        print()
        print("  ✗ ERREUR : le contrôleur os-ken n'est PAS joignable.")
        print()
        print("  Lancez d'abord sdn_executor.py dans un autre terminal :")
        print("    python3 ryu_app/run_manager.py ryu_app.sdn_executor")
        print()
        print("  Attendez de voir :")
        print("    INFO ryu_app.sdn_executor: SdnExecutor initialisée — REST sur port 8080")
        print("    INFO ryu_app.sdn_executor: Serveur REST démarré sur http://0.0.0.0:8080")
        print()
        sys.exit(1)
    print("  ✓ Contrôleur os-ken joignable.")

    # ── Chargement de la topologie Abilene ────────────────────────────────
    print(f"\n  Chargement de la topologie Abilene depuis {TOPOLOGY_FILE}…")
    G = nx.read_graphml(TOPOLOGY_FILE)
    nodes = list(G.nodes())
    edges = list(G.edges())
    print(f"  Topologie : {len(nodes)} nœuds, {len(edges)} liens")

    # ── Définition de la topologie Mininet ────────────────────────────────
    class AbileneTopo(Topo):
        def build(self):
            node_map = {}
            for i, n in enumerate(nodes):
                # failMode="secure" : si le contrôleur est absent, pas de flood
                sw = self.addSwitch(f"s{i}", protocols="OpenFlow13")
                h = self.addHost(f"h{i}")
                self.addLink(h, sw)
                node_map[n] = sw
            for src, dst in edges:
                self.addLink(node_map[src], node_map[dst])

    # Switch OVS en mode "secure" (délègue toutes les décisions au contrôleur)
    SecureOVSSwitch = partial(OVSSwitch, failMode="secure")

    # ── Démarrage du réseau ────────────────────────────────────────────────
    print(f"\n  Création du réseau Mininet avec RemoteController {CONTROLLER_IP}:{CONTROLLER_PORT}…")
    net = Mininet(
        topo=AbileneTopo(),
        switch=SecureOVSSwitch,
        controller=lambda name: RemoteController(
            name,
            ip=CONTROLLER_IP,
            port=CONTROLLER_PORT,
        ),
        waitConnected=True,
        autoSetMacs=True,
    )

    try:
        net.start()

        nb_switches = len(net.switches)
        nb_hosts = len(net.hosts)
        print()
        print(f"  ✅ Abilene déployée et connectée au contrôleur os-ken !")
        print(f"     Switches OVS : {nb_switches}")
        print(f"     Hosts        : {nb_hosts}")
        print()
        print("  Les switches envoient leurs FEATURES_REQUEST au contrôleur.")
        print("  Vous pouvez maintenant déployer une chaîne via :")
        print("    curl -X POST http://127.0.0.1:8080/firewall/install \\")
        print("         -H 'Content-Type: application/json' \\")
        print("         -d @chains/chain_malware_app.json")
        print()
        print("  Commandes Mininet utiles :")
        print("    nodes                          → liste des nœuds")
        print("    dump                           → IPs des hosts")
        print("    h0 ping h4                     → test de connectivité")
        print("    s0 ovs-ofctl -O OpenFlow13 dump-flows s0   → flows sur s0")
        print("    s0 ovs-ofctl -O OpenFlow13 dump-tables s0  → tables sur s0")
        print("    exit                           → quitter et nettoyer")
        print()
        print("=" * 65)

        CLI(net)

    finally:
        print("\n  Arrêt du réseau Mininet…")
        net.stop()
        print("  ✓ Réseau arrêté proprement.")


if __name__ == "__main__":
    main()
