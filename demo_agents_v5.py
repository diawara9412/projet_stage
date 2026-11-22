"""Demo v5 : Abilene + agents + CLI SANS doublons."""
import logging
import time
from datetime import datetime
from functools import partial

import networkx as nx
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.node import OVSSwitch

# ═══════════════════════════════════════════════════════════════════════
# CORRECTIF DOUBLON : on désactive la propagation du logger Mininet
# pour éviter que ses messages soient affichés 2 fois (une par print
# de Mininet, une par le handler Python racine)
# ═══════════════════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s'
)
# Empêche le logger "mininet" de remonter au logger racine
logging.getLogger("mininet").propagate = False
logging.getLogger("mininet.log").propagate = False
# Mininet en niveau info pour que le CLI affiche les sorties
setLogLevel("info")

print("="*70)
print(" DEMO v5 : Abilene + Agents LangGraph (sans doublons)")
print("="*70)


def kill_zombies_in_hosts(net):
    """Tue les processus en arrière-plan dans les hosts."""
    print("\n[NETTOYAGE] Suppression des processus zombies...")
    for h in net.hosts:
        h.cmd("pkill -9 -f 'http.server' 2>/dev/null || true")
        h.cmd("pkill -9 -f 'iperf' 2>/dev/null || true")
        h.cmd("pkill -9 -f 'hping3' 2>/dev/null || true")
        h.cmd("pkill -9 -f 'nmap' 2>/dev/null || true")
    print("[NETTOYAGE] ✅ Processus zombies supprimés")
    time.sleep(1)


# ÉTAPE 1 : Déploiement Abilene
print("\n[ÉTAPE 1] Déploiement de la topologie Abilene...")
G = nx.read_graphml("/home/kali/Desktop/projet/topologies/Abilene.graphml")
nodes = list(G.nodes())
edges = list(G.edges())

class AbileneTopo(Topo):
    def build(self):
        node_map = {}
        for i, n in enumerate(nodes):
            sw = self.addSwitch(f's{i}', stp=True)
            h = self.addHost(f'h{i}')
            self.addLink(h, sw)
            node_map[n] = sw
        for src, dst in edges:
            self.addLink(node_map[src], node_map[dst])

StandaloneSwitch = partial(OVSSwitch, failMode="standalone", stp=True)
net = Mininet(topo=AbileneTopo(), switch=StandaloneSwitch, controller=None, waitConnected=False)
net.start()

import tools.topology_tools as tt
tt._active_network = net
tt._active_topology_name = "Abilene"

print("[ÉTAPE 1] ✅ Abilene déployée")

# ÉTAPE 2 : TrafficGenerator
print("\n[ÉTAPE 2] L'agent TrafficGenerator prend le contrôle...")
from state import GraphState, DeployedTopology
from agents.traffic_generator import traffic_generator_node

fake_topo = DeployedTopology(
    topology_name='Abilene',
    nb_hosts=11,
    nb_switches=11,
    nb_links=14,
    hosts=[f'h{i}' for i in range(11)],
    host_ips={f'h{i}': f'10.0.0.{i+1}' for i in range(11)},
    deployed_at=datetime.now().isoformat()
)

state = GraphState(
    user_request='Génère du trafic HTTP léger entre quelques hosts',
    deployed_topology=fake_topo,
    max_iterations=2
)
traffic_result = traffic_generator_node(state)
flows = traffic_result.get('generated_traffic_flows', [])
print(f"[ÉTAPE 2] ✅ {len(flows)} flux générés")
kill_zombies_in_hosts(net)

# ÉTAPE 3 : AttackSimulator
print("\n[ÉTAPE 3] L'agent AttackSimulator prend le contrôle...")
from agents.attack_simulator import attack_simulator_node

state.requested_attacks = ['syn_flood']
attack_result = attack_simulator_node(state)
attacks = attack_result.get('attack_scenarios', [])
obs = attack_result.get('network_observations', [])
print(f"[ÉTAPE 3] ✅ {len(attacks)} attaques lancées")
kill_zombies_in_hosts(net)

# RÉSUMÉ
print("\n" + "="*70)
print(" RÉSUMÉ DES ACTIONS DES AGENTS")
print("="*70)
print(f"\nFlux générés : {len(flows)}")
for f in flows:
    if hasattr(f, 'flow_type'):
        print(f"  • {f.flow_type:8s} {f.source} → {f.destination}  ({f.duration_s}s)")
print(f"\nAttaques lancées : {len(attacks)}")
for a in attacks:
    if hasattr(a, 'attack_type'):
        print(f"  • {a.attack_type:12s} {a.attacker} → {a.victim or a.target_subnet}  ({a.duration_s}s)")
print(f"\nObservations réseau : {len(obs)}")
for o in obs:
    if hasattr(o, 'victim'):
        print(f"  • {o.victim}  loss={o.loss_percent}%  RTT={o.avg_rtt_ms}ms  [{o.assessment}]")

# CLI Mininet — affichage propre
print("\n" + "="*70)
print(" Mininet est prêt — Commandes utiles :")
print("   nodes        → liste des éléments")
print("   pingall      → test connectivité")
print("   dump         → IPs des hosts")
print("   h0 ping h1   → ping spécifique")
print("   exit         → quitter")
print("="*70)

CLI(net)
net.stop()
print("\n✅ Démo terminée.")
