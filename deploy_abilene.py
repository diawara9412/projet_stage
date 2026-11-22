"""Déploiement Abilene + CLI interactif Mininet."""
import networkx as nx
from functools import partial
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.node import OVSSwitch


def main():
    setLogLevel("info")
    
    print("=" * 60)
    print("Déploiement de la topologie Abilene")
    print("=" * 60)
    
    G = nx.read_graphml("/home/kali/Desktop/projet/topologies/Abilene.graphml")
    nodes = list(G.nodes())
    edges = list(G.edges())
    print(f"Topologie : {len(nodes)} nœuds, {len(edges)} liens")
    
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
    net = Mininet(
        topo=AbileneTopo(), 
        switch=StandaloneSwitch, 
        controller=None,
        waitConnected=False
    )
    net.start()
    
    print("\n✅ Abilene déployée !")
    print("\nCommandes utiles :")
    print("  nodes        → liste des éléments")
    print("  dump         → IPs des hosts")
    print("  pingall      → test connectivité (attends 30s STP)")
    print("  h0 ping h4   → ping spécifique")
    print("  h0 ifconfig  → config réseau de h0")
    print("  s0 ovs-ofctl show s0  → infos du switch s0")
    print("  exit         → quitter\n")
    print("=" * 60)
    
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
