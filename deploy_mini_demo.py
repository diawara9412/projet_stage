"""
deploy_mini_demo.py — Topologie Mininet minimale pour démo Phase 2.

Topologie légère pour VM modestes :
  h0 (10.0.0.1) ──┐
                   s1 ──── RemoteController os-ken (127.0.0.1:6653)
  h1 (10.0.0.2) ──┘

Prérequis (dans l'ordre) :
  1. Lancer le contrôleur dans un premier terminal :
       python3 ryu_app/run_manager.py ryu_app.sdn_executor
  2. Lancer ce script avec sudo :
       sudo python3 deploy_mini_demo.py
"""

import argparse
import shutil
import socket
import sys
from functools import partial

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

CONTROLLER_IP   = "127.0.0.1"
CONTROLLER_PORT = 6653


# ── Topologie ─────────────────────────────────────────────────────────────────

class MiniDemoTopo(Topo):
    """2 hosts (h0, h1) reliés à 1 switch OVS (s1) — topologie LEGACY (1 switch)."""

    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        h0 = self.addHost("h0", ip="10.0.0.1/24")
        h1 = self.addHost("h1", ip="10.0.0.2/24")
        self.addLink(h0, s1)
        self.addLink(h1, s1)


class TwoSwitchTopo(Topo):
    """ÉTAPE 1 — chaîne de 2 switches : h0 → s1 (FIREWALL) → s2 (IDS) → nat0.

    s1 (dpid 1) = FIREWALL : porte les règles ALLOW/BLOCK + les décisions runtime.
    s2 (dpid 2) = IDS      : surveille (900) SANS bloquer → l'IDS n'est plus masquée
                             par le BLOCK 950 (qui, lui, reste sur s1).
    Le NAT est rattaché à s2 (fait dans main) → le trafic h0→Internet traverse
    d'abord le FW puis l'IDS. h1 reste sur s1 (pair LAN pour les tests ping).
    """

    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13", dpid="1")   # FIREWALL
        s2 = self.addSwitch("s2", protocols="OpenFlow13", dpid="2")   # IDS
        h0 = self.addHost("h0", ip="10.0.0.1/24")
        h1 = self.addHost("h1", ip="10.0.0.2/24")
        self.addLink(h0, s1)   # h0  → FW
        self.addLink(h1, s1)   # h1 (LAN) → FW
        self.addLink(s1, s2)   # FW → IDS (chaînage)


# ── Entrée principale ──────────────────────────────────────────────────────────

def main(use_nat: bool = False, two_switch: bool = False) -> None:
    setLogLevel("info")

    print("=" * 60)
    if two_switch:
        print("  Mini-démo ÉTAPE 1 : h0 → s1 (FW) → s2 (IDS)"
              + ("  [+ NAT via s2]" if use_nat else ""))
    else:
        print("  Mini-démo Phase 2 : 2 hosts + 1 switch + os-ken"
              + ("  [+ NAT Internet]" if use_nat else ""))
    print("=" * 60)

    # ── Vérification préalable du contrôleur ──────────────────────────
    print(f"\n  Vérification du contrôleur os-ken sur {CONTROLLER_IP}:{CONTROLLER_PORT}…")
    try:
        s = socket.create_connection((CONTROLLER_IP, CONTROLLER_PORT), timeout=2)
        s.close()
        print("  ✓ Contrôleur os-ken joignable.\n")
    except (ConnectionRefusedError, socket.timeout, OSError):
        print()
        print("  ✗ ERREUR : le contrôleur os-ken n'est PAS joignable.")
        print()
        print("  Lance d'abord firewall_app dans un autre terminal :")
        print("    python3 ryu_app/run_manager.py ryu_app.sdn_executor")
        print()
        sys.exit(1)

    # ── Création du réseau ─────────────────────────────────────────────
    # failMode="secure" : sans contrôleur, le switch ne flood pas
    SecureOVS = partial(OVSSwitch, failMode="secure")

    net = Mininet(
        topo=TwoSwitchTopo() if two_switch else MiniDemoTopo(),
        switch=SecureOVS,
        controller=lambda name: RemoteController(
            name,
            ip=CONTROLLER_IP,
            port=CONTROLLER_PORT,
        ),
        waitConnected=True,
        autoSetMacs=True,
    )

    # ── Option NAT : accès Internet réel À TRAVERS s1 (la liste blanche
    #    s'applique entre h0 et nat0). connect=switches[0]=s1 → le trafic
    #    h0→Internet traverse s1. addNAT pose la route par défaut des hôtes
    #    vers 10.0.0.254. Pattern canonique (examples/nat.py) : AVANT net.start().
    #    Fallback si nat0 ne démarre pas : déplacer ces lignes APRÈS net.start().
    if use_nat:
        # En mode deux-switches, nat0 est rattaché à s2 (IDS) → la chaîne devient
        # h0 → s1 (FW) → s2 (IDS) → nat0 → Internet. Sinon (legacy), nat0 sur s1.
        if two_switch:
            net.addNAT(ip="10.0.0.254/24", connect=net.get("s2")).configDefault()
            print("  ▶ NAT activé : nat0=10.0.0.254 rattaché à s2 (IDS) — h0 sort via s1→s2→nat0.")
        else:
            net.addNAT(ip="10.0.0.254/24").configDefault()
            print("  ▶ NAT activé : nat0=10.0.0.254 (passerelle) — h0 sort vers Internet via s1.")

    resolv_backup = None
    try:
        net.start()

        # ── DNS de h0 forcé sur 1.1.1.1. /etc/resolv.conf est PARTAGÉ avec la VM
        #    (les hôtes Mininet n'ont pas de mount-namespace privé) : on le
        #    sauvegarde puis on le RESTAURE à l'arrêt (cf. finally). ──
        if use_nat:
            try:
                resolv_backup = "/tmp/resolv.conf.minidemo.bak"
                shutil.copyfile("/etc/resolv.conf", resolv_backup)
                with open("/etc/resolv.conf", "w") as _f:
                    _f.write("nameserver 1.1.1.1\n")
                print("  ▶ DNS forcé sur 1.1.1.1 (resolv.conf sauvegardé → restauré à l'arrêt).")
            except Exception as _exc:
                resolv_backup = None
                print(f"  ⚠️ Impossible de forcer le DNS sur 1.1.1.1 : {_exc}")

        print()
        _nb_sw = 2 if two_switch else 1
        print(f"  ✅ Mini-demo démarré : 2 hosts + {_nb_sw} switch(es) connecté(s) au contrôleur")
        print(f"     h0 = {net.hosts[0].IP()}")
        print(f"     h1 = {net.hosts[1].IP()}")
        if two_switch:
            print("     s1 = FIREWALL (dpid 1)  ·  s2 = IDS (dpid 2)  ·  chaîne h0→s1→s2→nat0")
            print("     Vérif : sh ovs-ofctl dump-flows s1 -O OpenFlow13  (ALLOW/BLOCK)")
            print("             sh ovs-ofctl dump-flows s2 -O OpenFlow13  (IDS 900, pas de BLOCK)")
        print()
        print("  Commandes utiles :")
        print("    h0 ping -c 3 h1")
        print("      → 0% packet loss si la chaîne est déployée (FW-003 ICMP LAN)")
        print("    sh ovs-ofctl dump-flows s1 -O OpenFlow13")
        print("      → flows installés par os-ken (priorité 50/100/900/950)")
        print("    exit")
        print("      → quitter et nettoyer proprement")
        print()
        print("  Pour déployer une chaîne depuis un autre terminal :")
        print("    python3 main_phase2.py --automate automates/pokemon_go.json")
        print()
        print("=" * 60)

        CLI(net)

    finally:
        if resolv_backup:
            try:
                shutil.copyfile(resolv_backup, "/etc/resolv.conf")
                print("  ✓ /etc/resolv.conf restauré.")
            except Exception as _exc:
                print(f"  ⚠️ Restauration de /etc/resolv.conf échouée : {_exc}")
        print("\n  Arrêt du réseau Mininet…")
        net.stop()
        print("  ✓ Réseau arrêté proprement.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Topo Mini-démo (option --nat pour l'accès Internet réel via s1)")
    parser.add_argument("--nat", action="store_true",
                        help="ajoute nat0 relié à s1 → accès Internet réel à travers la liste blanche")
    parser.add_argument("--two-switch", action="store_true",
                        help="ÉTAPE 1 : topologie 2 switches h0→s1(FW)→s2(IDS)→nat0 (nat0 sur s2)")
    args = parser.parse_args()
    main(use_nat=args.nat, two_switch=args.two_switch)
