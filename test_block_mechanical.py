"""
test_block_mechanical.py — PREUVE MÉCANIQUE qu'une règle BLOCK agit réellement
sur le trafic (pas seulement qu'elle est installée).

But scientifique
----------------
`hardware_installed=True` prouve que la règle est POSÉE. Ce test prouve qu'elle
INTERCEPTE le trafic : un BLOCK sur une IP présente dans le réseau jette les
paquets correspondants ET le compteur OpenFlow `n_packets` du flow DROP monte.

CAVEAT ASSUMÉ (documenté)
-------------------------
La chaîne réelle vise des IP PUBLIQUES (ex. OVH 37.187.86.136) qu'AUCUN hôte
Mininet ne possède : ces IP n'apparaissent jamais comme trafic dans Mininet.
Ce test substitue donc une IP LOCALE existante (h1 = 10.0.0.2) comme banc d'essai
du MÉCANISME drop+compteurs. Il prouve « un BLOCK sur une IP présente → drop +
compteur », PAS que la chaîne agit sur les IP publiques. C'est le maximum testable
sans rejouer du vrai trafic vers ces IP.

Chemin testé = chemin de PRODUCTION (Option A) : règle → REST sdn_executor →
OFPFlowMod → drop sur OVS. Nettoyage par DELETE /firewall/flush (cookie-scopé :
n'efface QUE les flows de la chaîne, la topo de base reste intacte).

Protocole
---------
0. Pré-vol : contrôleur OpenFlow (6653) + REST (8080) joignables.
1. Baseline ICMP : h0 ping h1 (10.0.0.2)            → attendu PASSE (switch L2).
2. Installer BLOCK ICMP dst=10.0.0.2 (prio 950, REST).
3. Trafic BLOQUÉ : h0 ping h1                        → attendu 100% perte.
4. Contraste SÉLECTIVITÉ : h0 curl http://10.0.0.2  → attendu PASSE (TCP non bloqué
   alors que l'ICMP vers la même IP est jeté → le BLOCK est spécifique, pas un
   coupe-circuit total). NB : un ping inverse h1→h0 ne serait PAS un contraste
   valide car l'echo-reply (dst=10.0.0.2, ICMP) serait lui aussi jeté.
5. Compteurs : ovs-ofctl dump-flows s1 -O OpenFlow13 → n_packets du flow DROP > 0.
6. /firewall/stats (état contrôleur).
7. Flush + restauration : h0 ping h1                 → attendu PASSE de nouveau.

Prérequis (comme deploy_mini_demo.py)
-------------------------------------
  Terminal 1 :  python3 ryu_app/run_manager.py ryu_app.sdn_executor
  Terminal 2 :  sudo python3 test_block_mechanical.py

Aucun LLM, aucun quota : 100% réseau Mininet/OpenFlow.
"""

from __future__ import annotations

import json
import re
import socket
import sys
import urllib.request
from functools import partial

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653
REST_BASE = "http://127.0.0.1:8080"

TARGET_IP = "10.0.0.2"          # = h1 (PAS « h2 » : la topo n'a que h0 et h1)
HTTP_PORT = 8000               # serveur de contraste TCP sur h1
PING_COUNT = 3


# ── Topologie (identique à deploy_mini_demo : on ne touche pas à ce fichier) ──

class MiniDemoTopo(Topo):
    """2 hosts (h0=10.0.0.1, h1=10.0.0.2) reliés à 1 switch OVS (s1)."""

    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        h0 = self.addHost("h0", ip="10.0.0.1/24")
        h1 = self.addHost("h1", ip="10.0.0.2/24")
        self.addLink(h0, s1)
        self.addLink(h1, s1)


# ── Helpers REST (stdlib, aucune dépendance) ────────────────────────────────

def _rest(method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        f"{REST_BASE}{path}", data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode()
            return resp.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:200]}


def _preflight() -> bool:
    """Vérifie contrôleur OpenFlow (6653) + REST (8080) avant de monter le réseau."""
    try:
        socket.create_connection((CONTROLLER_IP, CONTROLLER_PORT), timeout=2).close()
    except OSError:
        print(f"  ✗ Contrôleur OpenFlow injoignable sur {CONTROLLER_IP}:{CONTROLLER_PORT}.")
        print("    Lance d'abord :  python3 ryu_app/run_manager.py ryu_app.sdn_executor")
        return False
    status, _ = _rest("GET", "/")
    if status != 200:
        print(f"  ✗ REST sdn_executor injoignable sur {REST_BASE} (status={status}).")
        return False
    print("  ✓ Contrôleur OpenFlow + REST sdn_executor joignables.")
    return True


# ── Mesures réseau (dans les namespaces Mininet) ────────────────────────────

def _ping_loss(src, dst_ip: str) -> int:
    """Retourne le % de perte d'un ping (100 = tout jeté, 0 = tout passé)."""
    out = src.cmd(f"ping -c {PING_COUNT} -W 1 {dst_ip}")
    m = re.search(r"(\d+)% packet loss", out)
    return int(m.group(1)) if m else 100


def _tcp_ok(src, dst_ip: str, port: int) -> bool:
    """True si une requête HTTP (TCP) aboutit (contraste de sélectivité)."""
    out = src.cmd(f"curl -s -o /dev/null -w '%{{http_code}}' -m 3 http://{dst_ip}:{port}/")
    return "200" in out or "30" in out  # 200 OK ou redirection = TCP a abouti


def _drop_counter(switch) -> tuple[int, str]:
    """Lit n_packets du flow DROP (cookie chaîne, ICMP, nw_dst cible) via ovs-ofctl."""
    dump = switch.cmd("ovs-ofctl dump-flows s1 -O OpenFlow13")
    for line in dump.splitlines():
        low = line.lower()
        if "icmp" in low and f"nw_dst={TARGET_IP}".lower() in low and "actions=drop" in low:
            m = re.search(r"n_packets=(\d+)", line)
            return (int(m.group(1)) if m else -1), line.strip()
    return -1, "(flow DROP introuvable dans dump-flows)"


# ── Chaîne de test minimale (1 BLOCK ICMP, le reste vide) ───────────────────

def _block_chain() -> dict:
    return {
        "chain_id": "TEST-MECH-BLOCK",
        "source_app_name": "test_block_mechanical",
        "global_risk_level": "test",
        "firewall_rules": [{
            "id": "FW-TEST-BLOCK",
            "action": "BLOCK",
            "direction": "outbound",
            "dst_ip": TARGET_IP,
            "dst_port": None,
            "protocol": "ICMP",
            "priority": 950,
            "source_transition_id": None,
            "comment": "test mécanique : BLOCK ICMP vers 10.0.0.2 (h1)",
        }],
        "ids_signatures": [],
        "ips_actions": [],
    }


# ── Scénario ────────────────────────────────────────────────────────────────

def main() -> int:
    setLogLevel("warning")
    print("=" * 68)
    print("  TEST MÉCANIQUE BLOCK — preuve drop + compteurs (chemin REST prod)")
    print("=" * 68)

    if not _preflight():
        return 1

    SecureOVS = partial(OVSSwitch, failMode="secure")
    net = Mininet(
        topo=MiniDemoTopo(), switch=SecureOVS,
        controller=lambda name: RemoteController(name, ip=CONTROLLER_IP, port=CONTROLLER_PORT),
        waitConnected=True, autoSetMacs=True,
    )

    results: list[tuple[str, bool, str]] = []
    try:
        net.start()
        h0, h1, s1 = net.get("h0"), net.get("h1"), net.get("s1")

        # Lance un serveur HTTP sur h1 pour le contraste TCP (sélectivité).
        h1.cmd(f"cd /tmp && python3 -m http.server {HTTP_PORT} >/dev/null 2>&1 &")
        h0.cmd("sleep 1")  # laisse le serveur démarrer + ARP s'amorcer

        # 1. Baseline ICMP (doit passer via le switch L2 apprenant) ───────────
        loss0 = _ping_loss(h0, TARGET_IP)
        ok = loss0 == 0
        results.append(("1. Baseline   h0 ping h1 (avant BLOCK)", ok, f"{loss0}% perte (attendu 0%)"))

        # 2. Installer le BLOCK via REST (chemin de production) ────────────────
        st, body = _rest("POST", "/firewall/install", _block_chain())
        installed = st == 200 and body.get("status") in ("ok", "partial")
        results.append(("2. Install BLOCK via REST", installed, f"HTTP {st}, status={body.get('status')}"))

        # 3. Trafic BLOQUÉ : le ping doit être jeté ───────────────────────────
        loss1 = _ping_loss(h0, TARGET_IP)
        ok = loss1 == 100
        results.append(("3. BLOQUÉ     h0 ping h1 (après BLOCK)", ok, f"{loss1}% perte (attendu 100%)"))

        # 4. Contraste SÉLECTIVITÉ : TCP vers la MÊME IP doit passer ──────────
        tcp_ok = _tcp_ok(h0, TARGET_IP, HTTP_PORT)
        results.append(("4. Sélectivité h0 curl TCP→h1 (non bloqué)", tcp_ok,
                        "TCP passe alors que l'ICMP est jeté" if tcp_ok else "TCP a échoué (inattendu)"))

        # 5. PREUVE COMPTEURS : n_packets du flow DROP > 0 ────────────────────
        n_pkts, raw = _drop_counter(s1)
        ok = n_pkts > 0
        results.append(("5. Compteur OpenFlow n_packets du DROP", ok, f"n_packets={n_pkts} (attendu >0)"))
        print(f"\n  → flow DROP brut : {raw}\n")

        # 6. État contrôleur ──────────────────────────────────────────────────
        _, stats = _rest("GET", "/firewall/stats")
        print(f"  /firewall/stats : flows={stats.get('installed_flows')} "
              f"chain={stats.get('active_chain_id')}\n")

        # 7. Flush + restauration : le ping doit re-passer ────────────────────
        _rest("DELETE", "/firewall/flush")
        h0.cmd("sleep 1")
        loss2 = _ping_loss(h0, TARGET_IP)
        ok = loss2 == 0
        results.append(("7. Restauration h0 ping h1 (après flush)", ok, f"{loss2}% perte (attendu 0%)"))

        # Arrêt propre du serveur HTTP
        h1.cmd("kill %python3 2>/dev/null; pkill -f http.server 2>/dev/null")

    finally:
        net.stop()

    # ── Verdict ───────────────────────────────────────────────────────────────
    print("=" * 68)
    print("  RÉCAPITULATIF")
    print("=" * 68)
    all_ok = True
    for name, ok, detail in results:
        all_ok &= ok
        print(f"  {'✅' if ok else '❌'} {name:<44} {detail}")
    print("=" * 68)
    if all_ok:
        print("  ✅ PREUVE FAITE : le BLOCK jette le trafic ICMP (100% perte + n_packets>0),")
        print("     reste sélectif (TCP passe), et le flush restaure la connectivité.")
    else:
        print("  ❌ Au moins une étape a échoué — voir le détail ci-dessus.")
    print("  Rappel caveat : mécanisme prouvé sur IP locale (10.0.0.2) ; ne prouve PAS")
    print("  l'action sur les IP publiques OVH (absentes du réseau Mininet).")
    return 0 if all_ok else 2


if __name__ == "__main__":
    sys.exit(main())
