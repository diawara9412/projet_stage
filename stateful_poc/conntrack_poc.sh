#!/bin/bash
# stateful_poc/conntrack_poc.sh — ÉTAPE 3 : PoC stateful (conntrack) en CLI pure.
#
# Démontre le "allow-then-inspect" / pare-feu à états sur OVS, SANS os-ken
# (os-ken n'expose PAS l'action ct / NXActionCT). Pipeline multi-tables :
#   table 0 : IP non suivi (ct_state=-trk) → ct(table=1) ; ARP → NORMAL
#   table 1 : établi (+est) → NORMAL ; nouveau DEPUIS l'intérieur → ct(commit),NORMAL ;
#             nouveau depuis l'extérieur (non sollicité) → DROP ; invalide → DROP
#
# ISOLATION TOTALE : bridge dédié br-ct + 2 namespaces (ctin/ctout, sous-réseau
# 10.9.0.0/24). NE TOUCHE PAS s1/s2 ni le NAT du système (le conntrack noyau est
# partagé, mais nos flows ne s'appliquent qu'à br-ct). RÉVERSIBLE : `… clean`.
#
# Usage :
#   sudo ./stateful_poc/conntrack_poc.sh          # monte, teste, laisse en place
#   sudo ./stateful_poc/conntrack_poc.sh clean    # démonte tout (del-br + del netns)
set -u
BR=br-ct
IN_NS=ctin ; OUT_NS=ctout
IN_IP=10.9.0.1 ; OUT_IP=10.9.0.2

teardown() {
    ip netns del "$IN_NS"  2>/dev/null
    ip netns del "$OUT_NS" 2>/dev/null
    ip link del p-in  2>/dev/null
    ip link del p-out 2>/dev/null
    ovs-vsctl --if-exists del-br "$BR"
}

if [ "${1:-}" = "clean" ]; then
    echo "▶ Démontage du PoC (br-ct, ctin, ctout)…"
    teardown
    echo "✓ Nettoyé. Le système (s1/s2/NAT) n'a jamais été touché."
    exit 0
fi

echo "════════════════════════════════════════════════════════════"
echo "  ÉTAPE 3 — PoC stateful (conntrack) sur bridge ISOLÉ br-ct"
echo "════════════════════════════════════════════════════════════"

# ── 0. Repartir propre ───────────────────────────────────────────
teardown

# ── 1. Bridge isolé, fail-mode secure (aucun NORMAL par défaut) ──
ovs-vsctl add-br "$BR"
ovs-vsctl set bridge "$BR" protocols=OpenFlow13
ovs-vsctl set-fail-mode "$BR" secure

# ── 2. Namespace INTÉRIEUR (confiance) → ofport 1 ────────────────
ip netns add "$IN_NS"
ip link add veth-in type veth peer name p-in
ovs-vsctl add-port "$BR" p-in -- set interface p-in ofport_request=1
ip link set p-in up
ip link set veth-in netns "$IN_NS"
ip netns exec "$IN_NS" ip addr add "$IN_IP/24" dev veth-in
ip netns exec "$IN_NS" ip link set veth-in up
ip netns exec "$IN_NS" ip link set lo up

# ── 3. Namespace EXTÉRIEUR → ofport 2 ───────────────────────────
ip netns add "$OUT_NS"
ip link add veth-out type veth peer name p-out
ovs-vsctl add-port "$BR" p-out -- set interface p-out ofport_request=2
ip link set p-out up
ip link set veth-out netns "$OUT_NS"
ip netns exec "$OUT_NS" ip addr add "$OUT_IP/24" dev veth-out
ip netns exec "$OUT_NS" ip link set veth-out up
ip netns exec "$OUT_NS" ip link set lo up

# ── 4. Pipeline conntrack ────────────────────────────────────────
ovs-ofctl -O OpenFlow13 del-flows "$BR"
# table 0 : aiguillage vers le conntrack
ovs-ofctl -O OpenFlow13 add-flow "$BR" "table=0,priority=100,arp,actions=NORMAL"
ovs-ofctl -O OpenFlow13 add-flow "$BR" "table=0,priority=90,ip,ct_state=-trk,actions=ct(table=1)"
ovs-ofctl -O OpenFlow13 add-flow "$BR" "table=0,priority=0,actions=drop"
# table 1 : décision selon l'état de la connexion
ovs-ofctl -O OpenFlow13 add-flow "$BR" "table=1,priority=100,ip,ct_state=+est+trk,actions=NORMAL"
ovs-ofctl -O OpenFlow13 add-flow "$BR" "table=1,priority=100,ip,ct_state=+new+trk,in_port=1,actions=ct(commit),NORMAL"
ovs-ofctl -O OpenFlow13 add-flow "$BR" "table=1,priority=10,ip,ct_state=+inv+trk,actions=drop"
ovs-ofctl -O OpenFlow13 add-flow "$BR" "table=1,priority=10,ip,ct_state=+new+trk,actions=drop"

echo
echo "── Flows installés (pipeline ct) ──"
ovs-ofctl -O OpenFlow13 dump-flows "$BR" | sed 's/ duration=[^,]*,//; s/ cookie=[^,]*,//'

# ── 5. TESTS ─────────────────────────────────────────────────────
echo
echo "── TEST 1 : INTÉRIEUR → extérieur (doit PASSER : new commit + retour est) ──"
ip netns exec "$IN_NS" ping -c 3 -W 2 "$OUT_IP"

echo "── TEST 2 : EXTÉRIEUR → intérieur (doit ÊTRE BLOQUÉ : new non sollicité) ──"
ip netns exec "$OUT_NS" ping -c 3 -W 2 "$IN_IP"
echo "   (100% packet loss ci-dessus = comportement stateful CORRECT)"

echo
echo "── Entrées conntrack (état des connexions vues par OVS) ──"
ovs-appctl dpctl/dump-conntrack 2>/dev/null | grep -i "10.9.0" | head || echo "   (dump-conntrack indisponible)"

echo
echo "── Compteurs des flows après tests (n_packets par état) ──"
ovs-ofctl -O OpenFlow13 dump-flows "$BR" | sed 's/ duration=[^,]*,//; s/ cookie=[^,]*,//' \
  | grep -E "ct_state|new|est|drop"

echo
echo "════════════════════════════════════════════════════════════"
echo "  Fin du PoC. Démontage : sudo $0 clean"
echo "════════════════════════════════════════════════════════════"
