"""ryu_app/ct_probe.py — ÉTAPE 1 (stateful) : PREUVE que le contrôleur os-ken
installe ET fait fonctionner de vraies règles conntrack (NXActionCT), avec une
ZONE dédiée qui n'interfère PAS avec le conntrack du NAT.

App os-ken minimale, indépendante de sdn_executor (on ne touche à rien d'intégré).
Pipeline stateful sur chaque switch :
  table 0 : ARP → NORMAL ; IP non suivi (ct_state=-trk) → ct(zone=1, table=1) ; sinon NORMAL
  table 1 : établi (+est) → NORMAL ; nouveau (+new) → ct(commit,zone=1) + NORMAL ;
            invalide (+inv) → drop
Lancer : python3 ryu_app/run_manager.py ryu_app.ct_probe
"""
import logging

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3

logger = logging.getLogger(__name__)

CT_ZONE = 1                      # zone conntrack DÉDIÉE (isolée du NAT)
# bits ct_state (OXM standard)
NEW, EST, INV, TRK = 0x01, 0x02, 0x10, 0x20


class CtProbe(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        def add(table, prio, match, actions, goto=None):
            inst = []
            if actions:
                inst.append(parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions))
            if goto is not None:
                inst.append(parser.OFPInstructionGotoTable(goto))
            dp.send_msg(parser.OFPFlowMod(datapath=dp, table_id=table, priority=prio,
                                          match=match, instructions=inst))

        NORMAL = parser.OFPActionOutput(ofp.OFPP_NORMAL)

        # ── table 0 : aiguillage vers le conntrack (zone dédiée) ──
        add(0, 100, parser.OFPMatch(eth_type=0x0806), [NORMAL])          # ARP → NORMAL
        ct_track = parser.NXActionCT(flags=0, zone_src=None, zone_ofs_nbits=CT_ZONE,
                                     recirc_table=1, alg=0, actions=[])
        add(0, 90, parser.OFPMatch(eth_type=0x0800, ct_state=(0, TRK)), [ct_track])
        add(0, 1, parser.OFPMatch(), [NORMAL])                           # non-IP → NORMAL

        # ── table 1 : décision selon l'état ──
        add(1, 100, parser.OFPMatch(eth_type=0x0800, ct_state=(EST | TRK, EST | TRK)), [NORMAL])
        ct_commit = parser.NXActionCT(flags=1, zone_src=None, zone_ofs_nbits=CT_ZONE,
                                      recirc_table=255, alg=0, actions=[])
        add(1, 100, parser.OFPMatch(eth_type=0x0800, ct_state=(NEW | TRK, NEW | TRK)),
            [ct_commit, NORMAL])
        add(1, 50, parser.OFPMatch(eth_type=0x0800, ct_state=(INV | TRK, INV | TRK)), [])
        add(1, 0, parser.OFPMatch(), [])                                 # miss → drop

        logger.info("CtProbe : pipeline conntrack NATIF (NXActionCT, zone=%d) installé "
                    "sur switch %016x", CT_ZONE, dp.id)
