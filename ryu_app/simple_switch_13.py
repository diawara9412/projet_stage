"""
ryu_app/simple_switch_13.py — Switch L2 apprenant OpenFlow 1.3 pour os_ken.

Équivalent de ryu.app.simple_switch_13, adapté pour os-ken (fork maintenu de Ryu,
compatible Python 3.13). Sert de base de test pour valider l'intégration
os_ken ↔ OVS ↔ Mininet avant le déploiement des chaînes de sécurité.

Comportement :
  1. À la connexion d'un switch → installe une règle "table-miss" (envoyer
     les paquets inconnus au contrôleur).
  2. À chaque PacketIn → apprend l'association MAC/port source.
  3. Si la MAC destination est connue → installe un flux direct.
     Sinon → flood sur tous les ports.
"""

import logging
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types

logger = logging.getLogger(__name__)


class SimpleSwitch13(app_manager.OSKenApp):
    """Switch L2 apprenant OpenFlow 1.3 — app de base pour les tests Ryu/os_ken."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Table MAC → port : {datapath_id: {mac_addr: port_no}}
        self.mac_to_port: dict[int, dict[str, int]] = {}

    # ── Événement : switch connecté (phase CONFIG_DISPATCHER) ────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Installe la règle table-miss dès qu'un switch se connecte."""
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Règle table-miss : priorité 0, match *, action → controller
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
        ]
        self._add_flow(dp, priority=0, match=match, actions=actions)
        logger.info("Switch %016x connecté — règle table-miss installée", dp.id)

    # ── Événement : paquet reçu par le contrôleur ─────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Apprentissage MAC et installation de flux directs."""
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignorer les paquets LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = dp.id

        # Apprentissage MAC → port
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Si la destination est connue → installer un flux (évite les PacketIn futurs)
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self._add_flow(dp, priority=1, match=match, actions=actions,
                               buffer_id=msg.buffer_id)
                return
            else:
                self._add_flow(dp, priority=1, match=match, actions=actions)

        # Envoyer le paquet courant
        data = None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        dp.send_msg(out)

    # ── Helpers ────────────────────────────────────────────────────────────

    def _add_flow(self, dp, priority, match, actions, buffer_id=None):
        """Installe un flux OpenFlow 1.3 sur le switch."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        kwargs: dict = dict(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
        )
        if buffer_id is not None and buffer_id != ofp.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id
        mod = parser.OFPFlowMod(**kwargs)
        dp.send_msg(mod)
        logger.debug("Flow installé sur %016x : priorité=%d", dp.id, priority)
