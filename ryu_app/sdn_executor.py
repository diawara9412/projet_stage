"""
ryu_app/sdn_executor.py — Exécuteur d'ordres OpenFlow (déploiement de
SecurityChain sur OVS via os_ken).

Anciennement ``firewall_app.py`` : ce module ne « fait » plus le firewall, il
EXÉCUTE sur les switches les ordres OpenFlow décidés en amont par les agents
(chaîne de sécurité firewall + IDS + IPS). D'où le nom ``sdn_executor``.

NOTE : les routes REST conservent le préfixe ``/firewall`` pour ne PAS casser
le contrat HTTP consommé par ``tools/deployment_tools.py`` (endpoint par défaut
``http://127.0.0.1:8080/firewall``). Seuls le fichier et la classe sont renommés.

Architecture
------------
SdnExecutor (OSKenApp) :
  • Apprentissage MAC (hérite du comportement de simple_switch_13)
  • Sur connexion switch : installe la règle table-miss + ré-applique la chaîne active
  • apply_chain(chain_dict) : traduit SecurityChain → flows OpenFlow et les installe
  • flush_chain() : supprime tous les flows installés par la chaîne active
  • Sur PacketIn IDS : incrémente les compteurs d'alertes par signature

Serveur REST (port 8080, green-thread hub.spawn) :
  POST /firewall/install  → body = SecurityChain JSON → installe sur tous les switches
  GET  /firewall/stats    → statistiques : switches connectés, compteurs, alertes IDS
  GET  /firewall/rules    → liste détaillée des règles installées
  DELETE /firewall/flush  → supprime les rules de la chaîne active

Priorités OpenFlow utilisées :
  950  — BLOCK (DROP direct sur le switch) → menace connue jetée en hardware
  900  — IDS (OUTPUT:CONTROLLER) → surveillance ; atteinte seulement si pas de BLOCK
  100  — ALLOW (OFPP_NORMAL)
   50  — LAN/ARP/ICMP interne (OFPP_NORMAL)
    1  — Apprentissage MAC (flows L2 directs)
    0  — Table-miss (renvoie au contrôleur)

Lancer avec :
  sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone

from flask import Flask, jsonify, request, Response

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.dpset import DPSet, EventDP
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import ethernet, ether_types, packet, ipv4, tcp, udp
from os_ken.ofproto import ofproto_v1_3

logger = logging.getLogger(__name__)

# ── Constantes ────────────────────────────────────────────────────────────────

REST_PORT = 8080

# Cookie OpenFlow pour identifier les flows de notre chaîne
CHAIN_COOKIE      = 0xCAFE0001
CHAIN_COOKIE_MASK = 0xFFFFFFFF
# Cookie SÉPARÉ pour les décisions runtime DU CONTRÔLEUR (modes --decide/--hybrid).
# Distinct de CHAIN_COOKIE pour que le redéploiement du service (flush CHAIN_COOKIE)
# n'EFFACE PAS les règles posées par le contrôleur (sinon ses ALLOW/DROP disparaissent).
RUNTIME_COOKIE    = 0xCAFE0002

# Priorités OpenFlow (plus haut = prioritaire)
#   950 BLOCK (DROP direct sur le switch) > 900 IDS (CONTROLLER, surveillance)
#   > 100 ALLOW > 50 LAN > 1 MAC learning > 0 table-miss
# Le BLOCK est volontairement AU-DESSUS de l'IDS : une menace connue est
# jetée directement en hardware, sans passer par le contrôleur. L'IDS (900)
# n'est atteinte que par les menaces SANS règle BLOCK (surveillance pure).
PRIO_TABLE_MISS = 0
PRIO_MAC_LEARN  = 1
PRIO_ALLOW      = 100
PRIO_IDS        = 900
PRIO_BLOCK      = 950

# ── ÉTAPE 3 (stateful / conntrack) ────────────────────────────────────────────
# Le mode --stateful transforme l'ALLOW en allow-then-inspect via l'action ct
# native d'os-ken (NXActionCT). L'aller (h0→dst autorisée) passe par le conntrack
# (table 1) ; le retour passe par la règle LAN (comme aujourd'hui). Zone dédiée
# pour NE PAS perturber le conntrack du NAT (prouvé à l'étape 1).
CT_TABLE   = 1           # table de décision d'état (recirculation après ct)
# bits ct_state (OXM standard)
CT_NEW, CT_EST, CT_INV, CT_TRK = 0x01, 0x02, 0x10, 0x20
NX_CT_F_COMMIT   = 1     # flag "commit" (mémorise la connexion)
NX_CT_RECIRC_NONE = 255  # pas de recirculation (après commit)

# Mapping protocole SecurityChain → ip_proto OF
_PROTO_MAP = {
    "TCP": 6, "HTTP": 6, "HTTPS": 6,
    "UDP": 17,
    "ICMP": 1,
}


# ── Helpers de construction des matchs OpenFlow ───────────────────────────────

def _build_match(parser, dst_ip: str | None, protocol: str, dst_port: int | None,
                 ct_state: tuple | None = None):
    """Construit un OFPMatch depuis les champs d'une règle SecurityChain.

    Cas pris en charge :
    - ARP (eth_type=0x0806, aucun champ IP)
    - ICMP / TCP / UDP / HTTP / HTTPS (eth_type=0x0800 + ip_proto)
    - "any" sans port (eth_type=0x0800 seul ou avec dst_ip)
    - CIDR en dst_ip (ex: "10.0.0.0/24") → converti en tuple (network, netmask)
    - ct_state : tuple (value, mask) pour matcher l'état conntrack (mode stateful)
    """
    import ipaddress

    proto_upper = (protocol or "").upper()

    # ── ARP : Ethernet type 0x0806, aucun champ IP ────────────────────────
    if proto_upper == "ARP":
        return parser.OFPMatch(eth_type=0x0806)

    # ── IPv4 (tous les autres protocoles) ──────────────────────────────────
    fields: dict = {"eth_type": 0x0800}

    if dst_ip and dst_ip.lower() not in ("any",):
        if "/" in dst_ip:
            # CIDR (ex: "10.0.0.0/24") → tuple (network_address, netmask)
            net = ipaddress.IPv4Network(dst_ip, strict=False)
            fields["ipv4_dst"] = (str(net.network_address), str(net.netmask))
        else:
            fields["ipv4_dst"] = dst_ip

    ip_proto = _PROTO_MAP.get(proto_upper)
    if ip_proto:
        fields["ip_proto"] = ip_proto
        if dst_port:
            if ip_proto == 6:   # TCP / HTTP / HTTPS
                fields["tcp_dst"] = int(dst_port)
            elif ip_proto == 17:  # UDP
                fields["udp_dst"] = int(dst_port)

    if ct_state is not None:
        fields["ct_state"] = ct_state

    return parser.OFPMatch(**fields)


# ── Application principale ────────────────────────────────────────────────────

class SdnExecutor(app_manager.OSKenApp):
    """Exécuteur OpenFlow 1.3 : déploie les chaînes de sécurité sur OVS via REST."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"dpset": DPSet}

    # Singleton — permet aux routes Flask d'accéder à l'instance
    _instance: "SdnExecutor | None" = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        SdnExecutor._instance = self

        self.dpset: DPSet = kwargs["dpset"]

        # ── Mode d'enforcement ────────────────────────────────────────────────
        # DEFAULT-ALLOW (défaut) : table-miss → contrôleur (apprentissage + forward).
        # DEFAULT-DENY (flag --default-deny → env SDN_DEFAULT_DENY) : table-miss → DROP
        # ; seules les règles ALLOW de la chaîne déployée passent (liste blanche).
        # Le défaut est INCHANGÉ pour ne pas casser la comparaison A/B.
        self.default_deny: bool = os.environ.get("SDN_DEFAULT_DENY", "").lower() in ("1", "true", "yes")
        logger.info("Mode enforcement : %s",
                    "DEFAULT-DENY (liste blanche)" if self.default_deny else "default-allow")

        # ── Mode BOUCLE autonomique (flag --loop → env SDN_LOOP_MODE) ──────────
        # En boucle, la table-miss remonte au contrôleur (Packet-In) au lieu de
        # DROP silencieux : on VOIT les flux inconnus, on les pousse dans une file
        # Redis (pour les agents), et on les DROP en attendant (fail-closed).
        # N'a de sens qu'avec default-deny (whitelist). N'altère PAS le default-allow.
        self.loop_mode: bool = os.environ.get("SDN_LOOP_MODE", "").lower() in ("1", "true", "yes")
        self._redis = None
        self._seen_unknown: set = set()  # dédup (ip,port,proto) → 1 push par flux
        if self.loop_mode:
            try:
                import redis as _redis_lib
                self._redis = _redis_lib.Redis(host="127.0.0.1", port=6379, db=0)
                self._redis.ping()
                logger.info("Mode BOUCLE activé : file Redis 'sdn:anomalies' connectée.")
            except Exception as exc:
                logger.warning("Mode BOUCLE : Redis indisponible (%s) — push désactivé "
                               "(les inconnus seront seulement journalisés).", exc)
                self._redis = None

        # ── Décision DANS le contrôleur (flag --decide → env SDN_DECIDE) ───────
        # Au lieu d'escalader l'inconnu vers Redis/agents, le contrôleur tranche
        # LUI-MÊME le déterministe (/16) et pose la règle directement (niveau 2 :
        # latence ms, sans aller-retour Redis ni redéploiement complet de la chaîne).
        # L'ambigu (non déterministe) resterait, lui, pour les agents.
        self.controller_decide: bool = os.environ.get("SDN_DECIDE", "").lower() in ("1", "true", "yes")
        # Mode HYBRIDE : le contrôleur tranche le clair (/16 + réputation), escalade l'ambigu.
        self.hybrid: bool = os.environ.get("SDN_HYBRID", "").lower() in ("1", "true", "yes")
        self.known_prefixes: set[str] = set()   # /16 des destinations ALLOW (pour décider)
        self.decide_ext = 0
        self.decide_blk = 0
        if self.controller_decide:
            logger.info("Décision /16 DANS le contrôleur activée (fast-path, sans Redis).")
        if self.hybrid:
            logger.info("Mode HYBRIDE : contrôleur tranche /16+réputation, escalade l'ambigu aux agents.")

        # ── ÉTAPE 1 — Mode DEUX SWITCHES (flag --two-switch → env SDN_TWO_SWITCH) ──
        # Sépare le rôle unique en deux datapaths :
        #   • FW  (dpid SDN_FW_DPID, défaut 1)  : porte ALLOW/BLOCK + décisions runtime.
        #   • IDS (dpid SDN_IDS_DPID, défaut 2) : surveille (900) et FAIT SUIVRE, sans
        #     BLOCK 950 → l'IDS n'est plus masquée (bug « IDS inerte » corrigé).
        # RÉVERSIBLE : sans le flag, two_switch=False → _role_of renvoie "both" et tout
        # se comporte EXACTEMENT comme avant (toutes les règles sur chaque switch).
        self.two_switch: bool = os.environ.get("SDN_TWO_SWITCH", "").lower() in ("1", "true", "yes")
        self.fw_dpid: int = int(os.environ.get("SDN_FW_DPID", "1"))
        self.ids_dpid: int = int(os.environ.get("SDN_IDS_DPID", "2"))

        # ── ÉTAPE 2 — Chaînage SFC par STEERING EXPLICITE (flag --sfc → SDN_SFC_STEERING) ──
        # Au lieu de l'ALLOW en OFPP_NORMAL (apprentissage L2), on impose le chemin :
        #   FW : ALLOW spécifique → OUTPUT:fw_to_ids_port (pousse vers l'IDS).
        #   IDS : wire explicite (in_port fw ↔ in_port nat) + signature IDS(900) qui
        #         CLONE [CONTROLLER (tap) + OUTPUT:nat] → surveille ET fait suivre.
        # Le retour (dst = sous-réseau local) reste en NORMAL sur le FW → pas de blackhole.
        # Le steering IMPLIQUE deux switches. RÉVERSIBLE : sans --sfc, on garde l'Étape 1.
        self.sfc_steering: bool = os.environ.get("SDN_SFC_STEERING", "").lower() in ("1", "true", "yes")
        if self.sfc_steering:
            self.two_switch = True
        # Ports du chaînage (déduits de la topo TwoSwitchTopo : s1 p3→s2, s2 p1←s1, s2 p2→nat0)
        self.fw_to_ids_port: int = int(os.environ.get("SDN_FW_TO_IDS_PORT", "3"))
        self.ids_to_nat_port: int = int(os.environ.get("SDN_IDS_TO_NAT_PORT", "2"))
        self.ids_to_fw_port: int = int(os.environ.get("SDN_IDS_TO_FW_PORT", "1"))

        if self.two_switch:
            logger.info("Mode DEUX SWITCHES : FW=dpid %d (ALLOW/BLOCK+décisions), "
                        "IDS=dpid %d (surveillance seule, fait suivre).",
                        self.fw_dpid, self.ids_dpid)
        if self.sfc_steering:
            logger.info("Mode SFC STEERING (Étape 2) : FW ALLOW → OUTPUT:%d (IDS) ; "
                        "IDS wire %d↔%d + tap contrôleur.",
                        self.fw_to_ids_port, self.ids_to_fw_port, self.ids_to_nat_port)

        # ── ÉTAPE 3 — STATEFUL / conntrack (flag --stateful → SDN_STATEFUL) ──────
        # Sur le FW, l'ALLOW devient allow-then-inspect : l'ALLER (h0→dst autorisée)
        # passe par le conntrack (table 1 : +new→commit, +est→forward) via l'action
        # native NXActionCT ; le RETOUR reste en NORMAL/LAN. Zone ct DÉDIÉE →
        # n'affecte PAS le NAT (prouvé à l'étape 1). Le forward garde le steering/NORMAL
        # habituel (s2/IDS conservé). RÉVERSIBLE : sans le flag, aucun ct.
        self.stateful: bool = os.environ.get("SDN_STATEFUL", "").lower() in ("1", "true", "yes")
        self.ct_zone: int = int(os.environ.get("SDN_CT_ZONE", "1"))
        if self.stateful:
            logger.info("Mode STATEFUL (Étape 3) : ALLOW → conntrack natif (zone=%d), "
                        "allow-then-inspect sur le FW (compatible two-switch/sfc).", self.ct_zone)

        # ── POLITIQUE IDS — inspection du trafic AUTORISÉ (flag --inspect) ──────
        # Defense in depth : l'IDS n'a de sens que sur le trafic AUTORISÉ (le bloqué
        # est déjà jeté). Quand SDN_INSPECT_ALLOWED=1, chaque règle ALLOW spécifique
        # pose AUSSI une surveillance IDS sur le switch IDS (s2) → l'IDS voit et compte
        # le trafic permis (allow-then-inspect). Les règles ALLOW_AND_INSPECT sont
        # TOUJOURS inspectées (indépendamment du flag).
        self.inspect_allowed: bool = os.environ.get("SDN_INSPECT_ALLOWED", "").lower() in ("1", "true", "yes")
        # ÉTAPE 3 : IP déjà bloquées par une détection IDS (dédup, 1 block par IP).
        self.ids_detected: set = set()
        # ── Détection COMPORTEMENTALE (beaconing) sur le trafic surveillé ──
        # L'IDS observe DANS LE TEMPS les rappels vers une destination autorisée-surveillée.
        # Des rappels RÉGULIERS (faible variance des intervalles) = signature de C2.
        self.ids_timestamps: dict = {}     # dst_ip → [timestamps des derniers rappels]
        self.beaconing_flagged: set = set()
        if self.inspect_allowed:
            logger.info("Politique IDS : INSPECTION du trafic autorisé activée "
                        "(chaque ALLOW → surveillé sur l'IDS ; l'IDS re-vérifie la "
                        "réputation → BLOCK si une IP autorisée s'avère malveillante).")

        # Table MAC → port pour l'apprentissage L2
        self.mac_to_port: dict[int, dict[str, int]] = {}

        # Chaîne active
        self.active_chain: dict | None = None
        self.active_chain_id: str | None = None
        self.installed_at: str | None = None

        # Règles installées : liste de dicts avec métadonnées (pour /rules et flush)
        self.installed_rules: list[dict] = []

        # Compteurs IDS : sig_id → {"count": int, "pattern_type": str, "dst_ip": str}
        self.ids_counters: dict[str, dict] = {}

        # Verrou pour accès concurrent Flask ↔ os_ken (green-threads coopératifs)
        self._lock = threading.Lock()

        # Démarrer le serveur REST dans un green-thread os_ken
        hub.spawn(self._start_rest_server)
        logger.info("SdnExecutor initialisé — REST sur port %d", REST_PORT)

    # ── ÉTAPE 1 — Rôle d'un switch (mode deux-switches) ─────────────────────────

    def _role_of(self, dpid: int) -> str:
        """Rôle d'un datapath : 'fw', 'ids', ou 'both' (legacy, un seul switch).

        En mode deux-switches, le dpid IDS surveille ; tout autre dpid est FW.
        Sans le mode, tout switch est 'both' → comportement historique inchangé.
        """
        if not self.two_switch:
            return "both"
        return "ids" if dpid == self.ids_dpid else "fw"

    def _enforcement_datapaths(self) -> list:
        """Datapath(s) où POSER l'enforcement (ALLOW/BLOCK + décisions runtime).

        Mode deux-switches → uniquement le FW (poser un BLOCK/ALLOW sur l'IDS
        n'aurait pas de sens : l'IDS ne bloque pas). Sinon → tous les switches.
        """
        dps = []
        for _i in self.dpset.get_all():
            dp = _i[1] if isinstance(_i, tuple) else _i
            if not self.two_switch or dp.id == self.fw_dpid:
                dps.append(dp)
        return dps

    def _allow_actions(self, dp) -> list:
        """Action de forward d'un ALLOW spécifique (IP externe).

        Étape 2 (SFC) sur le FW → steering EXPLICITE vers le switch IDS.
        Sinon → OFPP_NORMAL (apprentissage L2, comportement historique).
        """
        parser = dp.ofproto_parser
        if self.sfc_steering and self._role_of(dp.id) == "fw":
            return [parser.OFPActionOutput(self.fw_to_ids_port)]
        return [parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)]

    def _rule_is_inspected(self, rule: dict) -> bool:
        """Une règle ALLOW doit-elle être SURVEILLÉE par l'IDS (allow-then-inspect) ?

        Politique sécurité : on inspecte le trafic AUTORISÉ (pas le bloqué). Oui si
        action=ALLOW_AND_INSPECT (explicite), ou si le mode --inspect est actif et
        que c'est un ALLOW vers une IP spécifique (externe)."""
        action = rule.get("action", "")
        dst = rule.get("dst_ip")
        specific = bool(dst) and "/" not in dst and dst.lower() != "any"
        if action == "ALLOW_AND_INSPECT":
            return True
        return self.inspect_allowed and action == "ALLOW" and specific

    # ── ÉTAPE 3 — Helpers conntrack (stateful) ──────────────────────────────────

    def _ct_track(self, parser):
        """Action ct native : envoie le paquet au conntrack (zone dédiée) puis
        recircule vers la table de décision d'état (CT_TABLE)."""
        return parser.NXActionCT(flags=0, zone_src=None, zone_ofs_nbits=self.ct_zone,
                                 recirc_table=CT_TABLE, alg=0, actions=[])

    def _ct_commit(self, parser):
        """Action ct native : MÉMORISE la connexion (commit), pas de recirculation."""
        return parser.NXActionCT(flags=NX_CT_F_COMMIT, zone_src=None,
                                 zone_ofs_nbits=self.ct_zone,
                                 recirc_table=NX_CT_RECIRC_NONE, alg=0, actions=[])

    def _install_ct_decision_table(self, dp) -> None:
        """Pose l'ossature stateful BIDIRECTIONNELLE (une fois par switch FW).

        table 1 (décision d'état, forward = NORMAL → gère les 2 sens) :
          +est               → NORMAL (établi : aller re-passe, retour livré)
          +inv               → drop
          +new SANS règle X  → DROP (entrant/inconnu non sollicité ; le +new AUTORISÉ
                                 est posé par _install_stateful_allow, prio 90 > 10)
          miss               → drop
        table 0 : le sous-réseau local (retour + LAN) passe AUSSI par le conntrack
                  → l'établi (+est) est reconnu et l'entrant non sollicité vers h0
                  (+new non autorisé) est jeté par NOS règles. L'inconnu EXTERNE, lui,
                  ne matche pas ici → il va en table-miss → contrôleur (escalade préservée).
        """
        parser = dp.ofproto_parser
        NORMAL = [parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)]
        m = lambda st: parser.OFPMatch(eth_type=0x0800, ct_state=(st | CT_TRK, st | CT_TRK))
        self._add_flow(dp, PRIO_ALLOW, m(CT_EST), NORMAL, table_id=CT_TABLE)      # établi → NORMAL
        self._add_flow(dp, 50, m(CT_INV), [], table_id=CT_TABLE)                  # invalide → drop
        self._add_flow(dp, 10, m(CT_NEW), [], table_id=CT_TABLE)                  # nouveau non autorisé → DROP
        self._add_flow(dp, 0, parser.OFPMatch(), [], table_id=CT_TABLE)           # miss → drop
        # table 0 : LAN/retour (10.0.0.0/24) → conntrack
        lan = _build_match(parser, "10.0.0.0/24", "ip", None, ct_state=(0, CT_TRK))
        self._add_flow(dp, 50, lan, [self._ct_track(parser)])
        logger.info("Switch %016x [FW] : ossature stateful bidirectionnelle (zone=%d) posée.",
                    dp.id, self.ct_zone)

    def _install_stateful_allow(self, dp, dst_ip, protocol, dst_port, prio, cookie) -> None:
        """ALLOW stateful pour une destination autorisée :
          table 0 : aller non suivi vers dst_ip → ct (recirculation table 1) ;
          table 1 : +new vers dst_ip → COMMIT (mémorise) + NORMAL (prio 90 > drop-new 10)."""
        parser = dp.ofproto_parser
        NORMAL = [parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)]
        m0 = _build_match(parser, dst_ip, protocol, dst_port, ct_state=(0, CT_TRK))
        self._add_flow(dp, prio, m0, [self._ct_track(parser)], cookie=cookie)
        m1 = _build_match(parser, dst_ip, protocol, dst_port,
                          ct_state=(CT_NEW | CT_TRK, CT_NEW | CT_TRK))
        self._add_flow(dp, PRIO_ALLOW - 10, m1, [self._ct_commit(parser)] + NORMAL,
                       cookie=cookie, table_id=CT_TABLE)

    # ── Événements OpenFlow ────────────────────────────────────────────────────

    @set_ev_cls(EventDP, MAIN_DISPATCHER)
    def dp_event_handler(self, ev):
        """Réagit à la connexion/déconnexion d'un switch via DPSet."""
        dp = ev.dp
        if ev.enter:
            logger.info("Switch %016x connecté", dp.id)
            self._setup_switch(dp)
        else:
            logger.info("Switch %016x déconnecté", dp.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Installe la règle table-miss dès qu'un switch se connecte."""
        dp = ev.msg.datapath
        self._setup_switch(dp)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Apprentissage MAC + comptage des alertes IDS (surveillance).

        Les menaces CONNUES (règle BLOCK, priorité 950) sont jetées en hardware
        et n'arrivent JAMAIS ici. Ce handler ne voit donc que :
          - les paquets de surveillance IDS (priorité 900, OUTPUT:CONTROLLER) :
            on incrémente le compteur d'alertes, puis on les forwarde ;
          - les paquets inconnus via table-miss (cookie 0) : apprentissage MAC.
        """
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # ── Mode BOUCLE : un flux IPv4 inconnu (arrivé par table-miss, donc
        #    cookie != CHAIN_COOKIE) est escaladé vers les agents puis DROPPÉ
        #    (fail-closed). Seul l'IPv4 est intercepté ; ARP/L2 suivent la voie
        #    normale (apprentissage) pour ne pas casser la plomberie.
        # NB : sur le switch IDS (mode deux-switches), on N'ESCALADE PAS — le trafic
        # qui arrive là a DÉJÀ été validé par le FW en amont ; l'IDS ne fait que
        # surveiller et laisser passer (sinon il re-dropperait du trafic légitime).
        if (self.loop_mode and msg.cookie != CHAIN_COOKIE
                and self._role_of(dp.id) != "ids"):
            ip4 = pkt.get_protocol(ipv4.ipv4)
            if ip4 is not None:
                self._handle_unknown_flow(ip4, pkt)
                return  # on ne forwarde PAS l'inconnu

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = dp.id

        # ── Comptage IDS + détection fine (surveillance du trafic AUTORISÉ) ──
        # Un PacketIn IDS provient d'un flow 900 : soit de la chaîne déployée
        # (CHAIN_COOKIE), soit d'une surveillance posée AU RUNTIME sur un ALLOW /16
        # (RUNTIME_COOKIE, ex. cohost). Dans les deux cas on compte + on applique la
        # détection fine (→ escalade/BLOCK si l'IDS repère une menace dans l'autorisé).
        if msg.cookie in (CHAIN_COOKIE, RUNTIME_COOKIE):
            self._increment_ids_counter(msg)
            # ÉTAPE 2 : en mode steering, le flow IDS a DÉJÀ fait suivre le paquet en
            # hardware (clone [CONTROLLER, OUTPUT:nat]). On ne le ré-émet donc PAS ici
            # (sinon doublon). En Étape 1 (sans steering), on continue vers le forward.
            if self.sfc_steering and self._role_of(dp.id) == "ids":
                return

        # ── Apprentissage MAC ──────────────────────────────────────────────
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self._add_flow(dp, PRIO_MAC_LEARN, match, actions,
                               buffer_id=msg.buffer_id)
                return
            else:
                self._add_flow(dp, PRIO_MAC_LEARN, match, actions)

        data = None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data,
        )
        dp.send_msg(out)

    # ── Setup switch ───────────────────────────────────────────────────────────

    def _setup_switch(self, dp) -> None:
        """Installe la table-miss et ré-applique la chaîne active si elle existe."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Table-miss : priorité 0.
        #   default-allow (défaut) : → contrôleur (apprentissage MAC + forward).
        #   default-deny (flag)    : DROP (instructions vides) → seules les ALLOW passent.
        match = parser.OFPMatch()
        role = self._role_of(dp.id)
        if role == "ids":
            # Switch IDS : il NE bloque pas — il surveille et FAIT SUIVRE. Table-miss
            # → contrôleur pour que packet_in apprenne les MAC et forwarde (JAMAIS de
            # DROP ici, même en default-deny : l'enforcement est fait par le FW amont).
            actions: list = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        elif self.default_deny and not self.loop_mode:
            actions = []  # DROP silencieux (default-deny strict)
        else:
            # default-allow OU mode boucle : on remonte au contrôleur.
            # En boucle, c'est ce qui permet de VOIR les flux inconnus (Packet-In).
            actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, PRIO_TABLE_MISS, match, actions)
        logger.info("Switch %016x [%s] : table-miss %s", dp.id, role.upper(),
                    "→ contrôleur (IDS : surveille + fait suivre)" if role == "ids"
                    else ("→ contrôleur (BOUCLE, fail-closed)" if self.loop_mode
                    else ("= DROP (default-deny)" if self.default_deny else "→ contrôleur (default-allow)")))

        # ── ÉTAPE 2 — wire SFC sur le switch IDS (bump-in-the-wire) ──────────
        # Relie le port du FW au port du NAT dans les deux sens (prio 10, sous les
        # signatures IDS 900, au-dessus de la table-miss 0). Indépendant de la chaîne
        # (cookie 0 → survit au flush). Assure le pass-through explicite du trafic.
        if role == "ids" and self.sfc_steering:
            for _in, _out in ((self.ids_to_fw_port, self.ids_to_nat_port),
                              (self.ids_to_nat_port, self.ids_to_fw_port)):
                self._add_flow(dp, 10, parser.OFPMatch(in_port=_in),
                               [parser.OFPActionOutput(_out)])
            logger.info("Switch %016x [IDS] : wire SFC installé (%d→%d, %d→%d).",
                        dp.id, self.ids_to_fw_port, self.ids_to_nat_port,
                        self.ids_to_nat_port, self.ids_to_fw_port)

        # ── ÉTAPE 3 — table de décision conntrack sur le FW (mode stateful) ──
        if self.stateful and role in ("fw", "both"):
            self._install_ct_decision_table(dp)

        # Ré-appliquer la chaîne active (au cas d'une reconnexion)
        with self._lock:
            if self.active_chain:
                logger.info(
                    "Switch %016x : ré-application de la chaîne '%s'",
                    dp.id, self.active_chain_id,
                )
                self._apply_chain_to_dp(dp, self.active_chain)

    # ── Logique de déploiement des chaînes ────────────────────────────────────

    def apply_chain(self, chain: dict) -> dict:
        """Traduit une SecurityChain en flows OpenFlow et les installe.

        Traduit :
          BLOCK  → DROP direct sur le switch (priorité 950, instructions vides)
          ALLOW  → OFPP_NORMAL (priorité 100, LAN à 50)
          IDS    → OUTPUT:CONTROLLER (priorité 900, surveillance) :
                   atteinte seulement pour les menaces sans règle BLOCK

        Args:
            chain: dict conforme au modèle SecurityChain.

        Returns:
            dict avec "status", "flows_installed", "errors".
        """
        # ── Trace : la chaîne TELLE QUE REÇUE du déployeur (avant application) ──
        _fw = chain.get("firewall_rules", [])
        _allow = sum(1 for r in _fw if str(r.get("action", "")).startswith("ALLOW"))
        _block = sum(1 for r in _fw if r.get("action") == "BLOCK")
        _ids = chain.get("ids_signatures", [])
        _ips = chain.get("ips_actions", [])
        logger.info("═══ CHAÎNE REÇUE DU DÉPLOYEUR : '%s' (app=%s, risque=%s) ═══",
                    chain.get("chain_id", "?"),
                    chain.get("source_app_name") or chain.get("source_app", "?"),
                    chain.get("global_risk_level", "?"))
        logger.info("    reçu : %d firewall (%d ALLOW / %d BLOCK) · %d IDS · %d IPS",
                    len(_fw), _allow, _block, len(_ids), len(_ips))
        for _a in _ips:
            logger.info("    IPS reçue : %s  sur signature=%s  action=%s",
                        _a.get("id", "?"), _a.get("on_signature", "?"), _a.get("action", "?"))
        with self._lock:
            # Flush la chaîne précédente si elle existe
            if self.active_chain:
                self._flush_all_datapaths()

            self.active_chain = chain
            self.active_chain_id = chain.get("chain_id", "unknown")
            self.installed_at = datetime.now(timezone.utc).isoformat()
            self.installed_rules = []

            # /16 connus de la whitelist → base de décision fast-path du contrôleur
            self.known_prefixes = {
                ".".join(r["dst_ip"].split(".")[:2])
                for r in chain.get("firewall_rules", [])
                if str(r.get("action", "")).startswith("ALLOW") and r.get("dst_ip")
                and "/" not in r["dst_ip"] and r["dst_ip"].lower() != "any"
            }

            # Initialiser les compteurs IDS
            self.ids_counters = {}
            for sig in chain.get("ids_signatures", []):
                self.ids_counters[sig["id"]] = {
                    "count": 0,
                    "pattern_type": sig.get("pattern_type", "?"),
                    "dst_ip": sig.get("match_criteria", {}).get("dst_ip", "?"),
                    "dst_port": sig.get("match_criteria", {}).get("dst_port"),
                    "severity": sig.get("severity", "?"),
                }
            # Compteurs pour la surveillance du trafic AUTORISÉ (allow-then-inspect)
            for rule in chain.get("firewall_rules", []):
                if self._rule_is_inspected(rule):
                    self.ids_counters[f"INSPECT-{rule['id']}"] = {
                        "count": 0, "pattern_type": "allowed-inspect",
                        "dst_ip": rule.get("dst_ip", "?"),
                        "dst_port": rule.get("dst_port"), "severity": "INFO",
                    }

        # Pré-peupler installed_rules depuis la définition de la chaîne
        # (indépendamment des switches connectés, pour que /firewall/rules soit lisible)
        with self._lock:
            self._populate_rules_from_chain(chain)

        # Installer sur tous les switches connectés
        datapaths = self.dpset.get_all()
        flows_installed = 0
        errors: list[str] = []

        for _dp_info in datapaths:
            dp = _dp_info[1] if isinstance(_dp_info, tuple) else _dp_info
            try:
                n = self._apply_chain_to_dp(dp, chain)
                flows_installed += n
                logger.info(
                    "Chaîne '%s' installée sur switch %016x (%d flows)",
                    self.active_chain_id, dp.id, n,
                )
            except Exception as exc:
                msg = f"Erreur switch {dp.id:#018x}: {exc}"
                logger.error(msg)
                errors.append(msg)

        return {
            "status": "ok" if not errors else "partial",
            "chain_id": self.active_chain_id,
            "source_app": chain.get("source_app_name"),
            "switches_connected": len(datapaths),
            "flows_installed_on_hardware": flows_installed,
            "rules_configured": len(self.installed_rules),
            "errors": errors,
        }

    def _populate_rules_from_chain(self, chain: dict) -> None:
        """Pré-peuple installed_rules depuis la définition de la chaîne.

        Appelé avant l'installation hardware : permet à /firewall/rules
        de répondre même si aucun switch n'est connecté.
        """
        self.installed_rules = []

        for rule in chain.get("firewall_rules", []):
            action = rule.get("action", "")
            if action == "BLOCK":
                rule_type = "BLOCK"
                # BLOCK : priorité forcée à 950 (cohérent avec _apply_chain_to_dp),
                # on ignore le priority=900 figé dans le JSON.
                actual_prio = PRIO_BLOCK
            elif action in ("ALLOW", "ALLOW_AND_INSPECT"):
                rule_type = "ALLOW"
                # ALLOW : priorité réelle de la règle (100 spécifique, 50 LAN)
                actual_prio = rule.get("priority", PRIO_ALLOW)
            else:
                continue
            self.installed_rules.append({
                "rule_id": rule["id"],
                "type": rule_type,
                "dst_ip": rule.get("dst_ip"),
                "dst_port": rule.get("dst_port"),
                "protocol": rule.get("protocol"),
                "priority": actual_prio,
                "hardware_installed": False,
                "comment": rule.get("comment", ""),
            })

        for sig in chain.get("ids_signatures", []):
            criteria = sig.get("match_criteria", {})
            dst_ip = criteria.get("dst_ip")
            if not dst_ip:
                continue
            self.installed_rules.append({
                "rule_id": sig["id"],
                "type": "IDS",
                "pattern_type": sig.get("pattern_type"),
                "dst_ip": dst_ip,
                "dst_port": criteria.get("dst_port"),
                "protocol": criteria.get("protocol", "TCP"),
                "priority": PRIO_IDS,
                "severity": sig.get("severity"),
                "hardware_installed": False,
                "comment": sig.get("comment", ""),
            })

    def _apply_chain_to_dp(self, dp, chain: dict) -> int:
        """Installe toutes les règles d'une chaîne sur un datapath unique.

        Returns:
            Nombre de flows OpenFlow effectivement envoyés au switch.
        """
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        count = 0

        # ── ÉTAPE 1 — filtrage par rôle du switch (mode deux-switches) ──────
        #   FW  → pose BLOCK + ALLOW (pas d'IDS).
        #   IDS → pose les signatures IDS (900) seules (ni BLOCK ni ALLOW) → plus
        #         de masquage par le BLOCK 950, l'IDS voit enfin le trafic.
        #   both (legacy, un seul switch) → tout, comme avant.
        role = self._role_of(dp.id)
        _fw_rules = chain.get("firewall_rules", []) if role in ("fw", "both") else []
        _ids_sigs = chain.get("ids_signatures", []) if role in ("ids", "both") else []

        # ── 1. Règles Firewall BLOCK → instructions vides (DROP) ──────────
        for rule in _fw_rules:
            if rule.get("action") != "BLOCK":
                continue
            match = _build_match(
                parser, rule.get("dst_ip"),
                rule.get("protocol", "any"), rule.get("dst_port"),
            )
            # Priorité FORCÉE à PRIO_BLOCK (950) : les chaînes JSON contiennent
            # encore priority=900, mais on impose 950 pour que le DROP gagne sur
            # l'IDS (900). Action = instructions vides → DROP direct sur le switch.
            self._add_flow(dp, PRIO_BLOCK, match, actions=[], cookie=CHAIN_COOKIE)
            self._mark_installed(rule["id"])
            count += 1
            logger.info(
                "  BLOCK → DROP [prio=%d] : %s  %s:%s/%s (jeté en hardware)",
                PRIO_BLOCK, rule["id"], rule.get("dst_ip"), rule.get("dst_port"), rule.get("protocol"),
            )

        # ── 2. Règles Firewall ALLOW → OFPP_NORMAL ────────────────────────
        for rule in _fw_rules:
            if rule.get("action") not in ("ALLOW", "ALLOW_AND_INSPECT"):
                continue
            _dst = rule.get("dst_ip")
            # ÉTAPE 2 : un ALLOW vers une IP SPÉCIFIQUE (externe) est steeré vers l'IDS ;
            # un ALLOW LAN/CIDR/any reste en NORMAL (livraison locale + trafic retour).
            _specific = bool(_dst) and "/" not in _dst and _dst.lower() != "any"
            _is_arp = (rule.get("protocol", "") or "").upper() == "ARP"
            prio = rule.get("priority", PRIO_ALLOW)
            # ÉTAPE 3 : STATEFUL — un ALLOW spécifique sur le FW passe par le conntrack
            # (aller → ct + commit en table 1). Les règles LAN/CIDR/any NE sont PLUS
            # posées en NORMAL (sinon l'entrant non sollicité passerait) : elles sont
            # couvertes par l'ossature ct (redirect LAN + drop-new). L'ARP reste NORMAL.
            if self.stateful and role in ("fw", "both") and _specific:
                self._install_stateful_allow(dp, _dst, rule.get("protocol", "any"),
                                             rule.get("dst_port"), prio, CHAIN_COOKIE)
                _fwd = f"ct(zone={self.ct_zone})→table{CT_TABLE}"
            elif self.stateful and role in ("fw", "both") and not _is_arp:
                _fwd = "ct (LAN/any géré par l'ossature stateful)"   # pas de flow stateless
            else:
                match = _build_match(
                    parser, _dst,
                    rule.get("protocol", "any"), rule.get("dst_port"),
                )
                if self.sfc_steering and role == "fw" and _specific:
                    actions = [parser.OFPActionOutput(self.fw_to_ids_port)]
                    _fwd = f"OUTPUT:{self.fw_to_ids_port}→IDS"
                else:
                    actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
                    _fwd = "NORMAL"
                self._add_flow(dp, prio, match, actions, cookie=CHAIN_COOKIE)
            self._mark_installed(rule["id"])
            count += 1
            logger.info(
                "  ALLOW → %s [prio=%d] : %s  %s:%s/%s",
                _fwd, prio, rule["id"], rule.get("dst_ip"), rule.get("dst_port"), rule.get("protocol"),
            )

        # ── 3. Signatures IDS → clone vers contrôleur (surveillance, priorité 900) ──
        # L'IDS est à priorité 900, SOUS le BLOCK (950). Action = [OUTPUT:CONTROLLER].
        #
        # Conséquence du choix de conception :
        #   - Menace CONNUE (avec règle BLOCK) : le DROP à 950 la jette AVANT que
        #     l'IDS ne s'applique → l'IDS (900) n'est jamais atteinte pour elle.
        #     Le blocage est garanti en hardware, le compteur n_packets du flow
        #     BLOCK fait office de journal des tentatives bloquées.
        #   - Menace SANS BLOCK (surveillance pure) : l'IDS (900) capte le paquet,
        #     l'envoie au contrôleur (compteur ids_alerts +1) puis le handler
        #     Packet-In le réinjecte normalement → surveillé sans être bloqué.
        #
        # Le paquet envoyé au contrôleur est traité par packet_in_handler, qui
        # incrémente le compteur d'alertes puis le forwarde (apprentissage MAC).
        for sig in _ids_sigs:
            criteria = sig.get("match_criteria", {})
            dst_ip = criteria.get("dst_ip")
            dst_port = criteria.get("dst_port")
            protocol = criteria.get("protocol", "TCP")
            if not dst_ip:
                continue
            match = _build_match(parser, dst_ip, protocol, dst_port)
            if self.sfc_steering and role == "ids":
                # ÉTAPE 2 : l'IDS CLONE — tap contrôleur (compteur) ET forward explicite
                # vers le NAT. packet_in comptera sans ré-émettre (évite le doublon).
                actions = [
                    parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
                    parser.OFPActionOutput(self.ids_to_nat_port),
                ]
            else:
                actions = [
                    parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
                ]
            self._add_flow(dp, PRIO_IDS, match, actions, cookie=CHAIN_COOKIE)
            self._mark_installed(sig["id"])
            count += 1
            logger.info(
                "  IDS → CONTROLLER [prio=%d] : %s [%s]  %s:%s (surveillance)",
                PRIO_IDS, sig["id"], sig.get("pattern_type"), dst_ip, dst_port,
            )

        # ── 4. Surveillance IDS du trafic AUTORISÉ (allow-then-inspect) ─────
        # Politique defense-in-depth : l'IDS inspecte ce qui PASSE. Pour chaque ALLOW
        # à surveiller (ALLOW_AND_INSPECT, ou mode --inspect), on pose un clone IDS
        # sur le switch IDS → l'IDS voit et COMPTE le trafic permis (compteur qui monte).
        if role in ("ids", "both"):
            for rule in chain.get("firewall_rules", []):
                if not self._rule_is_inspected(rule):
                    continue
                dst_ip = rule.get("dst_ip")
                match = _build_match(parser, dst_ip, rule.get("protocol", "any"),
                                     rule.get("dst_port"))
                if self.sfc_steering and role == "ids":
                    actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
                               parser.OFPActionOutput(self.ids_to_nat_port)]
                else:
                    actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                self._add_flow(dp, PRIO_IDS, match, actions, cookie=CHAIN_COOKIE)
                count += 1
                logger.info("  ALLOW+INSPECT → IDS [prio=%d] : %s  %s:%s (surveillance du trafic AUTORISÉ)",
                            PRIO_IDS, rule["id"], dst_ip, rule.get("dst_port"))

        return count

    def _mark_installed(self, rule_id: str) -> None:
        """Marque une règle comme installée sur le hardware."""
        with self._lock:
            for r in self.installed_rules:
                if r.get("rule_id") == rule_id:
                    r["hardware_installed"] = True
                    break

    def flush_chain(self) -> dict:
        """Supprime tous les flows installés par la chaîne active."""
        with self._lock:
            if not self.active_chain:
                return {"status": "ok", "message": "Aucune chaîne active à supprimer."}
            chain_id = self.active_chain_id
            self._flush_all_datapaths()
            self.active_chain = None
            self.active_chain_id = None
            self.installed_rules = []
            self.ids_counters = {}
            self.installed_at = None

        return {"status": "ok", "message": f"Chaîne '{chain_id}' supprimée."}

    def _flush_all_datapaths(self) -> None:
        """Supprime les flows CHAIN_COOKIE sur tous les switches connectés."""
        for _dp_info in self.dpset.get_all():
            dp = _dp_info[1] if isinstance(_dp_info, tuple) else _dp_info
            self._delete_chain_flows(dp)

    def _delete_chain_flows(self, dp) -> None:
        """Envoie un OFPFlowMod DELETE sur le datapath pour effacer les flows du cookie."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=CHAIN_COOKIE,
            cookie_mask=CHAIN_COOKIE_MASK,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=match,
        )
        dp.send_msg(mod)
        logger.info("Flows CHAIN_COOKIE supprimés sur switch %016x", dp.id)

    def get_stats(self) -> dict:
        """Retourne les statistiques de la chaîne active."""
        with self._lock:
            switches = [dp.id for _info in self.dpset.get_all()
                        for dp in [_info[1] if isinstance(_info, tuple) else _info]]

            rules_by_type: dict[str, int] = {}
            for r in self.installed_rules:
                t = r.get("type", "?")
                rules_by_type[t] = rules_by_type.get(t, 0) + 1

            return {
                "status": "running",
                "active_chain_id": self.active_chain_id,
                "source_app": (
                    self.active_chain.get("source_app_name") if self.active_chain else None
                ),
                "global_risk_level": (
                    self.active_chain.get("global_risk_level") if self.active_chain else None
                ),
                "installed_at": self.installed_at,
                "connected_switches": [f"{s:#018x}" for s in switches],
                "installed_flows": {
                    "total": len(self.installed_rules),
                    "by_type": rules_by_type,
                },
                "ids_alerts": self.ids_counters,
            }

    def _increment_ids_counter(self, msg) -> None:
        """Incrémente le compteur pour la signature IDS qui a déclenché ce PacketIn."""
        # Extraire l'IP dst du paquet pour identifier la signature concernée
        try:
            pkt = packet.Packet(msg.data)
            from os_ken.lib.packet import ipv4
            ip4 = pkt.get_protocol(ipv4.ipv4)
            if ip4:
                dst_ip = ip4.dst
                with self._lock:
                    for sig_id, counter in self.ids_counters.items():
                        if counter.get("dst_ip") == dst_ip:
                            counter["count"] += 1
                            logger.warning(
                                "IDS ALERTE : %s [%s] → %s (total: %d)",
                                sig_id, counter["pattern_type"],
                                dst_ip, counter["count"],
                            )
                # ÉTAPE 3 : l'IDS applique sa détection FINE sur ce trafic AUTORISÉ.
                self._ids_inspect_and_maybe_block(dst_ip)
                # DERNIER CHAÎNON : l'IDS observe le COMPORTEMENT dans le temps (beaconing).
                self._record_and_check_beaconing(dst_ip)
                # SNI : l'IDS regarde DANS le paquet (le DOMAINE), ce que le FW/réputation ne voient pas.
                self._ids_check_sni(dst_ip, pkt)
        except Exception:
            pass

    def _ids_check_sni(self, dst_ip: str, pkt) -> None:
        """INSPECTION PROFONDE — l'IDS lit le SNI (le DOMAINE) dans le TLS ClientHello
        miroité. C'est le seul niveau qui voit le domaine : ni le firewall (IP/port) ni
        la réputation (IP/ASN) ne le voient. Un C2 planqué sur un cloud de confiance
        (IP autorisée) mais avec un domaine malveillant est ATTRAPÉ ici → BLOCK."""
        if dst_ip in self.ids_detected:
            return
        payload = None
        for pr in pkt.protocols:
            if isinstance(pr, (bytes, bytearray)):
                payload = bytes(pr)
                break
        if not payload:
            return
        from whitelist import sni_parser
        sni = sni_parser.extract_sni(payload)
        if not sni:
            return
        # 1) LISTE LOCALE (offline, rapide) → BLOCK immédiat si le domaine est déjà connu
        if sni_parser.is_malicious_domain(sni):
            self.ids_detected.add(dst_ip)
            for dp in self._enforcement_datapaths():
                self._add_flow(dp, PRIO_BLOCK,
                               _build_match(dp.ofproto_parser, dst_ip, "ip", None),
                               actions=[], cookie=RUNTIME_COOKIE)
            try:
                from whitelist import threat_intel
                threat_intel.add_malicious(dst_ip)
            except Exception:
                pass
            self.decide_blk += 1
            logger.warning("🚨 IDS SNI : domaine MALVEILLANT '%s' (liste locale) (→ %s) → BLOCK "
                           "+ réputation mise à jour", sni, dst_ip)
            return
        # 2) domaine INCONNU → ESCALADE aux agents (ils appelleront VirusTotal-domaine,
        #    HORS du chemin critique). Le contrôleur ne fait AUCUN appel en ligne ici.
        self.ids_detected.add(dst_ip)              # dédup : une seule escalade par IP
        self._escalate_redis(dst_ip, 443, "tcp", why=f"SNI '{sni}'", domain=sni)
        logger.info("IDS SNI : domaine '%s' (→ %s) inconnu → ESCALADÉ aux agents (VT-domaine)",
                    sni, dst_ip)

    def _ids_inspect_and_maybe_block(self, dst_ip: str) -> None:
        """DEFENSE IN DEPTH — l'IDS re-vérifie la RÉPUTATION (threat_intel) de chaque
        IP EXACTE du trafic AUTORISÉ. Le firewall a pu laisser passer une IP (whitelist
        exacte, ou /16 de confiance) qui est en fait malveillante ; l'IDS la RATTRAPE et
        pose un BLOCK de l'IP exacte (autonomique). Signal = réputation (pas de liste
        magique). Déduplication : un seul BLOCK par IP.

        NB honnête : un cohost INCONNU de la réputation reste une fuite (aucun signal
        dans les données ne le distingue) → détection fine (SNI/DPI) = perspective."""
        if dst_ip in self.ids_detected:
            return
        try:
            from whitelist import threat_intel
        except Exception:
            return
        if threat_intel.reputation(dst_ip) != "malicious":
            return
        self.ids_detected.add(dst_ip)
        for dp in self._enforcement_datapaths():
            self._add_flow(dp, PRIO_BLOCK,
                           _build_match(dp.ofproto_parser, dst_ip, "ip", None),
                           actions=[], cookie=RUNTIME_COOKIE)
        self.decide_blk += 1
        logger.warning("🚨 IDS (defense-in-depth) : %s AUTORISÉ par le firewall mais RÉPUTATION "
                       "malveillante → BLOCK posé (l'IDS rattrape ce que le FW a laissé passer)",
                       dst_ip)

    def _record_and_check_beaconing(self, dst_ip: str) -> None:
        """DERNIER CHAÎNON — l'IDS observe le COMPORTEMENT dans le temps. Il enregistre
        les rappels vers une destination surveillée et mesure leur RÉGULARITÉ. Des
        rappels réguliers (faible coefficient de variation des intervalles) = beaconing
        = signature de C2 → l'IDS ferme la boucle en posant un BLOCK. C'est le signal que
        le contrôleur NE PEUT PAS voir sur un seul paquet (il faut le temps)."""
        import time as _t
        import statistics as _st
        if dst_ip in self.beaconing_flagged:
            return
        ts = self.ids_timestamps.setdefault(dst_ip, [])
        ts.append(_t.time())
        if len(ts) > 12:
            del ts[0]
        if len(ts) < 6:                       # il faut assez d'échantillons
            return
        intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
        mean = sum(intervals) / len(intervals)
        if mean <= 0 or mean > 30:            # trop espacés → pas du beaconing pertinent ici
            return
        cv = _st.pstdev(intervals) / mean     # coefficient de variation (régularité)
        logger.info("IDS beaconing-check %s : n=%d intervalle~%.2fs CV=%.2f", dst_ip, len(ts), mean, cv)
        if cv >= 0.35:                        # trop irrégulier → trafic normal
            return
        self.beaconing_flagged.add(dst_ip)
        for dp in self._enforcement_datapaths():
            self._add_flow(dp, PRIO_BLOCK,
                           _build_match(dp.ofproto_parser, dst_ip, "ip", None),
                           actions=[], cookie=RUNTIME_COOKIE)
        self.decide_blk += 1
        logger.warning("🚨 IDS COMPORTEMENT : %s = BEACONING (%d rappels, intervalle ~%.1fs, "
                       "régularité CV=%.2f < 0.25) → BLOCK (signature comportementale de C2, "
                       "invisible au contrôleur sur 1 paquet)", dst_ip, len(ts), mean, cv)

    def _install_runtime_ids_watch(self, dst_ip, protocol, port) -> None:
        """Surveillance IDS d'un flux AUTORISÉ AU RUNTIME (ex. cohost /16 accepté par
        le contrôleur) : pose un clone IDS sur le switch IDS → l'IDS voit ce trafic
        permis et peut appliquer sa détection fine (→ escalade/BLOCK). Sans ça, seul
        le trafic de la whitelist DÉPLOYÉE serait inspecté."""
        if not self.inspect_allowed:
            return
        for _i in self.dpset.get_all():
            dp = _i[1] if isinstance(_i, tuple) else _i
            if self._role_of(dp.id) != "ids":
                continue
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = _build_match(parser, dst_ip, protocol, port)
            if self.sfc_steering:
                actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
                           parser.OFPActionOutput(self.ids_to_nat_port)]
            else:
                actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
            self._add_flow(dp, PRIO_IDS, match, actions, cookie=RUNTIME_COOKIE)
        with self._lock:
            self.ids_counters.setdefault(f"INSPECT-RT-{dst_ip}", {
                "count": 0, "pattern_type": "allowed-inspect",
                "dst_ip": dst_ip, "dst_port": port, "severity": "INFO"})

    # ── Mode boucle : escalade des flux inconnus ────────────────────────────────

    def _handle_unknown_flow(self, ip4, pkt) -> None:
        """Flux IPv4 inconnu (table-miss) : extrait (ip,port,proto), pousse dans
        Redis pour les agents, dédupe (1 push par flux). Le paquet est droppé par
        l'appelant (fail-closed)."""
        dst_ip = ip4.dst
        port = None
        proto = "ip"
        t = pkt.get_protocol(tcp.tcp)
        u = pkt.get_protocol(udp.udp)
        if t is not None:
            proto, port = "tcp", t.dst_port
        elif u is not None:
            proto, port = "udp", u.dst_port
        elif ip4.proto == 1:
            proto = "icmp"

        key = (dst_ip, port, proto)
        if key in self._seen_unknown:
            return  # déjà signalé → on évite d'inonder la file
        self._seen_unknown.add(key)

        # ── Mode HYBRIDE : le contrôleur tranche le CLAIR, escalade l'AMBIGU ────
        if self.hybrid:
            self._hybrid_decide(dst_ip, port, proto)
            return

        # ── Niveau 2 : le contrôleur décide LUI-MÊME (déterministe /16) ────────
        if self.controller_decide:
            self._decide_and_install(dst_ip, port, proto)
            return

        # ── Sinon : escalade vers les agents via Redis (cas ambigu / futur) ────
        self._escalate_redis(dst_ip, port, proto, why="mode boucle")

    def _escalate_redis(self, dst_ip, port, proto, why="", domain=None) -> None:
        """Pousse le flux inconnu dans Redis pour les agents (fail-closed : droppé).
        `domain` (optionnel) : escalade aussi le domaine SNI → l'agent appellera VT-domaine
        (l'appel en ligne se fait chez les agents, PAS dans le contrôleur)."""
        event = {"ip": dst_ip, "port": port, "proto": proto,
                 "ts": datetime.now(timezone.utc).isoformat()}
        if domain:
            event["domain"] = domain
        if self._redis is not None:
            try:
                self._redis.rpush("sdn:anomalies", json.dumps(event))
            except Exception as exc:
                logger.warning("Push Redis échoué pour %s : %s", (dst_ip, port, proto), exc)
        logger.info("→ ESCALADÉ aux agents (Redis) : %s:%s/%s  [%s] (droppé en attendant)",
                    dst_ip, port, proto, why)

    def _hybrid_decide(self, dst_ip: str, port, proto: str) -> None:
        """MODE HYBRIDE — le contrôleur tranche ce qui est CLAIR (rapide), et n'escalade
        aux agents que l'AMBIGU :
          1) réputation malveillante connue (threat-intel) → BLOCK direct,
          2) /16 connu de la whitelist                     → ALLOW direct,
          3) sinon (ni l'un ni l'autre)                    → escalade aux agents.
        """
        from whitelist import threat_intel
        pref = ".".join(dst_ip.split(".")[:2])
        if threat_intel.reputation(dst_ip) == "malicious":
            for dp in self._enforcement_datapaths():
                self._add_flow(dp, PRIO_BLOCK, _build_match(dp.ofproto_parser, dst_ip, "ip", None),
                               actions=[], cookie=RUNTIME_COOKIE)
            self.decide_blk += 1
            logger.info("DÉCISION contrôleur : RÉPUTATION malveillante → BLOCK %s (DROP posé)  "
                        "[clair : géré par le contrôleur]", dst_ip)
        elif pref in self.known_prefixes:
            for dp in self._enforcement_datapaths():
                if self.stateful and self._role_of(dp.id) in ("fw", "both"):
                    self._install_stateful_allow(dp, dst_ip, proto, port, PRIO_ALLOW, RUNTIME_COOKIE)
                else:
                    self._add_flow(dp, PRIO_ALLOW, _build_match(dp.ofproto_parser, dst_ip, proto, port),
                                   self._allow_actions(dp), cookie=RUNTIME_COOKIE)
            self._install_runtime_ids_watch(dst_ip, proto, port)  # IDS surveille l'autorisé
            self.decide_ext += 1
            logger.info("DÉCISION contrôleur : /16 connu (%s.x) → ALLOW %s (laissé passer)  "
                        "[clair : géré par le contrôleur]", pref, dst_ip)
        else:
            logger.info("AMBIGU : %s (ni réputation, ni /16 %s.x connu) → le contrôleur NE PEUT PAS",
                        dst_ip, pref)
            self._escalate_redis(dst_ip, port, proto, why="ambigu → agents")

    def _decide_and_install(self, dst_ip: str, port, proto: str) -> None:
        """NIVEAU 2 — décision déterministe DANS le contrôleur, sans Redis ni agents.

        Règle /16 : même préfixe /16 qu'une destination de la whitelist → EXTEND
        (ALLOW posé directement) ; sinon → BLOCK (DROP posé). Latence = ms (une
        seule règle OpenFlow installée, pas de redéploiement complet de la chaîne).
        """
        pref = ".".join(dst_ip.split(".")[:2])
        allow = pref in self.known_prefixes
        # Mode deux-switches : la décision d'enforcement va sur le FW uniquement.
        for dp in self._enforcement_datapaths():
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            if allow:
                if self.stateful and self._role_of(dp.id) in ("fw", "both"):
                    self._install_stateful_allow(dp, dst_ip, proto, port, PRIO_ALLOW, RUNTIME_COOKIE)
                else:
                    match = _build_match(parser, dst_ip, proto, port)
                    self._add_flow(dp, PRIO_ALLOW, match, self._allow_actions(dp), cookie=RUNTIME_COOKIE)
            else:
                # DROP tout trafic IP vers cette destination
                match = _build_match(parser, dst_ip, "ip", None)
                self._add_flow(dp, PRIO_BLOCK, match, actions=[], cookie=RUNTIME_COOKIE)
        if allow:
            self._install_runtime_ids_watch(dst_ip, proto, port)  # IDS surveille l'autorisé
            self.decide_ext += 1
        else:
            self.decide_blk += 1
        logger.info("DÉCISION contrôleur (/16) : %s %s (préfixe %s %s) → %s posé  "
                    "[ext=%d blk=%d]",
                    "EXTEND" if allow else "BLOCK", dst_ip, pref,
                    "connu" if allow else "inconnu",
                    "ALLOW" if allow else "DROP", self.decide_ext, self.decide_blk)

    # ── Helpers OpenFlow ───────────────────────────────────────────────────────

    def _add_flow(self, dp, priority: int, match, actions: list,
                  buffer_id=None, cookie: int = 0, table_id: int = 0) -> None:
        """Installe un flow OpenFlow 1.3 sur le datapath (table 0 par défaut)."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        if actions:
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []  # DROP : aucune instruction

        kwargs: dict = dict(
            datapath=dp, priority=priority, table_id=table_id,
            match=match, instructions=inst,
            cookie=cookie,
        )
        if buffer_id is not None and buffer_id != ofp.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id

        mod = parser.OFPFlowMod(**kwargs)
        dp.send_msg(mod)

    # ── Serveur REST ───────────────────────────────────────────────────────────

    def _start_rest_server(self) -> None:
        """Lance le serveur Flask dans un green-thread os_ken."""
        flask_app = self._build_flask_app()
        logger.info("Serveur REST démarré sur http://0.0.0.0:%d", REST_PORT)
        # threaded=False : un seul green-thread, compatible eventlet
        flask_app.run(
            host="0.0.0.0",
            port=REST_PORT,
            use_reloader=False,
            threaded=False,
        )

    def _build_flask_app(self) -> Flask:
        """Construit l'application Flask avec les 4 routes REST."""
        flask_app = Flask("sdn_executor_rest")
        fw = self  # capture

        # ── POST /firewall/install ─────────────────────────────────────────

        @flask_app.route("/firewall/install", methods=["POST"])
        def install():
            if not request.is_json:
                return jsonify({"error": "Content-Type doit être application/json"}), 400
            try:
                chain = request.get_json()
            except Exception as exc:
                return jsonify({"error": f"JSON invalide : {exc}"}), 400

            required = ("chain_id", "firewall_rules", "ids_signatures", "ips_actions")
            missing = [f for f in required if f not in chain]
            if missing:
                return jsonify({"error": f"Champs manquants : {missing}"}), 400

            result = fw.apply_chain(chain)
            status_code = 200 if result.get("status") in ("ok", "partial") else 500
            return jsonify(result), status_code

        # ── GET /firewall/stats ────────────────────────────────────────────

        @flask_app.route("/firewall/stats", methods=["GET"])
        def stats():
            return jsonify(fw.get_stats()), 200

        # ── GET /firewall/rules ────────────────────────────────────────────

        @flask_app.route("/firewall/rules", methods=["GET"])
        def rules():
            with fw._lock:
                return jsonify({
                    "chain_id": fw.active_chain_id,
                    "count": len(fw.installed_rules),
                    "rules": fw.installed_rules,
                }), 200

        # ── DELETE /firewall/flush ─────────────────────────────────────────

        @flask_app.route("/firewall/flush", methods=["DELETE"])
        def flush():
            result = fw.flush_chain()
            return jsonify(result), 200

        # ── GET / (santé) ──────────────────────────────────────────────────

        @flask_app.route("/", methods=["GET"])
        def health():
            return jsonify({
                "service": "sdn_executor",
                "version": "1.0",
                "endpoints": [
                    "POST /firewall/install",
                    "GET  /firewall/stats",
                    "GET  /firewall/rules",
                    "DELETE /firewall/flush",
                ],
            }), 200

        return flask_app
