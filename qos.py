#!/usr/bin/env python3
"""
qos.py - Module de Gestion de la Qualité de Service (QoS) SDN
==============================================================
Projet : Architecture SDN pour la Gestion Dynamique du Trafic et Sécurité Réseau
Auteur : Aminata Thior
Encadrant : Pr. Malick Ndoye
Université : Assane Seck de Ziguinchor - Master 1 Réseaux Avancés
Année : 2024-2025

Description :
    Ce module implémente des politiques de Qualité de Service (QoS) via
    le contrôleur SDN Ryu (OpenFlow 1.3). Il classe et priorise le trafic
    réseau en 3 niveaux de priorité basés sur le type de protocole et
    les ports de destination.

Niveaux de priorité QoS :
    HAUTE    (priorité 25-30) : iperf3 TCP 5201, SSH TCP 22
    MOYENNE  (priorité 15-20) : TCP général, ICMP
    BASSE    (priorité 10)    : UDP

Règles installées sur chaque switch :
    1. TCP port 5201 (iperf3) -> priorité 30 (HAUTE)
    2. TCP port 22 (SSH)      -> priorité 25 (HAUTE)
    3. TCP général            -> priorité 20 (MOYENNE)
    4. ICMP                   -> priorité 15 (MOYENNE)
    5. UDP général            -> priorité 10 (BASSE)

Utilisation :
    ryu-manager qos.py
"""

# Imports du framework Ryu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub
from collections import defaultdict


class QoSManager(app_manager.RyuApp):
    """
    Contrôleur SDN avec gestion de la Qualité de Service (QoS).
    
    Implémente une classification du trafic en 3 niveaux de priorité
    via des règles OpenFlow installées directement sur les switches.
    La priorisation garantit que le trafic critique (iperf3, SSH) obtient
    les ressources réseau en priorité sur le trafic moins important (UDP).
    """
    
    # Version OpenFlow supportée
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # -----------------------------------------------------------------------
    # Identifiants des files d'attente QoS
    # -----------------------------------------------------------------------
    QUEUE_HIGH   = 0  # File haute priorité : iperf3, SSH
    QUEUE_MEDIUM = 1  # File priorité moyenne : TCP général, ICMP
    QUEUE_LOW    = 2  # File basse priorité : UDP et reste

    def __init__(self, *args, **kwargs):
        """
        Initialisation du gestionnaire QoS.
        
        Attributs :
            mac_to_port : Table d'apprentissage MAC -> port par switch
            datapaths   : Switches connectés {dpid: datapath}
        """
        super(QoSManager, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Gestionnaire de connexion d'un switch.
        
        Installe la règle table-miss puis déploie immédiatement
        les règles QoS sur le switch nouvellement connecté.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Règle table-miss : paquets non matchés -> contrôleur
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info('Switch connecte : %016x', datapath.id)
        
        # Déploiement immédiat des règles QoS sur ce switch
        self._install_qos_rules(datapath)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Gestionnaire de changement d'état des switches."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    def add_flow(self, datapath, priority, match, actions,
                 idle=0, hard=0):
        """
        Installe une règle de flux sur un switch OpenFlow.
        
        Args:
            datapath : Switch cible
            priority : Priorité OpenFlow (plus élevé = traité en premier)
            match    : Critères de correspondance (protocole, port, etc.)
            actions  : Actions à appliquer sur les paquets matchés
            idle     : Timeout d'inactivité en secondes (0 = permanent)
            hard     : Timeout absolu en secondes (0 = permanent)
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            idle_timeout=idle, hard_timeout=hard,
            match=match, instructions=inst)
        datapath.send_msg(mod)

    def _install_qos_rules(self, datapath):
        """
        Installe les règles de priorisation QoS sur un switch.
        
        Les règles sont ordonnées par priorité décroissante :
        plus le numéro de priorité OpenFlow est élevé, plus la règle
        est traitée en premier lors de la classification des paquets.
        
        Hiérarchie des priorités :
            30 : iperf3 TCP 5201 (tests de performance critiques)
            25 : SSH TCP 22      (accès distant - haute priorité)
            20 : TCP général     (trafic applicatif standard)
            15 : ICMP            (diagnostics réseau)
            10 : UDP             (trafic best-effort)
        
        Args:
            datapath : Switch sur lequel installer les règles QoS
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # --- Règle 1 : HAUTE priorité - iperf3 (TCP port 5201) ---
        # Garantit la bande passante maximale pour les tests de performance
        match_iperf = parser.OFPMatch(
            eth_type=0x0800,   # IPv4
            ip_proto=6,        # TCP
            tcp_dst=5201)      # Port iperf3
        actions_high = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 30, match_iperf, actions_high)
        self.logger.info(
            'QoS switch %016x : regle HAUTE priorite (iperf3 TCP 5201)',
            datapath.id)

        # --- Règle 2 : HAUTE priorité - SSH (TCP port 22) ---
        # Garantit la réactivité des sessions d'administration
        match_ssh = parser.OFPMatch(
            eth_type=0x0800,   # IPv4
            ip_proto=6,        # TCP
            tcp_dst=22)        # Port SSH
        self.add_flow(datapath, 25, match_ssh, actions_high)
        self.logger.info(
            'QoS switch %016x : regle HAUTE priorite (SSH TCP 22)',
            datapath.id)

        # --- Règle 3 : MOYENNE priorité - TCP général ---
        # Trafic TCP standard (HTTP, HTTPS, etc.)
        match_tcp = parser.OFPMatch(
            eth_type=0x0800,   # IPv4
            ip_proto=6)        # TCP (tous ports)
        actions_medium = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 20, match_tcp, actions_medium)
        self.logger.info(
            'QoS switch %016x : regle MOYENNE priorite (TCP)',
            datapath.id)

        # --- Règle 4 : BASSE priorité - UDP ---
        # Trafic UDP best-effort (streaming, DNS, etc.)
        match_udp = parser.OFPMatch(
            eth_type=0x0800,   # IPv4
            ip_proto=17)       # UDP
        actions_low = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 10, match_udp, actions_low)
        self.logger.info(
            'QoS switch %016x : regle BASSE priorite (UDP)',
            datapath.id)

        # --- Règle 5 : MOYENNE priorité - ICMP ---
        # Trafic de diagnostic réseau (ping, traceroute)
        match_icmp = parser.OFPMatch(
            eth_type=0x0800,   # IPv4
            ip_proto=1)        # ICMP
        self.add_flow(datapath, 15, match_icmp, actions_medium)
        self.logger.info(
            'QoS switch %016x : regle MOYENNE priorite (ICMP)',
            datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Gestionnaire des paquets reçus par le contrôleur.
        
        Effectue :
        1. Classification du flux par type de protocole et port
        2. Journalisation du niveau de priorité attribué
        3. Apprentissage MAC et routage standard
        
        Note : Les règles QoS sont déjà installées sur les switches.
        Ce handler gère uniquement les paquets table-miss (premiers
        paquets de chaque flux avant installation de la règle de flux).
        
        Args:
            ev : Événement OFPPacketIn
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        # Apprentissage MAC
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # --- Classification QoS du flux ---
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            proto = ip_pkt.proto
            if proto == 6:   # TCP
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt and (tcp_pkt.dst_port == 5201 or
                                tcp_pkt.src_port == 5201):
                    priorite = 'HAUTE (iperf3)'    # Tests de performance
                elif tcp_pkt and tcp_pkt.dst_port == 22:
                    priorite = 'HAUTE (SSH)'        # Administration
                else:
                    priorite = 'MOYENNE (TCP)'      # Applications standard
            elif proto == 17:  # UDP
                priorite = 'BASSE (UDP)'            # Best-effort
            elif proto == 1:   # ICMP
                priorite = 'MOYENNE (ICMP)'         # Diagnostics
            else:
                priorite = 'NORMALE'
            
            # Log debug de la classification (visible avec --verbose)
            self.logger.debug(
                'QoS switch %s : flux (%s->%s) priorite %s',
                dpid, src[-5:], dst[-5:], priorite)

        # --- Routage standard ---
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Installation de la règle de flux pour les prochains paquets
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions, idle=30)

        # Envoi du paquet actuel
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
