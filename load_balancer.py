#!/usr/bin/env python3
"""
load_balancer.py - Module de Répartition de Charge SDN
=======================================================
Projet : Architecture SDN pour la Gestion Dynamique du Trafic et Sécurité Réseau
Auteur : Aminata Thior
Encadrant : Pr. Malick Ndoye
Université : Assane Seck de Ziguinchor - Master 1 Réseaux Avancés
Année : 2024-2025

Description :
    Ce module implémente un algorithme de répartition de charge (load balancing)
    basé sur la technique Round-Robin. Il distribue les flux réseau de manière
    équitable entre les ports disponibles des switches SDN.

    Fonctionnement :
    - Chaque nouveau flux (src_mac, dst_mac) se voit assigner un port de sortie
      de façon cyclique (round-robin) parmi les ports uplink disponibles
    - L'assignation est mémorisée pour garantir la cohérence du flux
    - La charge par port est suivie pour affichage et diagnostic

Avantage SDN vs traditionnel :
    Le load balancing SDN est centralisé et global : le contrôleur voit
    tous les flux de tous les switches et peut équilibrer la charge
    de manière optimale, contrairement aux switches traditionnels qui
    n'ont qu'une vue locale.

Utilisation :
    ryu-manager load_balancer.py
"""

# Imports du framework Ryu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from collections import defaultdict


class LoadBalancer(app_manager.RyuApp):
    """
    Contrôleur SDN avec répartition de charge Round-Robin.
    
    Distribue les flux réseau équitablement entre les ports disponibles
    en utilisant un compteur cyclique par switch. Chaque flux unique
    (src_mac, dst_mac) reçoit une assignation de port fixe et mémorisée
    pour garantir la cohérence des paquets appartenant au même flux.
    """
    
    # Version OpenFlow supportée
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """
        Initialisation du load balancer.
        
        Attributs :
            mac_to_port : Table d'apprentissage MAC -> port
            rr_counter  : Compteur round-robin par switch {dpid: compteur}
            port_load   : Nombre de flux assignés par port {dpid: {port: count}}
            flow_port   : Port assigné par flux {dpid: {(src,dst): port}}
        """
        super(LoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        # Compteur round-robin : incrémenté à chaque nouveau flux assigné
        self.rr_counter = defaultdict(int)
        
        # Charge par port : nombre de flux actifs par port
        self.port_load = defaultdict(lambda: defaultdict(int))
        
        # Assignation flux -> port : mémorise le port choisi pour chaque flux
        # Structure : {dpid: {(mac_src, mac_dst): port_assigné}}
        self.flow_port = defaultdict(dict)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Gestionnaire de connexion d'un switch.
        Installe la règle table-miss pour envoyer les paquets au contrôleur.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Règle table-miss : tous les paquets non matchés -> contrôleur
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle=0):
        """
        Installe une règle de flux sur un switch OpenFlow.
        
        Args:
            datapath : Switch cible
            priority : Priorité de la règle
            match    : Critères de correspondance
            actions  : Actions à appliquer
            idle     : Timeout d'inactivité (30s pour les flux load-balancés)
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            idle_timeout=idle, match=match, instructions=inst)
        datapath.send_msg(mod)

    def _assign_port_rr(self, dpid, src, dst, available_ports):
        """
        Assigne un port de sortie à un flux (src, dst) en Round-Robin.
        
        Algorithme Round-Robin :
        - Pour chaque nouveau flux, sélectionne le port à l'index
          (compteur % nb_ports) dans la liste des ports disponibles
        - Incrémente le compteur pour le prochain flux
        - Mémorise l'assignation pour les paquets suivants du même flux
        
        Si le flux existe déjà, retourne le port précédemment assigné
        (garantit la cohérence du flux = tous les paquets du même flux
        suivent le même chemin).
        
        Args:
            dpid            : Identifiant du switch
            src             : Adresse MAC source
            dst             : Adresse MAC destination
            available_ports : Liste des ports uplink disponibles
            
        Returns:
            int : Numéro du port assigné à ce flux
        """
        key = (src, dst)
        
        if key not in self.flow_port[dpid]:
            # Nouveau flux : sélection round-robin
            idx = self.rr_counter[dpid] % len(available_ports)
            self.rr_counter[dpid] += 1
            
            # Assignation et mémorisation du port pour ce flux
            self.flow_port[dpid][key] = available_ports[idx]
            self.port_load[dpid][available_ports[idx]] += 1
            
            self.logger.info(
                'LB RR nouveau flux : switch %s (%s->%s) -> port %s | charge: %s',
                dpid, src[-5:], dst[-5:],
                self.flow_port[dpid][key],
                dict(self.port_load[dpid]))
        
        return self.flow_port[dpid][key]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Gestionnaire des paquets avec load balancing Round-Robin.
        
        Logique de traitement :
        1. Si MAC destination connue -> routage direct (table MAC)
        2. Si MAC destination inconnue -> load balancing Round-Robin
           sur les ports uplink disponibles (ports 1-5 sauf port d'entrée)
        3. Flood si aucun port uplink disponible
        
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

        if dst in self.mac_to_port[dpid]:
            # MAC connue : routage direct sans load balancing
            out_port = self.mac_to_port[dpid][dst]
        else:
            # MAC inconnue : load balancing Round-Robin sur les ports uplink
            # Ports uplink = ports 1 à 5 sauf le port d'entrée
            uplink_ports = [p for p in range(1, 6) if p != in_port]
            if uplink_ports:
                out_port = self._assign_port_rr(
                    dpid, src, dst, uplink_ports)
            else:
                # Aucun port uplink disponible -> flood
                out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Installation d'une règle de flux (idle=30s)
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
