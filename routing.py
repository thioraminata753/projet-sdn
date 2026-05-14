#!/usr/bin/env python3
"""
routing.py - Module de Routage Dynamique SDN
============================================
Projet : Architecture SDN pour la Gestion Dynamique du Trafic et Sécurité Réseau
Auteur : Aminata Thior
Encadrant : Pr. Malick Ndoye
Université : Assane Seck de Ziguinchor - Master 1 Réseaux Avancés
Année : 2024-2025

Description :
    Ce module implémente un algorithme de routage dynamique basé sur
    l'état du réseau. Contrairement au routage statique traditionnel,
    le routage SDN s'adapte en temps réel aux conditions du réseau :

    - Surveillance continue des métriques de performance (bande passante,
      taux de perte) via les compteurs OpenFlow (port_stats)
    - Sélection du meilleur port de sortie selon un score combinant
      le taux de perte et la charge du lien
    - Apprentissage MAC pour le routage direct quand la destination est connue

Algorithme de sélection du meilleur port :
    score = taux_perte(%) + débit(MB/s)
    Le port avec le score le plus bas est sélectionné (moins chargé et fiable)

Utilisation :
    ryu-manager routing.py
"""

# Imports du framework Ryu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, arp
from collections import defaultdict


class DynamicRouting(app_manager.RyuApp):
    """
    Contrôleur SDN avec routage dynamique basé sur les métriques réseau.
    
    Implémente un routage adaptatif qui choisit le meilleur chemin
    en fonction de la bande passante disponible et du taux de perte
    mesuré sur chaque port des switches.
    """
    
    # Version OpenFlow supportée
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """
        Initialisation du module de routage dynamique.
        
        Attributs :
            datapaths      : Switches connectés {dpid: datapath}
            mac_to_port    : Table d'apprentissage MAC -> port
            port_stats     : Métriques par port {dpid: {port: {speed, loss, rx_pkts, tx_pkts}}}
            port_speed     : Débits par port {dpid: {port: bytes/sec}}
            prev_bytes     : Bytes précédents pour calcul différentiel {dpid: {port: bytes}}
            monitor_thread : Thread de collecte périodique des métriques
        """
        super(DynamicRouting, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        
        # Métriques réseau par switch et par port
        # Structure : {dpid: {port: {'speed': B/s, 'loss': %, 'rx_pkts': n, 'tx_pkts': n}}}
        self.port_stats = defaultdict(lambda: defaultdict(dict))
        
        # Débits instantanés par port (bytes/sec)
        self.port_speed = defaultdict(lambda: defaultdict(float))
        
        # Compteurs de bytes précédents pour calcul du débit différentiel
        self.prev_bytes = defaultdict(lambda: defaultdict(int))
        
        # Démarrage du thread de monitoring périodique
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        Gestionnaire de changement d'état des switches.
        Met à jour le dictionnaire des switches actifs.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info('Switch connecte : %016x', datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        """
        Thread de monitoring périodique.
        Collecte les statistiques de ports toutes les 5 secondes.
        """
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        """
        Envoie une requête de statistiques de ports à un switch.
        
        Args:
            datapath : Switch cible
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
        Gestionnaire des réponses de statistiques de ports.
        
        Calcule pour chaque port :
        - Bande passante instantanée (bytes/sec) par différence
        - Taux de perte de paquets (%)
        
        Ces métriques alimentent l'algorithme de sélection du meilleur port.
        
        Args:
            ev : Événement OFPPortStatsReply
        """
        dpid = ev.msg.datapath.id
        for stat in ev.msg.body:
            port = stat.port_no
            
            # Ignorer le port local (OFPP_LOCAL = 0xfffffffe)
            if port == 0xfffffffe:
                continue
            
            # Calcul de la bande passante : (bytes_actuels - bytes_précédents) / 5s
            curr_bytes = stat.tx_bytes + stat.rx_bytes
            prev = self.prev_bytes[dpid][port]
            speed = (curr_bytes - prev) / 5.0  # bytes/sec sur intervalle de 5s
            self.prev_bytes[dpid][port] = curr_bytes
            self.port_speed[dpid][port] = speed
            
            # Calcul du taux de perte : (paquets émis - paquets reçus) / paquets émis
            tx = stat.tx_packets
            rx = stat.rx_packets
            loss = 0.0
            if tx > 0:
                loss = max(0.0, (tx - rx) / tx * 100)
            
            # Stockage des métriques pour cet port
            self.port_stats[dpid][port] = {
                'speed': speed,   # Débit en bytes/sec
                'loss': loss,     # Taux de perte en %
                'rx_pkts': rx,    # Paquets reçus (total cumulé)
                'tx_pkts': tx     # Paquets émis (total cumulé)
            }
        
        self._log_metrics(dpid)

    def _log_metrics(self, dpid):
        """
        Affiche les métriques réseau d'un switch dans les logs.
        
        Args:
            dpid : Identifiant du switch
        """
        self.logger.info('=== METRIQUES RESEAU (switch %016x) ===', dpid)
        self.logger.info('%6s %12s %10s', 'port', 'bande(B/s)', 'perte(%)')
        for port, metrics in sorted(self.port_stats[dpid].items()):
            self.logger.info('%6d %12.1f %10.2f',
                           port,
                           metrics.get('speed', 0),
                           metrics.get('loss', 0))

    def _best_port(self, dpid, available_ports):
        """
        Sélectionne le meilleur port selon les métriques de performance.
        
        Algorithme de score :
            score = taux_perte(%) + débit_normalisé(MB/s)
        
        Le port avec le score le plus bas est préféré car il combine
        un faible taux de perte et une faible charge (débit bas = moins utilisé).
        
        Args:
            dpid            : Identifiant du switch
            available_ports : Liste des ports candidats
            
        Returns:
            int : Numéro du meilleur port, ou None si aucun disponible
        """
        best_port = None
        best_score = float('inf')
        
        for port in available_ports:
            metrics = self.port_stats[dpid].get(port, {})
            speed = metrics.get('speed', 0)
            loss = metrics.get('loss', 0)
            
            # Score combiné : perte pondérée + charge normalisée en MB/s
            score = loss + (speed / 1e6)
            
            if score < best_score:
                best_score = score
                best_port = port
        
        return best_port

    def add_flow(self, datapath, priority, match, actions, idle=10):
        """
        Installe une règle de flux sur un switch OpenFlow.
        
        Args:
            datapath : Switch cible
            priority : Priorité de la règle
            match    : Critères de correspondance
            actions  : Actions à appliquer
            idle     : Timeout d'inactivité (10s par défaut pour le routage)
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            idle_timeout=idle, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Gestionnaire des paquets avec routage dynamique.
        
        Logique de routage :
        1. Si MAC destination connue -> port direct (table MAC)
        2. Si MAC destination inconnue -> sélection du meilleur port
           selon les métriques (score = perte + charge)
        3. Flood si aucune métrique disponible
        
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

        # Apprentissage MAC : enregistrement du port d'entrée
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            # MAC destination connue : routage direct
            out_port = self.mac_to_port[dpid][dst]
        else:
            # MAC destination inconnue : sélection du meilleur port
            all_ports = list(self.port_stats[dpid].keys())
            if all_ports:
                out_port = self._best_port(dpid, all_ports)
                if out_port is None:
                    out_port = ofproto.OFPP_FLOOD
            else:
                # Pas encore de métriques disponibles -> flood
                out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Installation d'une règle de flux si port connu
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)
            self.logger.info(
                'Route dynamique : switch %s port %s -> %s via port %s',
                dpid, in_port, dst, out_port)

        # Envoi du paquet actuel
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
