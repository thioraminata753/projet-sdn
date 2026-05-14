#!/usr/bin/env python3
"""
monitoring.py - Module de Surveillance du Trafic Réseau SDN
============================================================
Projet : Architecture SDN pour la Gestion Dynamique du Trafic et Sécurité Réseau
Auteur : Aminata Thior
Encadrant : Pr. Malick Ndoye
Université : Assane Seck de Ziguinchor - Master 1 Réseaux Avancés
Année : 2024-2025

Description :
    Ce module implémente la surveillance en temps réel des flux réseau
    via les compteurs OpenFlow (flow_stats et port_stats).
    
    Il collecte toutes les 5 secondes :
    - Les statistiques de flux (flow_stats) : priorité, src, dst, paquets, octets
    - Les statistiques de ports (port_stats) : rx/tx paquets et octets par port

Utilisation :
    ryu-manager monitoring.py
"""

# Imports du framework Ryu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub  # Threads légers Eventlet


class TrafficMonitor(app_manager.RyuApp):
    """
    Module de surveillance du trafic réseau SDN.
    
    Collecte périodiquement les statistiques OpenFlow de tous les switches
    connectés et les affiche dans les logs pour analyse et diagnostic.
    """
    
    # Version OpenFlow supportée
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """
        Initialisation du moniteur de trafic.
        
        Attributs :
            datapaths      : Switches connectés {dpid: datapath}
            monitor_thread : Thread de collecte périodique (toutes les 5s)
        """
        super(TrafficMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        # Démarrage du thread de monitoring périodique
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        Gestionnaire de changement d'état des switches.
        
        Met à jour le dictionnaire des switches actifs :
        - MAIN_DISPATCHER : switch connecté -> ajout
        - DEAD_DISPATCHER : switch déconnecté -> suppression
        
        Args:
            ev : Événement de changement d'état
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info('Switch connecte : %016x', datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info('Switch deconnecte : %016x', datapath.id)

    def _monitor(self):
        """
        Thread de monitoring périodique.
        
        Envoie des requêtes de statistiques à tous les switches
        connectés toutes les 5 secondes.
        """
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)  # Intervalle de collecte : 5 secondes

    def _request_stats(self, datapath):
        """
        Envoie les requêtes de statistiques à un switch.
        
        Demande deux types de statistiques :
        1. OFPFlowStatsRequest : statistiques par flux (règles de la table)
        2. OFPPortStatsRequest : statistiques par port physique
        
        Args:
            datapath : Switch cible pour les requêtes
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Requête des statistiques de flux (toutes les règles de la table)
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        
        # Requête des statistiques de ports (tous les ports : OFPP_ANY)
        req = parser.OFPPortStatsRequest(
            datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Gestionnaire des réponses de statistiques de flux.
        
        Affiche pour chaque règle de flux installée :
        - Priorité de la règle
        - Adresses MAC source et destination
        - Nombre de paquets traités
        - Nombre d'octets traités
        
        Args:
            ev : Événement OFPFlowStatsReply contenant les statistiques
        """
        body = ev.msg.body
        self.logger.info('=== STATS FLUX (switch %016x) ===',
                         ev.msg.datapath.id)
        self.logger.info('%8s %17s %17s %10s %10s',
                         'priorite', 'src', 'dst',
                         'paquets', 'octets')
        
        # Tri par priorité décroissante pour afficher les règles importantes en premier
        for stat in sorted(body,
                           key=lambda s: s.priority,
                           reverse=True):
            src = stat.match.get('eth_src', '*')
            dst = stat.match.get('eth_dst', '*')
            self.logger.info('%8d %17s %17s %10d %10d',
                             stat.priority, src, dst,
                             stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
        Gestionnaire des réponses de statistiques de ports.
        
        Affiche pour chaque port du switch :
        - Numéro de port
        - Paquets reçus (rx) et émis (tx)
        - Octets reçus (rx) et émis (tx)
        
        Ces statistiques permettent de surveiller la charge
        et détecter les liens saturés ou défaillants.
        
        Args:
            ev : Événement OFPPortStatsReply contenant les statistiques
        """
        body = ev.msg.body
        self.logger.info('=== STATS PORTS (switch %016x) ===',
                         ev.msg.datapath.id)
        self.logger.info('%8s %10s %10s %10s %10s',
                         'port', 'rx-pkts', 'rx-bytes',
                         'tx-pkts', 'tx-bytes')
        
        # Tri par numéro de port croissant
        for stat in sorted(body, key=lambda s: s.port_no):
            self.logger.info('%8d %10d %10d %10d %10d',
                             stat.port_no,
                             stat.rx_packets, stat.rx_bytes,
                             stat.tx_packets, stat.tx_bytes)
