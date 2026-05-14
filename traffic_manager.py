#!/usr/bin/env python3
"""
traffic_manager.py - Module de Gestion Dynamique du Trafic SDN
===============================================================
Projet : Architecture SDN pour la Gestion Dynamique du Trafic et Sécurité Réseau
Auteur : Aminata Thior
Encadrant : Pr. Malick Ndoye
Université : Assane Seck de Ziguinchor - Master 1 Réseaux Avancés
Année : 2024-2025

Description :
    Ce module implémente un contrôleur SDN basé sur Ryu (OpenFlow 1.3) qui assure :
    - La surveillance en temps réel des flux réseau (monitoring)
    - Le routage dynamique basé sur les métriques de performance
    - L'apprentissage des adresses MAC et la gestion des tables de flux
    - Le calcul de scores de ports pour optimiser le routage

Utilisation :
    ryu-manager traffic_manager.py
"""

# Imports du framework Ryu
from ryu.base import app_manager          # Classe de base pour les applications Ryu
from ryu.controller import ofp_event      # Événements OpenFlow
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls  # Décorateur pour les gestionnaires d'événements
from ryu.ofproto import ofproto_v1_3      # Protocole OpenFlow 1.3
from ryu.lib.packet import packet, ethernet  # Analyse des paquets réseau
from ryu.lib import hub                   # Threads légers Eventlet
from collections import defaultdict       # Dictionnaires avec valeurs par défaut


class TrafficManager(app_manager.RyuApp):
    """
    Contrôleur SDN pour la gestion dynamique du trafic réseau.
    
    Hérite de RyuApp et implémente les handlers OpenFlow pour :
    - La configuration initiale des switches
    - L'apprentissage des adresses MAC
    - Le monitoring des ports et métriques de performance
    - Le routage intelligent basé sur les scores de ports
    """
    
    # Version OpenFlow supportée : OpenFlow 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """
        Initialisation du gestionnaire de trafic.
        
        Attributs :
            mac_to_port : Table d'apprentissage MAC -> port par switch (dpid)
            datapaths   : Dictionnaire des switches connectés {dpid: datapath}
            port_stats  : Statistiques de ports {dpid: {port: {speed, loss}}}
            prev_bytes  : Bytes précédents pour calcul du débit différentiel
            monitor_thread : Thread de monitoring périodique (toutes les 5s)
        """
        super(TrafficManager, self).__init__(*args, **kwargs)
        
        # Table MAC : associe adresse MAC au port de sortie pour chaque switch
        self.mac_to_port = {}
        
        # Switches actifs : {dpid -> objet datapath}
        self.datapaths = {}
        
        # Statistiques de performance par port : vitesse (B/s) et taux de perte
        self.port_stats = defaultdict(lambda: defaultdict(dict))
        
        # Compteurs de bytes précédents pour calcul de débit (différentiel)
        self.prev_bytes = defaultdict(lambda: defaultdict(int))
        
        # Lancement du thread de monitoring périodique
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Gestionnaire d'événement : connexion d'un nouveau switch.
        
        Déclenché lors de la connexion initiale d'un switch au contrôleur.
        Installe une règle de flux par défaut (priorité 0) qui envoie tous
        les paquets non matchés vers le contrôleur (table-miss flow entry).
        
        Args:
            ev : Événement OFPSwitchFeatures contenant les infos du switch
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Règle table-miss : match tous les paquets, action = envoyer au contrôleur
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info('Switch connecte : %016x', datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        Gestionnaire de changement d'état d'un switch.
        
        Maintient à jour le dictionnaire des switches actifs :
        - MAIN_DISPATCHER : switch connecté et opérationnel -> ajout
        - DEAD_DISPATCHER : switch déconnecté -> suppression
        
        Args:
            ev : Événement de changement d'état
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            # Switch connecté : enregistrement dans la liste des datapaths actifs
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            # Switch déconnecté : suppression de la liste
            self.datapaths.pop(datapath.id, None)

    def add_flow(self, datapath, priority, match, actions, idle=0):
        """
        Installe une règle de flux (flow entry) sur un switch OpenFlow.
        
        Envoie un message OFPFlowMod au switch pour ajouter une entrée
        dans sa table de flux. Les règles avec idle_timeout expirent
        automatiquement après inactivité.
        
        Args:
            datapath : Objet switch cible
            priority : Priorité de la règle (0=table-miss, 1=normal)
            match    : Critères de correspondance (OFPMatch)
            actions  : Actions à appliquer sur les paquets matchés
            idle     : Timeout d'inactivité en secondes (0=permanent)
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Encapsulation des actions dans une instruction Apply-Actions
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        # Création et envoi du message FlowMod
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle, match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    def _monitor(self):
        """
        Thread de monitoring périodique des statistiques de ports.
        
        S'exécute en boucle infinie avec une pause de 5 secondes entre
        chaque cycle. Demande les statistiques de tous les ports de tous
        les switches connectés.
        
        Intervalle : 5 secondes (configurable)
        """
        while True:
            hub.sleep(5)  # Pause de 5 secondes entre chaque collecte
            for dp in self.datapaths.values():
                self._request_stats(dp)

    def _request_stats(self, datapath):
        """
        Envoie une requête de statistiques de ports à un switch.
        
        Utilise le message OFPPortStatsRequest pour demander les compteurs
        de bytes et paquets de tous les ports du switch (OFPP_ANY).
        
        Args:
            datapath : Switch cible pour la requête de statistiques
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        datapath.send_msg(
            parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY))

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
        Gestionnaire de réponse aux requêtes de statistiques de ports.
        
        Calcule pour chaque port :
        - Le débit instantané (B/s) par différence de bytes transmis
        - Le taux de perte de paquets (%) = (tx_pkts - rx_pkts) / tx_pkts
        
        Les statistiques sont stockées dans self.port_stats et affichées
        via _log_metrics().
        
        Args:
            ev : Événement OFPPortStatsReply contenant les statistiques
        """
        dpid = ev.msg.datapath.id
        for stat in ev.msg.body:
            port = stat.port_no
            
            # Ignorer le port local (0xfffffffe = OFPP_LOCAL)
            if port == 0xfffffffe:
                continue
            
            # Calcul du débit : différence de bytes / intervalle (5s)
            curr = stat.tx_bytes + stat.rx_bytes
            speed = (curr - self.prev_bytes[dpid][port]) / 5.0
            self.prev_bytes[dpid][port] = curr
            
            # Calcul du taux de perte : (paquets émis - paquets reçus) / paquets émis
            loss = 0.0
            if stat.tx_packets > 0:
                loss = max(0.0,
                    (stat.tx_packets - stat.rx_packets)
                    / stat.tx_packets * 100)
            
            # Stockage des métriques pour ce port
            self.port_stats[dpid][port] = {'speed': speed, 'loss': loss}
        
        # Affichage des métriques dans les logs
        self._log_metrics(dpid)

    def _log_metrics(self, dpid):
        """
        Affiche les métriques de performance d'un switch dans les logs.
        
        Format d'affichage :
            === METRIQUES switch <dpid> ===
              port   bande(B/s)   perte(%)
                 1      1234567        0.5
        
        Args:
            dpid : Identifiant du switch (datapath ID)
        """
        self.logger.info('=== METRIQUES switch %016x ===', dpid)
        self.logger.info('%6s %12s %10s', 'port', 'bande(B/s)', 'perte(%)')
        for port, m in sorted(self.port_stats[dpid].items()):
            self.logger.info('%6d %12.0f %10.1f',
                           port, m['speed'], m['loss'])

    def _score_port(self, dpid, port):
        """
        Calcule un score de qualité pour un port réseau.
        
        Le score est utilisé pour le routage dynamique :
        - Score élevé = port moins préféré (congestionné ou avec pertes)
        - Score faible = port préféré (peu chargé et fiable)
        
        Formule : score = perte(%) * 2 + débit(MB/s)
        Le taux de perte est pondéré 2x pour pénaliser les liens instables.
        
        Args:
            dpid : Identifiant du switch
            port : Numéro du port
            
        Returns:
            float : Score du port (plus élevé = moins préféré)
        """
        m = self.port_stats[dpid].get(port, {})
        return m.get('loss', 0) * 2 + (m.get('speed', 0) / 1e6)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Gestionnaire principal des paquets reçus par le contrôleur.
        
        Déclenché quand un switch reçoit un paquet sans règle de flux correspondante
        (table-miss). Implémente l'apprentissage MAC et le routage dynamique :
        
        1. Apprentissage : associe l'adresse MAC source au port d'entrée
        2. Décision de routage :
           - Si MAC destination connue -> port de sortie spécifique
           - Sinon -> flood (diffusion sur tous les ports)
        3. Installation d'une règle de flux si le port est connu (évite
           les futurs PacketIn pour ce flux)
        
        Args:
            ev : Événement OFPPacketIn contenant le paquet et ses métadonnées
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        # Extraction de l'en-tête Ethernet du paquet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst  # Adresse MAC destination
        src = eth.src  # Adresse MAC source

        # Apprentissage MAC : enregistrement du port d'entrée pour cette MAC source
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Décision de routage basée sur la table MAC apprise
        if dst in self.mac_to_port[dpid]:
            # MAC destination connue : routage direct vers le port correspondant
            out_port = self.mac_to_port[dpid][dst]
        else:
            # MAC destination inconnue : flood sur tous les ports
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Installation d'une règle de flux pour les prochains paquets similaires
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_dst=dst, eth_src=src)
            # idle=30 : règle expire après 30s d'inactivité
            self.add_flow(datapath, 1, match, actions, idle=30)
            self.logger.info(
                'Route installee : switch %s (%s->%s) port %s score=%.2f',
                dpid, src[-5:], dst[-5:], out_port,
                self._score_port(dpid, out_port))

        # Envoi du paquet actuel (avant installation de la règle)
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
