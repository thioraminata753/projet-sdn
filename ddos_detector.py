#!/usr/bin/env python3
"""
ddos_detector.py - Module de Détection et Mitigation des Attaques DDoS
=======================================================================
Projet : Architecture SDN pour la Gestion Dynamique du Trafic et Sécurité Réseau
Auteur : Aminata Thior
Encadrant : Pr. Malick Ndoye
Université : Assane Seck de Ziguinchor - Master 1 Réseaux Avancés
Année : 2024-2025

Description :
    Ce module implémente un système de détection et mitigation automatique
    des attaques DDoS basé sur l'analyse statistique du trafic réseau :
    
    - Calcul de l'entropie des adresses IP source/destination
    - Détection de seuils anormaux de paquets par seconde (pkt/s)
    - Détection de balayage de ports (port scan) par nombre de destinations
    - Mitigation automatique par insertion de règles DROP (60s)
    - Journalisation des événements de sécurité

Paramètres de détection :
    SEUIL_PAQUETS_PAR_SEC = 2   : Alerte si > 2 pkt/s par IP source
    SEUIL_ENTROPIE        = 0.5 : Alerte si entropie < 0.5 (trafic concentré)
    SEUIL_FLUX_PAR_IP     = 10  : Alerte si > 10 destinations par IP source
    INTERVALLE_ANALYSE    = 5   : Analyse toutes les 5 secondes

Logs générés :
    /tmp/sdn_logs/security_events.log

Utilisation :
    ryu-manager ddos_detector.py
"""

# Imports du framework Ryu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp
from ryu.lib import hub
from collections import defaultdict
import math    # Pour le calcul logarithmique de l'entropie
import time    # Pour les horodatages et intervalles d'analyse
import logging # Pour la journalisation des événements de sécurité
import os      # Pour la création du répertoire de logs


class DDoSDetector(app_manager.RyuApp):
    """
    Contrôleur SDN avec détection et mitigation automatique des attaques DDoS.
    
    Implémente une analyse statistique du trafic basée sur :
    1. L'entropie de Shannon des adresses IP source et destination
    2. Le taux de paquets par seconde par IP source
    3. Le nombre de destinations uniques par IP source (détection scan)
    """
    
    # Version OpenFlow supportée
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # -----------------------------------------------------------------------
    # Paramètres de détection DDoS (seuils configurables)
    # -----------------------------------------------------------------------
    SEUIL_PAQUETS_PAR_SEC = 2   # Seuil de paquets/sec par IP source
    SEUIL_ENTROPIE        = 0.5 # Seuil d'entropie normalisée (0=concentré, 1=uniforme)
    SEUIL_FLUX_PAR_IP     = 10  # Nombre max de destinations par IP (détection scan)
    INTERVALLE_ANALYSE    = 5   # Intervalle d'analyse en secondes

    def __init__(self, *args, **kwargs):
        """
        Initialisation du détecteur DDoS.
        
        Attributs :
            mac_to_port   : Table d'apprentissage MAC -> port
            datapaths     : Switches connectés {dpid: datapath}
            ip_src_count  : Compteurs de paquets par IP source {dpid: {ip: count}}
            ip_dst_count  : Compteurs de paquets par IP dest {dpid: {ip: count}}
            ip_flow_count : Destinations uniques par IP source {dpid: {ip: set}}
            blocked_ips   : IPs bloquées par switch {dpid: set(ip)}
            last_analysis : Timestamp de la dernière analyse
            detect_thread : Thread de détection périodique
        """
        super(DDoSDetector, self).__init__(*args, **kwargs)
        self.mac_to_port   = {}
        self.datapaths     = {}
        
        # Compteurs IP sources : {dpid: {ip_src: nb_paquets}}
        self.ip_src_count  = defaultdict(lambda: defaultdict(int))
        
        # Compteurs IP destinations : {dpid: {ip_dst: nb_paquets}}
        self.ip_dst_count  = defaultdict(lambda: defaultdict(int))
        
        # Flux par IP source : {dpid: {ip_src: set(ip_dst)}} pour détecter les scans
        self.ip_flow_count = defaultdict(lambda: defaultdict(set))
        
        # IPs bloquées par switch pour éviter les doublons de règles DROP
        self.blocked_ips   = defaultdict(set)
        
        # Timestamp de la dernière analyse pour calcul de l'intervalle réel
        self.last_analysis = time.time()
        
        # Configuration du logger de sécurité et démarrage du thread de détection
        self._setup_logger()
        self.detect_thread = hub.spawn(self._detection_loop)

    def _setup_logger(self):
        """
        Configure le système de journalisation des événements de sécurité.
        
        Crée un logger dédié qui écrit dans /tmp/sdn_logs/security_events.log
        en plus des logs standard de Ryu. Format : timestamp [niveau] message.
        """
        os.makedirs('/tmp/sdn_logs', exist_ok=True)
        self.sec_logger = logging.getLogger('SDN_Security')
        self.sec_logger.setLevel(logging.INFO)
        fh = logging.FileHandler('/tmp/sdn_logs/security_events.log')
        fh.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s'))
        if not self.sec_logger.handlers:
            self.sec_logger.addHandler(fh)
        self.sec_logger.info('=== Module securite SDN demarre ===')
        self.logger.info('=== Module securite SDN demarre ===')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Gestionnaire de connexion d'un switch.
        Installe la règle table-miss pour envoyer les paquets inconnus au contrôleur.
        """
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        match    = parser.OFPMatch()
        actions  = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info('Switch connecte : %016x', datapath.id)

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
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    def add_flow(self, datapath, priority, match, actions,
                 idle=0, hard=0):
        """
        Installe une règle de flux sur un switch OpenFlow.
        
        Args:
            datapath : Switch cible
            priority : Priorité de la règle (100 pour les règles de blocage DDoS)
            match    : Critères de correspondance
            actions  : Actions (vide [] = DROP pour les règles de blocage)
            idle     : Timeout d'inactivité en secondes
            hard     : Timeout absolu en secondes (60s pour les règles DDoS)
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            idle_timeout=idle, hard_timeout=hard,
            match=match, instructions=inst)
        datapath.send_msg(mod)

    def _calcul_entropie(self, compteurs):
        """
        Calcule l'entropie de Shannon normalisée d'une distribution de compteurs.
        
        L'entropie mesure la diversité du trafic :
        - Entropie = 1.0 : trafic uniformément distribué (normal)
        - Entropie ≈ 0.0 : trafic concentré sur peu d'IPs (suspect)
        
        Formule : H = -Σ(p_i * log2(p_i)) / log2(N)
        où p_i = proportion de chaque IP, N = nombre d'IPs distinctes
        
        Args:
            compteurs : dict {ip: nb_paquets}
            
        Returns:
            float : Entropie normalisée entre 0.0 et 1.0
        """
        total = sum(compteurs.values())
        if total == 0:
            return 1.0  # Pas de trafic = entropie maximale par convention
        
        entropie = 0.0
        for count in compteurs.values():
            p = count / total
            if p > 0:
                entropie -= p * math.log2(p)  # Formule de Shannon
        
        # Normalisation par log2(N) pour obtenir une valeur entre 0 et 1
        nb = len(compteurs)
        if nb > 1:
            entropie /= math.log2(nb)
        return entropie

    def _block_ip(self, datapath, ip_src):
        """
        Bloque une IP source suspecte par insertion d'une règle DROP.
        
        Installe une règle OpenFlow de haute priorité (100) avec action DROP
        et timeout de 60 secondes. Évite les doublons grâce à blocked_ips.
        
        Args:
            datapath : Switch sur lequel installer la règle de blocage
            ip_src   : Adresse IP source à bloquer
        """
        # Vérification : IP déjà bloquée sur ce switch ?
        if ip_src in self.blocked_ips[datapath.id]:
            return
        
        parser = datapath.ofproto_parser
        
        # Match sur l'IP source avec type Ethernet IPv4 (0x0800)
        match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        
        # Action vide = DROP, hard_timeout=60s (blocage temporaire)
        self.add_flow(datapath, 100, match, [], hard=60)
        self.blocked_ips[datapath.id].add(ip_src)
        
        msg = (f'[MITIGATION] BLOCAGE IP {ip_src} '
               f'switch {datapath.id:016x} — regle DROP 60s')
        self.logger.warning(msg)
        self.sec_logger.warning(msg)

    def _detection_loop(self):
        """
        Boucle principale de détection DDoS (thread périodique).
        
        S'exécute toutes les INTERVALLE_ANALYSE secondes et analyse
        les compteurs de trafic accumulés depuis la dernière analyse.
        
        Algorithmes de détection appliqués :
        1. Taux de paquets/sec par IP source > SEUIL_PAQUETS_PAR_SEC
        2. Nombre de destinations par IP > SEUIL_FLUX_PAR_IP (scan)
        3. Entropie source < SEUIL_ENTROPIE (flood concentré)
        4. Entropie destination < SEUIL_ENTROPIE (cible concentrée)
        
        En cas de détection : appel à _block_ip() pour mitigation automatique.
        Les compteurs sont réinitialisés après chaque analyse.
        """
        while True:
            hub.sleep(self.INTERVALLE_ANALYSE)
            now   = time.time()
            delta = now - self.last_analysis  # Intervalle réel écoulé
            self.last_analysis = now

            for dpid in list(self.ip_src_count.keys()):
                ip_src_counts = self.ip_src_count[dpid]
                ip_dst_counts = self.ip_dst_count[dpid]
                if not ip_src_counts:
                    continue
                datapath = self.datapaths.get(dpid)
                if not datapath:
                    continue

                # Calcul des entropies source et destination
                entropie_src = self._calcul_entropie(ip_src_counts)
                entropie_dst = self._calcul_entropie(ip_dst_counts)

                self.logger.info(
                    '=== ANALYSE switch %s : '
                    'entropie_src=%.3f entropie_dst=%.3f '
                    'nb_sources=%d nb_dest=%d intervalle=%.1fs ===',
                    dpid, entropie_src, entropie_dst,
                    len(ip_src_counts), len(ip_dst_counts), delta)
                self.sec_logger.info(
                    'ANALYSE switch %s entropie_src=%.3f '
                    'entropie_dst=%.3f sources=%d destinations=%d',
                    dpid, entropie_src, entropie_dst,
                    len(ip_src_counts), len(ip_dst_counts))

                # --- Détection 1 : Taux de paquets par IP source ---
                for ip_src, count in ip_src_counts.items():
                    pps = count / delta if delta > 0 else 0
                    self.logger.info(
                        '  SRC %s : %d paquets = %.1f pkt/s',
                        ip_src, count, pps)

                    # Alerte si débit > seuil configuré
                    if pps > self.SEUIL_PAQUETS_PAR_SEC:
                        msg = (f'[ALERTE DDoS] switch {dpid} : '
                               f'IP {ip_src} = {pps:.0f} pkt/s '
                               f'> seuil {self.SEUIL_PAQUETS_PAR_SEC}')
                        self.logger.warning(msg)
                        self.sec_logger.warning(msg)
                        self._block_ip(datapath, ip_src)

                    # --- Détection 2 : Scan de ports/destinations ---
                    nb_dst = len(
                        self.ip_flow_count[dpid].get(ip_src, set()))
                    if nb_dst > self.SEUIL_FLUX_PAR_IP:
                        msg = (f'[ALERTE SCAN] switch {dpid} : '
                               f'IP {ip_src} -> {nb_dst} destinations')
                        self.logger.warning(msg)
                        self.sec_logger.warning(msg)
                        self._block_ip(datapath, ip_src)

                # --- Détection 3 : Entropie source faible ---
                # (flood depuis peu d'IPs sources = trafic concentré)
                if entropie_src < self.SEUIL_ENTROPIE and \
                        len(ip_src_counts) > 3:
                    top_ip = max(ip_src_counts, key=ip_src_counts.get)
                    msg = (f'[ALERTE DDoS] switch {dpid} : '
                           f'entropie_src faible {entropie_src:.3f} '
                           f'— IP dominante {top_ip}')
                    self.logger.warning(msg)
                    self.sec_logger.warning(msg)
                    self._block_ip(datapath, top_ip)

                # --- Détection 4 : Entropie destination faible ---
                # (flood vers peu de cibles = attaque ciblée)
                if entropie_dst < self.SEUIL_ENTROPIE and \
                        len(ip_dst_counts) > 3:
                    top_dst = max(ip_dst_counts, key=ip_dst_counts.get)
                    msg = (f'[ALERTE DDoS] switch {dpid} : '
                           f'entropie_dst faible {entropie_dst:.3f} '
                           f'— cible dominante {top_dst}')
                    self.logger.warning(msg)
                    self.sec_logger.warning(msg)

                # Réinitialisation des compteurs pour le prochain intervalle
                self.ip_src_count[dpid].clear()
                self.ip_dst_count[dpid].clear()
                self.ip_flow_count[dpid].clear()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Gestionnaire des paquets reçus par le contrôleur.
        
        Pour chaque paquet IPv4 reçu :
        1. Vérifie si l'IP source est bloquée -> ignore si oui
        2. Incrémente les compteurs IP source, destination et flux
        3. Effectue l'apprentissage MAC et le routage normal
        
        Note : idle=2 pour forcer la remontée des paquets au contrôleur
        afin de maintenir les compteurs à jour pour la détection.
        
        Args:
            ev : Événement OFPPacketIn contenant le paquet
        """
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id
        in_port  = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        # Analyse de la couche IP pour la détection DDoS
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst
            
            # Ne comptabiliser que les IPs non bloquées
            if ip_src not in self.blocked_ips[dpid]:
                self.ip_src_count[dpid][ip_src] += 1
                self.ip_dst_count[dpid][ip_dst] += 1
                # Tracking des destinations pour détection de scan
                self.ip_flow_count[dpid][ip_src].add(ip_dst)

        # Apprentissage MAC et routage standard
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_dst=dst, eth_src=src)
            # idle=2 : règle expire après 2s pour forcer la remontée des paquets
            self.add_flow(datapath, 1, match, actions, idle=2)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
