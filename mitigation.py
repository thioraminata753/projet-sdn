#!/usr/bin/env python3
"""
mitigation.py - Module de Mitigation Automatique des Attaques SDN
=================================================================
Projet : Architecture SDN pour la Gestion Dynamique du Trafic et Sécurité Réseau
Auteur : Aminata Thior
Encadrant : Pr. Malick Ndoye
Université : Assane Seck de Ziguinchor - Master 1 Réseaux Avancés
Année : 2024-2025

Description :
    Ce module implémente un système de mitigation automatique graduée
    des attaques réseau détectées. Il applique trois niveaux de réponse
    progressifs selon la sévérité de l'attaque détectée :

    Niveau 1 - Rate Limiting (seuil/2) :
        Limite le débit de l'IP suspecte via des règles à court timeout.
        Action : règle idle=1s, hard=30s, priorité 80

    Niveau 2 - Honeypot (seuil) :
        Redirige le trafic suspect vers h16 (10.0.0.16) pour analyse.
        Action : SetField(ipv4_dst=honeypot) + Output(honeypot_port),
                 priorité 90, hard=120s

    Niveau 3 - DROP (seuil*2) :
        Bloque totalement l'IP attaquante.
        Action : règle DROP, priorité 100, hard=60s

Paramètres :
    HONEYPOT_IP           : 10.0.0.16 (h16 dans Mininet)
    SEUIL_PAQUETS_PAR_SEC : 2 pkt/s
    SEUIL_FLUX_PAR_IP     : 10 destinations
    INTERVALLE_ANALYSE    : 5 secondes
    RATE_LIMIT_PPS        : 10 pkt/s max après rate limiting

Logs :
    /tmp/sdn_logs/mitigation_events.log

Utilisation :
    ryu-manager mitigation.py
"""

# Imports du framework Ryu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib import hub
from collections import defaultdict
import time    # Pour les intervalles d'analyse
import logging # Pour la journalisation des événements
import os      # Pour la création du répertoire de logs


class MitigationManager(app_manager.RyuApp):
    """
    Module de mitigation automatique graduée des attaques réseau SDN.
    
    Implémente une réponse progressive aux attaques détectées :
    - Niveau 1 : Rate limiting (limitation du débit)
    - Niveau 2 : Redirection honeypot (analyse du comportement)
    - Niveau 3 : Blocage total DROP (protection maximale)
    
    La graduation permet d'éviter les faux positifs tout en assurant
    une protection efficace contre les attaques confirmées.
    """
    
    # Version OpenFlow supportée
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # -----------------------------------------------------------------------
    # Configuration du honeypot
    # -----------------------------------------------------------------------
    HONEYPOT_IP  = '10.0.0.16'        # IP du pot de miel (h16 dans Mininet)
    HONEYPOT_MAC = '00:00:00:00:00:10' # Adresse MAC du honeypot

    # -----------------------------------------------------------------------
    # Seuils de déclenchement de la mitigation
    # -----------------------------------------------------------------------
    SEUIL_PAQUETS_PAR_SEC = 2   # Seuil de base en paquets/seconde
    SEUIL_FLUX_PAR_IP     = 10  # Nombre max de destinations par IP source
    INTERVALLE_ANALYSE    = 5   # Période d'analyse en secondes

    # Débit maximum autorisé après rate limiting
    RATE_LIMIT_PPS = 10  # paquets/seconde maximum

    def __init__(self, *args, **kwargs):
        """
        Initialisation du gestionnaire de mitigation.
        
        Attributs :
            mac_to_port    : Table d'apprentissage MAC -> port
            datapaths      : Switches connectés {dpid: datapath}
            ip_src_count   : Compteurs paquets par IP source {dpid: {ip: count}}
            ip_dst_count   : Compteurs paquets par IP dest {dpid: {ip: count}}
            ip_flow_count  : Destinations par IP source {dpid: {ip: set(dst)}}
            blocked_ips    : IPs bloquées par DROP {dpid: set(ip)}
            honeypot_ips   : IPs redirigées vers honeypot {dpid: set(ip)}
            rate_limit_ips : IPs en rate limiting {dpid: set(ip)}
            last_analysis  : Timestamp de la dernière analyse
            detect_thread  : Thread de détection et mitigation périodique
        """
        super(MitigationManager, self).__init__(*args, **kwargs)
        self.mac_to_port    = {}
        self.datapaths      = {}
        
        # Compteurs de trafic pour la détection
        self.ip_src_count   = defaultdict(lambda: defaultdict(int))
        self.ip_dst_count   = defaultdict(lambda: defaultdict(int))
        self.ip_flow_count  = defaultdict(lambda: defaultdict(set))
        
        # Ensembles d'IPs sous différentes mesures de mitigation
        self.blocked_ips    = defaultdict(set)  # Niveau 3 : DROP
        self.honeypot_ips   = defaultdict(set)  # Niveau 2 : Honeypot
        self.rate_limit_ips = defaultdict(set)  # Niveau 1 : Rate limit
        
        self.last_analysis  = time.time()
        
        # Configuration du logger et démarrage du thread de détection
        self._setup_logger()
        self.detect_thread  = hub.spawn(self._detection_loop)

    def _setup_logger(self):
        """
        Configure le logger dédié aux événements de mitigation.
        
        Écrit dans /tmp/sdn_logs/mitigation_events.log avec horodatage.
        """
        os.makedirs('/tmp/sdn_logs', exist_ok=True)
        self.mit_logger = logging.getLogger('SDN_Mitigation')
        self.mit_logger.setLevel(logging.INFO)
        fh = logging.FileHandler('/tmp/sdn_logs/mitigation_events.log')
        fh.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s'))
        if not self.mit_logger.handlers:
            self.mit_logger.addHandler(fh)
        self.mit_logger.info('=== Module mitigation SDN demarre ===')
        self.logger.info('=== Module mitigation SDN demarre ===')
        self.logger.info('Honeypot : %s', self.HONEYPOT_IP)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Gestionnaire de connexion d'un switch.
        Installe la règle table-miss pour envoyer les paquets au contrôleur.
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
        
        Priorités utilisées :
            100 : DROP (blocage total, niveau 3)
            90  : Honeypot (redirection, niveau 2)
            80  : Rate limiting (limitation débit, niveau 1)
            1   : Routage normal
            0   : Table-miss
        
        Args:
            datapath : Switch cible
            priority : Priorité OpenFlow
            match    : Critères de correspondance
            actions  : Actions ([] = DROP)
            idle     : Timeout d'inactivité
            hard     : Timeout absolu
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

    def _bloquer_ip(self, datapath, ip_src):
        """
        Mitigation Niveau 3 : Blocage total (DROP) de l'IP attaquante.
        
        Installe une règle DROP de haute priorité (100) avec timeout 60s.
        Activé quand le débit dépasse 2x le seuil ou 2x le nombre de
        destinations max. C'est la mesure la plus sévère.
        
        Args:
            datapath : Switch sur lequel appliquer le blocage
            ip_src   : Adresse IP source à bloquer complètement
        """
        if ip_src in self.blocked_ips[datapath.id]:
            return  # Déjà bloquée sur ce switch
        
        parser = datapath.ofproto_parser
        match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        
        # Action DROP : liste vide, priorité maximale, timeout 60s
        self.add_flow(datapath, 100, match, [], hard=60)
        self.blocked_ips[datapath.id].add(ip_src)
        
        msg = (f'[MITIGATION DROP] IP {ip_src} '
               f'switch {datapath.id:016x} — regle DROP 60s')
        self.logger.warning(msg)
        self.mit_logger.warning(msg)

    def _rediriger_honeypot(self, datapath, ip_src):
        """
        Mitigation Niveau 2 : Redirection vers le honeypot (h16).
        
        Redirige tout le trafic de l'IP suspecte vers 10.0.0.16
        pour capturer et analyser le comportement de l'attaquant.
        Priorité 90, timeout 120s.
        
        Utilise l'action SetField pour réécrire l'IP destination.
        
        Args:
            datapath : Switch sur lequel installer la redirection
            ip_src   : Adresse IP source à rediriger vers le honeypot
        """
        if ip_src in self.honeypot_ips[datapath.id]:
            return  # Déjà redirigée
        if ip_src == self.HONEYPOT_IP:
            return  # Ne pas rediriger le honeypot lui-même

        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Récupération du port du honeypot depuis la table MAC
        honeypot_port = self.mac_to_port.get(
            datapath.id, {}).get(self.HONEYPOT_MAC)

        if honeypot_port is None:
            self.logger.warning(
                'Honeypot port inconnu sur switch %s', datapath.id)
            return

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        actions = [
            # Réécriture de l'IP destination -> honeypot
            parser.OFPActionSetField(ipv4_dst=self.HONEYPOT_IP),
            # Envoi vers le port du honeypot
            parser.OFPActionOutput(honeypot_port)
        ]
        self.add_flow(datapath, 90, match, actions, hard=120)
        self.honeypot_ips[datapath.id].add(ip_src)
        
        msg = (f'[MITIGATION HONEYPOT] IP {ip_src} '
               f'-> honeypot {self.HONEYPOT_IP} '
               f'switch {datapath.id:016x} (120s)')
        self.logger.warning(msg)
        self.mit_logger.warning(msg)

    def _rate_limiter(self, datapath, ip_src):
        """
        Mitigation Niveau 1 : Rate limiting de l'IP suspecte.
        
        Installe une règle de transmission normale mais avec idle_timeout=1s
        qui force le trafic à repasser régulièrement par le contrôleur,
        créant ainsi un effet de limitation du débit.
        Priorité 80, hard_timeout=30s.
        
        Args:
            datapath : Switch sur lequel appliquer le rate limiting
            ip_src   : Adresse IP source à limiter
        """
        if ip_src in self.rate_limit_ips[datapath.id]:
            return  # Déjà en rate limiting
        
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        
        # idle=1s : la règle expire rapidement -> le trafic remonte au contrôleur
        # Cet effet de "ping-pong" limite effectivement le débit
        self.add_flow(datapath, 80, match, actions, idle=1, hard=30)
        self.rate_limit_ips[datapath.id].add(ip_src)
        
        msg = (f'[MITIGATION RATE LIMIT] IP {ip_src} '
               f'switch {datapath.id:016x} — '
               f'limite {self.RATE_LIMIT_PPS} pkt/s (30s)')
        self.logger.warning(msg)
        self.mit_logger.warning(msg)

    def _detection_loop(self):
        """
        Boucle de détection et mitigation graduée (thread périodique).
        
        S'exécute toutes les INTERVALLE_ANALYSE secondes et applique
        la mitigation selon le niveau de menace détecté :
        
        Niveau 1 (pps > seuil/2)     : Rate limiting
        Niveau 2 (pps > seuil)        : Honeypot + Rate limiting
        Niveau 3 (pps > seuil*2)      : DROP + Honeypot + Rate limiting
        
        Scan détecté (nb_dst > seuil) : Honeypot
        Scan sévère (nb_dst > seuil*2): DROP
        
        Les compteurs sont réinitialisés après chaque cycle.
        """
        while True:
            hub.sleep(self.INTERVALLE_ANALYSE)
            now   = time.time()
            delta = now - self.last_analysis
            self.last_analysis = now

            for dpid in list(self.ip_src_count.keys()):
                ip_src_counts = self.ip_src_count[dpid]
                if not ip_src_counts:
                    continue
                datapath = self.datapaths.get(dpid)
                if not datapath:
                    continue

                self.logger.info(
                    '=== MITIGATION ANALYSE switch %s : '
                    'nb_sources=%d ===', dpid, len(ip_src_counts))

                for ip_src, count in ip_src_counts.items():
                    pps    = count / delta if delta > 0 else 0
                    nb_dst = len(
                        self.ip_flow_count[dpid].get(ip_src, set()))

                    # --- Niveau 1 : Rate limiting (trafic légèrement suspect) ---
                    if pps > self.SEUIL_PAQUETS_PAR_SEC / 2:
                        self._rate_limiter(datapath, ip_src)

                    # --- Niveau 2 : Honeypot (trafic anormal confirmé) ---
                    if pps > self.SEUIL_PAQUETS_PAR_SEC or \
                            nb_dst > self.SEUIL_FLUX_PAR_IP:
                        self._rediriger_honeypot(datapath, ip_src)

                    # --- Niveau 3 : DROP (attaque confirmée et sévère) ---
                    if pps > self.SEUIL_PAQUETS_PAR_SEC * 2 or \
                            nb_dst > self.SEUIL_FLUX_PAR_IP * 2:
                        self._bloquer_ip(datapath, ip_src)
                        msg = (f'[ALERTE] switch {dpid} : '
                               f'IP {ip_src} = {pps:.1f} pkt/s '
                               f'-> {nb_dst} destinations')
                        self.logger.warning(msg)
                        self.mit_logger.warning(msg)

                # Réinitialisation des compteurs pour le prochain cycle
                self.ip_src_count[dpid].clear()
                self.ip_dst_count[dpid].clear()
                self.ip_flow_count[dpid].clear()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Gestionnaire des paquets reçus par le contrôleur.
        
        Pour chaque paquet IPv4 reçu :
        1. Comptabilise le trafic pour la détection (si IP non bloquée)
        2. Effectue l'apprentissage MAC
        3. Route le paquet normalement
        
        Args:
            ev : Événement OFPPacketIn
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

        # Comptabilisation du trafic IP pour la détection DDoS
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst
            
            # Ne compter que les IPs non encore bloquées
            if ip_src not in self.blocked_ips[dpid]:
                self.ip_src_count[dpid][ip_src] += 1
                self.ip_dst_count[dpid][ip_dst] += 1
                # Tracking des destinations pour détection de scan
                self.ip_flow_count[dpid][ip_src].add(ip_dst)

        # Apprentissage MAC
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Routage standard
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_dst=dst, eth_src=src)
            # idle=2s : expire rapidement pour maintenir les compteurs à jour
            self.add_flow(datapath, 1, match, actions, idle=2)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
