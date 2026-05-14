#!/usr/bin/env python3
"""
firewall.py - Module Pare-feu Stateful SDN
==========================================
Projet : Architecture SDN pour la Gestion Dynamique du Trafic et Sécurité Réseau
Auteur : Aminata Thior
Encadrant : Pr. Malick Ndoye
Université : Assane Seck de Ziguinchor - Master 1 Réseaux Avancés
Année : 2024-2025

Description :
    Ce module implémente un pare-feu stateful (avec suivi d'état des connexions)
    basé sur le contrôleur SDN Ryu (OpenFlow 1.3). Il intègre :

    - Des règles ACL (Access Control List) statiques configurables
    - Un suivi d'état des connexions TCP (SYN, ESTABLISHED, CLOSING)
    - Un blocage automatique des protocoles non sécurisés
    - Une journalisation des événements de sécurité

Règles ACL configurées :
    DENY  : Telnet (23), FTP (21), RPC (135), TFTP UDP (69)
    ALLOW : SSH (22), HTTP (80), HTTPS (443), iperf3 (5201), ICMP

États TCP suivis :
    SYN         : Connexion initiée (paquet SYN reçu)
    ESTABLISHED : Connexion établie (SYN-ACK reçu)
    CLOSING     : Connexion en cours de fermeture (FIN reçu)

Logs générés :
    /tmp/sdn_logs/firewall_events.log

Utilisation :
    ryu-manager firewall.py
"""

# Imports du framework Ryu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.lib import hub
from collections import defaultdict
import time    # Pour les timestamps des connexions
import logging # Pour la journalisation des événements
import os      # Pour la création du répertoire de logs


class StatefulFirewall(app_manager.RyuApp):
    """
    Pare-feu stateful SDN avec suivi des connexions TCP et règles ACL.
    
    Combine deux mécanismes de sécurité :
    1. Règles ACL statiques installées directement sur les switches OpenFlow
    2. Inspection stateful des paquets TCP avec suivi d'état des connexions
    """
    
    # Version OpenFlow supportée
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """
        Initialisation du pare-feu stateful.
        
        Attributs :
            mac_to_port     : Table d'apprentissage MAC -> port
            datapaths       : Switches connectés {dpid: datapath}
            connexions      : Table des connexions TCP actives
                              {(ip_src, ip_dst, port_src, port_dst):
                               {'state': état, 'time': timestamp}}
            acl_rules       : Liste des règles ACL (action, proto, port)
            cleanup_thread  : Thread de nettoyage des connexions expirées
        """
        super(StatefulFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths   = {}
        
        # Table des connexions TCP actives avec leur état
        # Clé : tuple (ip_src, ip_dst, port_src, port_dst)
        # Valeur : {'state': 'SYN'|'ESTABLISHED'|'CLOSING', 'time': timestamp}
        self.connexions  = {}
        
        # Liste des règles ACL chargées depuis _charger_acl()
        self.acl_rules   = []
        
        # Configuration du logger, chargement des ACL et démarrage du nettoyage
        self._setup_logger()
        self._charger_acl()
        self.cleanup_thread = hub.spawn(self._cleanup_connexions)

    def _setup_logger(self):
        """
        Configure le logger dédié aux événements du pare-feu.
        
        Écrit dans /tmp/sdn_logs/firewall_events.log avec horodatage.
        """
        os.makedirs('/tmp/sdn_logs', exist_ok=True)
        self.fw_logger = logging.getLogger('SDN_Firewall')
        self.fw_logger.setLevel(logging.INFO)
        fh = logging.FileHandler('/tmp/sdn_logs/firewall_events.log')
        fh.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s'))
        if not self.fw_logger.handlers:
            self.fw_logger.addHandler(fh)
        self.fw_logger.info('=== Pare-feu stateful SDN demarre ===')
        self.logger.info('=== Pare-feu stateful SDN demarre ===')

    def _charger_acl(self):
        """
        Charge et affiche les règles ACL du pare-feu.
        
        Les règles sont évaluées dans l'ordre, la première correspondance
        détermine l'action (DENY ou ALLOW).
        
        Format : (action, protocole, port_destination)
        - action  : 'DENY' ou 'ALLOW'
        - proto   : 'tcp', 'udp', 'icmp' ou None (tous)
        - port    : numéro de port ou None (tous ports)
        """
        self.acl_rules = [
            # --- Protocoles non sécurisés : BLOQUER ---
            ('DENY',  'tcp', 23),    # Telnet : connexion non chiffrée
            ('DENY',  'tcp', 21),    # FTP : transfert en clair
            ('DENY',  'tcp', 135),   # RPC : vecteur d'attaque Windows
            ('DENY',  'udp', 69),    # TFTP : pas d'authentification
            
            # --- Services légitimes : AUTORISER ---
            ('ALLOW', 'tcp', 22),    # SSH : accès distant sécurisé
            ('ALLOW', 'tcp', 80),    # HTTP : navigation web
            ('ALLOW', 'tcp', 443),   # HTTPS : navigation sécurisée
            ('ALLOW', 'tcp', 5201),  # iperf3 : tests de performance
            ('ALLOW', 'icmp', None), # ICMP : ping et diagnostics réseau
            
            # --- Règle par défaut : tout autoriser ---
            ('ALLOW', None,  None),
        ]
        self.logger.info('=== REGLES ACL PARE-FEU ===')
        for i, (action, proto, port) in enumerate(self.acl_rules):
            self.logger.info(
                '  Regle %d : %s proto=%s port=%s',
                i+1, action, proto or '*', port or '*')
            self.fw_logger.info(
                'ACL %d : %s proto=%s port=%s',
                i+1, action, proto or '*', port or '*')

    def _verifier_acl(self, proto, port_dst):
        """
        Vérifie si un paquet est autorisé selon les règles ACL.
        
        Parcourt les règles dans l'ordre et retourne l'action de la
        première règle correspondante.
        
        Args:
            proto    : Protocole du paquet ('tcp', 'udp', 'icmp')
            port_dst : Port de destination du paquet
            
        Returns:
            str : 'ALLOW' ou 'DENY'
        """
        for action, r_proto, r_port in self.acl_rules:
            # Vérification du protocole (None = tous les protocoles)
            if r_proto and r_proto != proto:
                continue
            # Vérification du port (None = tous les ports)
            if r_port and r_port != port_dst:
                continue
            return action
        return 'ALLOW'  # Politique par défaut : autoriser

    def _cleanup_connexions(self):
        """
        Thread de nettoyage périodique des connexions TCP expirées.
        
        Supprime les entrées de la table de connexions inactives depuis
        plus de 300 secondes (5 minutes). S'exécute toutes les 30 secondes.
        """
        while True:
            hub.sleep(30)  # Nettoyage toutes les 30 secondes
            now     = time.time()
            
            # Identifie les connexions expirées (inactives > 300s)
            expired = [k for k, v in self.connexions.items()
                      if now - v['time'] > 300]
            
            # Suppression des connexions expirées
            for k in expired:
                del self.connexions[k]
            
            if expired:
                self.logger.info(
                    'Firewall : %d connexions expirees nettoyees',
                    len(expired))
                self.fw_logger.info(
                    '%d connexions expirees nettoyees', len(expired))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Gestionnaire de connexion d'un switch.
        
        Installe la règle table-miss et les règles de blocage statiques
        (ACL Telnet, FTP, RPC, TFTP) directement sur le switch via FlowMod.
        """
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        match    = parser.OFPMatch()
        actions  = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        # Installation des règles ACL statiques de blocage
        self._installer_regles_blocage(datapath)
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
        
        Args:
            datapath : Switch cible
            priority : Priorité (50 pour ACL statiques, 1 pour routage normal)
            match    : Critères de correspondance
            actions  : Actions ([] = DROP pour blocage)
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

    def _installer_regles_blocage(self, datapath):
        """
        Installe les règles ACL de blocage statiques sur un switch.
        
        Ces règles sont installées à priorité 50 avec action DROP (liste
        d'actions vide). Elles bloquent les protocoles non sécurisés
        avant même que les paquets n'atteignent le contrôleur.
        
        Protocoles bloqués : Telnet(23), FTP(21), RPC(135), TFTP-UDP(69)
        
        Args:
            datapath : Switch sur lequel installer les règles
        """
        parser = datapath.ofproto_parser

        # Blocage Telnet (TCP port 23) - protocole non chiffré dangereux
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=23)
        self.add_flow(datapath, 50, match, [])
        self.logger.info(
            '[FW] switch %016x : BLOCAGE Telnet (TCP 23)', datapath.id)
        self.fw_logger.info('BLOCAGE Telnet switch %016x', datapath.id)

        # Blocage FTP (TCP port 21) - transfert de fichiers en clair
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=21)
        self.add_flow(datapath, 50, match, [])
        self.logger.info(
            '[FW] switch %016x : BLOCAGE FTP (TCP 21)', datapath.id)
        self.fw_logger.info('BLOCAGE FTP switch %016x', datapath.id)

        # Blocage RPC (TCP port 135) - vecteur d'attaque réseau Windows
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=135)
        self.add_flow(datapath, 50, match, [])
        self.logger.info(
            '[FW] switch %016x : BLOCAGE RPC (TCP 135)', datapath.id)

        # Blocage TFTP (UDP port 69) - protocole sans authentification
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=69)
        self.add_flow(datapath, 50, match, [])
        self.logger.info(
            '[FW] switch %016x : BLOCAGE TFTP (UDP 69)', datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Gestionnaire principal des paquets avec inspection stateful.
        
        Pour chaque paquet reçu, effectue :
        1. Inspection de la couche IP et transport (TCP/UDP/ICMP)
        2. Vérification ACL et suivi d'état TCP :
           - SYN     : nouvelle connexion -> vérification ACL
           - SYN-ACK : confirmation -> état ESTABLISHED
           - FIN     : fermeture -> état CLOSING
           - Données : vérification connexion établie
        3. Routage normal si paquet autorisé, DROP sinon
        
        États TCP gérés :
            SYN         -> connexion initiée
            ESTABLISHED -> connexion active
            CLOSING     -> fermeture en cours
        
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

        # Apprentissage MAC
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # --- Inspection stateful du paquet IP ---
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        allowed = True  # Par défaut : autoriser

        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst
            tcp_pkt  = pkt.get_protocol(tcp.tcp)
            udp_pkt  = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)

            if tcp_pkt:
                port_dst = tcp_pkt.dst_port
                port_src = tcp_pkt.src_port
                # Clés pour identifier la connexion dans les deux sens
                conn_key = (ip_src, ip_dst, port_src, port_dst)
                conn_rev = (ip_dst, ip_src, port_dst, port_src)

                # --- SYN : nouvelle connexion TCP ---
                if tcp_pkt.bits & 0x02 and not (tcp_pkt.bits & 0x10):
                    action = self._verifier_acl('tcp', port_dst)
                    if action == 'DENY':
                        allowed = False
                        msg_log = (f'[FW DENY] TCP {ip_src}:{port_src} '
                                   f'-> {ip_dst}:{port_dst} — BLOQUE')
                        self.logger.warning(msg_log)
                        self.fw_logger.warning(msg_log)
                    else:
                        # Enregistrement de la nouvelle connexion
                        self.connexions[conn_key] = {
                            'state': 'SYN', 'time': time.time()}
                        msg_log = (f'[FW ALLOW] TCP {ip_src}:{port_src} '
                                   f'-> {ip_dst}:{port_dst} — SYN autorise')
                        self.logger.info(msg_log)
                        self.fw_logger.info(msg_log)

                # --- SYN-ACK : connexion établie ---
                elif tcp_pkt.bits & 0x02 and tcp_pkt.bits & 0x10:
                    if conn_rev in self.connexions:
                        self.connexions[conn_rev]['state'] = 'ESTABLISHED'
                        self.connexions[conn_rev]['time']  = time.time()
                        msg_log = (f'[FW STATE] TCP {ip_src}:{port_src} '
                                   f'-> {ip_dst}:{port_dst} — ESTABLISHED')
                        self.logger.info(msg_log)
                        self.fw_logger.info(msg_log)

                # --- FIN : fermeture de connexion ---
                elif tcp_pkt.bits & 0x01:
                    for k in [conn_key, conn_rev]:
                        if k in self.connexions:
                            self.connexions[k]['state'] = 'CLOSING'
                            msg_log = (f'[FW STATE] TCP connexion '
                                       f'{ip_src} -> {ip_dst} — CLOSING')
                            self.logger.info(msg_log)
                            self.fw_logger.info(msg_log)

                # --- Paquet de données : vérifier connexion établie ---
                else:
                    if conn_key in self.connexions or \
                            conn_rev in self.connexions:
                        # Mise à jour du timestamp de la connexion active
                        for k in [conn_key, conn_rev]:
                            if k in self.connexions:
                                self.connexions[k]['time'] = time.time()
                    else:
                        # Paquet sans connexion établie -> vérifier ACL
                        action = self._verifier_acl('tcp', port_dst)
                        if action == 'DENY':
                            allowed = False

            elif udp_pkt:
                # --- Inspection UDP (stateless) ---
                port_dst = udp_pkt.dst_port
                action   = self._verifier_acl('udp', port_dst)
                if action == 'DENY':
                    allowed = False
                    msg_log = (f'[FW DENY] UDP {ip_src} '
                               f'-> {ip_dst}:{port_dst} — BLOQUE')
                    self.logger.warning(msg_log)
                    self.fw_logger.warning(msg_log)

            elif icmp_pkt:
                # --- Inspection ICMP ---
                action  = self._verifier_acl('icmp', None)
                allowed = (action == 'ALLOW')

        # --- Décision de routage ---
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        if allowed:
            # Paquet autorisé : routage normal
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 1, match, actions, idle=30)
        else:
            # Paquet refusé : DROP (liste d'actions vide)
            actions = []

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
