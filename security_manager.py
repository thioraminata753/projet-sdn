#!/usr/bin/env python3
"""
security_manager.py - Module Unifié de Sécurité SDN
====================================================
Projet : Architecture SDN pour la Gestion Dynamique du Trafic et Sécurité Réseau
Auteur : Aminata Thior
Encadrant : Pr. Malick Ndoye
Université : Assane Seck de Ziguinchor - Master 1 Réseaux Avancés
Année : 2024-2025

Description :
    Module unifié combinant tous les mécanismes de sécurité SDN :

    1. Détection DDoS (entropie src/dst + paquets/sec + scan de ports)
    2. Mitigation automatique en 3 niveaux :
       - Rate limiting : limitation du débit (priorité 80, 30s)
       - Honeypot      : redirection vers pot de miel 10.0.0.16 (priorité 90, 120s)
       - DROP          : blocage total de l'IP (priorité 100, 60s)
    3. Pare-feu stateful : ACL + suivi connexions TCP
    4. Journalisation centralisée dans /tmp/sdn_logs/security_manager.log

Paramètres de détection :
    SEUIL_PAQUETS_PAR_SEC = 2   : Alerte si > 2 pkt/s par IP source
    SEUIL_ENTROPIE        = 0.5 : Alerte si entropie < 0.5
    SEUIL_FLUX_PAR_IP     = 10  : Alerte si > 10 destinations par IP
    INTERVALLE_ANALYSE    = 5   : Analyse toutes les 5 secondes

Honeypot :
    IP  : 10.0.0.16 (h16 dans la topologie Mininet)
    MAC : 00:00:00:00:00:10

Utilisation :
    ryu-manager security_manager.py
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
import math    # Calcul de l'entropie de Shannon
import time    # Timestamps pour les connexions et analyses
import logging # Journalisation des événements de sécurité
import os      # Création du répertoire de logs


class SecurityManager(app_manager.RyuApp):
    """
    Module unifié de sécurité SDN combinant détection DDoS,
    mitigation automatique et pare-feu stateful.
    
    Architecture de sécurité en couches :
    - Couche 1 : ACL statiques (Telnet, FTP, RPC, TFTP bloqués)
    - Couche 2 : Détection DDoS par analyse statistique (entropie + pkt/s)
    - Couche 3 : Mitigation graduée (rate limit -> honeypot -> DROP)
    - Couche 4 : Pare-feu stateful TCP (SYN/ESTABLISHED/CLOSING)
    """
    
    # Version OpenFlow supportée
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # -----------------------------------------------------------------------
    # Paramètres de détection DDoS
    # -----------------------------------------------------------------------
    SEUIL_PAQUETS_PAR_SEC = 2   # Seuil de déclenchement en paquets/seconde
    SEUIL_ENTROPIE        = 0.5 # Entropie normalisée minimale acceptable
    SEUIL_FLUX_PAR_IP     = 10  # Nombre max de destinations par IP source
    INTERVALLE_ANALYSE    = 5   # Période d'analyse en secondes

    # -----------------------------------------------------------------------
    # Configuration du honeypot
    # -----------------------------------------------------------------------
    HONEYPOT_IP  = '10.0.0.16'        # IP du pot de miel (h16 dans Mininet)
    HONEYPOT_MAC = '00:00:00:00:00:10' # MAC du pot de miel

    def __init__(self, *args, **kwargs):
        """
        Initialisation du gestionnaire de sécurité unifié.
        
        Attributs :
            mac_to_port    : Table d'apprentissage MAC -> port
            datapaths      : Switches connectés {dpid: datapath}
            ip_src_count   : Compteurs paquets par IP source {dpid: {ip: count}}
            ip_dst_count   : Compteurs paquets par IP dest {dpid: {ip: count}}
            ip_flow_count  : Destinations par IP source {dpid: {ip: set(dst)}}
            blocked_ips    : IPs bloquées (DROP) {dpid: set(ip)}
            honeypot_ips   : IPs redirigées vers honeypot {dpid: set(ip)}
            rate_limit_ips : IPs en rate limiting {dpid: set(ip)}
            last_analysis  : Timestamp de la dernière analyse DDoS
            connexions     : Table des connexions TCP actives
            acl_rules      : Règles ACL du pare-feu
            detect_thread  : Thread de détection DDoS périodique
            cleanup_thread : Thread de nettoyage des connexions expirées
        """
        super(SecurityManager, self).__init__(*args, **kwargs)
        self.mac_to_port    = {}
        self.datapaths      = {}
        
        # Compteurs pour la détection DDoS
        self.ip_src_count   = defaultdict(lambda: defaultdict(int))
        self.ip_dst_count   = defaultdict(lambda: defaultdict(int))
        self.ip_flow_count  = defaultdict(lambda: defaultdict(set))
        
        # IPs sous différentes mesures de mitigation
        self.blocked_ips    = defaultdict(set)  # DROP total
        self.honeypot_ips   = defaultdict(set)  # Redirection honeypot
        self.rate_limit_ips = defaultdict(set)  # Rate limiting
        
        self.last_analysis  = time.time()
        
        # Table des connexions TCP pour le pare-feu stateful
        self.connexions     = {}
        self.acl_rules      = []
        
        # Initialisation et démarrage des threads
        self._setup_logger()
        self._charger_acl()
        self.detect_thread  = hub.spawn(self._detection_loop)
        self.cleanup_thread = hub.spawn(self._cleanup_connexions)

    def _setup_logger(self):
        """
        Configure le système de journalisation centralisée.
        
        Tous les événements de sécurité (DDoS, firewall, mitigation)
        sont écrits dans /tmp/sdn_logs/security_manager.log.
        """
        os.makedirs('/tmp/sdn_logs', exist_ok=True)
        self.sec_logger = logging.getLogger('SDN_Security_Manager')
        self.sec_logger.setLevel(logging.INFO)
        fh = logging.FileHandler('/tmp/sdn_logs/security_manager.log')
        fh.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s'))
        if not self.sec_logger.handlers:
            self.sec_logger.addHandler(fh)
        self.sec_logger.info('=' * 50)
        self.sec_logger.info('=== Security Manager SDN demarre ===')
        self.sec_logger.info('=' * 50)
        self.logger.info('=== Security Manager SDN demarre ===')

    def _log(self, level, msg):
        """
        Logger centralisé pour tous les événements de sécurité.
        
        Écrit simultanément dans les logs Ryu et le fichier de sécurité.
        
        Args:
            level : Niveau de log ('WARNING' ou 'INFO')
            msg   : Message à journaliser
        """
        if level == 'WARNING':
            self.logger.warning(msg)
            self.sec_logger.warning(msg)
        else:
            self.logger.info(msg)
            self.sec_logger.info(msg)

    def _charger_acl(self):
        """
        Charge les règles ACL du pare-feu intégré.
        
        Protocoles bloqués : Telnet(23), FTP(21), RPC(135), TFTP-UDP(69)
        Protocoles autorisés : SSH(22), HTTP(80), HTTPS(443), iperf3(5201), ICMP
        """
        self.acl_rules = [
            # Protocoles non sécurisés -> DENY
            ('DENY',  'tcp',  23),   # Telnet
            ('DENY',  'tcp',  21),   # FTP
            ('DENY',  'tcp',  135),  # RPC
            ('DENY',  'udp',  69),   # TFTP
            # Services légitimes -> ALLOW
            ('ALLOW', 'tcp',  22),   # SSH
            ('ALLOW', 'tcp',  80),   # HTTP
            ('ALLOW', 'tcp',  443),  # HTTPS
            ('ALLOW', 'tcp',  5201), # iperf3
            ('ALLOW', 'icmp', None), # ICMP
            # Règle par défaut
            ('ALLOW', None,   None),
        ]
        self._log('INFO', '=== REGLES ACL PARE-FEU ===')
        for i, (action, proto, port) in enumerate(self.acl_rules):
            self._log('INFO',
                f'  ACL {i+1} : {action} proto={proto or "*"} '
                f'port={port or "*"}')

    def _verifier_acl(self, proto, port_dst):
        """
        Vérifie si un paquet est autorisé par les règles ACL.
        
        Args:
            proto    : Protocole ('tcp', 'udp', 'icmp')
            port_dst : Port de destination
            
        Returns:
            str : 'ALLOW' ou 'DENY'
        """
        for action, r_proto, r_port in self.acl_rules:
            if r_proto and r_proto != proto:
                continue
            if r_port and r_port != port_dst:
                continue
            return action
        return 'ALLOW'

    def _calcul_entropie(self, compteurs):
        """
        Calcule l'entropie de Shannon normalisée.
        
        Valeur proche de 0 = trafic concentré (suspect).
        Valeur proche de 1 = trafic uniforme (normal).
        
        Args:
            compteurs : dict {ip: nb_paquets}
            
        Returns:
            float : Entropie normalisée [0.0, 1.0]
        """
        total = sum(compteurs.values())
        if total == 0:
            return 1.0
        entropie = 0.0
        for count in compteurs.values():
            p = count / total
            if p > 0:
                entropie -= p * math.log2(p)
        nb = len(compteurs)
        if nb > 1:
            entropie /= math.log2(nb)
        return entropie

    def _bloquer_ip(self, datapath, ip_src):
        """
        Mitigation niveau 3 : Blocage total (DROP) d'une IP suspecte.
        
        Installe une règle DROP de haute priorité (100) avec timeout 60s.
        C'est la mesure la plus sévère, appliquée après rate limit et honeypot.
        
        Args:
            datapath : Switch cible
            ip_src   : IP source à bloquer
        """
        if ip_src in self.blocked_ips[datapath.id]:
            return
        parser = datapath.ofproto_parser
        match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        # Action vide = DROP, priorité 100, hard_timeout=60s
        self.add_flow(datapath, 100, match, [], hard=60)
        self.blocked_ips[datapath.id].add(ip_src)
        self._log('WARNING',
            f'[MITIGATION DROP] IP {ip_src} '
            f'switch {datapath.id:016x} — regle DROP 60s')

    def _rediriger_honeypot(self, datapath, ip_src):
        """
        Mitigation niveau 2 : Redirection vers le pot de miel (honeypot).
        
        Redirige le trafic suspect vers 10.0.0.16 (h16) pour analyse.
        Priorité 90, timeout 120s. Permet de capturer le comportement
        de l'attaquant sans impacter le réseau de production.
        
        Args:
            datapath : Switch cible
            ip_src   : IP source à rediriger
        """
        # Éviter de rediriger le honeypot lui-même ou une IP déjà redirigée
        if ip_src in self.honeypot_ips[datapath.id]:
            return
        if ip_src == self.HONEYPOT_IP:
            return
        
        parser = datapath.ofproto_parser
        honeypot_port = self.mac_to_port.get(
            datapath.id, {}).get(self.HONEYPOT_MAC)
        if honeypot_port is None:
            return  # Port honeypot non encore appris
        
        match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        actions = [
            # Réécriture de l'IP destination vers le honeypot
            parser.OFPActionSetField(ipv4_dst=self.HONEYPOT_IP),
            parser.OFPActionOutput(honeypot_port)]
        self.add_flow(datapath, 90, match, actions, hard=120)
        self.honeypot_ips[datapath.id].add(ip_src)
        self._log('WARNING',
            f'[MITIGATION HONEYPOT] IP {ip_src} '
            f'-> honeypot {self.HONEYPOT_IP} '
            f'switch {datapath.id:016x} (120s)')

    def _rate_limiter(self, datapath, ip_src):
        """
        Mitigation niveau 1 : Rate limiting d'une IP suspecte.
        
        Installe une règle de transmission normale mais avec une règle
        de flux à courte durée (idle=1s, hard=30s) qui force le trafic
        à repasser par le contrôleur régulièrement, limitant ainsi le débit.
        
        Args:
            datapath : Switch cible
            ip_src   : IP source à limiter
        """
        if ip_src in self.rate_limit_ips[datapath.id]:
            return
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        # idle=1s : règle expire rapidement -> limitation du débit
        self.add_flow(datapath, 80, match, actions, idle=1, hard=30)
        self.rate_limit_ips[datapath.id].add(ip_src)
        self._log('WARNING',
            f'[MITIGATION RATE LIMIT] IP {ip_src} '
            f'switch {datapath.id:016x} — limite 30s')

    def _cleanup_connexions(self):
        """
        Thread de nettoyage des connexions TCP expirées.
        Supprime les connexions inactives depuis plus de 300 secondes.
        S'exécute toutes les 30 secondes.
        """
        while True:
            hub.sleep(30)
            now     = time.time()
            expired = [k for k, v in self.connexions.items()
                      if now - v['time'] > 300]
            for k in expired:
                del self.connexions[k]
            if expired:
                self._log('INFO',
                    f'{len(expired)} connexions expirees nettoyees')

    def _detection_loop(self):
        """
        Boucle principale de détection DDoS (thread périodique).
        
        Analyse toutes les INTERVALLE_ANALYSE secondes les compteurs
        de trafic et applique la mitigation graduée en cas de détection :
        
        1. Détection par taux paquets/sec  -> rate limit + honeypot + DROP
        2. Détection par scan (nb dests)   -> DROP
        3. Détection par entropie src      -> DROP IP dominante
        4. Détection par entropie dst      -> alerte seulement
        
        Les compteurs sont réinitialisés après chaque cycle d'analyse.
        """
        while True:
            hub.sleep(self.INTERVALLE_ANALYSE)
            now   = time.time()
            delta = now - self.last_analysis
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

                self._log('INFO',
                    f'=== ANALYSE switch {dpid} : '
                    f'entropie_src={entropie_src:.3f} '
                    f'entropie_dst={entropie_dst:.3f} '
                    f'sources={len(ip_src_counts)} '
                    f'destinations={len(ip_dst_counts)} ===')

                # --- Détection 1 : Taux de paquets + scan de destinations ---
                for ip_src, count in ip_src_counts.items():
                    pps    = count / delta if delta > 0 else 0
                    nb_dst = len(
                        self.ip_flow_count[dpid].get(ip_src, set()))

                    # Alerte et mitigation graduée si débit excessif
                    if pps > self.SEUIL_PAQUETS_PAR_SEC:
                        self._log('WARNING',
                            f'[ALERTE DDoS] switch {dpid} : '
                            f'IP {ip_src} = {pps:.0f} pkt/s '
                            f'> seuil {self.SEUIL_PAQUETS_PAR_SEC}')
                        # Mitigation graduée : rate limit -> honeypot -> DROP
                        self._rate_limiter(datapath, ip_src)
                        self._rediriger_honeypot(datapath, ip_src)
                        self._bloquer_ip(datapath, ip_src)

                    # Alerte et blocage si trop de destinations (scan)
                    if nb_dst > self.SEUIL_FLUX_PAR_IP:
                        self._log('WARNING',
                            f'[ALERTE SCAN] switch {dpid} : '
                            f'IP {ip_src} -> {nb_dst} destinations')
                        self._bloquer_ip(datapath, ip_src)

                # --- Détection 2 : Entropie source faible (flood concentré) ---
                if entropie_src < self.SEUIL_ENTROPIE and \
                        len(ip_src_counts) > 3:
                    top_ip = max(ip_src_counts, key=ip_src_counts.get)
                    self._log('WARNING',
                        f'[ALERTE DDoS entropie_src] switch {dpid} : '
                        f'entropie={entropie_src:.3f} '
                        f'IP dominante={top_ip}')
                    self._bloquer_ip(datapath, top_ip)

                # --- Détection 3 : Entropie destination faible (cible unique) ---
                if entropie_dst < self.SEUIL_ENTROPIE and \
                        len(ip_dst_counts) > 3:
                    top_dst = max(ip_dst_counts, key=ip_dst_counts.get)
                    self._log('WARNING',
                        f'[ALERTE DDoS entropie_dst] switch {dpid} : '
                        f'entropie={entropie_dst:.3f} '
                        f'cible dominante={top_dst}')

                # Réinitialisation des compteurs pour le prochain cycle
                self.ip_src_count[dpid].clear()
                self.ip_dst_count[dpid].clear()
                self.ip_flow_count[dpid].clear()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Gestionnaire de connexion d'un switch.
        Installe la règle table-miss et les ACL statiques de blocage.
        """
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        match    = parser.OFPMatch()
        actions  = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self._installer_regles_blocage(datapath)
        self._log('INFO', f'Switch connecte : {datapath.id:016x}')

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
        Installe une règle de flux OpenFlow sur un switch.
        
        Args:
            datapath : Switch cible
            priority : Priorité (100=DROP DDoS, 90=honeypot, 80=rate limit,
                       50=ACL firewall, 1=routage normal, 0=table-miss)
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

    def _installer_regles_blocage(self, datapath):
        """
        Installe les règles ACL statiques de blocage sur un switch.
        
        Priorité 50 avec action DROP pour les protocoles non sécurisés.
        Ces règles sont permanentes (pas de timeout).
        """
        parser = datapath.ofproto_parser
        
        # Blocage Telnet TCP 23
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=23)
        self.add_flow(datapath, 50, match, [])
        self._log('INFO',
            f'[FW] switch {datapath.id:016x} : BLOCAGE Telnet TCP 23')
        
        # Blocage FTP TCP 21
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=21)
        self.add_flow(datapath, 50, match, [])
        self._log('INFO',
            f'[FW] switch {datapath.id:016x} : BLOCAGE FTP TCP 21')
        
        # Blocage RPC TCP 135
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=135)
        self.add_flow(datapath, 50, match, [])
        self._log('INFO',
            f'[FW] switch {datapath.id:016x} : BLOCAGE RPC TCP 135')
        
        # Blocage TFTP UDP 69
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=69)
        self.add_flow(datapath, 50, match, [])
        self._log('INFO',
            f'[FW] switch {datapath.id:016x} : BLOCAGE TFTP UDP 69')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Gestionnaire principal des paquets avec sécurité intégrée.
        
        Pipeline de traitement pour chaque paquet :
        1. Comptabilisation pour la détection DDoS (si IP non bloquée)
        2. Inspection pare-feu stateful TCP/UDP/ICMP
        3. Vérification ACL
        4. Routage si autorisé, DROP sinon
        
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

        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        allowed = True  # Autoriser par défaut

        if ip_pkt:
            ip_src   = ip_pkt.src
            ip_dst   = ip_pkt.dst
            tcp_pkt  = pkt.get_protocol(tcp.tcp)
            udp_pkt  = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)

            # Comptabilisation DDoS uniquement pour les IPs non bloquées
            if ip_src not in self.blocked_ips[dpid]:
                self.ip_src_count[dpid][ip_src] += 1
                self.ip_dst_count[dpid][ip_dst] += 1
                self.ip_flow_count[dpid][ip_src].add(ip_dst)

            # --- Inspection stateful TCP ---
            if tcp_pkt:
                port_dst = tcp_pkt.dst_port
                port_src = tcp_pkt.src_port
                conn_key = (ip_src, ip_dst, port_src, port_dst)
                conn_rev = (ip_dst, ip_src, port_dst, port_src)

                # SYN : nouvelle connexion -> vérifier ACL
                if tcp_pkt.bits & 0x02 and not (tcp_pkt.bits & 0x10):
                    action = self._verifier_acl('tcp', port_dst)
                    if action == 'DENY':
                        allowed = False
                        self._log('WARNING',
                            f'[FW DENY] TCP {ip_src}:{port_src} '
                            f'-> {ip_dst}:{port_dst} — BLOQUE')
                    else:
                        self.connexions[conn_key] = {
                            'state': 'SYN', 'time': time.time()}
                        self._log('INFO',
                            f'[FW ALLOW] TCP {ip_src}:{port_src} '
                            f'-> {ip_dst}:{port_dst} — SYN autorise')

                # SYN-ACK : connexion établie
                elif tcp_pkt.bits & 0x02 and tcp_pkt.bits & 0x10:
                    if conn_rev in self.connexions:
                        self.connexions[conn_rev]['state'] = 'ESTABLISHED'
                        self.connexions[conn_rev]['time']  = time.time()
                        self._log('INFO',
                            f'[FW STATE] TCP {ip_src} -> {ip_dst} '
                            f'— ESTABLISHED')

                # FIN : fermeture de connexion
                elif tcp_pkt.bits & 0x01:
                    for k in [conn_key, conn_rev]:
                        if k in self.connexions:
                            self.connexions[k]['state'] = 'CLOSING'
                            self._log('INFO',
                                f'[FW STATE] TCP {ip_src} -> {ip_dst} '
                                f'— CLOSING')

                # Données : vérifier connexion établie
                else:
                    if conn_key not in self.connexions and \
                            conn_rev not in self.connexions:
                        action = self._verifier_acl('tcp', port_dst)
                        if action == 'DENY':
                            allowed = False

            # --- Inspection UDP ---
            elif udp_pkt:
                port_dst = udp_pkt.dst_port
                action   = self._verifier_acl('udp', port_dst)
                if action == 'DENY':
                    allowed = False
                    self._log('WARNING',
                        f'[FW DENY] UDP {ip_src} '
                        f'-> {ip_dst}:{port_dst} — BLOQUE')

            # --- Inspection ICMP ---
            elif icmp_pkt:
                action  = self._verifier_acl('icmp', None)
                allowed = (action == 'ALLOW')

        # --- Décision finale de routage ---
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        if allowed:
            # Paquet autorisé : routage avec règle de flux (idle=2s)
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 1, match, actions, idle=2)
        else:
            # Paquet refusé : DROP
            actions = []

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
