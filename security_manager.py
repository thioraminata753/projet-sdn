from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.lib import hub
from collections import defaultdict
import math
import time
import logging
import os

class SecurityManager(app_manager.RyuApp):
    """
    Module unifie de securite SDN :
    - Detection DDoS (entropie src/dst + paquets/sec)
    - Mitigation automatique (DROP + honeypot + rate limiting)
    - Pare-feu stateful (ACL + suivi connexions TCP)
    - Journalisation centralisee des evenements de securite
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Parametres DDoS
    SEUIL_PAQUETS_PAR_SEC = 2
    SEUIL_ENTROPIE        = 0.5
    SEUIL_FLUX_PAR_IP     = 10
    INTERVALLE_ANALYSE    = 5

    # Honeypot
    HONEYPOT_IP  = '10.0.0.16'
    HONEYPOT_MAC = '00:00:00:00:00:10'

    def __init__(self, *args, **kwargs):
        super(SecurityManager, self).__init__(*args, **kwargs)
        self.mac_to_port    = {}
        self.datapaths      = {}
        self.ip_src_count   = defaultdict(lambda: defaultdict(int))
        self.ip_dst_count   = defaultdict(lambda: defaultdict(int))
        self.ip_flow_count  = defaultdict(lambda: defaultdict(set))
        self.blocked_ips    = defaultdict(set)
        self.honeypot_ips   = defaultdict(set)
        self.rate_limit_ips = defaultdict(set)
        self.last_analysis  = time.time()
        self.connexions     = {}
        self.acl_rules      = []
        self._setup_logger()
        self._charger_acl()
        self.detect_thread  = hub.spawn(self._detection_loop)
        self.cleanup_thread = hub.spawn(self._cleanup_connexions)

    def _setup_logger(self):
        """Journalisation centralisee de tous les evenements de securite."""
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
        """Logger centralisé pour tous les événements."""
        if level == 'WARNING':
            self.logger.warning(msg)
            self.sec_logger.warning(msg)
        else:
            self.logger.info(msg)
            self.sec_logger.info(msg)

    def _charger_acl(self):
        self.acl_rules = [
            ('DENY',  'tcp',  23),
            ('DENY',  'tcp',  21),
            ('DENY',  'tcp',  135),
            ('DENY',  'udp',  69),
            ('ALLOW', 'tcp',  22),
            ('ALLOW', 'tcp',  80),
            ('ALLOW', 'tcp',  443),
            ('ALLOW', 'tcp',  5201),
            ('ALLOW', 'icmp', None),
            ('ALLOW', None,   None),
        ]
        self._log('INFO', '=== REGLES ACL PARE-FEU ===')
        for i, (action, proto, port) in enumerate(self.acl_rules):
            self._log('INFO',
                f'  ACL {i+1} : {action} proto={proto or "*"} '
                f'port={port or "*"}')

    def _verifier_acl(self, proto, port_dst):
        for action, r_proto, r_port in self.acl_rules:
            if r_proto and r_proto != proto:
                continue
            if r_port and r_port != port_dst:
                continue
            return action
        return 'ALLOW'

    def _calcul_entropie(self, compteurs):
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
        if ip_src in self.blocked_ips[datapath.id]:
            return
        parser = datapath.ofproto_parser
        match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        self.add_flow(datapath, 100, match, [], hard=60)
        self.blocked_ips[datapath.id].add(ip_src)
        self._log('WARNING',
            f'[MITIGATION DROP] IP {ip_src} '
            f'switch {datapath.id:016x} — regle DROP 60s')

    def _rediriger_honeypot(self, datapath, ip_src):
        if ip_src in self.honeypot_ips[datapath.id]:
            return
        if ip_src == self.HONEYPOT_IP:
            return
        parser = datapath.ofproto_parser
        honeypot_port = self.mac_to_port.get(
            datapath.id, {}).get(self.HONEYPOT_MAC)
        if honeypot_port is None:
            return
        match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        actions = [
            parser.OFPActionSetField(ipv4_dst=self.HONEYPOT_IP),
            parser.OFPActionOutput(honeypot_port)]
        self.add_flow(datapath, 90, match, actions, hard=120)
        self.honeypot_ips[datapath.id].add(ip_src)
        self._log('WARNING',
            f'[MITIGATION HONEYPOT] IP {ip_src} '
            f'-> honeypot {self.HONEYPOT_IP} '
            f'switch {datapath.id:016x} (120s)')

    def _rate_limiter(self, datapath, ip_src):
        if ip_src in self.rate_limit_ips[datapath.id]:
            return
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 80, match, actions, idle=1, hard=30)
        self.rate_limit_ips[datapath.id].add(ip_src)
        self._log('WARNING',
            f'[MITIGATION RATE LIMIT] IP {ip_src} '
            f'switch {datapath.id:016x} — limite 30s')

    def _cleanup_connexions(self):
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

                entropie_src = self._calcul_entropie(ip_src_counts)
                entropie_dst = self._calcul_entropie(ip_dst_counts)

                self._log('INFO',
                    f'=== ANALYSE switch {dpid} : '
                    f'entropie_src={entropie_src:.3f} '
                    f'entropie_dst={entropie_dst:.3f} '
                    f'sources={len(ip_src_counts)} '
                    f'destinations={len(ip_dst_counts)} ===')

                for ip_src, count in ip_src_counts.items():
                    pps    = count / delta if delta > 0 else 0
                    nb_dst = len(
                        self.ip_flow_count[dpid].get(ip_src, set()))

                    if pps > self.SEUIL_PAQUETS_PAR_SEC:
                        self._log('WARNING',
                            f'[ALERTE DDoS] switch {dpid} : '
                            f'IP {ip_src} = {pps:.0f} pkt/s '
                            f'> seuil {self.SEUIL_PAQUETS_PAR_SEC}')
                        self._rate_limiter(datapath, ip_src)
                        self._rediriger_honeypot(datapath, ip_src)
                        self._bloquer_ip(datapath, ip_src)

                    if nb_dst > self.SEUIL_FLUX_PAR_IP:
                        self._log('WARNING',
                            f'[ALERTE SCAN] switch {dpid} : '
                            f'IP {ip_src} -> {nb_dst} destinations')
                        self._bloquer_ip(datapath, ip_src)

                if entropie_src < self.SEUIL_ENTROPIE and \
                        len(ip_src_counts) > 3:
                    top_ip = max(ip_src_counts, key=ip_src_counts.get)
                    self._log('WARNING',
                        f'[ALERTE DDoS entropie_src] switch {dpid} : '
                        f'entropie={entropie_src:.3f} '
                        f'IP dominante={top_ip}')
                    self._bloquer_ip(datapath, top_ip)

                if entropie_dst < self.SEUIL_ENTROPIE and \
                        len(ip_dst_counts) > 3:
                    top_dst = max(ip_dst_counts, key=ip_dst_counts.get)
                    self._log('WARNING',
                        f'[ALERTE DDoS entropie_dst] switch {dpid} : '
                        f'entropie={entropie_dst:.3f} '
                        f'cible dominante={top_dst}')

                self.ip_src_count[dpid].clear()
                self.ip_dst_count[dpid].clear()
                self.ip_flow_count[dpid].clear()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
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
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    def add_flow(self, datapath, priority, match, actions,
                 idle=0, hard=0):
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
        parser = datapath.ofproto_parser
        # Telnet
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=23)
        self.add_flow(datapath, 50, match, [])
        self._log('INFO',
            f'[FW] switch {datapath.id:016x} : BLOCAGE Telnet TCP 23')
        # FTP
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=21)
        self.add_flow(datapath, 50, match, [])
        self._log('INFO',
            f'[FW] switch {datapath.id:016x} : BLOCAGE FTP TCP 21')
        # RPC
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=135)
        self.add_flow(datapath, 50, match, [])
        self._log('INFO',
            f'[FW] switch {datapath.id:016x} : BLOCAGE RPC TCP 135')
        # TFTP
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=69)
        self.add_flow(datapath, 50, match, [])
        self._log('INFO',
            f'[FW] switch {datapath.id:016x} : BLOCAGE TFTP UDP 69')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        allowed = True

        if ip_pkt:
            ip_src   = ip_pkt.src
            ip_dst   = ip_pkt.dst
            tcp_pkt  = pkt.get_protocol(tcp.tcp)
            udp_pkt  = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)

            if ip_src not in self.blocked_ips[dpid]:
                self.ip_src_count[dpid][ip_src] += 1
                self.ip_dst_count[dpid][ip_dst] += 1
                self.ip_flow_count[dpid][ip_src].add(ip_dst)

            if tcp_pkt:
                port_dst = tcp_pkt.dst_port
                port_src = tcp_pkt.src_port
                conn_key = (ip_src, ip_dst, port_src, port_dst)
                conn_rev = (ip_dst, ip_src, port_dst, port_src)

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

                elif tcp_pkt.bits & 0x02 and tcp_pkt.bits & 0x10:
                    if conn_rev in self.connexions:
                        self.connexions[conn_rev]['state'] = 'ESTABLISHED'
                        self.connexions[conn_rev]['time']  = time.time()
                        self._log('INFO',
                            f'[FW STATE] TCP {ip_src} -> {ip_dst} '
                            f'— ESTABLISHED')

                elif tcp_pkt.bits & 0x01:
                    for k in [conn_key, conn_rev]:
                        if k in self.connexions:
                            self.connexions[k]['state'] = 'CLOSING'
                            self._log('INFO',
                                f'[FW STATE] TCP {ip_src} -> {ip_dst} '
                                f'— CLOSING')

                else:
                    if conn_key not in self.connexions and \
                            conn_rev not in self.connexions:
                        action = self._verifier_acl('tcp', port_dst)
                        if action == 'DENY':
                            allowed = False

            elif udp_pkt:
                port_dst = udp_pkt.dst_port
                action   = self._verifier_acl('udp', port_dst)
                if action == 'DENY':
                    allowed = False
                    self._log('WARNING',
                        f'[FW DENY] UDP {ip_src} '
                        f'-> {ip_dst}:{port_dst} — BLOQUE')

            elif icmp_pkt:
                action  = self._verifier_acl('icmp', None)
                allowed = (action == 'ALLOW')

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        if allowed:
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 1, match, actions, idle=2)
        else:
            actions = []

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
