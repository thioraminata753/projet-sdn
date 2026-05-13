from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.lib import hub
from collections import defaultdict
import time
import logging
import os

class StatefulFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StatefulFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths   = {}
        # Table des connexions actives
        # {(ip_src, ip_dst, port_src, port_dst): {'state': state, 'time': timestamp}}
        self.connexions  = {}
        # Règles ACL
        self.acl_rules   = []
        self._setup_logger()
        self._charger_acl()
        self.cleanup_thread = hub.spawn(self._cleanup_connexions)

    def _setup_logger(self):
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
        """Charger les règles ACL du pare-feu."""
        # Format : (action, proto, port_dst)
        # 'DENY' = bloquer, 'ALLOW' = autoriser
        self.acl_rules = [
            # Bloquer protocoles non sécurisés
            ('DENY',  'tcp', 23),    # Telnet
            ('DENY',  'tcp', 21),    # FTP
            ('DENY',  'tcp', 135),   # RPC
            ('DENY',  'udp', 69),    # TFTP
            # Autoriser services légitimes
            ('ALLOW', 'tcp', 22),    # SSH
            ('ALLOW', 'tcp', 80),    # HTTP
            ('ALLOW', 'tcp', 443),   # HTTPS
            ('ALLOW', 'tcp', 5201),  # iperf3
            ('ALLOW', 'icmp', None), # ICMP
            # Règle par défaut
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
        """Vérifier si un paquet est autorisé selon les ACL."""
        for action, r_proto, r_port in self.acl_rules:
            if r_proto and r_proto != proto:
                continue
            if r_port and r_port != port_dst:
                continue
            return action
        return 'ALLOW'

    def _cleanup_connexions(self):
        """Nettoyer les connexions expirées toutes les 30 secondes."""
        while True:
            hub.sleep(30)
            now     = time.time()
            expired = [k for k, v in self.connexions.items()
                      if now - v['time'] > 300]
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
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        match    = parser.OFPMatch()
        actions  = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self._installer_regles_blocage(datapath)
        self.logger.info('Switch connecte : %016x', datapath.id)

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
        """Installer les règles de blocage statiques sur le switch."""
        parser = datapath.ofproto_parser

        # Bloquer Telnet
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=23)
        self.add_flow(datapath, 50, match, [])
        self.logger.info(
            '[FW] switch %016x : BLOCAGE Telnet (TCP 23)', datapath.id)
        self.fw_logger.info(
            'BLOCAGE Telnet switch %016x', datapath.id)

        # Bloquer FTP
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=21)
        self.add_flow(datapath, 50, match, [])
        self.logger.info(
            '[FW] switch %016x : BLOCAGE FTP (TCP 21)', datapath.id)
        self.fw_logger.info(
            'BLOCAGE FTP switch %016x', datapath.id)

        # Bloquer RPC
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=135)
        self.add_flow(datapath, 50, match, [])
        self.logger.info(
            '[FW] switch %016x : BLOCAGE RPC (TCP 135)', datapath.id)

        # Bloquer TFTP
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=69)
        self.add_flow(datapath, 50, match, [])
        self.logger.info(
            '[FW] switch %016x : BLOCAGE TFTP (UDP 69)', datapath.id)

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

        # Analyse firewall stateful
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        allowed = True

        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst
            tcp_pkt  = pkt.get_protocol(tcp.tcp)
            udp_pkt  = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)

            if tcp_pkt:
                port_dst = tcp_pkt.dst_port
                port_src = tcp_pkt.src_port
                conn_key = (ip_src, ip_dst, port_src, port_dst)
                conn_rev = (ip_dst, ip_src, port_dst, port_src)

                # SYN — nouvelle connexion
                if tcp_pkt.bits & 0x02 and not (tcp_pkt.bits & 0x10):
                    action = self._verifier_acl('tcp', port_dst)
                    if action == 'DENY':
                        allowed = False
                        msg_log = (f'[FW DENY] TCP {ip_src}:{port_src} '
                                   f'-> {ip_dst}:{port_dst} — BLOQUE')
                        self.logger.warning(msg_log)
                        self.fw_logger.warning(msg_log)
                    else:
                        self.connexions[conn_key] = {
                            'state': 'SYN', 'time': time.time()}
                        msg_log = (f'[FW ALLOW] TCP {ip_src}:{port_src} '
                                   f'-> {ip_dst}:{port_dst} — SYN autorise')
                        self.logger.info(msg_log)
                        self.fw_logger.info(msg_log)

                # SYN-ACK — connexion établie
                elif tcp_pkt.bits & 0x02 and tcp_pkt.bits & 0x10:
                    if conn_rev in self.connexions:
                        self.connexions[conn_rev]['state'] = 'ESTABLISHED'
                        self.connexions[conn_rev]['time']  = time.time()
                        msg_log = (f'[FW STATE] TCP {ip_src}:{port_src} '
                                   f'-> {ip_dst}:{port_dst} — ESTABLISHED')
                        self.logger.info(msg_log)
                        self.fw_logger.info(msg_log)

                # FIN — fermeture connexion
                elif tcp_pkt.bits & 0x01:
                    for k in [conn_key, conn_rev]:
                        if k in self.connexions:
                            self.connexions[k]['state'] = 'CLOSING'
                            msg_log = (f'[FW STATE] TCP connexion '
                                       f'{ip_src} -> {ip_dst} — CLOSING')
                            self.logger.info(msg_log)
                            self.fw_logger.info(msg_log)

                # Paquet dans connexion établie
                else:
                    if conn_key in self.connexions or \
                            conn_rev in self.connexions:
                        for k in [conn_key, conn_rev]:
                            if k in self.connexions:
                                self.connexions[k]['time'] = time.time()
                    else:
                        # Paquet sans connexion établie
                        action = self._verifier_acl('tcp', port_dst)
                        if action == 'DENY':
                            allowed = False

            elif udp_pkt:
                port_dst = udp_pkt.dst_port
                action   = self._verifier_acl('udp', port_dst)
                if action == 'DENY':
                    allowed = False
                    msg_log = (f'[FW DENY] UDP {ip_src} '
                               f'-> {ip_dst}:{port_dst} — BLOQUE')
                    self.logger.warning(msg_log)
                    self.fw_logger.warning(msg_log)

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
                self.add_flow(datapath, 1, match, actions, idle=30)
        else:
            actions = []

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
