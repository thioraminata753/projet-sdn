from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib import hub
from collections import defaultdict
import time
import logging
import os

class MitigationManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # IP du honeypot (h16 dans notre topologie)
    HONEYPOT_IP  = '10.0.0.16'
    HONEYPOT_MAC = '00:00:00:00:00:10'

    # Seuils pour déclencher la mitigation
    SEUIL_PAQUETS_PAR_SEC = 2
    SEUIL_FLUX_PAR_IP     = 10
    INTERVALLE_ANALYSE    = 5

    # Rate limiting : max paquets/sec autorisés après détection
    RATE_LIMIT_PPS = 10

    def __init__(self, *args, **kwargs):
        super(MitigationManager, self).__init__(*args, **kwargs)
        self.mac_to_port    = {}
        self.datapaths      = {}
        self.ip_src_count   = defaultdict(lambda: defaultdict(int))
        self.ip_dst_count   = defaultdict(lambda: defaultdict(int))
        self.ip_flow_count  = defaultdict(lambda: defaultdict(set))
        self.blocked_ips    = defaultdict(set)
        self.honeypot_ips   = defaultdict(set)
        self.rate_limit_ips = defaultdict(set)
        self.last_analysis  = time.time()
        self._setup_logger()
        self.detect_thread  = hub.spawn(self._detection_loop)

    def _setup_logger(self):
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

    def _bloquer_ip(self, datapath, ip_src):
        """Mitigation 1 : DROP — bloquer l'IP suspecte."""
        if ip_src in self.blocked_ips[datapath.id]:
            return
        parser = datapath.ofproto_parser
        match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        self.add_flow(datapath, 100, match, [], hard=60)
        self.blocked_ips[datapath.id].add(ip_src)
        msg = (f'[MITIGATION DROP] IP {ip_src} '
               f'switch {datapath.id:016x} — regle DROP 60s')
        self.logger.warning(msg)
        self.mit_logger.warning(msg)

    def _rediriger_honeypot(self, datapath, ip_src):
        """Mitigation 2 : HONEYPOT — rediriger vers h16."""
        if ip_src in self.honeypot_ips[datapath.id]:
            return
        if ip_src == self.HONEYPOT_IP:
            return

        parser   = datapath.ofproto_parser
        ofproto  = datapath.ofproto

        # Rediriger tout le trafic de ip_src vers le honeypot
        honeypot_port = self.mac_to_port.get(
            datapath.id, {}).get(self.HONEYPOT_MAC)

        if honeypot_port is None:
            self.logger.warning(
                'Honeypot port inconnu sur switch %s', datapath.id)
            return

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        actions = [
            parser.OFPActionSetField(ipv4_dst=self.HONEYPOT_IP),
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
        """Mitigation 3 : RATE LIMITING — limiter le débit."""
        if ip_src in self.rate_limit_ips[datapath.id]:
            return
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Installer règle avec priorité moyenne — laisse passer
        # mais avec idle_timeout court pour forcer réévaluation
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        # idle=1 force le paquet à remonter fréquemment = rate limiting
        self.add_flow(datapath, 80, match, actions, idle=1, hard=30)
        self.rate_limit_ips[datapath.id].add(ip_src)
        msg = (f'[MITIGATION RATE LIMIT] IP {ip_src} '
               f'switch {datapath.id:016x} — '
               f'limite {self.RATE_LIMIT_PPS} pkt/s (30s)')
        self.logger.warning(msg)
        self.mit_logger.warning(msg)

    def _detection_loop(self):
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

                    # Niveau 1 : Rate limiting (trafic suspect)
                    if pps > self.SEUIL_PAQUETS_PAR_SEC / 2:
                        self._rate_limiter(datapath, ip_src)

                    # Niveau 2 : Honeypot (trafic anormal)
                    if pps > self.SEUIL_PAQUETS_PAR_SEC or \
                            nb_dst > self.SEUIL_FLUX_PAR_IP:
                        self._rediriger_honeypot(datapath, ip_src)

                    # Niveau 3 : DROP (attaque confirmée)
                    if pps > self.SEUIL_PAQUETS_PAR_SEC * 2 or \
                            nb_dst > self.SEUIL_FLUX_PAR_IP * 2:
                        self._bloquer_ip(datapath, ip_src)
                        msg = (f'[ALERTE] switch {dpid} : '
                               f'IP {ip_src} = {pps:.1f} pkt/s '
                               f'-> {nb_dst} destinations')
                        self.logger.warning(msg)
                        self.mit_logger.warning(msg)

                self.ip_src_count[dpid].clear()
                self.ip_dst_count[dpid].clear()
                self.ip_flow_count[dpid].clear()

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

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst
            if ip_src not in self.blocked_ips[dpid]:
                self.ip_src_count[dpid][ip_src] += 1
                self.ip_dst_count[dpid][ip_dst] += 1
                self.ip_flow_count[dpid][ip_src].add(ip_dst)

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
            self.add_flow(datapath, 1, match, actions, idle=2)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
