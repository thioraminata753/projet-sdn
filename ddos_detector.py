from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp
from ryu.lib import hub
from collections import defaultdict
import math
import time
import logging
import os

class DDoSDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    SEUIL_PAQUETS_PAR_SEC = 2
    SEUIL_ENTROPIE        = 0.5
    SEUIL_FLUX_PAR_IP     = 10
    INTERVALLE_ANALYSE    = 5

    def __init__(self, *args, **kwargs):
        super(DDoSDetector, self).__init__(*args, **kwargs)
        self.mac_to_port   = {}
        self.datapaths     = {}
        # Compteurs IP sources {dpid: {ip_src: count}}
        self.ip_src_count  = defaultdict(lambda: defaultdict(int))
        # Compteurs IP destinations {dpid: {ip_dst: count}}
        self.ip_dst_count  = defaultdict(lambda: defaultdict(int))
        # Flux par IP source {dpid: {ip_src: set(ip_dst)}}
        self.ip_flow_count = defaultdict(lambda: defaultdict(set))
        self.blocked_ips   = defaultdict(set)
        self.last_analysis = time.time()
        self._setup_logger()
        self.detect_thread = hub.spawn(self._detection_loop)

    def _setup_logger(self):
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

    def _block_ip(self, datapath, ip_src):
        if ip_src in self.blocked_ips[datapath.id]:
            return
        parser = datapath.ofproto_parser
        match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        self.add_flow(datapath, 100, match, [], hard=60)
        self.blocked_ips[datapath.id].add(ip_src)
        msg = (f'[MITIGATION] BLOCAGE IP {ip_src} '
               f'switch {datapath.id:016x} — regle DROP 60s')
        self.logger.warning(msg)
        self.sec_logger.warning(msg)

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

                # Entropie IP sources
                entropie_src = self._calcul_entropie(ip_src_counts)
                # Entropie IP destinations
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

                # Détection par taux de paquets par IP source
                for ip_src, count in ip_src_counts.items():
                    pps = count / delta if delta > 0 else 0
                    self.logger.info(
                        '  SRC %s : %d paquets = %.1f pkt/s',
                        ip_src, count, pps)

                    if pps > self.SEUIL_PAQUETS_PAR_SEC:
                        msg = (f'[ALERTE DDoS] switch {dpid} : '
                               f'IP {ip_src} = {pps:.0f} pkt/s '
                               f'> seuil {self.SEUIL_PAQUETS_PAR_SEC}')
                        self.logger.warning(msg)
                        self.sec_logger.warning(msg)
                        self._block_ip(datapath, ip_src)

                    nb_dst = len(
                        self.ip_flow_count[dpid].get(ip_src, set()))
                    if nb_dst > self.SEUIL_FLUX_PAR_IP:
                        msg = (f'[ALERTE SCAN] switch {dpid} : '
                               f'IP {ip_src} -> {nb_dst} destinations')
                        self.logger.warning(msg)
                        self.sec_logger.warning(msg)
                        self._block_ip(datapath, ip_src)

                # Détection entropie src faible (flood depuis peu d'IPs)
                if entropie_src < self.SEUIL_ENTROPIE and \
                        len(ip_src_counts) > 3:
                    top_ip = max(ip_src_counts, key=ip_src_counts.get)
                    msg = (f'[ALERTE DDoS] switch {dpid} : '
                           f'entropie_src faible {entropie_src:.3f} '
                           f'— IP dominante {top_ip}')
                    self.logger.warning(msg)
                    self.sec_logger.warning(msg)
                    self._block_ip(datapath, top_ip)

                # Détection entropie dst faible (flood vers peu de cibles)
                if entropie_dst < self.SEUIL_ENTROPIE and \
                        len(ip_dst_counts) > 3:
                    top_dst = max(ip_dst_counts, key=ip_dst_counts.get)
                    msg = (f'[ALERTE DDoS] switch {dpid} : '
                           f'entropie_dst faible {entropie_dst:.3f} '
                           f'— cible dominante {top_dst}')
                    self.logger.warning(msg)
                    self.sec_logger.warning(msg)

                # Réinitialiser les compteurs
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
