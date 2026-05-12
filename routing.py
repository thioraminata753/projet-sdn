from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, arp
from collections import defaultdict

class DynamicRouting(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicRouting, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        # Métriques réseau par switch : {dpid: {port: {bw, latency, loss}}}
        self.port_stats = defaultdict(lambda: defaultdict(dict))
        self.port_speed = defaultdict(lambda: defaultdict(float))
        self.prev_bytes = defaultdict(lambda: defaultdict(int))
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info('Switch connecte : %016x', datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        for stat in ev.msg.body:
            port = stat.port_no
            if port == 0xfffffffe:
                continue
            # Calculer la bande passante (bytes/sec)
            curr_bytes = stat.tx_bytes + stat.rx_bytes
            prev = self.prev_bytes[dpid][port]
            speed = (curr_bytes - prev) / 5.0  # bytes/sec sur 5s
            self.prev_bytes[dpid][port] = curr_bytes
            self.port_speed[dpid][port] = speed
            # Calculer le taux de perte
            tx = stat.tx_packets
            rx = stat.rx_packets
            loss = 0.0
            if tx > 0:
                loss = max(0.0, (tx - rx) / tx * 100)
            self.port_stats[dpid][port] = {
                'speed': speed,
                'loss': loss,
                'rx_pkts': rx,
                'tx_pkts': tx
            }
        self._log_metrics(dpid)

    def _log_metrics(self, dpid):
        self.logger.info('=== METRIQUES RESEAU (switch %016x) ===', dpid)
        self.logger.info('%6s %12s %10s', 'port', 'bande(B/s)', 'perte(%)')
        for port, metrics in sorted(self.port_stats[dpid].items()):
            self.logger.info('%6d %12.1f %10.2f',
                           port,
                           metrics.get('speed', 0),
                           metrics.get('loss', 0))

    def _best_port(self, dpid, available_ports):
        """Choisit le meilleur port selon bande passante et taux de perte."""
        best_port = None
        best_score = float('inf')
        for port in available_ports:
            metrics = self.port_stats[dpid].get(port, {})
            speed = metrics.get('speed', 0)
            loss = metrics.get('loss', 0)
            # Score = perte + charge normalisée (plus bas = meilleur)
            score = loss + (speed / 1e6)
            if score < best_score:
                best_score = score
                best_port = port
        return best_port

    def add_flow(self, datapath, priority, match, actions, idle=10):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            idle_timeout=idle, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # Choisir le meilleur port disponible
            all_ports = list(self.port_stats[dpid].keys())
            if all_ports:
                out_port = self._best_port(dpid, all_ports)
                if out_port is None:
                    out_port = ofproto.OFPP_FLOOD
            else:
                out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)
            self.logger.info('Route dynamique : switch %s port %s -> %s via port %s',
                           dpid, in_port, dst, out_port)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
