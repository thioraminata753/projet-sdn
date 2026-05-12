from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

class TrafficMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
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
                self.logger.info('Switch deconnecte : %016x', datapath.id)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(
            datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('=== STATS FLUX (switch %016x) ===',
                         ev.msg.datapath.id)
        self.logger.info('%8s %17s %17s %10s %10s',
                         'priorite', 'src', 'dst',
                         'paquets', 'octets')
        for stat in sorted(body,
                           key=lambda s: s.priority,
                           reverse=True):
            src = stat.match.get('eth_src', '*')
            dst = stat.match.get('eth_dst', '*')
            self.logger.info('%8d %17s %17s %10d %10d',
                             stat.priority, src, dst,
                             stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('=== STATS PORTS (switch %016x) ===',
                         ev.msg.datapath.id)
        self.logger.info('%8s %10s %10s %10s %10s',
                         'port', 'rx-pkts', 'rx-bytes',
                         'tx-pkts', 'tx-bytes')
        for stat in sorted(body, key=lambda s: s.port_no):
            self.logger.info('%8d %10d %10d %10d %10d',
                             stat.port_no,
                             stat.rx_packets, stat.rx_bytes,
                             stat.tx_packets, stat.tx_bytes)
