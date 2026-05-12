from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

class FatTreeTopo(Topo):
    def build(self, k=4):
        core = []
        for i in range((k//2)**2):
            core.append(self.addSwitch(f'c{i+1}'))

        for pod in range(k):
            agg = []
            for i in range(k//2):
                s = self.addSwitch(f'a{pod}{i}')
                agg.append(s)
                for c in core[i*(k//2):(i+1)*(k//2)]:
                    self.addLink(s, c)
            for i in range(k//2):
                edge = self.addSwitch(f'e{pod}{i}')
                for a in agg:
                    self.addLink(edge, a)
                for h in range(k//2):
                    self.addLink(self.addHost(f'h{pod}{i}{h}'), edge)

if __name__ == '__main__':
    setLogLevel('info')
    topo = FatTreeTopo(k=4)
    net = Mininet(
        topo=topo,
        controller=RemoteController('c0', ip='127.0.0.1', port=6633),
        switch=OVSSwitch,
        autoSetMacs=True,
        autoStaticArp=True
    )
    net.start()
    print("Fat-tree k=4 démarré !")
    net.pingAll()
    CLI(net)
    net.stop()
