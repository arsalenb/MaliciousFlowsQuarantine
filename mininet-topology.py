from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

class MaliciousFlowQuarantineTopo(Topo):
    def build(self):
        # Add switches with specific DPIDs
        s1 = self.addSwitch('s1', dpid='1')  # Central switch
        s2 = self.addSwitch('s2', dpid='2')  # Servers 1,2 switch
        s3 = self.addSwitch('s3', dpid='3')  # Server 3 switch
        s4 = self.addSwitch('s4', dpid='4')  # Quarantine switch

       # Add hosts
        h1 = self.addHost('h1', ip='192.168.1.2/24', defaultRoute = "via 192.168.1.2")
        h2 = self.addHost('h2', ip='192.168.1.3/24', defaultRoute = "via 192.168.1.3")

        # Add servers
        srv1 = self.addHost('srv1', ip='10.0.0.2/24', defaultRoute = "via 10.0.0.2")
        srv2 = self.addHost('srv2', ip='10.0.0.3/24', defaultRoute = "via 10.0.0.3")
        srv3 = self.addHost('srv3', ip='10.0.1.2/24', defaultRoute = "via 10.0.1.2")  # Different subnet

        # Connect hosts to their switch
        self.addLink(h1, s1)
        self.addLink(h2, s1)

        # Connect servers to their switch
        self.addLink(srv1, s2)
        self.addLink(srv2, s2)
        self.addLink(srv3, s3)

        # Connect switches
        self.addLink(s1, s2)  # "Central" switch to "Servers 1,2" switch
        self.addLink(s1, s3)  # "Central" switch to "Server 3" switch
        self.addLink(s1, s4)  # "Central" switch to "Quarantine" switch

def run():
    # Define the controller IP and port
    controller_ip = '127.0.0.1'  
    controller_port = 6653 

    # Create the Mininet network with a remote controller
    net = Mininet(topo=MaliciousFlowQuarantineTopo(),
     controller=lambda name: RemoteController(name, ip=controller_ip, port=controller_port),
     switch=lambda name, **opts: OVSSwitch(name, protocols='OpenFlow13', **opts))

    net.start()

    # Display DPIDs & MAC Addresses
    print("\n🔹 Switch DPIDs and MAC Addresses:")
    for switch in net.switches:
        mac = switch.MAC()
        print(f"🔸 {switch.name}: DPID={switch.dpid}, MAC={mac}")

    print("\n🔹 Host MAC Addresses:")
    for host in net.hosts:
        mac = host.MAC()
        print(f"🔸 {host.name}: MAC={mac}")

    # Start the Mininet CLI
    CLI(net) 

    # After the user exits the CLI, shutdown the network.

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
