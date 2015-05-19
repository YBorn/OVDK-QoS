OVS_HOME=$HOME/DPDK-OVS/OVS/openvswitch/utilities

sudo $OVS_HOME/ovs-ofctl add-flow br0 ip,nw_src=10.0.0.1,nw_dst=10.0.0.10,actions=enqueue:17:0x11
sudo $OVS_HOME/ovs-ofctl add-flow br0 ip,nw_src=10.0.0.10,nw_dst=10.0.0.1,actions=output:16

sudo $OVS_HOME/ovs-ofctl add-flow br0 ip,nw_src=10.0.0.2,nw_dst=10.0.0.10,actions=enqueue:17:0x21
sudo $OVS_HOME/ovs-ofctl add-flow br0 ip,nw_src=10.0.0.10,nw_dst=10.0.0.2,actions=output:16

sudo $OVS_HOME/ovs-ofctl add-flow br0 ip,nw_src=10.0.0.3,nw_dst=10.0.0.10,actions=enqueue:17:0x22
sudo $OVS_HOME/ovs-ofctl add-flow br0 ip,nw_src=10.0.0.10,nw_dst=10.0.0.3,actions=output:16

#sudo $OVS_HOME/ovs-ofctl add-flow br0 ip,nw_src=10.0.0.4,nw_dst=10.0.0.10,actions=enqueue:17:0x20
#sudo $OVS_HOME/ovs-ofctl add-flow br0 ip,nw_src=10.0.0.10,nw_dst=10.0.0.4,actions=output:18

#sudo $OVS_HOME/ovs-ofctl add-flow br0 ip,nw_src=10.0.0.4,nw_dst=10.0.0.1,actions=output:16
#sudo $OVS_HOME/ovs-ofctl add-flow br0 ip,nw_src=10.0.0.1,nw_dst=10.0.0.4,actions=output:18
