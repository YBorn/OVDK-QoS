# OVDK-QoS
Provide Traffic Control  on DPDK OVS

The Intel(R) DPDK Accelerated Open vSwitch (Intel(R) DPDK vSwitch/OVDK) is a fork of the open source Open vSwitch multilayer virtual switch found at http://openvswitch.org/.

For more information on the project, check out the Intel(R) DPDK vSwitch/OVDK homepage at 01.org.

OVDK-QoS is OVDK with QoS ability, which provides traffic control function similar to linux TC module. OVDK-QoS provide a user-configure-tool, namely ovdk-tc which can configure TC Structure Object: Qdisc and Class. OVDK-QoS provide a user-configure-tool, namely ovs-ofctl which can configure flow table and classify network traffic using enqueue. Action: enqueue can specify target output port and queue for packet which match the flow table.
