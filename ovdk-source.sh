#!/bin/bash

DPDK_OVS=$HOME/DPDK-OVS/OVS/openvswitch

function Start_ovs_db_server()
{
    echo "Start ovs database server"
    sudo $DPDK_OVS/ovsdb/ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock --remote=db:Open_vSwitch,Open_vSwitch,manager_options&
}

function Configure_br()
{
    echo "Configure the database"
sudo $DPDK_OVS/utilities/ovs-vsctl --no-wait add-br br0 -- set Bridge br0 datapath_type=dpdk

    echo "Add ports to ovs bridge"
    sudo $DPDK_OVS/utilities/ovs-vsctl --no-wait add-port br0 ovs_dpdk_16 -- set Interface ovs_dpdk_16 type=dpdk ofport_request=16
    sudo $DPDK_OVS/utilities/ovs-vsctl --no-wait add-port br0 ovs_dpdk_17 -- set Interface ovs_dpdk_17 type=dpdk ofport_request=17
    sudo $DPDK_OVS/utilities/ovs-vsctl --no-wait add-port br0 ovs_dpdk_18 -- set Interface ovs_dpdk_18 type=dpdk ofport_request=18
    sudo $DPDK_OVS/utilities/ovs-vsctl --no-wait add-port br0 ovs_dpdk_19 -- set Interface ovs_dpdk_19 type=dpdk ofport_request=19
}

function Start_ovsdpdk()
{
    echo "Start ovs_dpdk"
    sudo $DPDK_OVS/datapath/dpdk/build/ovs_dpdk  -c 0xf -n 2  --proc-type=primary -- -p 0xf -n 1 --stats=1 --vswitchd=0 --client_switching_core=1 --config="(0,0,2),(1,0,2),(2,0,2)(3,0,2)" --qos_core=3
}

function Start_ovs_daemon()
{
    echo "Start ovs daemon"
    sudo $DPDK_OVS/vswitchd/ovs-vswitchd -c 0x01 --proc-type=secondary
}

export DPDK_OVS=$HOME/DPDK-OVS/OVS/openvswitch

export Start_ovs_db_server
export Configure_br
export Start_ovsdpdk
export Start_ovs_daemon
