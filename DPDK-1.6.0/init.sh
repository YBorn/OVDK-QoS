#!/bin/bash

note()
{
    TEXT[1]="The Script Usage"

    TEXT[2]="Setup the DPDK Run-Time Enviroment"

    TEXT[3]="Unbind Nics form PMD And Bind to Kernel Driver"

    TEXT[4]="Exit"

}

usage()
{
    if [ -z "$1" ]; then
        echo "Usage: init.sh  number"
    fi
}

setup_enviroment()
{
    echo "Initialize the program enviroment"

    echo "Load kernel modules"
    sudo modprobe uio
    sudo insmod build/kmod/igb_uio.ko
    read

    echo "Ifconfig ethX down"
    sudo ifconfig eth1 down
    sudo ifconfig eth2 down
    sudo ifconfig eth3 down
    sudo ifconfig eth4 down
    read

    echo "Bind Intel devices to igb_uio"
    sudo ./tools/pci_unbind.py --bind=igb_uio eth1
    sudo ./tools/pci_unbind.py --bind=igb_uio eth2
    sudo ./tools/pci_unbind.py --bind=igb_uio eth3
    sudo ./tools/pci_unbind.py --bind=igb_uio eth4
    read

    echo "Reserve huge pages memory"
    #mkdir -p /mnt/huge
    sudo mount -t hugetlbfs nodev /mnt/huge
    echo $1 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
}

unbind_nics()
{
    sudo ./tools/pci_unbind.py --status
    echo ""
    echo "unbinding now"
    sudo ./tools/pci_unbind.py -b e1000 00:04.0
    sudo ./tools/pci_unbind.py -b e1000 00:05.0
    sudo ./tools/pci_unbind.py -b e1000 00:06.0
    sudo ./tools/pci_unbind.py -b e1000 00:07.0
    echo "OK"
}

quit()
{
    QUIT='1'
}

FUNC[1]="usage"
FUNC[2]="setup_enviroment"
FUNC[3]="unbind_nics"
FUNC[4]="quit"
FUNC[5]="note"

QUIT='0'
${FUNC[5]}
while [ $QUIT = '0' ]; do
    echo "**************Notice***************"
    echo ""
    for i in $(seq ${#TEXT[@]}); do
        echo "[$i] ${TEXT[i]}"
    done
    echo ""
    read num
    ${FUNC[$num]} $1
    echo ""
done
