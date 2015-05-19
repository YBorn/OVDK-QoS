sudo ovdk-tc qdisc add dev ovdk17 root handle 1: htb default 12
sudo ovdk-tc class add  dev ovdk17 parent 1: classid 1:1 htb rate 100mbit ceil 100mbit
sudo ovdk-tc class add  dev ovdk17 parent 1:1 classid 1:11 htb rate 20mbit ceil 100mbit
sudo ovdk-tc class add  dev ovdk17 parent 1:1 classid 1:12 htb rate 80mbit ceil 200mbit

sudo ovdk-tc qdisc add dev ovdk17 handle 2: parent 1:12 drr
sudo ovdk-tc class add dev ovdk17 parent 2: classid 2:21 drr quantum 3000
sudo ovdk-tc class add dev ovdk17 parent 2: classid 2:22 drr quantum 5000

#sudo $DPDK_TC/tc class add  dev opdk17 parent 1:1 classid 1:20 htb rate 20mbit ceil 500mbit
