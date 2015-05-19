sudo ovdk-tc qdisc add dev ovdk17 root handle 1: htb
sudo ovdk-tc class add  dev ovdk17 parent 1: classid 1:1 htb rate 100mbit ceil 100mbit
sudo ovdk-tc class add  dev ovdk17 parent 1:1 classid 1:11 htb rate 20mbit ceil 100mbit quantum 20000
sudo ovdk-tc class add  dev ovdk17 parent 1:1 classid 1:12 htb rate 20mbit ceil 100mbit quantum 40000
sudo ovdk-tc class add  dev ovdk17 parent 1:1 classid 1:13 htb rate 60mbit ceil 100mbit quantum 40000
#sudo $DPDK_TC/tc class add  dev opdk17 parent 1:1 classid 1:20 htb rate 20mbit ceil 500mbit
