sudo ifconfig eth0:0 10.102.81.100 netmask 255.255.255.0
sudo ifconfig eth0:1 10.102.81.102 netmask 255.255.255.0
sudo ifconfig eth0:2 10.102.81.103 netmask 255.255.255.0
sudo ifconfig eth0:3 10.102.81.104 netmask 255.255.255.0
sudo ifconfig eth0:4 10.102.81.105 netmask 255.255.255.0
sudo ifconfig eth0:5 10.102.81.106 netmask 255.255.255.0

sudo iptables -A OUTPUT -p tcp --tcp-flags ALL RST -j DROP
