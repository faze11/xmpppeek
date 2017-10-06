 #!/bin/sh

echo "WAN (External) Interface: "

read wanInt

echo "LAN (Shared) Interface: "

read lanInt

#echo "Stopping network manager"

#/etc/init.d/NetworkManager* stop
#service network-manager stop

echo "Stopping dnsmasq"

/etc/init.d/dnsmasq stop

echo "Configuring interface $lanInt"
#ifdown $lanInt
#ifconfig $lanInt down
ifconfig $lanInt 192.168.137.1 netmask 255.255.255.0
#ifup $lanInt
#ifconfig $lanInt up

echo "Starting DHCP server"

dnsmasq --interface $lanInt --no-hosts --no-poll --except-interface=lo --listen-address=192.168.137.1 --dhcp-range=192.168.137.10,192.168.137.100,60m --dhcp-option=option:router,192.168.137.1 --dhcp-lease-max=50 --pid-file=/var/run/nm-dnsmasq-$lanInt.pid

echo "Stopping firewall and allowing everyone..."

iptables -F

iptables -X

iptables -t nat -F

iptables -t nat -X

iptables -t mangle -F

iptables -t mangle -X

iptables -P INPUT ACCEPT

iptables -P FORWARD ACCEPT

iptables -P OUTPUT ACCEPT

# commented out this line to NOT intercept port 5222
#iptables -t nat -A PREROUTING -i $lanInt -p tcp --dport 5222 -j DNAT --to-destination 192.168.137.1:5222

echo "Turning on Natting"

iptables -t nat -A POSTROUTING -o $wanInt -j MASQUERADE

echo "Allowing ip forwarding"

echo 1 > /proc/sys/net/ipv4/ip_forward

echo "Adding 4.2.2.1 to resolv.conf"

echo "nameserver 4.2.2.1" >> /etc/resolv.conf

echo "GO GO gadget gateway"
