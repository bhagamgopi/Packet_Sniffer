#!/usr/bin/python3

print("Use Sudo")
print("Format: sudo python3 packet_sniffer.py interface_name packet_count time protocol(arp|icmp|all)")
print("Example: sudo python3 packet_sniffer.py virbr0 20 20 all")

#Packet sniffer script using scapy
from datetime import datetime 
import sys
import subprocess 
from scapy.all import *

# Interface name
net_iface = sys.argv[1]

#promisceous mode transfer the interface data packets to cpu to processs and you capture from there
subprocess.call(["ifconfig",net_iface,"promisc"]) 

# The packet count you want to capture
num_of_pkt = int(sys.argv[2])

# Time how long(in sec) run to capture
time_sec =int(sys.argv[3])

# Protocol(arp | icmp |all)
proto = sys.argv[4]

#sniff function call it and pass every packet in byte format
def logs(packet):
    packet.show() #SHow whole packet
    print(f"SRC_MAC: {str(packet[0].src)} DEST_MAC: {str(packet[0].dst)}")


if proto == "all":
    sniff(iface = net_iface ,count = num_of_pkt, timeout = time_sec, prn=logs ) 
elif proto == "arp":
    sniff(iface = net_iface, count = num_of_pkt,timeout = time_sec , prn = logs , filter = proto) 
elif proto == "icmp":
    sniff(iface = net_iface, count = num_of_pkt,timeout = time_sec , prn = logs , filter = proto) 
else:
    print("Wrong protocol")
