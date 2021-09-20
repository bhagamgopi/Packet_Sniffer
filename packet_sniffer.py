#!/usr/bin/python3

from rich.prompt import Prompt
from rich import style
from rich.console import Console

console = Console()

console.print("1.Use Sudo",style='bold red')
console.print("2.Format: sudo python3 packet_sniffer.py interface_name packet_count time protocol(arp|icmp|all)",style='bold  green ')
console.print("3.Example: sudo python3 packet_sniffer.py virbr0 20 20 all",style='bold blue ')

#Packet sniffer script using scapy
from datetime import datetime 
import sys
import subprocess 
from scapy.all import *

# interface nmae
net_iface = input("Enter interface name:-   ")

#promisceous mode transfer the interface data packets to cpu to processs and you capture from there
subprocess.call(["ifconfig",net_iface,"promisc"]) 

# The packet count you want to capture
num_of_pkt = int(input("Enter the packet count you want to capture:- "))


# Time how long(in sec) run to capture
time_sec =int(input("Enter the time how long(in sec) run to capture:- "))

# Protocol(arp | icmp |all)
proto = input("Enter the protocol( arp | icmp | tcp |all):- ")

#sniff function call it and pass every packet in byte format
def logs(packet):
   console.print(f'packet.show()',style='bold #01F9EB ') #SHow whole packet
   console.print(f"SRC_MAC: {str(packet[0].src)} DEST_MAC: {str(packet[0].dst)}",style='bold #F908E6 ')


if proto == "all":
    sniff(iface = net_iface ,count = num_of_pkt, timeout = time_sec, prn=logs ) 
 
elif proto == "arp":
    sniff(iface = net_iface, count = num_of_pkt,timeout = time_sec , prn = logs , filter = proto) 
elif proto == "icmp":
    sniff(iface = net_iface, count = num_of_pkt,timeout = time_sec , prn = logs , filter = proto)
elif proto == 'tcp':
    sniff(iface = net_iface, count = num_of_pkt,timeout = time_sec , prn = logs , filter = proto) 
else:
    console.print('Wrong protocol',style='bold red')
