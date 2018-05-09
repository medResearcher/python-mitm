from scapy.all import *

def sniffPackets(packet):
    if packet.haslayer(IP):
        pckt_src = packet[IP].src
        pckt_dst = packet[IP].dst
        pckt_ttl = packet[IP].ttl
        print("IP Packet: {} is going to {} and has ttl value {}".format(pckt_src, pckt_dst, pckt_ttl))

def main():
    print("Packet sniffer")
    sniff(filter="ip", iface="eth0", prn=sniffPackets)

if __name__ == '__main__':
    main()
