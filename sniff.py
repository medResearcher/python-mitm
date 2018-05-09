from scapy.all import *
import argparse
import sys

def querysniff(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            print str(ip_src) + " -> " + str(ip_dst) + " : (" + pkt.getlayer(DNS).qd.qname + ")"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', '-i', help='interface')
    args = parser.parse_args()

    try:
        interface = args.interface
    except KeyboardInterrupt:
        print "[*] User requested shutdown..."
        print "[*] Exiting..."
        sys.exit(1)

    sniff(iface = interface, filter = "port 53", prn=querysniff, store=0)
    print "\n[*] Shutting down..."

if __name__ == '__main__':
    main()
