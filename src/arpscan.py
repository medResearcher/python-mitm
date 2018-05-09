import sys
from datetime import datetime

try:
    interface = input("[*] Enter desired interface: ")
    ips = input("[*] Enter range of IPs to scan for: ")
except KeyboardInterrupt:
    print("\n[*] User requested shutdown...")
    print("[*] Quitting...")
    sys.exit(1)

print("\n[*] Scanning...")
start_time = datetime.now()

from scapy.all import srp, Ether, ARP, conf

conf.verb = 0
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips), timeout=2, iface=interface,inter=0.1)

print("MAC - IP\n")
for snd, rcv in ans:
    print(rcv.sprintf(r"%Ether.src% - %ARP.psrc%"))
stop_time = datetime.now()
total_time = stop_time - start_time
print("\n[*] Scan complete!")
print("[*] Scan duration: {}".format(total_time))
