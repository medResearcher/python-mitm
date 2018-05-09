from __future__ import print_function
from scapy.all import *
import netaddr

# Define IP range to ping
network = '10.0.0/24'

# make list of addresses out of network, set live host counter
addresses = netaddr.IPNetwork(network)
liveCounter = 0

# Send ICMP ping request, wait for answer
for host in addresses:
    if (host == addresses.network or host == addresses.broadcast):
        # Skip network and broadcast addresses
        continue
    
    resp = sr1(IP(dst=str(host))/ICMP(),timeout=2,verbose=0)
    
    if resp is None:
        print(host, 'is down or not responding.')
    elif (
        int(resp.getlayer(ICMP).type)==3 and
        int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
    ):
        print(host, 'is blocking ICMP.')
    else:
        print(host, 'is responding.')
        liveCounter += 1

print('{}/{} hosts are online.'.format(liveCounter, addresses.size))

'''
============================Console Output:===========================
172.16.20.1 is responding.
WARNING: Mac address to reach destination not found. Using broadcast.
172.16.20.2 is down or not responding.
WARNING: Mac address to reach destination not found. Using broadcast.
172.16.20.3 is down or not responding.
172.16.20.4 is responding.
172.16.20.5 is responding.
172.16.20.6 is responding.
172.16.20.7 is responding.
WARNING: Mac address to reach destination not found. Using broadcast.
172.16.20.8 is down or not responding.
WARNING: Mac address to reach destination not found. Using broadcast.
172.16.20.9 is down or not responding.
172.16.20.10 is responding.
172.16.20.11 is responding.
... (truncated)
19/254 hosts are online.
'''
