#from scapy.all import *

#target = "10.0.0.246"

#res, unans = sr(IP(dst='10.0.0.246')/TCP(flags='S', dport=(1, 1024)))
#res, unans = sr( IP(dst=target)/TCP(flags="S", dport=(1,1024)), timeout=2 )
#res.nsummary(lfilter = lambda s,r: (r.haslayer(TCP) and (r.getlayer(TCP).flags & 2)))
#res.summary()


from __future__ import print_function
from scapy.all import *
import random

# Define end host and TCP port range
host = '10.0.0.246'
portRange = [22, 23, 80, 443, 3389]

# Send SYN with random Src Port for each Dst port
for dstPort in portRange:
    srcPort = random.randint(1025,65534)
    resp = sr1(IP(dst=host)/TCP(sport=srcPort,dport=dstPort,flags="S"),timeout=1,verbose=0)

    if resp is None:
        print('{}:{} is filtered (silently dropped).'.format(host, str(dstPort)))
    elif(resp.haslayer(TCP)):
        if(resp.getlayer(TCP).flags == 0x12):
            # Send a gratuitous RST to close the connection
            send_rst = sr(IP(dst=host)/TCP(sport=srcPort,dport=dstPort,flags='R'),timeout=1,verbose=0)
            print('{}:{} is open.'.format(host, str(dstPort)))
        elif (resp.getlayer(TCP).flags == 0x14):
            print('{}:{} is closed.'.format(host, str(dstPort)))        
    elif(resp.haslayer(ICMP)):
        if(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print('{}:{} is filtered (silently dropped).'.format(host, str(dstPort)))

'''            
============================Console Output:===========================
172.16.20.40:22 is filtered (silently dropped).
172.16.20.40:23 is filtered (silently dropped).
172.16.20.40:80 is open.
172.16.20.40:443 is open.
172.16.20.40:449 is filtered (silently dropped).
'''
