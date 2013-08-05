#! /usr/bin/env python
from scapy.all import *


def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
        return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")

sniff(prn=arp_monitor_callback, filter="arp", store=0, count = 5)


a = sniff(count = 10)
hexdump(a[1])
print "a[3] = \n"
hexdump(a[3])



