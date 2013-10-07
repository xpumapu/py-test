#!/usr/bin/env python
from socket import *
from sys import *
import time
import commands
import threading
import subprocess
from RemoteClient import RemoteClient
from subprocess import Popen






def test():
        ip = "127.0.0.1"
        iface = "moni0"
        log = "tc1.pcap"
	res = "tc1_res.pcap"
	text_res = "tc1_text_res.log"

        #snif = Sniffer(ip = ip, iface = iface)
        #snif.show_info()
        #snif.set_log_file(log)

        sniffer = RemoteClient(ip)
        #start snifer
        #delete old sniffer logs 
        sniffer.execute("rm -rfv %s" % log)
	sniffer.execute("rm -rfv %s" % res)
	sniffer.execute("rm -rfv %s" % text_res)
        sniffer_cmd = "tcpdump -i %s -w %s" % (iface, log)
        t = sniffer.start_sniffer(sniffer_cmd)

        time.sleep(1)

        sniffer.stop_sniffer()
	
	
	flr1 = "wlan.fc.type_subtype==0x08"
	flr2 = "wlan_mgt.ssid==\"ASUS_RT_G32\""
	flr3 = "wlan.seq==3660"
	
	tshark_cmd = "tshark -r%s -R%s -R%s -R%s -w%s" % ("sample.pcap", flr1, flr2, flr3, res)
	sniffer.execute(tshark_cmd)

	tshark_cmd = "tshark -r%s" % res
	status, buf = sniffer.execute(tshark_cmd)
	print "status: %s\n" % status
	print "buf: %s\n" % buf

test()

