#!/usr/bin/env python
from socket import *
from sys import *
import time
import commands
import threading
import subprocess
from RemoteClient import RemoteClient
from subprocess import Popen



class Sniffer(object):
	ip = ""
	iface = ""
	log_file = "sniffer.pcap"
	sniffer_lock = threading.Lock()
	
	def __init__(self, iface, ip = "127.0.0.1"):
		self.ip = ip
		self.iface = iface

	def show_info(self):
		print ""
		print "Sniffer IP: %s" % self.ip
		print "Sniffer interface: %s" % self.iface 
		print "Sniffer log file: %s" % self.log_file
		print ""

	def execute(self,cmd1, cmd2, cmd3):
		args = (cmd1, cmd2, cmd3)
		self.child = Popen(args)
		print "Sniffer: sniffing ...\n"
		self.sniffer_lock.acquire()
		print "Sniffer: sniffing complete\n"
		self.child.terminate()
		self.child.wait()
		print "sniffer return code:%d\n" % child.returncode
		self.sniffer_lock.release()

	# execute command remotely
	def execu(self, cmd):
		print "exec"	

	# start sniffer
	def start(self):
		rm_cmd = "rm -rfv %s" % self.log_file

	        sniffer_cmd = "tcpdump -i %s -w %s" % (iface3, sniffer_log_file)
		cmd = ('ssh', 'root@' + self.ip, command)
		print "execute_sniffer: "
		print  cmd
		self.sniffer_lock.acquire()
		self.thread = threading.Thread(target = self.execute, args=cmd)
		t.start()
		return t

	# stop sniffer
	def stop(self):
		self.sniffer_lock.release()

	def set_log_file(self, log_file):
		self.log_file = log_file


def test():
	ip = "127.0.0.1"
	iface = "moni0"
	log = "tc1.pcap"

	#snif = Sniffer(ip = ip, iface = iface)
	#snif.show_info()
	#snif.set_log_file(log)

	sniffer = RemoteClient(ip)
        #start snifer
        #delete old sniffer logs 
        sniffer.execute("rm -rfv %s" % log)
        sniffer_cmd = "tcpdump -i %s -w %s" % (iface, log)
        s_res = ""
        t = sniffer.start_sniffer(sniffer_cmd)

	time.sleep(5)
	
	sniffer.stop_sniffer()


test()

