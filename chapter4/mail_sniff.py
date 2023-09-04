#!/usr/bin/env python3

from cryptography.utils import CryptographyDeprecationWarning
import warnings
warnings.filterwarnings("ignore",category=CryptographyDeprecationWarning)
from scapy.all import *


def pkt_callback(packet):
	if packet[TCP].payload:
		mypkt = str(packet[TCP].payload)

		if 'user' in mypkt.lower() or 'pass' in mypkt.lower():
			print(f'[+] Destination : {packet[IP].dst}')
			print(f'[+] Payload 	: {packet[TCP].payload}')

sniff(filter="tcp port 21",prn=pkt_callback)