#!/usr/bin/env python3

from cryptography.utils import CryptographyDeprecationWarning
import warnings
warnings.filterwarnings("ignore",category=CryptographyDeprecationWarning)
from scapy.all import *

SUBNET = '192.168.43.0/24'

def callback(packet):
	pass


pkt,_ = arping(SUBNET,verbose=False)
print(f"Fetching HW Address of devices in {SUBNET} ..")


for i in pkt:
	print(f'[+] Found : hwaddr : {i[1].getlayer(ARP).hwsrc} => ({i[1].getlayer(ARP).psrc})')



