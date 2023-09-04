#!/usr/bin/env python3

import ipaddress
import socket
import os
import sys
from ctypes import *
import struct
import threading
import time


SUBNET = '192.168.43.0/24'
MESSAGE = "HELLO!"


class IP(Structure):

	# fields structure is created as the Structure from the ctypes requires to have a _fields_ array created before creating any object.
	_fields_ = \
	[
		# here is something wrong i don know , ver should be first then hdrlen , but doing so the magic process of ctypes.Structure is putting ip version into hdrlen variable and same for the version , but the same thing when we do for ttl and protocol , regardless of the position of the variable , the data is being stored perfectly , I think its the issue of nibble that ctypes can't handle :(
		("hdrlen"	 , c_ubyte 	, 4),
		("ver" 		 , c_ubyte 	, 4),
		("tos"		 , c_ubyte	, 8),
		("totlen"	 , c_ushort	, 16),
		("id"		 , c_ushort , 16),
		# ("offset"	 , c_ushort , 16),
		("frag_off"	 , c_ushort , 13),
		("flags"	 , c_ubyte  , 3),
		("ttl"		 , c_ubyte	, 8),
		("proto_num" , c_ubyte  , 8),
		("checksum"	 , c_ushort , 16),
		("src_ip"	 , c_uint32	, 32),
		("dst_ip"	 , c_uint32	, 32),
	]


	# Structure class uses _new_ function to create an object as the class to be the first parameter which is class of structure , ctypes.Structure gives a method from_buffer_copy which creates a C instance of the readable buffer which is our fields here going to be initialized by the __init__ method. so the function copies the structure fields into the Structure class and is returned as an object by the init function

	def __new__(cls,buff=None):
		return cls.from_buffer_copy(buff)


	def __init__(self,cls,buff=None):
		self.socket_buffer = buff
		self.protocol_map = {1:"ICMP",6:"TCP",17:"UDP"}

		self.src_addr = socket.inet_ntoa(struct.pack("<L",self.src_ip))
		self.dst_addr = socket.inet_ntoa(struct.pack("<L",self.dst_ip))

		try:
			self.protocol = self.protocol_map[self.proto_num]
		except:
			self.protocol = str(self.proto_num)

class structIP():
	def __init__(self,buff=None):
		header = struct.unpack("<BBHHHBBH4s4s",buff)
		self.ver = header[0] >> 4	# [0 1 0 0] 0 1 1 0 
		self.hdrlen = header[0] & 0xf # 0 1 1 0
		self.tos = header[1]
		self.totlen = header[2]
		self.id = header[3]

		# self.fragment_off= header[4]
		self.flags = header[4] >> 13
		self.frag_off = header[4] & 0x1fff # to get the fragment offset and-ed 
		self.ttl = header[5]
		self.proto_num = header[6]
		self.checksum = header[7]
		self.src_ip = header[8]
		self.dst_ip = header[9]

		self.socket_buffer = buff
		self.protocol_map = {1:"ICMP",6:"TCP",17:"UDP"}


		self.src_addr = ipaddress.ip_address(self.src_ip)
		self.dst_addr = ipaddress.ip_address(self.dst_ip)

		try:
			self.protocol = self.protocol_map[self.proto_num]
		except:
			self.protocol = str(self.proto_num)

class ICMP(Structure):
	_fields_ = [
		('type'			, c_ubyte,	8),
		('code'			, c_ubyte,	8),
		('checksum'		, c_ushort,	16),
		('unused'		, c_ushort,	16),
		('next_hop_mtu'	, c_ushort, 16)
	]

	def __new__(cls,buff=None):
		return cls.from_buffer_copy(buff)

	def __init__(self,buff=None):
		self.socket_buffer = buff;



def print_fields(ipdecoded):
	
	print(ipdecoded.ver)
	print(ipdecoded.hdrlen)
	print(ipdecoded.tos)
	print(ipdecoded.totlen)
	print(ipdecoded.id)
	print(ipdecoded.flags)
	print(ipdecoded.frag_off)
	print(ipdecoded.ttl)
	print(ipdecoded.proto_num)
	print(ipdecoded.protocol)
	print(ipdecoded.checksum)
	print(ipdecoded.src_ip)
	print(ipdecoded.dst_ip)
	print(ipdecoded.src_addr)
	print(ipdecoded.dst_addr)
	print(ipdecoded.socket_buffer)



def udp_sniffer():
	with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
		for ip in ipaddress.IPv4Network(SUBNET).hosts():
			s.sendto(bytes(MESSAGE,'utf8'),(str(ip),65212)) # second part is ip and udp port on which to connect to

class Scanner():
	def __init__(self,host):
		if os.name == 'nt':
			protocol = socket.IPPROTO_IP
		else:
			protocol = socket.IPPROTO_ICMP

		self.host = host
		self.sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,protocol)
		self.sock.bind((host,0))
		self.sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

		# enter promiscous mode on windows
		if os.name == 'nt':
			sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)



	def sniff(self):
		hosts_up = set([f'{str(self.host)} *']) # to make the listening host identified 

		try:
			while True:
				packet = self.sock.recvfrom(65565)[0]
				ip_pkt = IP(packet)

				if ip_pkt.protocol == 'ICMP':
					offset = ip_pkt.hdrlen *4
					buf = packet[offset:offset + sizeof(ICMP)]
					icmp_pkt = ICMP(buf)

					# if type = 3 and code = 3 
					if icmp_pkt.type == 3 and icmp_pkt.code == 3:
						if ipaddress.ip_address(ip_pkt.src_addr) in ipaddress.IPv4Network(SUBNET):


							if packet[len(packet) - len(MESSAGE): ] == bytes(MESSAGE,'utf8'):
								tgt = str(ip_pkt.src_addr)
								if tgt != self.host and tgt not in hosts_up:
									hosts_up.add(tgt)
									print(f"Host is up : {tgt}")


		except KeyboardInterrupt:
			if os.name == 'nt':
				sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)

			print("Terminating process !!")
			if hosts_up:
				print(f"\nSummary Of Hosts (Live) on {SUBNET} : ")

			for host in sorted(hosts_up):
				print(host)

			print('')
			self.sock.close()
			sys.exit()


def main():
	if len(sys.argv) == 2:
		sys.argv[1]
	else:
		host = '192.168.43.100'

	s = Scanner(host)
	time.sleep(3)
	t = threading.Thread(target=udp_sniffer,)
	t.start()
	s.sniff()

if __name__ == '__main__':
	main()