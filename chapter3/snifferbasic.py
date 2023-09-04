#!/usr/bin/env python3

import ipaddress
import socket
import os
import sys
from ctypes import *
import struct



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





def main(HOST):
	if os.name == 'nt':
		protocol = socket.IPPROTO_IP
	else:
		protocol = socket.IPPROTO_ICMP

	# packet = (b'E\x00\x00T\xdf#\x00\x00@\x01\xc3\xcf\xc0\xa8+\x01\xc0\xa8+d\x00\x00\xc3l\xfb\xef\x00\x01\x1d\x89\xecd\x00\x00\x00\x00w\xe1\x00\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567', ('192.168.43.1', 0))
	# ippacket = packet[0]
	# ipdecoded = structIP(ippacket[:20])
	# a = IP(ippacket)
	# print_fields(ipdecoded)
	# print()
	# print_fields(a)

	sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,protocol)
	sock.bind((HOST,0))
	sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

	if os.name == 'nt':
		sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)


		
	print("[+] Starting scanning ..")
	i = 1
	try:
		while True:
			packet = sock.recvfrom(65565)[0]
			# ip_pkt = structIP(packet[:20])
			ip_pkt = IP(packet)

			# print_fields(ip_pkt)
			print("-"*32+"\n")
			print(f"{i} -> Protocol:{ip_pkt.protocol} : {ip_pkt.src_addr} => {ip_pkt.dst_addr} \n")
			i = i+1

			if ip_pkt.protocol == "ICMP":
				icmp_hdrlen = ip_pkt.hdrlen*4 # icmp block starts after ip_hdrlen * 4
				buf_icmp = packet[icmp_hdrlen:icmp_hdrlen + sizeof(ICMP)]
				icmp_pkt = ICMP(buf_icmp)

				print(f"\tType: {icmp_pkt.type} , Code: {icmp_pkt.code} , checksum : {icmp_pkt.checksum} , ID : {icmp_pkt.unused} , NextHopMTU: {icmp_pkt.next_hop_mtu}")



	except KeyboardInterrupt:
		if os.name == 'nt':
			sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
		sock.close()
		print("Terminating process ..")
		sys.exit(0)


if __name__ == '__main__':
	if len(sys.argv) == 2:
		host = sys.argv[2]
	else:
		host = "192.168.43.100"
	main(host)