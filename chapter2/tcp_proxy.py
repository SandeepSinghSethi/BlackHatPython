#!/usr/bin/env python3

import os
import threading
import socket
import argparse
import sys

# global localip,localport,remoteip,remoteport,receivef

def parser():
	global localport,localip,remoteport,remoteip

	parser = argparse.ArgumentParser(description="Simple Proxy File which prints the hexadecimal print of network traffic .")
	parser.add_argument('-lip','--localip',default='127.0.0.1',type=str,help="Local IP Address")
	parser.add_argument('-lp','--localport',default=1337,type=int,help="Local Port Number")
	parser.add_argument('-rip','--remoteip',type=str,help='Remote IP Address')
	parser.add_argument('-rp','--remoteport',type=int,help='Remote Port Number')
	parser.add_argument('-rf','--receive-first',default=False,action='store_true',help="To receive data first from the remote server.")

	args = parser.parse_args()

	if not args.remoteip or not args.remoteport:
		parser.print_help()
		sys.exit(1)

	localip=args.localip
	localport=args.localport

	if args.remoteip:
		remoteip = args.remoteip

	if args.remoteport:
		remoteport = args.remoteport

	if args.receive_first:
		receive = args.receive_first

	return args

HEX_FILTER = ''.join(
[(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

class tcpProxy():
	def __init__(self,args):
		self.localip = args.localip
		self.localport = args.localport
		self.remoteip = args.remoteip
		self.remoteport = args.remoteport
		self.receive_first = args.receive_first


	def hexdump(self,src, length=16, show=True):
		if isinstance(src, bytes):		
			src = src.decode()
		results = list()
		for i in range(0, len(src), length):
	 		word = str(src[i:i+length])
	 		printable = word.translate(HEX_FILTER)
	 		hexa = ' '.join([f'{ord(c):02X}' for c in word])
	 		hexwidth = length*3
	 		results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
		if show:
			for line in results:
				print(line)
		else:
			return results





	def proxy_handler(self,cl_sock):
		remsrvip = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		remsrvip.connect((self.remoteip,self.remoteport))

		data = b""

		if self.receive_first:
			data = self.receive_from(remsrvip)

		if len(data):
			print(f"[<--] Received {len(data)} bytes of data from remotehost ..")
			self.hexdump(data)
			print(f"[<--] Sending to localhost .. ")
			cl_sock.send(data)

		while True:

				localbuffer = self.receive_from(cl_sock)

				# print(localbuffer)

				if len(localbuffer):
					print(f"[-->] Received {len(localbuffer)} from localhost ..")
					self.hexdump(localbuffer)
					print(f"[-->] Sending to remotehost ..")
					remsrvip.send(localbuffer)


				remotebuffer = self.receive_from(remsrvip)

				if len(remotebuffer):
					print(f"[<--] Received {len(remotebuffer)} from remotehost ..")
					self.hexdump(remotebuffer)
					print(f"[<--] Sending to localhost ..")
					cl_sock.send(remotebuffer)

				if not len(localbuffer) or not len(remotebuffer):
					remsrvip.close()
					cl_sock.close()
					print(f"[*] No more data to receive , closing connections ...")
					break


	def receive_from(self,rem_sock):
		buffer = b""
		rem_sock.settimeout(5)
		try:
			while True:
				data = rem_sock.recv(4096)
				if not data:
					break
				buffer += data
		except Exception as e:
			pass
		return buffer


	def server(self):
		locsrvip = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		locsrvip.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

		try:
			try:
				locsrvip.bind((self.localip,self.localport))
			except Exception as e:
				print(f'[!] Some error occured while bind() : {e}')
				print("[*] Closing the listening server ..")
				print("[*] Terminating the process ..")
				sys.exit(1)

			print(f"[+] Listening on {self.localip}:{self.localport}")
			locsrvip.listen(5)

			while True:
				cl_sock , addr = locsrvip.accept()
				print(f"[+] Received Connection From {addr[0]}:{addr[1]}")

				proxythread = threading.Thread(target=self.proxy_handler,args=(cl_sock,))
				proxythread.daemon = True
				proxythread.start()
		except KeyboardInterrupt:
			print(f"[!] Exiting ..")
			sys.exit(1)

	


if __name__ == '__main__':
	args = parser()
	# print(localport,localip,remoteport,remoteip)

	print("[+++---+++] Connection Timeout is 60sec/1min ... \n")
	print(f"[*] LocalIP = {args.localip}\t , LocalPort = {args.localport}")
	print(f"[*] RemoteIP = {args.remoteip}\t , RemotePort = {args.remoteport}")


	program = tcpProxy(args)
	program.server()