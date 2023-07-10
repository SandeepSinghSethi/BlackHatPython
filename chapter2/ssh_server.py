#!/usr/bin/env python3

import socket
import threading
import paramiko
import os
import sys
import shlex
import argparse

CWD = os.path.dirname(os.path.realpath(__file__))
HOSTKEY = paramiko.RSAKey(filename=os.path.join(CWD,'test_rsa.key'))

def parser():
	parser = argparse.ArgumentParser(description="Simple SSH server that can be used on any host with python and paramiko installed ..")
	parser.add_argument('-s','--server',type=str,default='127.0.0.1',help="SSH server IP ..")
	parser.add_argument('-p','--port',type=int,default=1337,help='SSH server listening port ..')

	args = parser.parse_args()
	return args

class Server(paramiko.ServerInterface):
	def __init__(self):
		self.event = threading.Event()

	def check_channel_request(self,kind,chanid):
		if kind == "session":
			return paramiko.OPEN_SUCCEEDED
		return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

	def check_auth_password(self,username,password):
		if username == "wadu" and password == "wadu":
			return paramiko.AUTH_SUCCESSFUL

if __name__ == '__main__':
	args = parser()
	ip = args.server
	port = args.port

	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

	try:
		sock.bind((ip,port))
		print(f"[*] Listening on {ip}:{port}")
		sock.listen(100)
		cl_sock , addr = sock.accept()

	except Exception as e:
		print(f"[!] Error Binding the socket : {e}")
		print("Terminating ...")
		sys.exit(1)
	else:
		print(f"[+] Received Connection from {addr[0]}:{addr[1]} ..")

	bhSession = paramiko.Transport(cl_sock)
	bhSession.add_server_key(HOSTKEY)
	server = Server()
	bhSession.start_server(server=server)

	channel = bhSession.accept(20)
	if channel is None:
		print("[!] No channel .. \n[!] Terminating ..")
		sys.exit(1)
	
	print("[+] Authenticated ..")
	print(channel.recv(1024))
	channel.send("Welcome to python SSH Server !! ")

	try:
		while True:
			cmd = input("Enter Command : ")
			if cmd != 'exit':
				channel.send(cmd)
				r = channel.recv(4096)
				print(r.decode())
			else:
				channel.send("exit")
				print("Exiting .")
				bhSession.close()
				break

	except KeyboardInterrupt:
		print("[*] Closing the server ")
		bhSession.close()
		cl_sock.close()
		sock.close()
		sys.exit(0)
