#!/usr/bin/env python3

import paramiko
import socket
import shlex
import argparse
import sys
import getpass
import threading
import select

SH_PORT = 22                                                                                         
DEFAULT_PORT = 1234                                                                                  
                                                                                                     
def parser():                                                                                        
    parser = argparse.ArgumentParser(description="Simple python implementation of reverse ssh port forwarding using paramiko")
    parser.add_argument("-sh","--serverHost",type=str,default="localhost",help="Server host by which forwarding is to be done ..")
    parser.add_argument("-sp","--serverPort",type=int,default=9090,help="The port which we need to forward to remote ssh server")
    parser.add_argument("-rh","--remoteHost",type=str,help="Remote SSH server's ip address")                                                    
    parser.add_argument("-rp","--remotePort",type=int,default=8000,help="Remote SSH server's port to enable forwarding to . ")
    parser.add_argument("-P",'--password',action="store_true",help="To enter the password for the ssh server")                                  
    parser.add_argument("-U","--user",type=str,default="localhost",help="To enter the username of which ssh connection is to be initiated")
                                    
    args = parser.parse_args()                                          
                                    
    if not args.serverHost or not args.serverPort:                                                                                              
        print(f"[!!] Either serverHost or serverPort is not provided by user \n[!!] Using {args.serverHost}:{args.serverPort}")                                         

    if not args.remoteHost or not args.remotePort:                                                                                                                      
        print(f"[-] RemoteHost or RemotePort Not Provided !! \n[-] Terminating Process !")
        parser.print_help()
        sys.exit(1)                               

    if not args.user:                             
        print(f"[*] Username for ssh server is not given , using {args.user} as default .")

    if not args.password:
        print(f"[*] Password is not given for the remote SSH server , it can terminate with an error , so use the -P option ")                                                                            

    return args                                   

def handler(chan,remoteHost,remotePort):
	sock = socket.socket()

	try:
		sock.connect((remoteHost,remotePort))
	except Exception as e:
		print(f"Exception occured : {e}")

	while True:
		r,w,x = select.select([sock,chan],[],[])

		if sock in r:
			data = sock.recv(4096)
			if len(data) == 0:
				break
			chan.send(data)

		if chan in r:
			data = chan.recv(4096)
			if len(data) == 0:
				break
			sock.send(data)

	sock.close()
	chan.close()


def reverse_port_forwarding_tunnel(serverPort,remoteHost,remotePort,transport):
	transport.request_port_forward("",serverPort)
	while True:
		chan = transport.accept(1000)
		if chan is None:
			continue
		thr = threading.Thread(target=handler,args=(chan,remoteHost,remotePort))
		thr.setDaemon(True)
		thr.start()


def main():                                       
    args = parser()                               

    password = None                               
    if args.password:                             
        password = getpass.getpass("Enter SSH Password: ")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"Connecting to SSH remote-> {args.remoteHost}:22")
                                                  
    try:                                        
    	client.connect(args.remoteHost,port=22,username=args.user,password=password)
    except Exception as e:
        print(f"Exception occured :{e}")
        sys.exit(1)                               

    #now we have successfully connected to the remote ssh server , now we are going to initiate a remote port forwarding on that remote host                                                              

    try:                                          
        reverse_port_forwarding_tunnel(args.serverPort,args.remoteHost,args.remotePort,client.get_transport())
    except Exception as e:
    	print(f"Exception occured : {e}")

    client.close()


if __name__ == '__main__':
    main()                                        

