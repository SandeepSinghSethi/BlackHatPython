#!/usr/bin/env python3

import paramiko
import os
import threading
import argparse
import sys
import getpass

def parser():
    parser = argparse.ArgumentParser(description="This is a simple implementation of local port forwarding in paramiko  in python3 via ssh ..")
    parser.add_argument('-lh','--localHost',type=str,default='localhost',help="The host on which to apply port forwading to , can be localhost or your local network adapter ip address.")
    parser.add_argument('-lp','--localPort',type=int,default=1234,help="The port on which local port forwarding is to be done")
    parser.add_argument('-rh','--remoteHost',type=str,help="The ip address of the remote host from which the port is to be forwarded..")
    parser.add_argument('-rp','--remotePort',type=int,help="The port of remote server which has to be forwarded")
    parser.add_argument('-s','--sshusername',type=str,default='localhost',help="Username of the ssh server we are going to connect")


    args = parser.parse_args()

    if not args.localHost or not args.localPort:
        print(f"[*] Either localhost or localport is not provided by the user . Using {args.localHost}:{args.localPort} as default")

    if not args.remoteHost or not args.remotePort:
        print("[!] Either remotehost or remoteport is not provided , can't go any further . \n[!!] Terminating the process ..")
        parser.print_help()
        sys.exit(1)

    if not args.sshusername:
        print("Using default user as localhost for the ssh authentication")

    return args

def main():
    args =parser()

    try:
        username = 'localhost'
        if args.sshusername:
            username = args.sshusername
        password = getpass.getpass("Enter SSH Password: ")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(args.remoteHost,port=22,username=username,password=password)

        transport = client.get_transport() # got the transport for the ssh client can establish another client which will create a channel to transport data through and fro

        transport.request_port_forward("",args.localPort,args.remoteHost,args.remotePort)

        # if local_port_forwarding_status:
        #     print(f"[+] Successfully implemented local port forwarding on {args.localHost}:{args.localPort} of remote host {args.remoteHost}:{args.remotePort} , you can access {args.remotePort} on your local machine to get the remote ip's service .")

        try:
            while True:
                pass # keeping the transport connection alive
        except Exception as e:
            print(f"Exception occured : {e}")

        client.close()



    except Exception as e:
        print(f"[!!] Exception occured {e}")





if __name__ == '__main__':
    main()
