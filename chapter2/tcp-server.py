#!/usr/bin/env python3

import socket
import threading
import argparse
import sys
import psutil

global ip,port

ip = "127.0.0.1"
port = 9999

def list_devices():
    devices_dict = psutil.net_if_addrs()
    addresses = {}

    print("[++] Printing all the network devices : ")

    for inter,ad in devices_dict.items():
        for i in ad:
            if  i.family == 2:
                addresses[inter] = i.address

    for i in list(addresses.items()):
        print(i)

def parseargs():
    global ip,port
    parser = argparse.ArgumentParser(description="TCP SERVER that recieves data and prints it !!")
    parser.add_argument("-ip",'--ipaddr',type=str,help="Enter the ip address on which to listen on..")
    parser.add_argument("-p",'--port',type=int,help="Enter the port to listen on ..")
    parser.add_argument("-ld",'--list-devices',action='store_true',help="Used to print the available devices on the current system")
    args = parser.parse_args()

    if not args.ipaddr:
        print("[*] Using localhost as the default ip address ..")
    else:
        ip = args.ipaddr

    if not args.port:
        print("[*] Using 9999 port number as default port to listen on ..")
    else:
        port = args.port

    if args.list_devices:
        list_devices()

    return (ip,port)

def handlerfunction(clsocket,claddr):
    data = clsocket.recv(4096)
    print(f"[*] Data received from {claddr} : {data.decode('utf-8')}")
    clsocket.send(b"ACK!!")
    clsocket.close()


def main():
   s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
   s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
   s.bind((ip,port))
   s.listen(5)

   print(f"[+] Listening on {ip}:{port} ")

   while True:
       cl,addr = s.accept()

       print(f"[+] Accepted Connection from {addr[0]}:{addr[1]}")

       client_hand = threading.Thread(target=handlerfunction,args=(cl,addr[0],))

       client_hand.start()
        


if __name__ == '__main__':
    parseargs()
    main()
