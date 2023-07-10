#!/usr/bin/env python3

import socket
import os
import sys
import argparse
import threading
import subprocess
import shlex

global ip,port

def execute(cmd):
    cmd = cmd.strip()
    
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd))
    return output.decode()

class Netcat():
    def __init__(self,args,buffer=None):
        self.buffer = buffer
        self.args = args
        self.socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    
    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def send(self):
        self.socket.connect((self.args.ipaddr,self.args.port))
        # print(self.buffer)
        if self.buffer:
            self.socket.send(self.buffer)

        try:
            while True:
                recv_len = 1
                resp = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    resp += data.decode()
                    if recv_len < 4096:
                        break
                if resp:
                    print(resp)
                    buffer = input('> ')
                    buffer += '\n'
                    self.socket.send(buffer.encode())
        except KeyboardInterrupt:
            print('User terminated !! ')
            self.socket.close()
            sys.exit(0)

    def listen(self):
        self.socket.bind((self.args.ipaddr,self.args.port))
        self.socket.listen(5)
        print(f"[+] Listening on {self.args.ipaddr}:{self.args.port}")

        try:
            while True:
                cl,addr = self.socket.accept()
                print(f"[+] Received Connection from {addr[0]}:{addr[1]}")
                clthread = threading.Thread(target=self.handle,args=(cl,))
                clthread.start()
        except KeyboardInterrupt:
            print("[!] Closing listening server ..")
            sys.exit(0)

    def handle(self,client_socket):
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())

        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload,'wb') as f:
                f.write(file_buffer)
            message = f'Saved File {self.args.upload}'
            client_socket.send(message.encode())

        elif self.args.command:
            cmd_buff = b''
            while True:
                try:
                    client_socket.send(b'BHP #> ')
                    while '\n' not in cmd_buff.decode():
                        cmd_buff += client_socket.recv(64)
                    output = execute(cmd_buff.decode())
                    if output:
                        client_socket.send(output.encode())
                    cmd_buff = b''
                except Exception as e :
                    print(f"Server killed {e}")
                    client_socket.send(b'Session terminated !!')
                    client_socket.close()
                    sys.exit(0)

def parseargs():
    global ip,port
    parser = argparse.ArgumentParser(description="Python3 Implementation Of netcat")
    parser.add_argument("-ip","--ipaddr",type=str,help="Enter the ip address to connect to ..")
    parser.add_argument("-p","--port",type=int,help="Enter the port number to connect to ..")
    parser.add_argument("-l","--listen",action='store_true',help="To listen on a specific port")
    parser.add_argument("-c","--command",action='store_true',help="Get the command shell ..")
    parser.add_argument("-e","--execute",type=str,help="Execute system command")
    parser.add_argument("-u","--upload",type=str,help="Upload a file to the remote server")

    args = parser.parse_args()

    if not args.ipaddr or not args.port:
        parser.print_help()
        sys.exit(1)

    if args.ipaddr:
        ip = args.ipaddr

    if args.port:
        port = args.port

    return args

if __name__ == '__main__':
    global ip,port
    args = parseargs()

    if args.listen:
        buffer = ""
    else:
        print("[*] Press CTRL+D to send data ...")
        buffer = sys.stdin.read()


    nc = Netcat(args,buffer.encode())
    nc.run()

