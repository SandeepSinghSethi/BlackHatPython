#!/usr/bin/env python3

import socket

host = "ipinfo.io"
port = 80

c = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

c.sendto(b'helloworld',(host,port))

data,addr = c.recvfrom(4096)
c.close()

print(data)
