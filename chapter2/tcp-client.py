#!/usr/bin/env python3

import socket
import json

host = "ipinfo.io"
port = 80

c = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
c.connect((host,port))

c.send(b"GET / HTTP/1.1\r\nHost: ipinfo.io\r\n\r\n")

resp = c.recv(4096).decode().split('\r\n\r\n')[1]
resp = json.dumps(resp,indent=2)

c.close()
print(resp)
