#!./dns/bin/python3
import socket
import threading
import sys
import struct
import os
import queue
import time
import subprocess
from dnslib import DNSRecord
from multiprocessing import Process
from scapy.all import *

ip1 = '95.165.134.11'
ip2 = '77.73.132.32'

#UDP SOCK
def query(data, addr):
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send.settimeout(1)
    send.sendto(data, addr)
    try:
        answer, addr = send.recvfrom(512)
    except:
        answer = ''.encode('utf-8')
    send.close()
    return answer

def handle(udp, data, addr):
    if addr[0] == ip1: ip = ip2
    elif addr[0] == ip2: ip = ip1
    else: ip = None
    if ip:
        answer = query(data, (ip, 53))
        udp.sendto(answer, addr)
        try:
            print(f"to {ip}: {DNSRecord.parse(data).questions}")
            print(f"from {ip}: {DNSRecord.parse(answer).rr}")
        except: pass
def udpsock(udp, ip, port):
    server_address = (ip, port)
    udp.bind(server_address)
    while True:
        data, address = udp.recvfrom(512) #receive(udp)
        threading.Thread(target=handle, args=(udp, data, address)).start()

#TCP SOCK

def t_handle(conn, data, addr):
    if addr[0] == ip1: ip = ip2
    elif addr[0] == ip2: ip = ip1
    else: ip = None
    if ip:
        answer = t_sender(data, (ip, 53))
        conn.sendto(answer, addr)

    
def t_sender(data, addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(addr)
    s.sendall(data)
    answer, _ = s.recvfrom(16384)
    s.close()
    return answer
 
def tcpsock(tcp, ip, port):
    server_address = (ip, port)
    tcp.bind(server_address)
    while True:
        tcp.listen(0)
        conn, addr = tcp.accept()
        data = conn.recv(16384)
        if data: t_handle(conn, data, addr)

### Основной Блок

def quiter():
    q = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    q.bind(('127.0.0.1', 5300))
    while True:
        try:
            data, addres = q.recvfrom(1024)
            if data.decode('utf-8') == 'quit':
                subprocess.run(["killall", os.path.basename(__file__)])
        except: pass


def Parallel(data):
    proc = []
    for pos in data:
        for fn in pos:
            if type(pos[fn]) is dict:
                p = Process(target=fn, kwargs=pos[fn])
                p.start()
                proc.append(p)
            else:
                p = Process(target=fn, args=pos[fn])
                p.start()
                proc.append(p)
    for p in proc:
        p.join()


if __name__ == "__main__":
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with open('./pids', 'w+') as f:
        f.write('')
    ip = '192.168.1.10'
    port = 53      
    data = [
            {udpsock: [udp, ip, port]},
            {tcpsock: [tcp, ip, port]},
            {quiter: ''}
        ]
    try:
        Parallel(data)
    except KeyboardInterrupt:
        subprocess.run(["killall", os.path.basename(__file__)])


