#!./dns/bin/python3
import logging
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
from decoder import Decoder
from dns.query import *
from scapy.all import *
from scapy.layers.l2 import Ether
from bitstring import BitArray

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
            print('--------------------------------------------')
            print(f"\nto {ip}: {DNSRecord.parse(data)}")
            print(f"\nfrom {ip}: {DNSRecord.parse(answer)}")
            pass
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
        try:
            print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
            print(f"\nto {ip}: {DNSRecord.parse(data[2:])}")
            print(f"\nfrom {ip}: {DNSRecord.parse(answer[2:])}")
            pass
        except:
            logging.exception('TCP')
            pass

    
def t_sender(data, addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(addr)
    s.sendall(data)
    s.settimeout(2)
    answer = b''
    packet = True
    try:
        while packet:
            packet = s.recv(4096)
            answer+=packet
    except socket.timeout: pass
    s.close()
    return answer
 
def tcpsock(tcp, ip, port):
    server_address = (ip, port)
    tcp.bind(server_address)
    try:
        while True:
            tcp.listen(3)
            conn, addr = tcp.accept()
            data = conn.recv(32768)
            if data:
                threading.Thread(target=t_handle, args=(conn, data, addr)).start()
    except KeyboardInterrupt: tcp.close()

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
    ip = '192.168.1.10'
    port = 53      
    data = [
            {udpsock: [udp, ip, port]},
            {tcpsock: [tcp, ip, port]},
            {quiter: ''}
        ]
    try:
        Parallel(data)
        #threading.Thread(target=udpsock, args=(udp,ip,port)).start()
        #threading.Thread(target=tcpsock, args=(tcp,ip,port)).start()
        #sniff(prn=process_and_send, iface='ens192', count=100)
    except KeyboardInterrupt:
        udp.close()
        tcp.close()
        subprocess.run(["killall", os.path.basename(__file__)])


