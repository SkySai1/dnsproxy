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
ip2 = '192.168.1.12'

#UDP SOCK
def sender(data, addr):
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send.sendto(data, addr)
    answer, addr = receive(send)
    send.close()
    if not answer: answer = ''.encode('utf-8')
    return answer


def back(udp, data, addr):
    #udp.settimeout(1)
    udp.sendto(data, addr)
    try: answer, addr = receive(udp)
    except: answer = None
    return answer

def handle(udp, data, addr):
    if addr[0] == ip1: ip = ip2
    elif addr[0] == ip2: ip = ip1
    else: ip = None
    if ip:
        print(f'\nto {ip}: {DNSRecord.parse(data).questions}')
        answer = sender(data, (ip, 53))
        
        print(f'from {ip}: {DNSRecord.parse(answer).rr}')
        if answer: back(udp, answer, addr)


def receive(udp): 
    #udp.settimeout(2) # TimeOut
    while True:
        try:
            data, addres = udp.recvfrom(512)
        except Exception as e:
            print(e)
            data = ''   # Если ни каких данных не пришло, возвращаем пустые данные
            addres = ('', 0)
            return data, addres
        return data, addres

def udpsock(udp, ip, port):
    server_address = (ip, port)
    udp.bind(server_address)
    while True:
        data, address = receive(udp) #udp.recvfrom(512)
        #handle(udp, data, address)
        threading.Thread(target=handle, args=(udp, data, address )).start()



#TCP SOCK

def t_handle(conn, data, addr):
    if addr[0] == ip1: ip = ip2
    elif addr[0] == ip2: ip = ip1
    else: ip = None
    if ip:
        print('\n',data)
        answer = t_sender(data, (ip, 53))
        print('\n', answer)
        t_back(conn, answer, addr)

    

def t_sender(data, addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(addr)
    s.sendall(data)
    answer, _ = s.recvfrom(16384)
    s.close()
    return answer

def t_back(conn, data, addr):
    conn.sendto(data, addr)
    try: 
        answer, _ = conn.recv(16384)
        return answer
    except: conn.close()
    

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
            #{tcpsock: [tcp, ip, port]},
            {quiter: ''}
        ]
    try:
        Parallel(data)
    except KeyboardInterrupt:
        subprocess.run(["killall", os.path.basename(__file__)])


