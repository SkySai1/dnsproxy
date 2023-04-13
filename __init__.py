#!./dns/bin/python3
import socket
import threading
import sys
from dnslib import DNSRecord
from multiprocessing import Process

#UDP SOCK
def sender(data, addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(data, addr)
    answer, _ = s.recvfrom(512)
    s.close()
    return answer


def back(s, data, addr):
    s.sendto(data, addr)
    answer, _ = s.recvfrom(512)
    s.close()
    return answer

def handle(s, data, addr):
    if addr[0] == '95.165.134.11':
        answer = sender(data, ('77.73.132.32', 53))
        #print(DNSRecord.parse(answer))
        back(s, answer, addr)

    elif addr[0] == '77.73.132.32':
        answer = sender(data, ('95.165.134.11', 53))
        #print(DNSRecord.parse(answer))
        back(s, answer, addr)

#TCP SOCK

def t_handle(conn, data, addr):
    if addr[0] == '95.165.134.11':
        answer = t_sender(data, ('77.73.132.32', 53))
        #print(DNSRecord.parse(answer))
        t_back(s, answer, addr)

    elif addr[0] == '77.73.132.32':
        answer = t_sender(data, ('95.165.134.11', 53))
        #print(DNSRecord.parse(answer))
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
    #answer, _ = conn.recv(16384)
    conn.close()

def udpsock(ip, port):
    while True:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = (ip, port)
        udp.bind(server_address)
        data, address = udp.recvfrom(512)
        handle(udp, data, address)
        #threading.Thread(target=handle, args=(udp, data, address )).start()


def tcpsock(ip, port):
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (ip, port)
    tcp.bind(server_address)
    tcp.listen(1)
    while True:
        conn, addr = tcp.accept()
        data = conn.recv(16384)
        #print(conn)
        t_handle(conn, data, addr)
        try: print(DNSRecord.parse(data))
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
    ip = '192.168.1.10'
    port = 53        
    data = [
            {udpsock: [ip, port]},
            {tcpsock: [ip, port]}
        ]
    Parallel(data)


