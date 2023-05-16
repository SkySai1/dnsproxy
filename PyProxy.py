#!./dns/bin/python3
import logging
import socket
import sys
import threading
import os
import subprocess
import json
import ipaddress
from datetime import datetime
from dnslib import DNSRecord
from multiprocessing import Process

#UDP SOCK
class UDP:
    def __init__(self, ip, port):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ip = ip
        self.port = port

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.udp.close()

    def start(self):
        server_address = (self.ip, self.port)
        self.udp.bind(server_address)
        print(f'Server is UDP listen now: {self.ip, self.port}')
        try:
            while True:
                data, address = self.udp.recvfrom(512) #receive(udp)
                threading.Thread(target=UDP.handle, args=(self, data, address)).start()
        except KeyboardInterrupt:
            pass

    def handle(self, data, addr):
        if addr[0] == source: iplist = dest
        elif addr[0] in dest: iplist = [source]
        else: iplist = None
        if type(iplist) is list:
            for ip in iplist:
                answer = UDP.query(data, (ip, 53))
                self.udp.sendto(answer, addr)
                logger(data,answer,addr[0],ip)

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


#TCP SOCK
class TCP:

    def __init__(self, ip, port):
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = ip
        self.port = port

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.tcp.close()

    def start(self):
        server_address = (self.ip, self.port)
        self.tcp.bind(server_address)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        print(f'Server is TCP listen now: {self.ip, self.port}')
        try:
            while True:
                self.tcp.listen(3)
                self.conn, addr = self.tcp.accept()
                data = self.conn.recv(32768)
                if data:
                    threading.Thread(target=TCP.handle, args=(self, data, addr)).start()
        except KeyboardInterrupt:
            pass

    def handle(self, data, addr):
        if addr[0] == source: iplist = dest
        elif addr[0] in dest: iplist = [source]
        else: ip = None
        if type(iplist) is list:
            for ip in iplist:
                answer = TCP.query(data, (ip, 53))
                self.conn.sendto(answer, addr)
                logger(data,answer,addr[0],ip,False)

        
    def query(data, addr):
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
    

### Основной Блок

def logger(data:bytes, answer:bytes, source, dest, isudp:bool=True):
    try:
        if isudp is True: sep = "UDP"
        else:
            sep = "TCP"
            data = data[2:]
            answer = answer[2:]
        now = datetime.now().strftime('%m/%d %H:%M:%S')
        print('\n')
        print(now, sep)

        if data: message = DNSRecord.parse(data).questions
        else: message = None
        print(f"\t{now} {sep} # From {source} to {dest}: {message}")

        if answer: message = DNSRecord.parse(answer).get_a().rdata
        else: message = None
        print(f"\t{now} {sep} # From {dest} to {source}: {message}")
    except:
        logging.exception(f'{sep} LOGGER')
        pass


def confload(path):
    '''
    Example of config.json:
    {
        "port": 53,
        "listen": "10.162.128.4",
        "source": ["77.73.132.32"],
        "dest": "95.165.134.11",
        "logging": true
    }
    '''
    with open(path, 'r') as j:
        data = json.load(j)
    return data

if __name__ == "__main__":

    try:
        file = sys.argv[1]
    except:
        print('Specify path to config.json')
        sys.exit()

    conf = confload(os.path.abspath(file))
    try:
        listen = conf['listen']
        port = int(conf['port'])
        source = conf['source']
        dest = list(conf['dest'])
        islog = bool(conf['logging'])
        ipaddress.ip_address(listen)
        ipaddress.ip_address(source)
        for ip in dest:
            ipaddress.ip_address(ip)
    except:
        logging.exception('BAD CONFIG')
        sys.exit()

    try:
        with TCP(listen, port) as tcp: 
            tcpfork = Process(target=tcp.start)
            tcpfork.start()
        with UDP(listen, port) as udp: 
            udpfork = Process(target=udp.start)
            udpfork.start()
    except:
        logging.exception('LAUNCH')
        pass
    else:
        try: 
            while True: pass
        except KeyboardInterrupt: 
            tcpfork.terminate()
            udpfork.terminate()
            subprocess.run(["killall", os.path.basename(__file__)])




