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
        message = f'Server is UDP listen now: {server_address}'
        print(message)
        logger(message)
        while True:
            try:
                data, address = self.udp.recvfrom(512)
                threading.Thread(target=UDP.handle, args=(self, data, address)).start()
            except Exception as e:
                logger(str(e))


    def handle(self, data, addr):
        if addr[0] == source: iplist = dest
        elif addr[0] in dest: iplist = [source]
        else: iplist = None
        if type(iplist) is list:
            for ip in iplist:
                answer = UDP.query(data, (ip, 53))
                self.udp.sendto(answer, addr)
                parser(data,answer,addr[0],ip)

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
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.tcp.bind(server_address)
        message = f'Server is TCP listen now: {server_address}'
        print(message)
        logger(message)
        while True:
            try:
                self.tcp.listen(3)
                self.conn, addr = self.tcp.accept()
                data = self.conn.recv(32768)
                if data:
                    threading.Thread(target=TCP.handle, args=(self, data, addr)).start()
            except Exception as e:
                logger(str(e))
                pass

    def handle(self, data, addr):
        if addr[0] == source: iplist = dest
        elif addr[0] in dest: iplist = [source]
        else: ip = None
        if type(iplist) is list:
            for ip in iplist:
                answer = TCP.query(data, (ip, 53))
                self.conn.sendto(answer, addr)
                parser(data,answer,addr[0],ip,False)

        
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

def parser(data:bytes, answer:bytes, source, dest, isudp:bool=True):
    try:
        if isudp is True: sep = "UDP"
        else:
            sep = "TCP"
            data = data[2:]
            answer = answer[2:]
        if data: 
            message = DNSRecord.parse(data).questions
            id = DNSRecord.parse(data).header.id
        else: 
            message = id = None
        logger(f"{sep} {id} From {source} to {dest}: {message}")

        if answer: 
            message = DNSRecord.parse(answer).get_a().rdata
            id = DNSRecord.parse(data).header.id
        else: 
            message = id = None
        logger(f"{sep} {id} From {dest} to {source}: {message}")
    except Exception as e:
        logger(str(e))
        pass

def logger(line):
    try:
        if conf['logging'] is True:
            now = datetime.now().strftime('%m/%d/%Y %H:%M:%S')
            with open(logway, 'a+') as log:
                log.write(now + ' ' + line + '\n')
    except:
        logging.exception('LOGGER:')

def confload(path):
    '''
    Example of config.json:
    {
        "port": 53,
        "listen": "10.162.128.4",
        "source": "95.165.134.11",
        "dest": ["77.73.132.32", "8.8.8.8"],
        "logging": true,
        "logfile": "./pyproxy.log"
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
        logway = os.path.abspath(conf['logfile'])
        ipaddress.ip_address(listen)
        ipaddress.ip_address(source)
        for ip in dest:
            ipaddress.ip_address(ip)
    except:
        logging.exception('BAD CONFIG')
        sys.exit()

    if islog is not True: print('Logging of events is disabled!')

    try:
        with TCP(listen, port) as tcp: 
            tcpfork = Process(target=tcp.start)
            tcpfork.start()
        with UDP(listen, port) as udp: 
            udpfork = Process(target=udp.start)
            udpfork.start()
    except Exception as e:
        logger(str(e))
        logging.exception('LAUNCH')
        pass
    else:
        try: 
            while True: pass
        except KeyboardInterrupt: 
            tcpfork.terminate()
            udpfork.terminate()
            logger('PyProxy was stoped!')
            subprocess.run(["killall", os.path.basename(__file__)])




