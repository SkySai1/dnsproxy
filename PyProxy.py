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

# To packet forwards: 
'''
iptables -t nat -A PREROUTING -p udp -d <IP> --dport 53 -j DNAT --to-destination <IP>:<PROXY_PORT>
iptables -L -t nat
iptables-save > /etc/iptables.rules
iptables-restore < /etc/iptables.rules
vi /etc/network/if-pre-up.d/iptables:
    #!/bin/bash
    PATH=/etc:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
    iptables-restore < /etc/iptables.rules
    exit 0 
'''


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
        try:
            server_address = (self.ip, self.port)
            self.udp.bind(server_address)
            message = f'Server is UDP listen now: {server_address}'
            logger(message)
            while True:
                try:
                    data, address = self.udp.recvfrom(512)
                    threading.Thread(target=UDP.handle, args=(self, data, address)).start()
                except Exception as e:
                    logger(str(e))
        except Exception as e:
            logging.exception('UDP START:')
            logger(str(e))
            subprocess.run(["killall", main])

    def handle(self, data, addr):
        iplist, istosource = handler(addr)
        if type(iplist) is list:
            stream = []
            for ip in iplist:
                t = AnswerThread(UDP,data,ip,self.udp,addr)
                t.start()
                if istosource is True:
                    t.join()
                    parser(data, t.answer, addr[0], t.ip)
                    if t.answer: break
                else:
                    stream.append(t)
            if stream:
                for t in stream:
                    t.join()
                    parser(data, t.answer, addr[0], t.ip)
                '''answer = UDP.query(data, (ip, 53))
                self.udp.sendto(answer, addr)
                parser(data,answer,addr[0],ip)'''
                #if istosource is True and answer: break

    def query(data, addr):
        send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
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
        try:
            server_address = (self.ip, self.port)
            self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.tcp.bind(server_address)
            message = f'Server is TCP listen now: {server_address}'
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
        except Exception as e:
            logging.exception('TCP START:')
            logger(str(e))
            subprocess.run(["killall", main])

    def handle(self, data, addr):
        iplist = []
        iplist, istosource = handler(addr)
        if type(iplist) is list:
            stream = []
            for ip in iplist:
                t = AnswerThread(TCP,data,ip,self.conn,addr)
                t.start()
                if istosource is True:
                    t.join()
                    parser(data, t.answer, addr[0], t.ip, False)
                    if t.answer: break
                else:
                    stream.append(t)
            if stream:
                for t in stream:
                    t.join()
                    parser(data, t.answer, addr[0], t.ip, False)
            ''' answer = TCP.query(data, (ip, 53))
                self.conn.sendto(answer, addr)
                parser(data,answer,addr[0],ip,False)
                if answer: break'''


        
    def query(data, addr):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
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

class AnswerThread(threading.Thread):

    def __init__(self, PROTO:UDP|TCP, data, ip, socket:socket.socket, addr:tuple):
        threading.Thread.__init__(self)
        self.value = None
        self.proto = PROTO
        self.data = data
        self.ip = ip
        self.socket = socket
        self.addr = addr
 
    def run(self):
        answer = self.proto.query(self.data, (self.ip, 53))
        self.socket.sendto(answer, self.addr)
        self.answer = answer



def handler(addr):
    iplist = []
    istosource = False
    if addr[0] in source:
        try:
            for network in dest:
                for ip in ipaddress.ip_network(network):
                    iplist.append(str(ip))
        except:
            pass
    else:
        try:
            for network in dest:
                if ipaddress.ip_address(addr[0]) in ipaddress.ip_network(network):
                    iplist = source
                    istosource = True
                    break
        except:
                pass
    return iplist, istosource

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
        if _DEBUG >= 2: print('\n', DNSRecord.parse(answer))
    except Exception as e:
        logger(str(e))
        pass

def logger(line):
    try:
        if _DEBUG >= 1: print('\n', line)
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
    _DEBUG = False
    try:
        file = sys.argv[1]
        try:
            if sys.argv[2] == '1':
                _DEBUG = 1
            elif sys.argv[2] == '2':
                _DEBUG = 2
        except:
            pass
    except:
        print('Specify path to config.json')
        sys.exit()

    conf = confload(os.path.abspath(file))
    main = os.path.basename(__file__)

    try:
        listen = conf['listen']
        port = int(conf['port'])
        source = conf['source']
        dest = list(conf['dest'])
        islog = bool(conf['logging'])
        logway = os.path.abspath(conf['logfile'])
        ipaddress.ip_address(listen)
        for ip in source:
            ipaddress.ip_address(ip)
        for ip in dest:
            try: ipaddress.ip_address(ip)
            except: 
                broadcast = ipaddress.ip_network(ip)
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
            subprocess.run(["killall", main])




