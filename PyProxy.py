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
import time
from dnslib import DNSRecord, RCODE
from multiprocessing import Process

# To packet forwards: 
'''
iptables -t nat -A PREROUTING -p udp -d <IP> --dport 53 -j DNAT --to-destination <IP>:<PROXY_PORT>
iptables -L -t nat

To save way #1 (may not work):
    iptables-save > /etc/iptables.rules
    iptables-restore < /etc/iptables.rules
    vi /etc/network/if-pre-up.d/iptables:
        #!/bin/bash
        PATH=/etc:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
        iptables-restore < /etc/iptables.rules
        exit 0 

To save way #2:
    sudo apt-get install iptables-persistent
    sudo netfilter-persistent save
    sudo netfilter-persistent reload
'''


#UDP SOCK
class UDP:
    def __init__(self, ip, port):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # <- Сокет входящих TCP запросов
        self.ip = ip
        self.port = port

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.udp.close()

    def start(self):
        try:
            server_address = (self.ip, self.port)
            self.udp.bind(server_address) # <- Привязываем сокет к адресу и порту
            message = f'Server is UDP listen now: {server_address}'
            logger(message)
            while True:
                try:
                    data, address = self.udp.recvfrom(512) # <- Прослишваем и ловим запросы
                    threading.Thread(target=UDP.handle, args=(self, data, address)).start() # <- Как запрос пришёл отправялем его в отдельный поток
                except Exception as e:
                    logger(str(e))
        except Exception as e:
            #logging.exception('UDP START:')
            logger(str(e))
            subprocess.run(["killall", main])

    def handle(self, data, addr):
        iplist, istosource = handler(addr) # <- обработчик адреса клиента
        if type(iplist) is list:
            stream = []
            for ip in iplist: # <- Перенаправим запрос каждому адрессату в списке
                t = AnswerThread(UDP,data,ip,self.udp,addr) # <- в отдельном потоке
                t.start()
                if istosource is True: # <- Если запрос ушёл Источнику, сразу его обработаем
                    t.join()
                    parser(data, t.answer, addr[0], t.ip, True, t.error)
                    if t.answer: break
                else: # <- Если нет, то сформируем массив потоков и ниже его обработаем по факту завершения каждого из них
                    stream.append(t)
            if stream:
                for t in stream:
                    t.join()
                    parser(data, t.answer, addr[0], t.ip, True, t.error)
                '''answer = UDP.query(data, (ip, 53))
                self.udp.sendto(answer, addr)
                parser(data,answer,addr[0],ip)'''
                #if istosource is True and answer: break

    def query(data, addr):
        try:
            send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # <- Сокет для оптравки UDP сообщений
            send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # <- Разрашаем использовать широковещание
            send.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # <- Разрашаем переиспользовать сокет
            send.settimeout(0.2) # <- Установка таймаута на ответ
            answer = b''
            error = None
            send.sendto(data, addr)
            answer, addr = send.recvfrom(512) # <- В течении ожидаем получений одной датаграммы размеров не более 512 байт
        except Exception as e:
            #logging.exception('UDP QUERY')
            error = str(e)
        finally:
            send.close()
            return answer, error


#TCP SOCK
class TCP:

    def __init__(self, ip, port):
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # <- Сокет входящих TCP запросов
        self.ip = ip
        self.port = port

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.tcp.close()

    # --Функция старта
    def start(self):
        try:
            server_address = (self.ip, self.port) 
            self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1) # <- Для переиспользовании сокета входящих запросов
            self.tcp.bind(server_address) # <- Привязываем сокет к адресу и порту
            message = f'Server is TCP listen now: {server_address}'
            logger(message)
            while True:
                try:
                    self.tcp.listen(3) # <- количество безуспешных попыток подключится
                    self.conn, addr = self.tcp.accept() # <-Принятие запроса
                    self.conn.settimeout(3) # <- лимит времени открытия соединения
                    data = self.conn.recv(32768) # <- Установка соединения и получения данных
                    if data: # <- При получении данных создаём отдельный поток и обрабатываем их
                        threading.Thread(target=TCP.handle, args=(self, data, addr)).start()
                    #self.conn.close() # <- закрытие соединения
                except Exception as e:
                    logging.exception('TCP')
                    logger(str(e))
                    pass
        except Exception as e:
            logging.exception('TCP START:')
            logger(str(e))
            subprocess.run(["killall", main])

    # --Функция для использования в отдельном потоке и обработке данных
    def handle(self, data, addr):
        try:
            iplist = []
            iplist, istosource = handler(addr) # <- обработчик адреса клиента
            if type(iplist) is list:
                stream = []
                for ip in iplist: # <- Перенаправим запрос каждому адрессату в списке
                    t = AnswerThread(TCP,data,ip,self.conn,addr) # <- в отдельном потоке
                    t.start()
                    if istosource is True: # <- Если запрос ушёл Источнику, сразу его обработаем
                        t.join()
                        parser(data, t.answer, addr[0], t.ip, False, t.error)
                        if t.answer: break # <- Если удалось соединиться с первым Источником, то останавливаем
                    else: # <- Если нет, то сформируем массив потоков и ниже его обработаем по факту завершения каждого из них
                        stream.append(t)
                if stream:
                    for t in stream:
                        t.join()
                        parser(data, t.answer, addr[0], t.ip, False, t.error)
        except:
            pass
        finally:
            self.conn.close() # <- После всех операций закрываем соединение


    # -- Функция ответа        
    def query(data, addr):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # <- Сокет для оптравки TCP сообщений
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # <- Разрашаем использовать широковещание
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1) # <- Разрашаем переиспользовать сокет
        s.settimeout(1) # <- Ставим таймаут на получения пакетов после отправки запроса
        try:
            answer = b'' # <- Погдотвим, заранее, пустой ответ
            error = None
            s.connect(addr) # <- Подключаемся 
            s.sendall(data) # <- Отправляем запрос
            packet = True
            while True: # <- В рамках таймаута ждём получения пакетов, затем закрываем соединение, если ответ был большой мы его кастрариуем (и сломаем как следствие)
                try:
                    packet = s.recv(4096)
                    answer+=packet
                except socket.timeout: break # <- Закрываем соединение после таймаута
        except Exception as e:
            logging.exception('TCP QUERY')
            error = str(e)
        finally: 
            s.close()
            return answer, error # <- Возвращаем ответ и ошибку, если есть
    

### Основной Блок

class AnswerThread(threading.Thread):

    def __init__(self, PROTO:UDP|TCP, data, ip, socket:socket.socket, addr:tuple):
        threading.Thread.__init__(self)
        self.value = None
        self.proto = PROTO # <- Универасльный аргумент как для UDP сокета, так и для TCP коннекта
        self.data = data
        self.ip = ip
        self.socket = socket
        self.addr = addr
 
    def run(self):
        answer, error = self.proto.query(self.data, (self.ip, 53)) # <- Перенаправляем запрос в зависимости от протокола и получаем ответ
        try: self.socket.sendto(answer, self.addr) # <- Возращаем инициатору ответ
        except Exception as e: error = str(e)
        self.answer = answer
        self.error = error
        return


# --Обработчик адреса клиента
def handler(addr):
    iplist = [] # <- Лист адресов для отправки ответа
    istosource = False # <- Условие адреса (к Источнику (в конфиге), или от Источника)
    if addr[0] in source: # <- Если входящий адрес относится к Источнику
        try:
            for network in dest: # <- Формируем лист адресов для отправки ответа
                for ip in ipaddress.ip_network(network): # <- Преобразуем сеть в список адресов этой сети
                    iplist.append(str(ip))
        except:
            pass
    else: # <- Если входящий адрес не относится к источнику
        try:
            for network in dest:
                if ipaddress.ip_address(addr[0]) in ipaddress.ip_network(network):
                    iplist = source # <- адрессатом будет Источник
                    istosource = True # <- Явно указываем это
                    break
        except:
                pass
    return iplist, istosource

# -- Обработчик DNS сообщений для последующего их логирования
def parser(data:bytes, answer:bytes|str, source, dest, isudp:bool=True, error:str=None):
    try:
        if isudp is True: sep = "UDP" # <- Если это UDP, то всё ок
        else: # <- Если TCP, то отрежим первые дай байта, как от ответа, так и от запроса
            sep = "TCP" 
            data = data[2:]
            answer = answer[2:]
        if data: # <- Если есть ответ, то это DNS пакет, а значит декодируем его
            message = DNSRecord.parse(data).questions
            id = DNSRecord.parse(data).header.id
        else: 
            message = id = None
        logger(f"{sep} {id} From {source} to {dest}: {message}") # <- Запишем в лог строку запроса
        if answer: # <- Если есть ответ, то декодируем его
            message = f"{RCODE[DNSRecord.parse(answer).header.rcode]}: {DNSRecord.parse(answer).get_a().rdata}"
            id = DNSRecord.parse(data).header.id
        else: 
            message = error
        logger(f"{sep} {id} From {dest} to {source}: {message}") # <- Запише в лог строку ответа
        if _DEBUG >= 2: print('\n', DNSRecord.parse(answer)) # <- Если включен дебаг еще и в консоль выведем 
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
    _DEBUG = False # <- Режим отладки

    
    try:
        file = sys.argv[1] # <- Подключаем файл настроек
        try: # <- Включаем режим отладки при пуске в качестве третьего аругмента
            if sys.argv[2] == '1':
                _DEBUG = 1
            elif sys.argv[2] == '2':
                _DEBUG = 2
        except:
            pass
    except:
        print('Specify path to config.json')
        sys.exit()

    conf = confload(os.path.abspath(file)) # <- получаем абсолютный путь до конфига
    main = os.path.basename(__file__) # <-получаем директория самого файла

    # --Считываем конфиг, в случае несоотетствии формата - ошибка --
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

    if islog is not True: print('Logging of events is disabled!') # <-- Предупреждене об отключении логирование

    try:
        # -- Стартуем TCP сервер как форк-процесс:
        with TCP(listen, port) as tcp: # <- Инициализируем класс и передаём адрес и порт для прослушивания
            tcpfork = Process(target=tcp.start)
            tcpfork.start()
        
        # --Стартуем UDP сервер как форк-процесс:
        with UDP(listen, port) as udp: # <- Инициализируем класс и передаём адрес и порт для прослушивания
            udpfork = Process(target=udp.start)
            udpfork.start()
    except Exception as e: # <- Если что-то пошло не так
        logger(str(e))
        logging.exception('LAUNCH')
        pass
    else:
        # --Конструкция по отслеживанию нажатия CTRL+C и последующей остановки форков
        try: 
            while True: pass
        except KeyboardInterrupt: 
            tcpfork.terminate()
            udpfork.terminate()
            logger('PyProxy was stoped!')
            subprocess.run(["killall", main])




