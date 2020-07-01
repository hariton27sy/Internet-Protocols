import socket
import threading
import queue
import random

random_time = random.randint(2 ** 16, 2 ** 64 - 1).to_bytes(8, 'big')
udp_to_send = b'\x13' + b'\0' * 39 + random_time


def define_proto(data):
    if len(data) > 4 and data[:4] == b'HTTP':
        return ' HTTP'

    if b'SMTP' in data:
        return ' SMTP'

    if b'POP3' in data:
        return ' POP3'

    if b'IMAP' in data:
        return ' IMAP'

    if len(data) > 11 and data[:2] == udp_to_send[:2] and (data[3] & 1) == 1:
        return ' DNS'

    if len(data) > 39:
        mode = 7 & data[0]
        version = (data[0] >> 3) & 7

        if mode == 4 and version == 2 and random_time == data[24:32]:
            return ' NTP'

    return ''


def make_queue(start_port, end_port, tcp, udp):
    """Максимальное число записей равно 130`000, поэтому решил не заморачиваться"""
    q = queue.Queue()
    for i in range(start_port, end_port + 1):
        if tcp:
            q.put(('t', i))
        if udp:
            q.put(('u', i))

    return q


class Scanner:
    def __init__(self, host: str, start_port: int = 1, end_port: int = 65535, tcp: bool = True,
                 udp: bool = True, timeout: int = 0.5, workers: int = 20):
        self.host = host
        self.ports = make_queue(start_port, end_port, tcp, udp)
        socket.setdefaulttimeout(timeout)

        self.to_print = queue.Queue()
        self.isWorking = True

        self.threads = [threading.Thread(target=self._do_work) for _ in range(workers)]

    def start(self):
        for t in self.threads:
            t.setDaemon(True)
            t.start()
        while not self.ports.empty() and self.isWorking:
            try:
                print(self.to_print.get(block=False))
            except queue.Empty:
                pass

        for t in self.threads:
            t.join()

        while not self.to_print.empty():
            print(self.to_print.get())

    def stop(self):
        self.isWorking = False
        for t in self.threads:
            t.join()

    def _do_work(self):
        while self.isWorking:
            try:
                _type, port = self.ports.get(block=False)
            except queue.Empty:
                break
            else:
                if _type == 't':
                    self._check_tcp(port)
                if _type == 'u':
                    self._check_udp(port)

    def _check_tcp(self, port):
        sock = socket.socket()
        try:
            sock.connect((self.host, port))
        except socket.error:
            pass
        except ConnectionResetError:
            pass
        else:
            sock.send(b'a'*250 + b'\r\n\r\n')
            try:
                data = sock.recv(1024)
                self.to_print.put(f'TCP {port}{define_proto(data)}')
            except socket.timeout:
                self.to_print.put(f'TCP {port}')
        finally:
            sock.close()

    def _check_udp(self, port):
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(udp_to_send, (self.host, port))
            data, host = sender.recvfrom(1024)
        except ConnectionResetError:
            pass
        except socket.timeout:
            self.to_print.put(f'UDP {port}')
        else:
            self.to_print.put(f'UDP {port}{define_proto(data)}')
        finally:
            sender.close()
