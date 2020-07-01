import socket
import threading
import sys
import argparse
import queue
import struct
import time
import datetime


TIME_DIFFERENCE = (datetime.date(1970, 1, 1) - datetime.date(1900, 1, 1)).days * 24 * 3600


def format_time(time_):
    return int(time_ * (2 ** 32))


class SNTP:
    _FORMAT = '!BBBb3I4Q'

    def __init__(self, version: int = 3, mode: int = 3, transmit: int = 0, raw: bytes = b'',
                 time_offset: int = 0, **kwargs):
        self.raw = raw
        self.time_offset = time_offset
        self.leap_indicator = 0
        self.version = version
        self.mode = mode
        self.stratum = 0
        self.poll = 0
        self.precision = 0
        self.root_delay = 0
        self.root_dispersion = 0
        self.ref_id = 0
        self.ref_time = 0
        self.originate_time = 0
        self.receive_time = 0
        self.transmit_time = transmit

        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def request_from_bytes(cls, data: bytes):
        if len(data) < 48:
            print('incorrect')
            return SNTP(correct=False)
        version = (data[0] & 56) >> 3
        mode = data[0] & 7
        transmit = int.from_bytes(data[40:48], 'big')
        if mode != 3:
            return None
        return SNTP(version, 4, originate_time=transmit, receive_time=time.time() + TIME_DIFFERENCE)

    def __bytes__(self):
        first = (self.leap_indicator << 6) | (self.version << 3) | self.mode
        receive_time = format_time(self.receive_time + self.time_offset)
        transmit_time = format_time(time.time() + TIME_DIFFERENCE + self.time_offset)
        return struct.pack('>3Bb5I3Q', first, self.stratum, self.poll, self.precision, 0, 0, 0, 0, 0,
                           self.originate_time, receive_time, transmit_time)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        result = ['SNTP(', ", ".join(map(lambda x: f'{x[0]}={x[1]}', self.__dict__.items())), ')']
        return ''.join(result)

    def offset_answer(self, time_offset):
        pass


class UdpServer:
    def __init__(self, server_port: int = 123, time_offset: int = 0, workers: int = 5, timeout: int = 2):
        self.isWorking = True
        self.server_port = server_port
        self.time_offset = time_offset

        self.to_send = queue.Queue()
        self.received = queue.Queue()

        socket.setdefaulttimeout(timeout)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(('', server_port))

        self.receiver = threading.Thread(target=self.receive)
        self.workers = [threading.Thread(target=self.handle_received) for _ in range(workers)]

    def start(self):
        print('Server is starting...')
        for w in self.workers:
            w.setDaemon(True)
            w.start()
        self.receiver.setDaemon(True)
        self.receiver.start()
        print(f'Server has started. Listen on port {self.server_port}.\nTime offset: {self.time_offset}s\n')

        while self.isWorking:
            pass

    def handle_received(self):
        while self.isWorking:
            try:
                sntp, addr = self.received.get(block=False)
            except queue.Empty:
                time.sleep(0.5)
            else:
                if sntp:
                    sntp.time_offset = self.time_offset
                    self.server.sendto(bytes(sntp), addr)

    def receive(self):
        while self.isWorking:
            try:
                data, addr = self.server.recvfrom(1024)
                self.received.put((SNTP.request_from_bytes(data), addr))
                print(f'Request:\nIP: {addr[0]}\nPort: {addr[1]}\n')
            except socket.error:
                pass

    def stop(self):
        print('Server is stopping...')
        self.isWorking = False
        self.receiver.join()
        for w in self.workers:
            w.join()
        self.server.close()
        print('Server has stopped')


def parse_args(args):
    parser = argparse.ArgumentParser(description="SNTP server, that allows to send time with offset.")
    parser.add_argument('-d', action='store', dest='time', type=int, default=0,
                        help='Time offset to right time in seconds. '
                             'Can be position or negative number')
    parser.add_argument('-p', '--port', action='store', type=int, default=123, help='Server port. If port before 1024 '
                                                                                    'requires root user')
    args = parser.parse_args(args)

    if args.port < 1 or args.port > 65535:
        print('Enter correct port', file=sys.stderr)
        exit(2)

    return args


def main(argv):
    args = parse_args(argv[1:])
    server = UdpServer(args.port, args.time, workers=10)
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main(sys.argv)
