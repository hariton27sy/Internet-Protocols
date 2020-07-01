import socket
import argparse
import os
import sys
import re

TEMPLATE = r'\(\|\|\|(\d+)\|\)'


class FTPClient:
    def __init__(self, server, port, filename, login, password, connection_timeout=1, log=False):
        self.server = server
        self.port = port
        self.filename = filename
        self.login = login
        self.password = password
        self.log = log

        socket.setdefaulttimeout(connection_timeout)
        self.socket = socket.socket()
        self.data_socket = socket.socket()

    def start(self):
        try:
            self.socket.connect((self.server, self.port))
        except socket.timeout:
            print('Can not connect to the server', file=sys.stderr)
            return

        try:
            data = self.socket.recv(1024)
            if b'FTP' not in data:
                raise socket.error('Is not FTP server')
        except socket.error:
            print('Connection is not FTP server', file=sys.stderr)
            return

        print(f'Connection to {self.server}:{self.port} established')

        if not self._auth():
            return
        print(f'Authorized using User: {self.login}')

        self._send('HELP')
        data = self._receive()
        command = 'EPSV' if b'EPSV' in data else 'PASV'
        self._send(command)
        data = self._receive().decode('utf8', errors='ignore')
        port = re.search(TEMPLATE, data)
        if port is None:
            print('Cannot send file', file=sys.stderr)
            return

        port = int(port.group(1))
        self.data_socket.connect((self.server, port))
        print(f'Established passive connection through port: {port}')

        self._send(f'STOR {os.path.split(self.filename)[1]}')
        with open(self.filename, 'rb') as f:
            if self._send(f.read(), log=False, sock=self.data_socket):
                print(f'File {self.filename} uploaded')
            else:
                print(f'Cannot send file {self.filename}')
        self.data_socket.close()
        self._receive()

    def _send(self, data: (str, bytes), log=None, sock=None):
        if log is None:
            log = self.log
        if sock is None:
            sock = self.socket
        if isinstance(data, str):
            data = data.encode('utf8')
        if not data.endswith(b'\r\n'):
            data += b'\r\n'

        try:
            sock.send(data)
        except socket.error:
            return False

        if log:
            print(data.decode('utf8', errors='ignore'))

        return True

    def _receive(self, log=None, sock=None):
        if log is None:
            log = self.log
        if sock is None:
            sock = self.socket

        data = b''
        try:
            while True:
                data += sock.recv(65535)
        except socket.timeout:
            pass
        except socket.error:
            return None

        if log:
            print(data.decode('utf8', errors='ignore'))

        return data

    def _auth(self):
        if not self._send(f'USER {self.login}'):
            return False

        data = self._receive()
        if data is None or not data.startswith(b'3'):
            message = ":\n\t" + data.decode("utf8") if data is not None else "."
            print(f'Cannot authorize{message}')
            return False

        self._send(f'PASS {self.password}')
        data = self._receive()
        if data is None or not data.startswith(b'2'):
            message = ":\n\t" + data.decode("utf8") if data is not None else "."
            print(f'Cannot authorize{message}')
            return False

        return True

    def close(self):
        self.socket.close()
        self.data_socket.close()


def parse(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--auth', action='store', type=str, nargs=2, default=['anonymous', 'test@example.com'],
                        help='If server require authorization, enter login and password')
    parser.add_argument('-p', '--port', action='store', type=int, default=21,
                        help='FTP port, 21 by default')
    parser.add_argument('server', action='store', help='FTP server')
    parser.add_argument('filename', action='store', help='File to send')

    args = parser.parse_args(args)

    if not os.path.exists(args.filename) or not os.path.isfile(args.filename):
        print('Path is not found or path is not file', file=sys.stderr)
        exit(2)

    return args


def main(args):
    args = parse(args)
    ftp = FTPClient(args.server, args.port, args.filename, args.auth[0], args.auth[1])
    try:
        ftp.start()
    finally:
        ftp.close()


if __name__ == '__main__':
    main(sys.argv[1:])
