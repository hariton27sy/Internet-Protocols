# Brief manual:
#   Отправителя, получателя письма, дату и тему находим в FETCH {ID} BODY[HEADER]
#   Размер определеяем из FETCH {ID} RFC822.SIZE
#   Информация о вложениях скорее всего в FETCH {ID} BODYSTRUCTURE

import sys
import getpass
import argparse
import re

import socket
import ssl

import m_base64

context = ssl.create_default_context()

atachment_regex = re.compile(r'(\d+) NIL \(\"attachment\" \(\"filename\" \"(.*?)\"\)')

ENCODINGS = {
    'UTF-8': 'utf8'
}


def format_print(data: (str, bytes)):
    if isinstance(data, bytes):
        data = data.decode('utf8', 'ignore')
    len_pref = 0
    new_line = False
    for s in data:
        if s == '\n':
            new_line = True
            print()
            continue
        if s == '\r':
            continue
        if s == ')':
            pref = "\t" * (len_pref - 1)
            print(f'\n{pref}{s}')
            new_line = True
            len_pref -= 1
            continue
        if new_line:
            print('\t' * len_pref, end='')
        print(s, end='')
        new_line = False
        if s == '(':
            len_pref += 1
            new_line = True
            print()


class IMAP:
    def __init__(self, host, port, user, verbose=True, secure=True, indices=None, timeout=1):
        self._sock = None
        self._additional_socket = None
        self.host = host
        self.port = port
        self.secure = secure
        self.verbose = verbose

        self.user = user
        self.start_index = -1
        self.end_index = -1
        if len(indices) > 0:
            self.start_index = indices[0]
        if len(indices) > 1:
            self.end_index = indices[1]

        self.counter = 0

        socket.setdefaulttimeout(timeout)

    def _connect(self):
        try:
            self._sock = socket.create_connection((self.host, self.port))
        except socket.error:
            print('Can not connect to the server')
            exit(0)
        print(f'Common connection has established. Server: {self.host}:{self.port}')

        if self.secure:
            print('Trying to establish preliminary secure connection')
            self._additional_socket = self._sock
            try:
                self._sock = context.wrap_socket(self._sock, server_hostname=self.host)
            except ssl.SSLError:
                print('Can not establish preliminary secure connection')
                self._sock = socket.create_connection((self.host, self.port))
            else:
                print('Preliminary secure connection has established')
                return

            print('Trying to establish secure connection using STARTTLS')
            self._send('A0001 STARTTLS', use_counter=False)
            data = self._receive(False)
            if b'NO' not in data and b'BAD' not in data:
                self._additional_socket = self._sock
                try:
                    self._sock = context.wrap_socket(self._sock, server_hostname=self.host)
                except ssl.SSLError:
                    self._sock = socket.create_connection((self.host, self.port))
                else:
                    self._receive(False)
                    print('Secure connection over STARTTLS has established')
                    return

            print('Can not establish secure connection using STARTTLS.')

        print('WARNING!\nYou use unsafe connection. You shouldn\'t enter confidential data.')

    def start(self):
        self._connect()
        self._receive(False)
        self._auth()
        self._send('SELECT INBOX')
        self._receive(False)
        ids = self._get_messages_ids()
        for id_ in ids:
            sender, receiver, subject, date, size = self._get_message_info(id_)
            attaches = self._get_message_attachments_info(id_)
            print(f'ID: {id_}\nSENDER: {sender}\nRECEIVER: {receiver}\n'
                  f'SUBJECT: {subject}\nDATE: {date}\nSIZE: {size}bytes')
            if attaches:
                print(f'ATTACHES ({len(attaches)}):')
                print('\n'.join(map(lambda x: f'{x[0] + 1}. {x[1][1]}: {x[1][0]}bytes', enumerate(attaches))))
            print()

    def _receive(self, need_print=None):
        if need_print is None:
            need_print = self.verbose

        data = []
        while True:
            try:
                data.append(self._sock.recv(1024))
            except socket.timeout:
                break
            except ConnectionResetError as e:
                raise ConnectionAbortedError(e)
            except ConnectionAbortedError:
                print('Connection closed by server')
                exit(0)
            else:
                if data[-1] == b'':
                    break
        data = b''.join(data)
        if need_print:
            print(data.decode('utf8', 'ignore'))

        return data

    def _send(self, data: (bytes, str), need_print=False, use_counter=True):
        if isinstance(data, str):
            data = data.encode('utf8')

        # Посылка команды для синхронизации ввода, использовалось в тестовом "интерактивном" режиме
        if data == b'\\SYN':
            self._receive()
            return

        if use_counter:
            data = f'A{self.counter} '.encode('utf8') + data
            self.counter += 1

        if data[-2:] != b'\r\n':
            data += b'\r\n'

        try:
            self._sock.send(data)
        except Exception:
            print('Connection closed by server')
            exit(0)

        splitted = data.split()
        if len(splitted) > 1 and splitted[1].upper() == b'LOGOUT':
            print('Connection closed by user')
            self.stop()
            exit(0)
        if need_print:
            print(data.decode('utf8', 'ignore'))

        if use_counter:
            return b'A' + str(self.counter - 1).encode('utf8')

    def _auth(self):
        while True:
            login, password = auth(self.user)
            counter = self._send(f'LOGIN {login} {password}')
            response = self._receive(False)
            if counter + b' OK' in response:
                print('Authentication successful\n')
                break
            print('Login or password is not correct')
            self.user = -1
            # Некоторые сервера разрывают соединение после неправильных данных поэтому пингуем
            for i in range(5):
                self._send('NOOP')
            self._receive(False)

    def _get_messages_ids(self):
        if self.start_index == -1:
            self._send('SEARCH ALL')
        elif self.end_index == -1:
            self._send(f'SEARCH {self.start_index}')
        else:
            self._send(f'SEARCH {self.start_index}:{self.end_index}')
        data = self._receive(False)
        start_index = data.find(b'SEARCH') + 7
        end_index = data.find(b'\r\n', start_index)
        return list(map(int, data[start_index:end_index].split()))

    def _get_message_info(self, id_):
        self._send(f'FETCH {id_} BODY[HEADER]')
        from_, to_, subject, date_ = parse_header(self._receive(False))
        self._send(f'FETCH {id_} RFC822.SIZE')
        data = self._receive(False)
        size_index = data.find(b'SIZE') + 5
        size = int(data[size_index:data.find(b')\r\n', size_index)])

        return from_, to_, subject, date_, size

    def _get_message_attachments_info(self, id_):
        self._send(f'FETCH {id_} BODYSTRUCTURE')
        return atachment_regex.findall(self._receive(False).decode('utf8', 'ignore'))

    def stop(self):
        if self._sock:
            self._sock.close()
        if self._additional_socket:
            self._additional_socket.close()


def parse(args):
    parser = argparse.ArgumentParser(description='IMAP client')
    parser.add_argument('--ssl', action='store_true', help='Using secure connection')
    parser.add_argument('-s', '--server', required=True, action='store', help='Mail Server')
    parser.add_argument('-n', action='store', type=int, nargs='+', default=[],
                        help='Mail indices. Takes 1 or 2 parameters')
    parser.add_argument('-u', '--user', action='store', default=-1, help='Username')

    args = parser.parse_args(args)

    if len(args.n) > 2:
        print('Mail indices parameter takes 1 or 2 parameters')
        exit(2)

    split_host = args.server.split(':')
    args.server = split_host[0]
    args.port = 143
    if len(split_host) > 1:
        args.port = int(split_host[1])

    return args


def auth(login=None):
    if login is None or login == -1:
        login = input('Enter username: ')
    password = getpass.getpass('Enter password: ')

    return login, password


def parse_header(data: bytes):
    from_index = data.rfind(b'From:')
    date_index = data.rfind(b'Date:')
    to_index = data.rfind(b'To:')
    subject_index = data.rfind(b'Subject:')

    sender = data[from_index+6:data.find(b'\r\n', from_index)]
    receiver = data[to_index+4:data.find(b'\r\n', to_index)]
    date_ = data[date_index+6:data.find(b'\r\n', date_index)].decode('utf8')
    subject_end_index = data.find(b'\r\n', subject_index)
    while len(data) > subject_end_index + 2 and data[subject_end_index + 2] == ord(' '):
        subject_end_index = data.find(b'\r\n', subject_end_index + 2)
    subject = data[subject_index+9:subject_end_index]

    sender = ''.join(map(try_decode_base64, sender.split()))
    receiver = ''.join(map(try_decode_base64, receiver.split()))
    subject = ''.join(map(try_decode_base64, subject.split()))

    return sender, receiver, subject, date_


def try_decode_base64(data: bytes):
    if not data.startswith(b'=?'):
        return data.decode('utf8', 'ignore')

    end_encod_index = data.find(b'?', 2)
    encoding = data.decode('utf8')[2:end_encod_index]
    if encoding in ENCODINGS:
        encoding = ENCODINGS[encoding]
    else:
        encoding = 'utf8'
    message = data[end_encod_index + 3:len(data) - 2]
    return m_base64.decode(message).decode(encoding, 'ignore')


def parse_body_structure(data: bytes):
    print(atachment_regex.findall(data.decode('utf8', 'ignore')))


def main(args):
    args = parse(args[1:])
    server = IMAP(args.server, args.port, args.user, secure=args.ssl, indices=args.n)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main(sys.argv)
