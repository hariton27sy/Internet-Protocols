import random
import socket


def take_icmp(data: bytes):
    version = (data[0] & 0xf0) // 16
    if version == 4:
        header_length = (data[0] & 0x0f) * 4
        if data[9] == 1:
            return data[header_length:]
    return None


def checksum(data: bytes, checksum_offset: int):
    words = [int.from_bytes(data[_:_ + 2], "big") for _ in range(0, len(data), 2)]
    checksum_ = sum(words)
    while checksum_ > 0xffff:
        checksum_ = (checksum_ & 0xffff) + (checksum_ >> 16)

    return data[:checksum_offset] + int.to_bytes(0xffff - checksum_, 2, 'big') + data[checksum_offset + 2:]


class ICMP:
    TEST_DATA = b'abcdefghijklmnopqrstuvwxyz hello'
    TYPE_ECHO_REQUEST = 8
    TYPE_ECHO_REPLY = 0
    TYPE_TIME_TO_LIVE_EXCEED = 11
    CODE_ECHO = 0

    def __init__(self, type_: int, code: int, other: bytes = None, **kwargs):
        self.type = type_
        self.code = code
        self.other = other
        if self.type == self.TYPE_ECHO_REQUEST or self.TYPE_ECHO_REPLY:
            self.id = random.randint(0, 2 ** 16 - 1)
            self.sequence_number = random.randint(0, 2 ** 16 - 1)
        if self.type == self.TYPE_TIME_TO_LIVE_EXCEED:
            self.child = None

        for key, item in kwargs.items():
            setattr(self, key, item)

    @classmethod
    def from_bytes(cls, data):
        if data[0] == cls.TYPE_TIME_TO_LIVE_EXCEED:
            child = ICMP.from_bytes(take_icmp(data[8:]))
            return ICMP(data[0], data[1], child=child)
        if data[0] == cls.TYPE_ECHO_REPLY or data[0] == cls.TYPE_ECHO_REQUEST:
            return ICMP(data[0], data[1],
                        id=int.from_bytes(data[4:6], 'big'),
                        sequence_number=int.from_bytes(data[6:8], 'big'))

    def __bytes__(self):
        result = bytes([self.type, self.code]) + b'\0\0'
        if self.type == ICMP.TYPE_ECHO_REQUEST:
            result += (int.to_bytes(self.id, 2, 'big') +
                       int.to_bytes(self.sequence_number, 2, 'big'))
        result += ICMP.TEST_DATA
        return checksum(result, 2)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        args = [f'ICMP({self.type}, {self.code}']
        if self.type == self.TYPE_ECHO_REPLY or self.type == self.TYPE_ECHO_REQUEST:
            args.append(f'id={self.id}, sequence_number={self.sequence_number}')
        if self.type == self.TYPE_TIME_TO_LIVE_EXCEED:
            args.append(f'child={repr(self.child)}')
        return ',\n'.join(args) + ')'

    @property
    def checksum(self):
        return 0x83b5

    def is_answer(self, other):
        if other is None:
            return False
        if other.type == ICMP.TYPE_ECHO_REPLY:
            return self.id == other.id and self.sequence_number == other.sequence_number
        if other.type == ICMP.TYPE_TIME_TO_LIVE_EXCEED:
            return (other.child is not None and self.id == other.child.id and
                    self.sequence_number == other.child.sequence_number)


def icmp_sniffer(interf_ip: str, timeout: int = 0):
    """Requires root user"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind((interf_ip, 0))
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    sock.settimeout(timeout)
    return sock


def get_trace(inter_ip: str, dest_ip: str, depth: int = 15, timeout_for_step: int = 2):
    sock = icmp_sniffer(inter_ip, timeout_for_step)

    icmp = ICMP(8, 0, id=random.randint(0, 2 ** 16), sequence_number=15)
    for i in range(1, depth + 1):
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, i)
        icmp.sequence_number += 1
        sock.sendto(bytes(icmp), (dest_ip, 0))
        while True:
            try:
                data_, addr = sock.recvfrom(65535)
                answ_icmp = ICMP.from_bytes(take_icmp(data_))
                if addr[0] == inter_ip or not icmp.is_answer(answ_icmp):
                    continue
                result = addr[0]
            except socket.error:
                result = '*'
            break
        yield result
        if result == dest_ip:
            break
